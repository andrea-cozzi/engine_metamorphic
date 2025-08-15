import hashlib
import json
import logging
import random
from typing import Any, Dict, List, Optional, Set, Tuple

import capstone as cap
import lief
from engine_meta.engine_cfg import EngineMetaCFG, BasicBlock
from model import file_model
from shared.common_def import is_terminator
from shared.constants import TERMINATOR_TYPE

logger = logging.getLogger(__name__)

class MetamorphicEngine:
    """Motore completo per analisi e trasformazioni metamorfica di binari."""

    def __init__(self, file: file_model.FileModel):
        if file is None:
            raise ValueError("FileModel non può essere None")
        self.file = file
        self.arch = file.arch
        self.mode = file.mode
        self.cfg: Optional[EngineMetaCFG] = None

        logger.info(f"ARCHITECTURE: {self.arch}\t MODE:{self.mode} DI CAPSTONE")

    # ----------------------------
    # Disassemblaggio
    # ----------------------------
    def _get_base_address(self) -> int:
        binary = self.file.binary
        if isinstance(binary, lief.PE.Binary):
            return binary.optional_header.imagebase
        elif isinstance(binary, lief.ELF.Binary):
            load_segments = [s for s in binary.segments if s.type == lief.ELF.SEGMENT_TYPES.LOAD]
            return min((s.virtual_address for s in load_segments), default=0)
        raise ValueError("Formato binario non supportato.")

    def _disassemble(self, code_bytes: bytes, start_addr: int) -> List[cap.CsInsn]:
        md = cap.Cs(self.arch, self.mode)
        md.detail = True
        md.skipdata = True

        def skip_cb(insn: cap.CsInsn, size: int) -> int:
            logger.warning(f"Ignorata istruzione dati a 0x{insn.address:x} di {size} byte")
            return size

        md.skipdata_cb = skip_cb
        instructions = list(md.disasm(code_bytes, start_addr))
        logger.info(f"Disassemblate {len(instructions)} istruzioni dalla sezione")
        return instructions

    # ----------------------------
    # CFG
    # ----------------------------
    def create_graph_cfg(self, section: str = ".text") -> Optional[EngineMetaCFG]:
        text_section = self.file.binary.get_section(section)
        if not text_section:
            logger.warning(f"Sezione '{section}' non trovata.")
            return None

        section_address = self._get_base_address() + text_section.virtual_address
        code_bytes = bytes(text_section.content)
        instructions = self._disassemble(code_bytes, section_address)
        self.cfg = self._analyze(instructions)
        return self.cfg

    def _analyze(self, instructions: List[cap.CsInsn]) -> Optional[EngineMetaCFG]:
        if not instructions:
            return None

        cfg = EngineMetaCFG()
        leaders, addr_to_idx = self._find_leaders(instructions)
        sorted_leaders = sorted(leaders)
        leader_set = set(sorted_leaders)

        for i, start_addr in enumerate(sorted_leaders):
            block = BasicBlock(start_addr, self.arch, self.mode)
            next_leader = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else float("inf")
            idx = addr_to_idx[start_addr]

            while idx < len(instructions) and instructions[idx].address < next_leader:
                block.add_instruction(instructions[idx])
                idx += 1

            if block.instructions:
                cfg.add_block(block)

        cfg.link_successors()
        return cfg

    def _find_leaders(self, instructions: List[cap.CsInsn]) -> Tuple[List[int], Dict[int, int]]:
        leaders = set()
        addr_to_idx = {instr.address: idx for idx, instr in enumerate(instructions)}

        if instructions:
            leaders.add(instructions[0].address)

        for idx, instr in enumerate(instructions):
            try:
                term_type, is_conditional = is_terminator(instr)
            except Exception:
                term_type, is_conditional = None, False

            if term_type:
                if idx + 1 < len(instructions):
                    leaders.add(instructions[idx + 1].address)
                if term_type in (TERMINATOR_TYPE.JUMP, TERMINATOR_TYPE.CALL):
                    try:
                        for op in getattr(instr, 'operands', []):
                            if hasattr(op, 'imm'):
                                imm_addr = op.imm
                                if imm_addr in addr_to_idx:  # <-- aggiungi controllo
                                    leaders.add(imm_addr)
                    except Exception as e:
                        logger.error(f"error: find_leaders: {e}")
                        pass
        return sorted(leaders), addr_to_idx

    # ----------------------------
    # Analisi dipendenze
    # ----------------------------
    @staticmethod
    def _x86_ops(instr: cap.CsInsn):
        if getattr(instr, "detail", None) is None:
            return []
        x86 = getattr(instr.detail, "x86", None)
        return getattr(x86, "operands", []) if x86 else []

    @staticmethod
    def _regs_access(instr: cap.CsInsn) -> Tuple[List[int], List[int]]:
        if hasattr(instr, "regs_access"):
            try:
                return instr.regs_access()
            except Exception:
                pass
        rr = getattr(instr, "regs_read", []) or []
        rw = getattr(instr, "regs_write", []) or []
        return list(rr), list(rw)

    @staticmethod
    def _has_access_flag(op, flag: int) -> bool:
        if hasattr(op, "access"):
            try:
                return (op.access & flag) != 0
            except Exception:
                return True
        return True

    @staticmethod
    def _mem_addr_str(instr: cap.CsInsn, op: cap.x86.X86Op) -> str:
        parts = []
        if op.mem.base:
            parts.append(instr.reg_name(op.mem.base))
        if op.mem.index:
            parts.append(f"{instr.reg_name(op.mem.index)}*{op.mem.scale}")
        if op.mem.disp:
            parts.append(f"{op.mem.disp:#x}")
        return f"MEM[{'+'.join(parts) if parts else '0'}]"

    def _get_read_set(self, instr: cap.CsInsn) -> Set[str]:
        read: Set[str] = set()
        regs_r, _ = self._regs_access(instr)
        read.update(instr.reg_name(r) for r in regs_r)
        for op in self._x86_ops(instr):
            if op.type == cap.x86.X86_OP_MEM and self._has_access_flag(op, cap.CS_AC_READ):
                read.add(self._mem_addr_str(instr, op))
        return read

    def _get_write_set(self, instr: cap.CsInsn) -> Set[str]:
        write: Set[str] = set()
        _, regs_w = self._regs_access(instr)
        write.update(instr.reg_name(r) for r in regs_w)
        for op in self._x86_ops(instr):
            if op.type == cap.x86.X86_OP_MEM and self._has_access_flag(op, cap.CS_AC_WRITE):
                write.add(self._mem_addr_str(instr, op))
        return write

    def are_instructions_independent(self, inst1: cap.CsInsn, inst2: cap.CsInsn) -> bool:
        if not inst1 or not inst2:
            return False
        read1, write1 = self._get_read_set(inst1), self._get_write_set(inst1)
        read2, write2 = self._get_read_set(inst2), self._get_write_set(inst2)
        return write1.isdisjoint(read2) and read1.isdisjoint(write2) and write1.isdisjoint(write2)

    def are_blocks_independent(self, block_a_addr: int, block_b_addr: int) -> Optional[bool]:
        if self.cfg is None:
            raise RuntimeError("CFG non impostato")
        if block_a_addr == block_b_addr:
            return True
        block1 = self.cfg.blocks.get(block_a_addr)
        block2 = self.cfg.blocks.get(block_b_addr)
        if not block1 or not block2:
            return False
        if not block1.instructions or not block2.instructions:
            return True
        for inst1 in block1.instructions:
            for inst2 in block2.instructions:
                if not self.are_instructions_independent(inst1, inst2):
                    return False
        return True

    # ----------------------------
    # Permutazioni
    # ----------------------------
    def instruction_permutation(self, addr1: int, addr2: int, block: BasicBlock) -> None:
        inst1 = block.instructions_map.get(addr1)
        inst2 = block.instructions_map.get(addr2)
        if not inst1 or not inst2:
            raise RuntimeError("Indirizzi non presenti nel blocco")
        if self.are_instructions_independent(inst1, inst2):
            block.swap_instructions(inst1, inst2)
            logger.info("Istruzioni scambiate 0x%x ↔ 0x%x", addr1, addr2)

    def block_permutation(self, addr1: Optional[int] = None, addr2: Optional[int] = None, percent: int = -1) -> int:
        if self.cfg is None:
            raise RuntimeError("CFG non impostato")
        if addr1 is not None and addr2 is not None:
            self.cfg.swap_blocks(addr1, addr2)
            return 1
        if addr1 is None and addr2 is None:
            percent = 50 if percent == -1 else percent
            return self._swap_random_blocks_by_percent(percent)
        raise SyntaxError("Fornire entrambi gli indirizzi o nessuno dei due.")

    def _swap_random_blocks_by_percent(self, percent: int = 40) -> int:
        block_addresses = list(self.cfg.blocks.keys())
        total_blocks = len(block_addresses)
        if total_blocks < 2:
            return 0
        target_swaps = max(0, int((total_blocks * (percent / 100.0)) / 2))
        if target_swaps == 0:
            return 0
        random.shuffle(block_addresses)
        swapped = 0
        for addr1, addr2 in zip(block_addresses[::2], block_addresses[1::2]):
            if swapped >= target_swaps:
                break
            try:
                if self.are_blocks_independent(addr1, addr2):
                    self.cfg.swap_blocks(addr1, addr2)
                    swapped += 1
            except Exception:
                continue
        return swapped

    # ----------------------------
    # Hash
    # ----------------------------
    @staticmethod
    def calculate_hash(inst_list: List[cap.CsInsn]) -> str:
        m = hashlib.md5()
        for instr in inst_list:
            m.update(instr.bytes)
        return m.hexdigest()
    
    def test_and_compare_hashes(self, cfg: EngineMetaCFG, percent: int = 50) -> None:
        """Esegue permutazioni sui blocchi e confronta l'hash MD5 complessivo prima/dopo."""
        if cfg is None:
            raise ValueError("CFG non può essere None")

        # Funzione interna per calcolare hash complessivo del CFG
        def overall_cfg_hash(cfg: EngineMetaCFG) -> str:
            m = hashlib.md5()
            # Ordinare i blocchi per indirizzo per consistenza
            for addr in sorted(cfg.blocks.keys()):
                block = cfg.blocks[addr]
                for instr in block.instructions:
                    m.update(instr.bytes)
            return m.hexdigest()

        # Hash iniziale complessivo
        original_hash = overall_cfg_hash(cfg)
        logger.info(f"MD5 complessivo prima della permutazione: {original_hash}")

        # Swap dei blocchi
        swapped = self._swap_random_blocks_by_percent(percent)
        logger.info(f"Swapped {swapped} blocks")

        # Hash finale complessivo
        new_hash = overall_cfg_hash(cfg)
        logger.info(f"MD5 complessivo dopo la permutazione: {new_hash}")

        # Confronto
        if original_hash != new_hash:
            logger.info("CFG modificato dopo la permutazione")
        else:
            logger.info("CFG invariato dopo la permutazione")

        


    # ----------------------------
    # Salvataggio CFG
    # ----------------------------
    def save_cfg(self, path: str) -> None:
        if self.cfg is None:
            raise RuntimeError("CFG non impostato")
        serializable_cfg = {addr: block.to_dict() for addr, block in self.cfg.blocks.items()}
        with open(path, "w") as f:
            json.dump(serializable_cfg, f, indent=2)
        logger.info(f"CFG salvato in {path}")