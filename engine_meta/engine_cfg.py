import logging
from typing import List, Dict, Optional, Set
import capstone as cap
import keystone as ks
from shared.common_def import capstone_to_keystone, is_terminator
from shared.constants import CAPSTONE_TO_KEYSTONE_MAP, X86_FLOW_INSTRUCTIONS, TERMINATOR_TYPE

logger = logging.getLogger(__name__)



# ----------------------------
# Basic Block --> NON SUPPORTA I SALTI A 64 BIT
# PER COLPA DELLA LIBRERIA, TROVARE UN NUOVO METODO
# ----------------------------
class BasicBlock:
    """Rappresenta un blocco di base con istruzioni, terminatore e collegamenti nel CFG."""

    def __init__(self, start_address: int, arch: int, mode: int):
        self.start_address: int = start_address
        self.end_address: int = start_address
        self.instructions: List[cap.CsInsn] = []
        self.successors: List[int] = []
        self.terminator: Optional[cap.CsInsn] = None
        self.terminator_type: Optional[TERMINATOR_TYPE] = None
        self.instructions_map: Dict[int, cap.CsInsn] = {}
        self.arch = arch
        self.mode = mode

    def add_instruction(self, instruction: cap.CsInsn) -> None:
        if not instruction:
            return
        self.instructions.append(instruction)
        self.end_address = instruction.address
        self.instructions_map[instruction.address] = instruction

    def set_terminator(self, instruction: cap.CsInsn, term_type: TERMINATOR_TYPE) -> None:
        self.terminator = instruction
        self.terminator_type = term_type
        self.end_address = instruction.address + instruction.size

    def create_instruction(self, asm_string: str, address: int, target_address: int = None):
        try:
            # Converte Capstone -> Keystone
            ks_arch, ks_modes_map = CAPSTONE_TO_KEYSTONE_MAP[self.arch]
            ks_mode = ks_modes_map[self.mode]

            ks_engine = ks.Ks(ks_arch, ks_mode)

            parts = asm_string.strip().split(maxsplit=1)
            mnemonic = parts[0].lower()
            operands = parts[1] if len(parts) > 1 else ""

            # Controlla se è salto condizionale
            info = X86_FLOW_INSTRUCTIONS.get(mnemonic)
            if info and info[0] == TERMINATOR_TYPE.JUMP and info[1]:  # salto condizionale
                if target_address is not None:
                    size_of_jump = 6  # stima dimensione jump
                    rel_offset = target_address - (address + size_of_jump)
                    operands = f"{rel_offset:+}"  # formato +N o -N
                    asm_string = f"{mnemonic} {operands}"

            # Assembla con Keystone
            bytecode, _ = ks_engine.asm(asm_string.encode("utf-8"), addr=address)

            cs_engine = cap.Cs(self.arch, self.mode)
            cs_engine.detail = True
            cs_engine.skipdata = True

            def skip_cb(insn: cap.CsInsn, size: int) -> int:
                logger.warning(f"Ignorata istruzione dati a 0x{insn.address:x} di {size} byte")
                return size

            cs_engine.skipdata_cb = skip_cb
            instructions = list(cs_engine.disasm(bytecode, address))
            if not instructions:
                logger.error(f"[engine_cfg] Non sono riuscito a disassemblare '{asm_string}' a {hex(address)}")
                return None

            return instructions[0] if len(instructions) == 1 else None 

        except ks.KsError as e:
            logger.error(f"[engine_cfg] Errore creando '{asm_string}' a {hex(address)}: {e}")
            return None

    def recalculate_addresses(self) -> None:
        """Ricalcola gli indirizzi delle istruzioni."""
        current_address = self.start_address
        new_instructions = []

        for old_instruction in self.instructions:
            asm_string = f"{old_instruction.mnemonic} {old_instruction.op_str}".strip()
            
            # Controlla se è un salto condizionale usando X86_FLOW_INSTRUCTIONS
            target_address = None
            info = X86_FLOW_INSTRUCTIONS.get(old_instruction.mnemonic.lower())
            if info and info[0] == TERMINATOR_TYPE.JUMP and info[1]:  # salto condizionale
                for op in getattr(old_instruction, 'operands', []):
                    if hasattr(op, 'imm'):
                        target_address = op.imm
                        break

            new_inst = self.create_instruction(asm_string, current_address, target_address=target_address)
            
            if not new_inst:
                logger.warning(f"Impossibile ricreare '{asm_string}', salto ricreazione")
                continue

            new_instructions.append(new_inst)
            current_address += new_inst.size

        self.instructions = new_instructions
        self.instructions_map = {inst.address: inst for inst in self.instructions}
        self.end_address = self.instructions[-1].address if self.instructions else self.start_address


    def swap_instructions(self, inst_one: cap.CsInsn, inst_two: cap.CsInsn) -> None:
        try:
            idx1 = next(i for i, inst in enumerate(self.instructions) if inst.address == inst_one.address)
            idx2 = next(i for i, inst in enumerate(self.instructions) if inst.address == inst_two.address)
        except StopIteration:
            raise ValueError("Una o entrambe le istruzioni non sono presenti.")

        if self.terminator in (self.instructions[idx1], self.instructions[idx2]):
            raise ValueError("Non è possibile scambiare il terminatore.")

        self.instructions[idx1], self.instructions[idx2] = self.instructions[idx2], self.instructions[idx1]
        self.recalculate_addresses()

    def __repr__(self) -> str:
        term_type = self.terminator_type.name if self.terminator_type else "FALLTHROUGH"
        return f"<Block start={hex(self.start_address)}, end={hex(self.end_address)}, terminator={term_type}, successors={[hex(s) for s in self.successors]}>"

    def to_dict(self) -> dict:
        return {
            "start_address": self.start_address,
            "arch": self.arch,
            "mode": self.mode,
            "count": len(self.instructions),
            "instructions": [
                {
                    "address": instr.address,
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "bytes": instr.bytes.hex()
                }
                for instr in self.instructions
            ],
            "successors": list(self.successors) if hasattr(self, "successors") else []
        }


# ----------------------------
# EngineMeta CFG
# ----------------------------
class EngineMetaCFG:
    """CFG compatibile con EngineMeta, con swap fisico/logico e gestione robusta errori."""

    MAX_JUMP_DISTANCE = 0x70000000  # ~1.8 GB
    ZERO_OPERAND_TERMINATORS = {"ret", "iret", "nop"}

    def __init__(self):
        self.blocks: Dict[int, BasicBlock] = {}
        self.predecessors: Dict[int, List[int]] = {}

    def add_block(self, block: BasicBlock) -> None:
        if not isinstance(block, BasicBlock):
            raise TypeError("Expected a BasicBlock instance")
        self.blocks[block.start_address] = block
        for succ in block.successors:
            self.predecessors.setdefault(succ, []).append(block.start_address)

    def link_successors(self):
        leader_set = set(self.blocks.keys())

        for block in self.blocks.values():
            if not block.instructions:
                block.successors = set()
                continue

            last_instr = block.instructions[-1]
            successors: Set[int] = set()

            try:
                term_type, is_conditional = is_terminator(last_instr)
            except Exception:
                term_type, is_conditional = None, False

            if term_type:
                if term_type in (TERMINATOR_TYPE.JUMP, TERMINATOR_TYPE.CALL):
                    for op in getattr(last_instr, 'operands', []):
                        if hasattr(op, 'imm') and op.imm in leader_set:
                            successors.add(op.imm)

                if is_conditional:
                    next_addr = last_instr.address + last_instr.size
                    if next_addr in leader_set:
                        successors.add(next_addr)
            else:
                next_addr = last_instr.address + last_instr.size
                if next_addr in leader_set:
                    successors.add(next_addr)

            block.successors = successors

    def _update_predecessor_map(self, parent: BasicBlock, old_succ: int, new_succ: int) -> None:
        if old_succ in self.predecessors:
            self.predecessors[old_succ] = [p for p in self.predecessors[old_succ] if p != parent.start_address]
        self.predecessors.setdefault(new_succ, []).append(parent.start_address)

    def _physically_swap_blocks(self, addr_a: int, addr_b: int) -> None:
        block_a, block_b = self.blocks[addr_a], self.blocks[addr_b]
        block_a.start_address, block_b.start_address = block_b.start_address, block_a.start_address
        block_a.recalculate_addresses()
        block_b.recalculate_addresses()
        del self.blocks[addr_a], self.blocks[addr_b]
        self.blocks[block_a.start_address] = block_a
        self.blocks[block_b.start_address] = block_b
        logger.info(f"Physical swap completed: {hex(addr_a)} ↔ {hex(addr_b)}")

    def _logically_swap_blocks(self, addr_a: int, addr_b: int,
                               preds_a: List[BasicBlock], preds_b: List[BasicBlock]) -> None:
        modifications = (
            [{"parent": p, "old": addr_a, "new": addr_b} for p in preds_a] +
            [{"parent": p, "old": addr_b, "new": addr_a} for p in preds_b]
        )

        for mod in modifications:
            parent = mod["parent"]
            term = parent.terminator
            if not term:
                continue

            distance = abs(mod["new"] - term.address)
            if distance > self.MAX_JUMP_DISTANCE:
                continue

            mnemonic = term.mnemonic.lower()
            new_asm = mnemonic if mnemonic in self.ZERO_OPERAND_TERMINATORS else f"{mnemonic} {hex(mod['new'])}"

            try:
                new_term = parent.create_instruction(new_asm, term.address)
                if not new_term:
                    logger.warning(f"Impossibile ricreare terminatore '{new_asm}', salto swap per questo parent")
                    continue

                parent.instructions[-1] = new_term
                parent.set_terminator(new_term, parent.terminator_type)
                if mod["old"] in parent.successors:
                    parent.successors.remove(mod["old"])
                parent.successors.append(mod["new"])
                self._update_predecessor_map(parent, mod["old"], mod["new"])

            except Exception as e:
                logger.warning(f"Errore creando '{new_asm}' a {hex(term.address)}: {e}, salto swap")
