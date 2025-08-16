from bisect import bisect, bisect_right
import hashlib
import json
import logging
from typing import List, Dict, Optional, Set, Tuple
import capstone as cap
import keystone as ks
import lief as lf

from component.disassembler import Disassembler
from model.file_model import FileModelBinary
from shared.common_def import is_terminator
from shared.constants import CAPSTONE_TO_KEYSTONE_MAP, INVERT_MAP, TERMINATOR_TYPE

logger = logging.getLogger(__name__)


class BasicBlock:
    """Rappresenta un blocco di base con istruzioni, terminatore e collegamenti nel CFG."""

    def __init__(self, start_address: int):

        self.start_address: int = start_address
        self.end_address: int = start_address  # indirizzo subito dopo l'ultima istruzione
        self.instructions: List[cap.CsInsn] = []  # istruzioni del blocco
        self.successors: List[int] = []  # indirizzi dei blocchi successori
        self.terminator: Optional[cap.CsInsn] = None
        self.terminator_type: Optional[str] = None
        self.instructions_map: Dict[int, cap.CsInsn] = {}

    @property
    def id(self) -> str:
        """Restituisce un hash univoco del blocco basato sulle istruzioni."""
        hasher = hashlib.sha256()
        for instr in self.instructions:
            hasher.update(instr.bytes)
        return hasher.hexdigest()


    # === API ==== 
    def add_instruction(self, instruction: cap.CsInsn) -> None:
        """Aggiunge un'istruzione al blocco, aggiornando end_address fisico."""
        if not instruction:
            return
        self.instructions.append(instruction)
        self.instructions_map[instruction.address] = instruction
        # end_address rappresenta l'indirizzo subito dopo l'ultima istruzione nel blocco
        self.end_address = instruction.address + instruction.size


    def set_terminator(self, instruction: cap.CsInsn, term_type: str) -> None:
        """Imposta il terminatore del blocco e aggiorna end_address se necessario."""
        self.terminator = instruction
        self.terminator_type = term_type
        # L'end_address deve essere almeno fino al terminatore fisico
        self.end_address = max(self.end_address, instruction.address + instruction.size)
        self.add_instruction(instruction)  # aggiunge anche il terminatore nella map e aggiorna end_address



    def get_instruction_at(self, address: int) -> Optional["cap.CsInsn"]:
        """Ritorna l'istruzione che inizia a un dato indirizzo."""
        return self.instructions_map.get(address)
    


    def _reasing_addresses(self) -> None:
        current_address = self.start_address
        for i, instr in enumerate(self.instructions):
            instr.address = current_address
            current_address += instr.size


    def swipe_instruction(self, address_one: int, address_two: int) -> None:
        if not (0 <= address_one< len(self.instructions) and 0 <= address_two < len(self.instructions)):
            raise IndexError("Indici delle istruzioni fuori range")
        
        if address_one == self.terminator.address or address_two == self.terminator.address:
            raise ValueError("Cannot swipe the block terminator instruction")
        

    
        
    # ==== FUNZIONI DI UTIL ==================
    def to_dict(self) -> dict:
        return {
            "start_address": hex(self.start_address),
            "count": len(self.instructions),
            "instructions": [
                {
                    "address": hex(instr.address),
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "bytes": getattr(instr, 'bytes', b'').hex() if hasattr(instr, 'bytes') else ""
                }
                for instr in self.instructions
            ],
            "successors": list(self.successors) if hasattr(self, "successors") else []
        }
    
    def get_instruction(self) -> List[cap.CsInsn]:
      return list(self.instructions)


# -----------------------------------------------------------------------------
# EngineMeta CFG
# -----------------------------------------------------------------------------
class EngineMetaCFG:

    def __init__(self):
        self.blocks: Dict[int, BasicBlock] = {}
        self.predecessors: Dict[int, List[int]] = {}
        self.sorted_starts: List[int] = []
        #Utilie per la ricerca
        self.block_start_address_set: Set[int] = set()
        self.created : bool = False


    #----- FUNZIONI PRIVATE ---------------------
    def _find_terminators(self, instructions: List[cap.CsInsn]) -> Dict[int, TERMINATOR_TYPE]:
        """Ritorna un dict degli indirizzi dei terminatori e il loro tipo."""
        terminators = {}
        for instr in instructions:
            term_type, _ = is_terminator(instr)
            if term_type:
                terminators[instr.address] = term_type
        return terminators

    

    def _link_successors(self):
         for block in self.blocks.values():
            if not block.instructions:
                block.successors = []
                continue

            last_instr = block.instructions[-1]
            successors: Set[int] = set()

            try:
                term_type, is_conditional = is_terminator(last_instr)
            except Exception:
                groups = set(last_instr.groups)
                is_jump = cap.CS_GRP_JUMP in groups
                is_call = cap.CS_GRP_CALL in groups
                is_ret = cap.CS_GRP_RET in groups
                term_type = (TERMINATOR_TYPE.JUMP if is_jump else
                             TERMINATOR_TYPE.CALL if is_call else
                             TERMINATOR_TYPE.RETURN if is_ret else None)
                is_conditional = is_jump and last_instr.mnemonic.lower() != "jmp"

            # target immediato se è leader
            if term_type:
                successors.update(
                    int(op.imm) for op in getattr(last_instr, "operands", [])
                    if getattr(op, "type", None) == cap.x86_const.X86_OP_IMM
                    and int(op.imm) in self.block_start_address_set
                )

                # fallthrough per salti condizionali
                if is_conditional:
                    next_addr = last_instr.address + last_instr.size
                    if next_addr in self.block_start_address_set:
                        successors.add(next_addr)
            else:
                # istruzione normale -> fallthrough
                next_addr = last_instr.address + last_instr.size
                if next_addr in self.block_start_address_set:
                    successors.add(next_addr)

            block.successors = list(sorted(successors))  # opzionale: ordina se serve
            # aggiorna predecessori
            for succ in block.successors:
                self.predecessors.setdefault(succ, []).append(block.start_address)


    # ----- API DELLA CLASSE -----------------------
    def create_graph(self, file: FileModelBinary, 
                     disassembler: Disassembler,
                     section : str = ".text") -> None:
        
        section_binary = file.binary.get_section(section)

        if not section_binary:
            logger.error(f"Section {section_binary} ")

        section_address = file.get_base_address() + section_binary.virtual_address
        section_code = bytes(section_binary.content)

        instructions = disassembler.disassemble(codes=section_code, start_address=section_address)
        if instructions is None or len(instructions)<= 0:
            logger.warning("Cannot disassemble the instructions")
            return None
        else:
            logger.info(f"Sono state individuate { len(instructions)} sitruzioni")
    
        #CREAZIONE DEL CONTROL FLOW GRAPH
        terminators = self._find_terminators(instructions)
        block: BasicBlock = None
        for _, instr in enumerate(instructions):
            if block is None:
                block = BasicBlock(instr.address)
            
            block.add_instruction(instr)

            if instr.address in terminators:
                block.set_terminator(instr, terminators[instr.address])
                self._add_block(block)
                block = None  
        

        self._link_successors()

    def get_block_start(self, address: int) -> Optional[int]:
        sorted_starts = sorted(self.blocks.keys())  # meglio se memorizzato già ordinato
        idx = bisect.bisect_right(sorted_starts, address) - 1
        if idx >= 0:
            return sorted_starts[idx]
        return None



    def _add_block(self, block: BasicBlock) -> None:
        if block.start_address in self.block_start_address_set:
            logger.warning(f"Block at {hex(block.start_address)} already exists. Skipping.")
            return

        self.blocks[block.start_address] = block
        self.block_start_address_set.add(block.start_address)
        self.sorted_starts.append(block.start_address)
        self.sorted_starts.sort()

        self.predecessors.setdefault(block.start_address, [])
        self.created = True




    # --- FUNZIONI UTILI -----
    def save_to_json(self, file_path: str = "cfg.json", open_mode: str = 'w'):
        if len(file_path) <= 0 or not (open_mode == 'w' or open_mode == 'a'):
            logger.warning("params to save_to_json are not valid")
            return

        with open(file_path, open_mode) as file:
            serializable_cfg = {hex(addr): block.to_dict() for addr, block in self.blocks.items()}
            json_dump = {
                "block_number": len(self.blocks.keys()),
                "created": True if self.created else False,
                "blocks": serializable_cfg
            }
           
            json.dump(json_dump, file, indent=2)

        logger.info(f"CFG saved in {file_path}")


    # ----------------------------
    # Helpers predecessori
    # ----------------------------
    def _update_predecessor_map(self, parent: BasicBlock, old_succ: int, new_succ: int) -> None:
        if old_succ in self.predecessors:
            self.predecessors[old_succ] = [p for p in self.predecessors[old_succ] if p != parent.start_address]
        self.predecessors.setdefault(new_succ, []).append(parent.start_address)

    # ----------------------------
    # Swap fisico/logico
    # ----------------------------
    def _physically_swap_blocks(self, addr_a: int, addr_b: int) -> None:
        block_a, block_b = self.blocks[addr_a], self.blocks[addr_b]
        block_a.start_address, block_b.start_address = block_b.start_address, block_a.start_address
        block_a.bind_engines(self.ks_engine, self.cs_engine)
        block_b.bind_engines(self.ks_engine, self.cs_engine)
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

            mnemonic = term.mnemonic.lower()

            # Se terminatore è senza operandi (ret, ecc.) salta
            if mnemonic in self.ZERO_OPERAND_TERMINATORS:
                continue

            # Proviamo rel32, altrimenti long-jump
            try:
                seq = parent.build_jump_sequence(mnemonic, term.address, mod["new"])
                if not seq:
                    logger.warning(
                        f"Impossibile ricreare terminatore '{mnemonic}' verso {hex(mod['new'])}, salto")
                    continue

                # Rimpiazza *solo* il terminatore con la nuova sequenza
                parent.instructions = parent.instructions[:-1] + seq
                parent.set_terminator(seq[-1], parent.terminator_type)
                if mod["old"] in parent.successors:
                    parent.successors.remove(mod["old"])
                if mod["new"] not in parent.successors:
                    parent.successors.append(mod["new"])
                self._update_predecessor_map(parent, mod["old"], mod["new"])
                logger.info(f"Logically swap completed")
                parent.recalculate_addresses()

                self.sorted_starts = sorted(self.blocks.keys())
            except Exception as e:
                logger.warning(
                    f"Errore ricreando salto '{mnemonic}' a {hex(term.address)}: {e}, skip modifica")

    # API pubblico per swap
    def swap_blocks(self, addr_a: int, addr_b: int, physical: bool = False) -> None:
        if addr_a not in self.blocks or addr_b not in self.blocks:
            raise KeyError("Indirizzo di blocco non presente nel CFG")
        if physical:
            self._physically_swap_blocks(addr_a, addr_b)
        else:
            preds_a = [self.blocks[p] for p in self.predecessors.get(addr_a, []) if p in self.blocks]
            preds_b = [self.blocks[p] for p in self.predecessors.get(addr_b, []) if p in self.blocks]
            self._logically_swap_blocks(addr_a, addr_b, preds_a, preds_b)

    # ----------------------------
    # Ricostruzione globale degli indirizzi (tutti i blocchi)
    # ----------------------------
    def recalculate_all(self) -> None:
        for b in self.blocks.values():
            b.bind_engines(self.ks_engine, self.cs_engine)
            b.recalculate_addresses()
        self.link_successors()


    def get_code_instruction(self) -> List[cap.CsInsn]:
        return [
            instruction 
            for blocco in self.blocks.values() 
            for instruction in blocco.get_instruction()
        ]

    # ----------------------------
    # Debug/Export
    # ----------------------------
    def dump(self) -> List[dict]:
        return [blk.to_dict() for blk in sorted(self.blocks.values(), key=lambda x: x.start_address)]
