import capstone as cs
from enum import Enum
from typing import List, Dict, Set, Tuple, Optional

from enum import Enum

from engine_meta.instruction.shared import TERMINATOR_TYPE
from engine_meta.instruction.x86 import X86_FLOW_INSTRUCTIONS


class BasicBlock:
    def __init__(self, start_address: int):
        self.start_address: int = start_address
        self.end_address: int = start_address
        self.instructions: List[cs.CsInsn] = []
        self.successors: List[int] = []
        self.terminator: Optional[cs.CsInsn] = None
        self.terminator_type: Optional[TERMINATOR_TYPE] = None
        self.instructions_map = {}

    def add_instruction(self, instruction: cs.CsInsn):
        if instruction:
            self.instructions.append(instruction)
            self.end_address = instruction.address
            self.instructions_map[instruction.address] = instruction

    def set_terminator(self, instruction: cs.CsInsn, term_type: TERMINATOR_TYPE):
        self.terminator = instruction
        self.terminator_type = term_type
        self.end_address = instruction.address + instruction.size

    def swap_instructions(self, inst_one: cs.CsInsn, inst_two: cs.CsInsn) -> None:
        index1, index2 = -1, -1

        for i, insruzione_correnete in enumerate(self.instructions):
            if insruzione_correnete.address == inst_one.address:
                index1 = i
            elif insruzione_correnete.address == inst_two.address:
                index2 = i

            if index1 != -1 and index2 != -1:
                break
        
        if index1 == -1 or index2 == -1:
            not_found_addr = hex(inst_one.address if index1 == -1 else inst_two.address)
            raise ValueError(f"L'istruzione con indirizzo {not_found_addr} non è stata trovata in questo blocco.")

        last_index = len(self.instructions) - 1
        if self.terminator and (index1 == last_index or index2 == last_index):
            raise ValueError("Non è possibile scambiare l'istruzione terminator.")

        self.instructions[index1], self.instructions[index2] = self.instructions[index2], self.instructions[index1]


    def get_instruction(self, address) -> Optional[cs.CsInsn]:
        instruction = self.instructions_map.get(address)
        return instruction if instruction is not None else None

    def __repr__(self):
        return (f"<Block start={hex(self.start_address)}, end={hex(self.end_address)}, "
                f"terminator={self.terminator_type.name if self.terminator_type else 'FALLTHROUGH'}, "
                f"successors={list(map(hex, self.successors))}>")
    
    
class ControlFlowGraph: 
    def __init__(self):
        self.blocks: Dict[int, BasicBlock] = {}

    def add_block(self, block: BasicBlock):
        if block and isinstance(block, BasicBlock):
            self.blocks[block.start_address] = block
            
    def __repr__(self):
        return f"<ControlFlowGraph with {len(self.blocks)} blocks>"
    

def is_terminator(instruction: cs.CsInsn) -> Tuple[Optional[TERMINATOR_TYPE], bool]:
    if hasattr(instruction, 'detail') and instruction.detail:
        groups = instruction.detail.groups
        if cs.CS_GRP_JUMP in groups:
            is_unconditional = instruction.id == cs.x86.X86_INS_JMP
            return (TERMINATOR_TYPE.JUMP, not is_unconditional)
        if cs.CS_GRP_CALL in groups:
            return (TERMINATOR_TYPE.CALL, False)
        if cs.CS_GRP_RET in groups:
            return (TERMINATOR_TYPE.RETURN, False)
        if cs.CS_GRP_IRET in groups:
            return (TERMINATOR_TYPE.IRET, False)
        if cs.CS_GRP_INT in groups:
            return (TERMINATOR_TYPE.INT, False)
        return (None, False)

    mnemonic = instruction.mnemonic.lower()
    if mnemonic in X86_FLOW_INSTRUCTIONS:
        return X86_FLOW_INSTRUCTIONS[mnemonic]


    return (None, False)