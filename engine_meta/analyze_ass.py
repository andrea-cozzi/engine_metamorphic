from typing import List

import capstone as cs

from engine_meta.basic_block import BasicBlock, Chain, is_terminator


def analyze(ins : List[cs.CsInsn], len_code: int, BASE_ADDRESS):
    if ins is None or len(ins) <= 0 or len_code <= 0:
        return
    
    chain : Chain = Chain()

    leaders: List[cs.CsInsn] = []
    leaders.append(ins[0])

    block : BasicBlock = BasicBlock(leaders.address, leaders.address)
    chain.add_block(block=block)
    
    for instr in ins:
        if is_terminator(instr):
            if instr.operands:
                op = instr.operands[0]
                if op.type == cs.x86.X86_OP_IMM:
                    leaders.add(op.imm)
            if instr.address + instr.size < BASE_ADDRESS + len_code:
                leaders.add(instr.address + instr.size)

    current_block: BasicBlock = None

    for instru in ins:
        if instru in leaders:
            if current_block and is_terminator(current_block.instructions[-1]):
                current_block.successors_block_address.append(instr.address)

            current_block = BasicBlock(instr.address)
            chain[instr.address] = current_block

        if current_block:
            current_block.add_instruction(instr)

        if is_terminator(instr):
            if instr.operands and instr.operands[0].type == cs.x86.X86_OP_IMM:
                target_addr = instr.operands[0].imm
                current_block.successors_block_address.append(target_addr)

            if not (instr.mnemonic == 'jmp' or instr.mnemonic == 'ret'):
                fall_through_addr = instr.address + instr.size
                if fall_through_addr < BASE_ADDRESS + len_code:
                    current_block.successors_block_address.append(fall_through_addr)
            



    
    