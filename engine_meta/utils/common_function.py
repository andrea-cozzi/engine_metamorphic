import hashlib
import logging
import random
from typing import Dict, List, Optional, Set
from engine_meta.model.basic_instruction import BasicInstruction
import re
import capstone as cap

logger= logging.getLogger(__name__)

# Equivalenze corrette e più sicure
EQUIVALENCES = {
    "mov": {
        "reg, 0": ["xor reg, reg", "sub reg, reg"],
        # "mov reg1, reg2" is tricky. push/pop affects the stack.
        # Let's keep it simple for now or use lea if applicable.
        # "mov reg, reg" is often optimized out, but push/pop is a valid, though expensive, equivalent.
        "reg, reg": ["push reg2;pop reg1"], 
        "reg, imm": ["push imm;pop reg"]
    },
    "add": {
        "reg1, reg2": ["sub reg1, -reg2", "lea reg1, [reg1 + reg2]"],
        "reg, 1": ["inc reg", "sub reg, -1"],
        "reg, imm": ["sub reg, -imm"] # Corrected equivalence
    },
    "sub": {
        "reg1, reg2": ["add reg1, -reg2"],
        "reg, 1": ["dec reg"], # dec is the most common equivalent
        "reg, imm": ["add reg, -imm"] # Corrected equivalence
    },
    "nop": {
        "": ["xchg eax, eax", "mov eax, eax", "push eax;pop eax"]
    }
}


def generate_uuid(instruction: cap.CsInsn) -> str:
        data = f"{instruction.address:x}:{instruction.mnemonic}:{instruction.op_str}"
        return hashlib.md5(data.encode()).hexdigest()


def extract_jump_call_targets(instructions: List[cap.CsInsn],
                                #PASSARE L'ATTRRIBUTO DEL GRAFO
                                map_address_unique_istr : Dict[int, str]
                                ) -> Set[str]:
    banned_to_equi = set()
    for insn in instructions:
        if getattr(insn, "detail", None):
            groups = insn.detail.groups
            if cap.CS_GRP_JUMP in groups or cap.CS_GRP_CALL in groups:
                for op in insn.operands:
                    if op.type == cap.x86.X86_OP_IMM:
                        uuid = map_address_unique_istr.get(op.imm)
                        if uuid:
                            banned_to_equi.add(uuid)

    return banned_to_equi


def are_permutable(ins1 : BasicInstruction, ins2 : BasicInstruction) -> bool:

    if ins1 is None or ins2 is None:
        raise ValueError(f"One of the two instructions ot both is None")

    if ins1.is_permutable is False or ins2.is_permutable is False:
        return False
    
    read_one, write_one = set(ins1.regs_read), set(ins1.regs_write)
    read_two, write_two = set(ins2.regs_read), set(ins2.regs_write)

    if write_one & (read_two | write_two):
        return False
    if write_two & (read_one | write_one):
        return False

    return True




def get_equivalent(instruction: BasicInstruction) -> Optional[str]:
    """Restituisce un equivalente casuale di un'istruzione, se disponibile"""
    if instruction is None:
        raise ValueError("instruction is None")

    key: str = instruction.mnemonic.strip()


    if key not in EQUIVALENCES:
        return str(instruction)
    
    op_str: str = instruction.op_str

    # Match esatto (es. per "nop")
    if op_str in EQUIVALENCES[key]:
        return random.choice(EQUIVALENCES[key][op_str]).replace(";","\n")+"\n"
        

    # Pattern generici
    for pattern, equivalents in EQUIVALENCES[key].items():
        chosen = random.choice(equivalents)

        # --- PATTERN: reg1, reg2 ---
        if pattern == "reg1, reg2" and len(instruction.operands) == 2:
            op1 = instruction.operands[0]
            op2 = instruction.operands[1]
        
            # Usiamo .get() per sicurezza. Controlla se 'reg' esiste e non è None.
            reg1 = op1.get("reg")
            reg2 = op2.get("reg")

            if reg1 and reg2:
                return chosen.replace("reg1", reg1).replace("reg2", reg2).replace(";", "\n") +"\n"
                    

        # --- PATTERN: reg, imm ---
        elif pattern == "reg, imm" and len(instruction.operands) == 2:
            op1 = instruction.operands[0]
            op2 = instruction.operands[1]

            reg = op1.get("reg")
            imm = op2.get("imm")

            if reg and imm is not None:
                def repl(match):
                    expr = match.group(0)
                    value = eval(expr.replace("imm", str(imm)))
                    return str(value)

                result = chosen.replace("reg", reg)
                result = re.sub(r"[-]?imm", repl, result)
                return result.replace(";", "\n") +"\n"
    
    # Se nessun pattern ha funzionato
    return None
    


#TODO
def is_indipendent():
    pass
