import hashlib
import logging
import random
from typing import Dict, List, Optional, Set
from engine_meta.model.basic_instruction import BasicInstruction
import re
import capstone as cap
import keystone as ks
import lief as lf

logger= logging.getLogger(__name__)

# ==== FUNXIONE PER OTTENERE LE MODALITà PER I DUE COMPONENTI ====
def get_component_modes(binary: lf.Binary):
    """
    Restituisce le modalità Capstone e Keystone per un binario x86/x64.
    Considera solo little-endian (x86).
    """
    if isinstance(binary, lf.PE.Binary):
        arch = binary.header.machine.name
    elif isinstance(binary, lf.ELF.Binary):
        arch = binary.header.machine_type.name
    else:
        raise TypeError(f"Tipo di binario non supportato: {type(binary)}")

    if arch in (lf.ELF.ARCH.X86_64.name, lf.PE.Header.MACHINE_TYPES.AMD64.name):
        cs_arch, cs_mode = cap.CS_ARCH_X86, cap.CS_MODE_64
        ks_arch, ks_mode = ks.KS_ARCH_X86, ks.KS_MODE_64
        
    elif arch in (lf.ELF.ARCH.I386.name, lf.PE.Header.MACHINE_TYPES.I386.name):
        cs_arch, cs_mode = cap.CS_ARCH_X86, cap.CS_MODE_32
        ks_arch, ks_mode = ks.KS_ARCH_X86, ks.KS_MODE_32
        
    else:
        raise NotImplementedError(f"Architettura non supportata: {arch}")

    return {
        "capstone": (cs_arch, cs_mode),
        "keystone": (ks_arch, ks_mode)
    }
# ==================================================






# Equivalenze corrette e più sicure
EQUIVALENCES = {
    "mov": {
        "reg, 0": ["xor reg, reg", "sub reg, reg"],
        "reg, reg": ["push reg2;pop reg1"], 
        "reg, imm": ["push imm;pop reg"]
    },
    "add": {
        "reg1, reg2": ["sub reg1, -reg2", "lea reg1, [reg1 + reg2]"],
        "reg, 1": ["inc reg", "sub reg, -1"],
        "reg, imm": ["sub reg, -imm"] 
    },
    "sub": {
        "reg1, reg2": ["add reg1, -reg2"],
        "reg, 1": ["dec reg"], 
        "reg, imm": ["add reg, -imm"] 
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


def are_permutable(ins1: BasicInstruction, ins2: BasicInstruction) -> bool:
    """
    Determina se due istruzioni possono essere permutate in sicurezza.
    Tiene conto di:
    - registri letti/scritti
    - memoria letta/scritta
    - stack e registri critici (rsp, rbp)
    - flusso di controllo (jump/call/ret)
    """

    if not ins1 or not ins2:
        return False
    if not ins1.is_permutable or not ins2.is_permutable:
        return False

    # Registri critici da non permutare
    critical_regs = {"rsp", "rbp"}
    
    # Leggi/scrivi registri
    read1, write1 = set(ins1.regs_read), set(ins1.regs_write)
    read2, write2 = set(ins2.regs_read), set(ins2.regs_write)

    # Controllo registri critici
    if (read1 | write1) & critical_regs or (read2 | write2) & critical_regs:
        return False

    # Controllo conflitti tra registri
    if write1 & (read2 | write2):
        return False
    if write2 & (read1 | write1):
        return False

    # Conflitti tra memoria (se disponibili)
    mem_read1 = set(getattr(ins1, "mem_read", []))
    mem_write1 = set(getattr(ins1, "mem_write", []))
    mem_read2 = set(getattr(ins2, "mem_read", []))
    mem_write2 = set(getattr(ins2, "mem_write", []))

    if mem_write1 & (mem_read2 | mem_write2):
        return False
    if mem_write2 & (mem_read1 | mem_write1):
        return False

    # Flusso di controllo
    control_ops = {"jmp", "je", "jne", "call", "ret", "cmp", "test"}
    if ins1.mnemonic in control_ops or ins2.mnemonic in control_ops:
        return False

    # Controllo dipendenze tra registri generali (opzionale avanzato)
    # Se una istruzione legge un registro scritto dall’altra, non permutare
    if (read1 & write2) or (read2 & write1):
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
