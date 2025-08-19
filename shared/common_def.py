import logging
from typing import List, Tuple, Optional
import capstone as cap
import keystone as ks

from shared.constants import CAPSTONE_TO_KEYSTONE_MAP, TERMINATOR_TYPE

logger = logging.getLogger(__name__)

# Precompilazione globale
COND_JUMPS = frozenset([
    "je","jz","jne","jnz","jg","jnle","jge","jnl","jl","jnge","jle","jng",
    "ja","jnbe","jae","jnb","jb","jnae","jbe","jna","jo","jno","js","jns",
    "jp","jpe","jnp","jpo","jcxz","jecxz","jrcxz"
])
UNCOND_JUMPS = frozenset(["jmp"])
CALLS = frozenset(["call"])
RETURNS = frozenset(["ret","retf","sysexit","sysret"])
IRETS = frozenset(["iret","iretd","iretq"])
INTS = frozenset(["int","int3"])
LOOPS = frozenset(["loop","loope","loopne","loopnz","loopz"])
SYSCALLS = frozenset(["syscall","sysenter"])

# Dizionario generale per lookup O(1
X86_FLOW_INSTRUCTIONS: dict[str, Tuple[TERMINATOR_TYPE, bool]] = {
    **{mn: (TERMINATOR_TYPE.JUMP, False) for mn in UNCOND_JUMPS},
    **{mn: (TERMINATOR_TYPE.JUMP, True)  for mn in COND_JUMPS},
    **{mn: (TERMINATOR_TYPE.CALL, False) for mn in CALLS},
    **{mn: (TERMINATOR_TYPE.RETURN, False) for mn in RETURNS},
    **{mn: (TERMINATOR_TYPE.IRET, False) for mn in IRETS},
    **{mn: (TERMINATOR_TYPE.INT, False) for mn in INTS},
    **{mn: (TERMINATOR_TYPE.JUMP, True) for mn in LOOPS},
    **{mn: (TERMINATOR_TYPE.SYSCALL, False) for mn in SYSCALLS},
}

def is_terminator(instruction: cap.CsInsn) -> Tuple[Optional[TERMINATOR_TYPE], bool]:
    """
    Determina se un'istruzione è un terminatore di blocco 
    (jump, call, return, iret, int, syscall, loop).
    Ritorna una tupla: (tipo_terminatore, è_condizionale)
    """
    # Usa i gruppi se disponibili
    if hasattr(instruction, "groups") and instruction.groups:
        groups = instruction.groups
        if cap.CS_GRP_JUMP in groups:
            is_conditional = instruction.id != cap.x86.X86_INS_JMP
            return TERMINATOR_TYPE.JUMP, is_conditional
        if cap.CS_GRP_CALL in groups:
            return TERMINATOR_TYPE.CALL, False
        if cap.CS_GRP_RET in groups:
            return TERMINATOR_TYPE.RETURN, False
        if cap.CS_GRP_IRET in groups:
            return TERMINATOR_TYPE.IRET, False
        if cap.CS_GRP_INT in groups:
            return TERMINATOR_TYPE.INT, False

    # Fallback: lookup tramite mnemonic
    mnemonic = instruction.mnemonic.lower()
    if mnemonic in X86_FLOW_INSTRUCTIONS:
        return X86_FLOW_INSTRUCTIONS[mnemonic]

    return None, False


def capstone_to_keystone(cs_arch, cs_mode):
    entry = CAPSTONE_TO_KEYSTONE_MAP.get(cs_arch)
    if not entry:
        raise ValueError(f"Architettura Capstone {cs_arch} non supportata")
    ks_arch, mode_map = entry
    ks_mode = mode_map.get(cs_mode)
    if ks_mode is None:
        raise ValueError(f"Modalità Capstone {cs_mode} non supportata per {cs_arch}")
    return ks_arch, ks_mode
