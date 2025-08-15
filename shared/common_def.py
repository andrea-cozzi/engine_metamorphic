from typing import Optional, Tuple
import capstone as cap
from shared.constants import CAPSTONE_TO_KEYSTONE_MAP, TERMINATOR_TYPE, X86_FLOW_INSTRUCTIONS


def is_terminator(instruction: cap.CsInsn) -> Tuple[Optional[TERMINATOR_TYPE], bool]:
    """Determina se un'istruzione è un terminatore di blocco."""
    try:
        if hasattr(instruction, "detail") and instruction.detail:
            groups = instruction.detail.groups
            if cap.CS_GRP_JUMP in groups:
                return TERMINATOR_TYPE.JUMP, instruction.id != cap.x86.X86_INS_JMP
            if cap.CS_GRP_CALL in groups:
                return TERMINATOR_TYPE.CALL, False
            if cap.CS_GRP_RET in groups:
                return TERMINATOR_TYPE.RETURN, False
            if cap.CS_GRP_IRET in groups:
                return TERMINATOR_TYPE.IRET, False
            if cap.CS_GRP_INT in groups:
                return TERMINATOR_TYPE.INT, False
    except (AttributeError, cap.CsError):
        # Ignora istruzioni “dati” che non hanno detail
        pass

    mnemonic = instruction.mnemonic.lower()
    return X86_FLOW_INSTRUCTIONS.get(mnemonic, (None, False))

def capstone_to_keystone(cs_arch, cs_mode):
    entry = CAPSTONE_TO_KEYSTONE_MAP.get(cs_arch)
    if not entry:
        raise ValueError(f"Architettura Capstone {cs_arch} non supportata")
    ks_arch, mode_map = entry
    ks_mode = mode_map.get(cs_mode)
    if ks_mode is None:
        raise ValueError(f"Modalità Capstone {cs_mode} non supportata per {cs_arch}")
    return ks_arch, ks_mode
