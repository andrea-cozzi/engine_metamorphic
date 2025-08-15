from enum import Enum
import capstone as cp
import lief
import keystone as ks

class BinaryType(Enum):
    WINDOWS = 1
    LINUX = 2
    UNKNOWN = 3

class TERMINATOR_TYPE(Enum):
    JUMP = 1
    CALL = 2
    RETURN = 3
    IRET = 4
    INT = 5
    NONE = 0 

# =============================================================================
# MAPPA ARCHITETTURA BINARIO TO CAPSTONE
# =============================================================================
ARCHITECTURE_MAP = {
    BinaryType.WINDOWS: {
        lief.PE.Header.MACHINE_TYPES.I386:   (cp.CS_ARCH_X86, cp.CS_MODE_32),
        lief.PE.Header.MACHINE_TYPES.AMD64:  (cp.CS_ARCH_X86, cp.CS_MODE_64),
        lief.PE.Header.MACHINE_TYPES.ARM:    (cp.CS_ARCH_ARM, cp.CS_MODE_ARM),
        lief.PE.Header.MACHINE_TYPES.ARM64:  (cp.CS_ARCH_ARM64, cp.CS_MODE_ARM),
    },
    BinaryType.LINUX: {
        lief.ELF.ARCH.I386:       (cp.CS_ARCH_X86, cp.CS_MODE_32),
        lief.ELF.ARCH.X86_64:     (cp.CS_ARCH_X86, cp.CS_MODE_64),
        lief.ELF.ARCH.ARM:        (cp.CS_ARCH_ARM, cp.CS_MODE_ARM),
        lief.ELF.ARCH.AARCH64:    (cp.CS_ARCH_ARM64, cp.CS_MODE_ARM),
    }
}

# =============================================================================
# MAPPA CAPSTONE TO KEYSTONE
# =============================================================================
CAPSTONE_TO_KEYSTONE_MAP = {
    cp.CS_ARCH_X86: (
        ks.KS_ARCH_X86,
        {
            cp.CS_MODE_16: ks.KS_MODE_16,
            cp.CS_MODE_32: ks.KS_MODE_32,
            cp.CS_MODE_64: ks.KS_MODE_64,
        }
    ),
    cp.CS_ARCH_ARM: (
        ks.KS_ARCH_ARM,
        {
            cp.CS_MODE_ARM: ks.KS_MODE_ARM,
            cp.CS_MODE_THUMB: ks.KS_MODE_THUMB,
        }
    ),
    cp.CS_ARCH_ARM64: (
        ks.KS_ARCH_ARM64,
        {
            cp.CS_MODE_ARM: ks.KS_MODE_ARM,
        }
    ),
    cp.CS_ARCH_MIPS: (
        ks.KS_ARCH_MIPS,
        {
            cp.CS_MODE_MIPS32: ks.KS_MODE_MIPS32,
            cp.CS_MODE_MIPS64: ks.KS_MODE_MIPS64,
        }
    ),
}

X86_FLOW_INSTRUCTIONS = {
    # Salti Incondizionati
    "jmp": (TERMINATOR_TYPE.JUMP, False),

    # Salti Condizionati
    "je": (TERMINATOR_TYPE.JUMP, True),
    "jz": (TERMINATOR_TYPE.JUMP, True),
    "jne": (TERMINATOR_TYPE.JUMP, True),
    "jnz": (TERMINATOR_TYPE.JUMP, True),
    "jg": (TERMINATOR_TYPE.JUMP, True),
    "jnle": (TERMINATOR_TYPE.JUMP, True),
    "jge": (TERMINATOR_TYPE.JUMP, True),
    "jnl": (TERMINATOR_TYPE.JUMP, True),
    "jl": (TERMINATOR_TYPE.JUMP, True),
    "jnge": (TERMINATOR_TYPE.JUMP, True),
    "jle": (TERMINATOR_TYPE.JUMP, True),
    "jng": (TERMINATOR_TYPE.JUMP, True),
    "ja": (TERMINATOR_TYPE.JUMP, True),
    "jnbe": (TERMINATOR_TYPE.JUMP, True),
    "jae": (TERMINATOR_TYPE.JUMP, True),
    "jnb": (TERMINATOR_TYPE.JUMP, True),
    "jb": (TERMINATOR_TYPE.JUMP, True),
    "jnae": (TERMINATOR_TYPE.JUMP, True),
    "jbe": (TERMINATOR_TYPE.JUMP, True),
    "jna": (TERMINATOR_TYPE.JUMP, True),
    "jo": (TERMINATOR_TYPE.JUMP, True),
    "jno": (TERMINATOR_TYPE.JUMP, True),
    "js": (TERMINATOR_TYPE.JUMP, True),
    "jns": (TERMINATOR_TYPE.JUMP, True),
    "jp": (TERMINATOR_TYPE.JUMP, True),
    "jpe": (TERMINATOR_TYPE.JUMP, True),
    "jnp": (TERMINATOR_TYPE.JUMP, True),
    "jpo": (TERMINATOR_TYPE.JUMP, True),
    "jcxz": (TERMINATOR_TYPE.JUMP, True),
    "jecxz": (TERMINATOR_TYPE.JUMP, True),
    "jrcxz": (TERMINATOR_TYPE.JUMP, True),

    # Chiamate
    "call": (TERMINATOR_TYPE.CALL, False),

    # Ritorno
    "ret": (TERMINATOR_TYPE.RETURN, False),
    "retf": (TERMINATOR_TYPE.RETURN, False), # Ritorno Far
    "iret": (TERMINATOR_TYPE.IRET, False),
    "iretd": (TERMINATOR_TYPE.IRET, False),
    "iretq": (TERMINATOR_TYPE.IRET, False),
    
    # Interrupt
    "int": (TERMINATOR_TYPE.INT, False),
    "int3": (TERMINATOR_TYPE.INT, False), # Breakpoint
}