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
    SYSCALL = 6
    NONE = 0 


MAX_SAFE_JUMP_DISTANCE = 0x1000  # distanza massima sicura per swap fisico
PHYSICAL_SWAP_PROBABILITY = 0.3  # probabilità base di fare uno swap fisico

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




INVERT_MAP = {
            'ja': 'jbe', 'jae': 'jb', 'jb': 'jae', 'jbe': 'ja', 'jc': 'jnc', 'jcxz': 'jecxz',
            'je': 'jne', 'jg': 'jle', 'jge': 'jl', 'jl': 'jge', 'jle': 'jg', 'jna': 'ja',
            'jnae': 'jae', 'jnb': 'jb', 'jnbe': 'jbe', 'jnc': 'jc', 'jne': 'je', 'jng': 'jg',
            'jnge': 'jge', 'jnl': 'jl', 'jnle': 'jle', 'jno': 'jo', 'jnp': 'jp', 'jns': 'js',
            'jnz': 'jz', 'jo': 'jno', 'jp': 'jnp', 'jpe': 'jpo', 'jpo': 'jpe', 'js': 'jns', 'jz': 'jnz'
        }