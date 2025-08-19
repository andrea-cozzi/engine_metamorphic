import logging
from typing import List, Optional, Tuple

import lief
import capstone as cap
import keystone as ks
from shared.constants import BinaryType

logger = logging.getLogger(__name__)

# ==============================
# MAPPA ARCHITETTURE
# ==============================
ARCHITECTURE_MAP = {
    BinaryType.WINDOWS: {
        lief.PE.Header.MACHINE_TYPES.I386:   (cap.CS_ARCH_X86, cap.CS_MODE_32, ks.KS_ARCH_X86, ks.KS_MODE_32),
        lief.PE.Header.MACHINE_TYPES.AMD64:  (cap.CS_ARCH_X86, cap.CS_MODE_64, ks.KS_ARCH_X86, ks.KS_MODE_64),
        lief.PE.Header.MACHINE_TYPES.ARM:    (cap.CS_ARCH_ARM, cap.CS_MODE_ARM, ks.KS_ARCH_ARM, ks.KS_MODE_ARM),
        lief.PE.Header.MACHINE_TYPES.ARM64:  (cap.CS_ARCH_ARM64, cap.CS_MODE_64, ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN),
    },
    BinaryType.LINUX: {
        lief.ELF.ARCH.I386:    (cap.CS_ARCH_X86, cap.CS_MODE_32, ks.KS_ARCH_X86, ks.KS_MODE_32),
        lief.ELF.ARCH.X86_64:  (cap.CS_ARCH_X86, cap.CS_MODE_64, ks.KS_ARCH_X86, ks.KS_MODE_64),
        lief.ELF.ARCH.ARM:     (cap.CS_ARCH_ARM, cap.CS_MODE_ARM, ks.KS_ARCH_ARM, ks.KS_MODE_ARM),
        lief.ELF.ARCH.AARCH64: (cap.CS_ARCH_ARM64, cap.CS_MODE_64, ks.KS_ARCH_ARM64, ks.KS_MODE_LITTLE_ENDIAN),
    }
}


# ==============================
# ASSEMBLER (Keystone)
# ==============================

def assemble_code(asm_code: str, ks_arch: int, ks_mode: int) -> Optional[bytes]:
    """Assembla una stringa di codice assembly in bytes."""
    try:
        engine = ks.Ks(ks_arch, ks_mode)
        encoding, _ = engine.asm(asm_code)
        return bytes(encoding)
    except Exception as e:
        logger.error(f"Errore in assemble_code: {e}")
        return None


def assemble_file(path_asm: str, ks_arch: int, ks_mode: int) -> Optional[bytes]:
    """Legge un file .asm e lo assembla in bytes."""
    try:
        with open(path_asm, "r", encoding="utf-8") as f:
            asm_code = f.read()
        return assemble_code(asm_code, ks_arch, ks_mode)
    except Exception as e:
        logger.error(f"Errore in assemble_file: {e}")
        return None


# ==============================
# DISASSEMBLER (Capstone)
# ==============================

def create_disassembler(file_type: int, machine_identifier: int, use_skipdata: bool = True) -> Optional[cap.Cs]:
    """Crea un disassembler Capstone configurato in base al tipo di file."""
    try:
        cs_arch, cs_mode, _, _ = ARCHITECTURE_MAP[file_type][machine_identifier]
        dis = cap.Cs(cs_arch, cs_mode)
        dis.detail = True

        if use_skipdata:
            def skip_cb(insn: cap.CsInsn, size: int, user_data) -> int:
                logger.warning(f"Ignorata istruzione dati a 0x{insn.address:x} di {size} byte")
                return size
            dis.skipdata = True
    

        return dis
    except Exception as e:
        logger.error(f"Errore in create_disassembler: {e}")
        return None


def disassemble_bytes(codes: bytes, start_address: int, dis: cap.Cs, count: Optional[int] = None) -> List[cap.CsInsn]:
    """Disassembla bytes a partire da un indirizzo base."""
    if not dis:
        logger.warning("Disassembler non valido")
        return []
    if not codes:
        logger.warning("Codice vuoto")
        return []
    try:
        return list(dis.disasm(codes, start_address, count)) if count else list(dis.disasm(codes, start_address))
    except Exception as e:
        logger.error(f"Errore in disassemble_bytes: {e}")
        return []


def disassemble_file(path_bin: str, file_type: int, machine_identifier: int, base_addr: int = 0x1000) -> List[cap.CsInsn]:
    """Carica un file binario e lo disassembla."""
    try:
        with open(path_bin, "rb") as f:
            code = f.read()
        dis = create_disassembler(file_type, machine_identifier)
        if not dis:
            return []
        return disassemble_bytes(code, base_addr, dis)
    except Exception as e:
        logger.error(f"Errore in disassemble_file: {e}")
        return []

