from typing import Generator, List, Optional, Tuple
import capstone as cap
import logging
import lief
from shared.constants import BinaryType
logger = logging.getLogger(__name__)

import capstone as cap

ARCHITECTURE_MAP = {
    BinaryType.WINDOWS: {
        lief.PE.Header.MACHINE_TYPES.I386:   (cap.CS_ARCH_X86, cap.CS_MODE_32),
        lief.PE.Header.MACHINE_TYPES.AMD64:  (cap.CS_ARCH_X86, cap.CS_MODE_64),
        lief.PE.Header.MACHINE_TYPES.ARM:    (cap.CS_ARCH_ARM, cap.CS_MODE_ARM),
        lief.PE.Header.MACHINE_TYPES.ARM64:  (cap.CS_ARCH_ARM64, cap.CS_MODE_64),
    },
    BinaryType.LINUX: {
        lief.ELF.ARCH.I386:    (cap.CS_ARCH_X86, cap.CS_MODE_32),
        lief.ELF.ARCH.X86_64:  (cap.CS_ARCH_X86, cap.CS_MODE_64),
        lief.ELF.ARCH.ARM:     (cap.CS_ARCH_ARM, cap.CS_MODE_ARM),
        lief.ELF.ARCH.AARCH64: (cap.CS_ARCH_ARM64, cap.CS_MODE_64),
    }
}

class Disassembler:
    def __init__(self):
        self.arch : Optional[int] = None
        self.mode : Optional[int] = None

        self.dis : Optional[cap.Cs] = None
        pass


    def reset(self, arch: Optional[int] = None, mode : Optional[int] = None) -> None:
        if arch:
            self.arch = arch 
        if mode:
            self.mode = mode

    def _setup(self, file_type: int, machine_identifier: int) -> None:
        if file_type not in ARCHITECTURE_MAP:
            raise NotImplementedError(f"Nessuna mappa di architetture per il tipo di binario {file_type}")

        machine_type_map = ARCHITECTURE_MAP[file_type]
        capstone_config: Optional[Tuple[int, int]] = machine_type_map.get(machine_identifier)

        if capstone_config is None:
            raise NotImplementedError(f"L'architettura '{machine_identifier}' non è supportata per {file_type}.")

        # Ensure capstone_config is a tuple
        if not isinstance(capstone_config, tuple) or len(capstone_config) != 2:
            raise TypeError(f"Invalid Capstone configuration for {machine_identifier} in {file_type}")

        self.arch, self.mode = capstone_config

    def create(self, file_type: int,  
           machine_identifier: int, 
           use_skipdata: bool = True) -> None:    
        try:
            self._setup(file_type=file_type, machine_identifier=machine_identifier)
            if not self.mode or not self.arch: 
                raise ValueError("self.mode or self.arch is None")
            
            self.dis = cap.Cs(self.arch, self.mode)
            self.dis.detail = True
            if use_skipdata:
                def skip_cb(insn: cap.CsInsn, size: int) -> int:
                    logger.warning(f"Ignorata istruzione dati a 0x{insn.address:x} di {size} byte")
                    return size

                self.dis.skipdata_cb = skip_cb
            return

        except Exception as e:
            logger.error(f"Error in create_disassembler: {e}")
            self.dis = None


    def disassemble(self, codes: bytes, 
                    start_address: int, 
                    count: Optional[int] = None) -> List[cap.CsInsn]:
        if not self.dis:
            logger.warning("Assembler has not been created. Cannot disassemble the code")
            return list()
        try:
            if len(codes) <= 0:
                logger.warning("Code for disassebling has len <= 0")
                return None
            if count is not None:
                return list(self.dis.disasm(code=codes, offset=start_address, count=count))
            else:
                return list(self.dis.disasm(code=codes, offset=start_address))
        except Exception as e:
            logger.error(f"Error in disassemble_disassembler: {e}")
            return None

    
    


