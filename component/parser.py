import logging
from typing import Optional, Tuple
import capstone as cap
import lief as lf

from model.file_model import FileModelBinary
from shared.constants import ARCHITECTURE_MAP, BinaryType

logger = logging.getLogger(__name__)

class Parser:

    def __init__(self):
        return
    

    def _map_architecture_to_disassemler_private(self, tipo: BinaryType,
                                        machine_identifier,
                                        file: FileModelBinary) -> None:
        
        if tipo is None or machine_identifier is None or file is None:
            raise ValueError(f"{tipo} or {machine_identifier} or {file} is None")
        
        if tipo not in ARCHITECTURE_MAP:
            raise NotImplementedError(f"Nessuna mappa di architetture per il tipo di binario {tipo}")
        
        machine_type_map = ARCHITECTURE_MAP[tipo]
        capstone_config: Optional[Tuple[int, int]] = machine_type_map.get(machine_identifier)

        if capstone_config is None:
            raise NotImplementedError(f"L'architettura '{machine_identifier.name}' non è supportata per {type.name}.")
        
        file.arch, file.mode = capstone_config

            
    def parse(self, file_path : str) -> Optional[FileModelBinary]:
        if not file_path:
            raise ValueError(f"{file_path} cannot be empty")
        
        try:
            binary : lf.Binary = lf.parse(filepath=file_path)
            if binary is None:
                raise RuntimeError(f"File {file_path} is not LIEF or is not a binary supported format")
            
            if isinstance(binary, lf.PE.Binary):
                type = BinaryType.WINDOWS
                machine_identifier = binary.header.machine
            elif isinstance(binary, lf.ELF.Binary):
                type = BinaryType.LINUX
                machine_identifier = binary.header.machine_type
            else:
                raise NotImplementedError(f"{binary.format}' non is not supported")
        
            file: FileModelBinary = FileModelBinary(binary=binary, file_path=file_path, binary_type=type)
            if file is None:
                raise ValueError("File parsed is None")
            
            self._map_architecture_to_disassemler_private(file.type, machine_identifier, file)

            return file
        except Exception as e:
            logger.error(e)
            return None


            











