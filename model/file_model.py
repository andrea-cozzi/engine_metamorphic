import lief
import capstone as cp
from enum import Enum
from typing import Optional, Tuple

from shared.constants import ARCHITECTURE_MAP, BinaryType



class FileModel:
    def __init__(self, filepath: str):
        if not filepath:
            raise ValueError("Il percorso del file non può essere vuoto.")

        self.filepath: str = filepath
        self.binary: Optional[lief.Binary] = None
        self.type: Optional[BinaryType] = None
        self.arch: Optional[int] = None
        self.mode: Optional[int] = None
        self.ep: Optional[int] = None
        self.is_64: Optional[bool] = None

        try:
            # Esegui il parsing del file una sola volta
            binary = lief.parse(self.filepath)
            if binary is None:
                raise RuntimeError("File non riconosciuto da LIEF o non è un formato binario supportato.")
            
            self.binary = binary
            self.ep = self.binary.entrypoint 
            machine_identifier = None

            if isinstance(self.binary, lief.PE.Binary):
                self.type = BinaryType.WINDOWS
                machine_identifier = self.binary.header.machine
            elif isinstance(self.binary, lief.ELF.Binary):
                self.type = BinaryType.LINUX
                machine_identifier = self.binary.header.machine_type
            else:
                raise NotImplementedError(f"Il formato binario '{self.binary.format}' non è supportato.")
            
            self._map_architecture(machine_identifier)
            
        except RuntimeError as e:
            print(f"Errore di configurazione: Impossibile fare il parsing del file. {e}")
            raise
        except Exception as e:
            print(f"Errore di configurazione: {e}")
            raise

    def _map_architecture(self, machine_identifier: lief.lief_errors) -> None:
        if self.type not in ARCHITECTURE_MAP:
            raise NotImplementedError(f"Nessuna mappa di architetture per il tipo di binario {self.type.name}")

        machine_type_map = ARCHITECTURE_MAP[self.type]
        capstone_config: Optional[Tuple[int, int]] = machine_type_map.get(machine_identifier)

        if capstone_config is None:
            raise NotImplementedError(f"L'architettura '{machine_identifier.name}' non è supportata per {self.type.name}.")
            
        self.arch, self.mode = capstone_config