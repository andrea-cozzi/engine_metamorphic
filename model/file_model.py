from typing import Optional, Union
import lief as lf
from shared.constants import BinaryType


class FileModelBinary:

    def __init__(self, binary: lf.Binary, file_path : str, binary_type: BinaryType):
        self.file_path: str = file_path
        self.binary: Optional[lf.Binary] = binary
        self.type: Optional[BinaryType] = binary_type
        self.arch: Optional[int] = None
        self.mode: Optional[int] = None
        self.ep: Optional[int] = self.binary.entrypoint
        self.is_64: Optional[bool] = None

    def get_base_address(self) -> int:
        binary: Union[lf.PE.Binary, lf.ELF.Binary] = self.binary
        if isinstance(binary, lf.PE.Binary):
            return binary.optional_header.imagebase
        elif isinstance(binary, lf.ELF.Binary):
            load_segments = [s for s in binary.segments if s.type == lf.ELF.SEGMENT_TYPES.LOAD]
            return min((s.virtual_address for s in load_segments), default=0)
        raise ValueError("Binary file not supported")
    
    def get_machine_type(self):
        if self.type == BinaryType.WINDOWS:
            return self.binary.header.machine
        elif self.type == BinaryType.LINUX:
            return self.binary.header.machine
        else:
            raise ValueError(f"{self.filepath} is an unknown type")
            




