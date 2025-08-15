from enum import Enum


class TERMINATOR_TYPE(Enum):
    JUMP = 1
    CALL = 2
    RETURN = 3
    IRET = 4
    INT = 5
    NONE = 0 