from engine_meta.instruction.shared import TERMINATOR_TYPE


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