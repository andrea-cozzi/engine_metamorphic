import os
from dotenv import load_dotenv

load_dotenv()

def get_boolean_env_var(var_name, default_value=False) -> bool:
    value = os.environ.get(var_name)
    if value is not None:
        return value.lower() == 'true'
    return default_value


DEBUG_MODE = get_boolean_env_var("DEBUG_MODE")

PRO_PERMUTATION_ISTRUCTION=float(os.environ.get("PRO_PERMUTATION_ISTRUCTION"))
PRO_PERMUTATION_BLOCK=float(os.environ.get("PRO_PERMUTATION_BLOCK"))
ALLOW_PERMUTATION_BLOCK=get_boolean_env_var("ALLOW_PERMUTATION_BLOCK")
JSON_CFG_OUTPUT_PATH=str(os.environ.get("JSON_CFG_OUTPUT_PATH"))
SAVE_CFG_JSON = get_boolean_env_var("SAVE_CFG_JSON")


SAVE_ASM_DECODED = get_boolean_env_var("SAVE_ASM_DECODED")
SAVE_ASM_SHOW_ADDRESS = get_boolean_env_var("SAVE_ASM_SHOW_ADDRESS")
SAVE_ASM_CODE_MULTILINE = get_boolean_env_var("SAVE_ASM_CODE_MULTILINE")

ASSEMBLY_OUTPUT_PATH=str(os.environ.get("ASSEMBLY_OUTPUT_PATH"))
PATH_EXE=str(os.environ.get("PATH_EXE"))

PRO_ADD_DEAD_CODE=float(os.environ.get("PRO_ADD_DEAD_CODE"))
PRO_ADD_NOP_INST=float(os.environ.get("PRO_ADD_NOP_INST"))
PRO_ADD_JUNK_CODE_TERMINATOR=float(os.environ.get("PRO_ADD_JUNK_CODE_TERMINATOR"))

MAX_BLOCK_OBFUSCATION=float(os.environ.get("MAX_BLOCK_OBFUSCATION"))
PRO_ADD_OPAQUE_CODE=float(os.environ.get("PRO_ADD_OPAQUE_CODE"))
MIN_NOP_INSTRUCTION_BLOCK=int(os.environ.get("MIN_NOP_INSTRUCTION_BLOCK"))
MAX_NOP_INSTRUCTION_BLOCK=int(os.environ.get("MAX_NOP_INSTRUCTION_BLOCK"))
PRO_ADD_JUNK_CODE_AFTER_TERMINATOR=float(os.environ.get("PRO_ADD_JUNK_CODE_AFTER_TERMINATOR"))
