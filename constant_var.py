import os
from dotenv import load_dotenv

load_dotenv()


def get_boolean_env_var(var_name: str, default_value: bool = False) -> bool:
    value = os.environ.get(var_name)
    if value is not None:
        return value.lower() in ('true', '1', 'yes')
    return default_value


def get_float_env_var(var_name: str, default_value: float = 0.0) -> float:
    try:
        return float(os.environ.get(var_name, default_value))
    except ValueError:
        return default_value


def get_int_env_var(var_name: str, default_value: int = 0) -> int:
    try:
        return int(os.environ.get(var_name, default_value))
    except ValueError:
        return default_value


# =============================
# CONFIG VARIABLES
# =============================

DEBUG_MODE = get_boolean_env_var("DEBUG_MODE")

PRO_PERMUTATION_ISTRUCTION = get_float_env_var("PRO_PERMUTATION_ISTRUCTION", 0.5)
PRO_PERMUTATION_BLOCK = get_float_env_var("PRO_PERMUTATION_BLOCK", 0.3)
ALLOW_PERMUTATION_BLOCK = get_boolean_env_var("ALLOW_PERMUTATION_BLOCK", False)
JSON_CFG_OUTPUT_PATH = os.environ.get("JSON_CFG_OUTPUT_PATH", "./json_cfg_output/")
FILENAME_JSON_REPORT = os.environ.get("FILENAME_JSON_REPORT", "mutation_report.json")
REPORT_JSON_PATH = os.environ.get("REPORT_JSON_PATH", "./report/")

SAVE_CFG_JSON = get_boolean_env_var("SAVE_CFG_JSON", False)
SAVE_MUTATION_REPORT = get_boolean_env_var("SAVE_MUTATION_REPORT", False)
ADJ_AUTO_PROB = get_boolean_env_var("ADJ_AUTO_PROB", False)

SAVE_ASM_DECODED = get_boolean_env_var("SAVE_ASM_DECODED", True)
SAVE_ASM_SHOW_ADDRESS = get_boolean_env_var("SAVE_ASM_SHOW_ADDRESS", False)
SAVE_ASM_CODE_MULTILINE = get_boolean_env_var("SAVE_ASM_CODE_MULTILINE", False)

ASSEMBLY_OUTPUT_PATH = os.environ.get("ASSEMBLY_OUTPUT_PATH", "./assembly_output/")
PATH_EXE = os.environ.get("PATH_EXE", "")
PATH_OUTPUT_EXE = os.environ.get("PATH_OUTPUT_EXE", "./exe/")

PRO_ADD_DEAD_CODE = get_float_env_var("PRO_ADD_DEAD_CODE", 0.4)
PRO_ADD_NOP_INST = get_float_env_var("PRO_ADD_NOP_INST", 0.2)
PRO_ADD_JUNK_CODE_TERMINATOR = get_float_env_var("PRO_ADD_JUNK_CODE_TERMINATOR", 0.3)
PRO_EQUIVALENT_BLOCK = get_float_env_var("PRO_EQUIVALENT_BLOCK", 0.55)
PRO_EQUIVALENT_INSTRUCTION = get_float_env_var("PRO_EQUIVALENT_INSTRUCTION", 0.28)
TOTAL_EQUIVALENT_INSTRUCTION = get_float_env_var("TOTAL_EQUIVALENT_INSTRUCTION", 0.4)

MAX_BLOCK_OBFUSCATION = get_float_env_var("MAX_BLOCK_OBFUSCATION", 0.3)
PRO_ADD_OPAQUE_CODE = get_float_env_var("PRO_ADD_OPAQUE_CODE", 0.3)
MIN_NOP_INSTRUCTION_BLOCK = get_int_env_var("MIN_NOP_INSTRUCTION_BLOCK", 2)
MAX_NOP_INSTRUCTION_BLOCK = get_int_env_var("MAX_NOP_INSTRUCTION_BLOCK", 6)
PRO_ADD_JUNK_CODE_AFTER_TERMINATOR = get_float_env_var("PRO_ADD_JUNK_CODE_AFTER_TERMINATOR", 0.4)

NUMBER_MUTATION = get_int_env_var("NUMBER_MUTATION", 6)

FEATURE_ANALYSIS_PATH = os.environ.get("FEATURE_EXTRACT_PATH", "./analysis_results/")