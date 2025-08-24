"""
L'idea è quella di costruire un meccanismo che dato
un blocco, guarda se una se un'istruzione [ESCLUSO IL TERMINATORE]
prende in input LE 4 MODALITà e CERCA SE UNA DETERMINATA
ISTRUXIONE DEVE ESSERE MODIFICATA CON UNA EQUIVALENTE

CREA LA NUOVA ISTRUZIONE 
--> DIZIONARIO CON LE EQUIVALEBTI

1- controllo che l'istruzione sia modificabile
2- controllo che l'istruzione utilizzi dei registri compatibili
3- cerco la sua equivalente che ha dterminati path <--- questa scelta avviene random
4- creo la nuova istruzione con format e poi le buildo
5- aggiungo e rimuovo con add_after_remove
6- ricalcolo gli address di tutto il blocco

"""

import re
import traceback
from typing import List, Optional, Set
from constant_var import PRO_EQUIVALENT_INSTRUCTION, PRO_EQUIVALENT_BLOCK, TOTAL_EQUIVALENT_INSTRUCTION
import random
import logging
import capstone as cs


from engine_meta.factory.instruction_factory import InstructionFactoryStatic
from engine_meta.model.basic_block import BasicBlock
from engine_meta.model.basic_instruction import BasicInstruction
from engine_meta.model.ordered_uuidset import OrderedUUIDSet


logger = logging.getLogger(__name__)

# ------------------------------
# Dizionari equivalenti 32/64-bit
# ------------------------------
INSTRUCTION_EQUIVALENTS_32 = {
    "MOV": {
        "{reg}, {reg}": ["NOP", "XCHG {reg}, {reg}", "ADD {reg}, 0", "SUB {reg}, 0",
                         "PUSH {reg}; POP {reg}", "AND {reg}, 0xFFFFFFFF"],
        "{reg1}, {reg2}": ["PUSH {reg2}; POP {reg1}", "XCHG {reg1}, {reg2}; XCHG {reg1}, {reg2}"],
        "{reg}, {imm}": ["PUSH {imm}; POP {reg}"]
    },
    "ADD": {
        "{reg}, 0": ["NOP", "SUB {reg}, 0"],
        "{reg}, {imm}": ["SUB {reg}, -{imm}"],
        "{reg1}, {reg2}": ["LEA {reg1}, [{reg1}+{reg2}]"]
    },
    "SUB": {
        "{reg}, 0": ["NOP", "ADD {reg}, 0"],
        "{reg}, {imm}": ["ADD {reg}, -{imm}"],
        "{reg1}, {reg2}": ["LEA {reg1}, [{reg1}-{reg2}]"]
    },
    "XOR": {
        "{reg}, {reg}": ["MOV {reg}, 0", "SUB {reg}, {reg}"]
    },
    "INC": {
        "{reg}": ["ADD {reg}, 1"]
    },
    "DEC": {
        "{reg}": ["SUB {reg}, 1"]
    },
    "PUSH": {
        "{reg}": ["SUB ESP, 4; MOV [ESP], {reg}"],
        "{imm}": ["SUB ESP, 4; MOV [ESP], {imm}"]
    },
    "POP": {
        "{reg}": ["MOV {reg}, [ESP]; ADD ESP, 4"]
    },
    "NOP": {
        "": ["XCHG EAX, EAX"]
    }
}

INSTRUCTION_EQUIVALENTS_64 = {
    "MOV": {
        "{reg}, {reg}": ["NOP", "XCHG {reg}, {reg}", "ADD {reg}, 0", "SUB {reg}, 0",
                         "PUSH {reg}; POP {reg}", "AND {reg}, 0xFFFFFFFFFFFFFFFF"],
        "{reg1}, {reg2}": ["PUSH {reg2}; POP {reg1}", "XCHG {reg1}, {reg2}; XCHG {reg1}, {reg2}"],
        "{reg}, {imm}": ["PUSH {imm}; POP {reg}"]
    },
    "ADD": {
        "{reg}, 0": ["NOP", "SUB {reg}, 0"],
        "{reg}, {imm}": ["SUB {reg}, -{imm}"],
        "{reg1}, {reg2}": ["LEA {reg1}, [{reg1}+{reg2}]"]
    },
    "SUB": {
        "{reg}, 0": ["NOP", "ADD {reg}, 0"],
        "{reg}, {imm}": ["ADD {reg}, -{imm}"],
        "{reg1}, {reg2}": ["LEA {reg1}, [{reg1}-{reg2}]"]
    },
    "XOR": {
        "{reg}, {reg}": ["MOV {reg}, 0", "SUB {reg}, {reg}"]
    },
    "INC": {
        "{reg}": ["ADD {reg}, 1"]
    },
    "DEC": {
        "{reg}": ["SUB {reg}, 1"]
    },
    "PUSH": {
        "{reg}": ["SUB RSP, 8; MOV [RSP], {reg}"],
        "{imm}": ["SUB RSP, 8; MOV [RSP], {imm}"]
    },
    "POP": {
        "{reg}": ["MOV {reg}, [RSP]; ADD RSP, 8"]
    },
    "NOP": {
        "": ["XCHG RAX, RAX"]
    }
}

ALLOWED_REGISTER = {
    32: {"EAX", "EBX", "ECX", "EDX"},
    64: {"RAX", "RBX", "RCX", "RDX"}
}

COMPATIBILE_INSTRUCTION: Set[str] = {"MOV", "ADD", "SUB", "XOR", "INC", "DEC", "PUSH", "POP", "NOP"}


class EquivalentSwitcher:
    #==== FUNZIONE PER OTTENERE LA LISTA DEGLI EQUIVALENTI ==========
    @staticmethod
    def _find_equivalent(instruction: "BasicInstruction",
                         db) -> Optional[str]:

        def tokenize(pattern: str):
            return [] if not pattern.strip() else [p.strip() for p in pattern.split(",")]

        def kind_and_name(tok: str):
            m = re.fullmatch(r"\{([a-zA-Z0-9_]+)\}", tok)
            if not m:
                return None, None
            name = m.group(1)
            if name.startswith("reg") or name == "reg":
                return "reg", name
            if name == "imm":
                return "imm", "imm"
            return None, None

        op_view = []
        for op in getattr(instruction.original_object, "operands", []):
            if op.type == cs.x86.X86_OP_REG:
                op_view.append(("reg", instruction.original_object.reg_name(op.reg).upper()))
            elif op.type == cs.x86.X86_OP_IMM:
                op_view.append(("imm", str(op.imm)))
            else:
                op_view.append(("other", ""))

        mnem = instruction.original_object.mnemonic.upper()
        if mnem not in db:
            return None

        for pattern, equivalents in db[mnem].items():
            tokens = tokenize(pattern)
            if len(tokens) != len(op_view):
                continue

            mapping = {}
            ok = True
            for i, tok in enumerate(tokens):
                kind, name = kind_and_name(tok)
                if kind is None or op_view[i][0] != kind:
                    ok = False
                    break
                val = op_view[i][1]
                if name in mapping and mapping[name] != val:
                    ok = False
                    break
                mapping[name] = val
            if not ok:
                continue

            # scelgo randomicamente oppure restituisco tutti
            eqs = random.choice(equivalents)

            out = []
            for eq in eqs:
                s = eq
                if "imm" in mapping:
                    try:
                        s = re.sub(r"-\{imm\}", str(-int(mapping["imm"], 0)), s)
                    except ValueError:
                        pass
                for k, v in mapping.items():
                    s = s.replace("{" + k + "}", v)
                out.append(s)

            return out[0]

        return None 

    #==== FUNZIONE PER OTTENERE L’EQUIVALENTE ==========
    @staticmethod
    def _get_equivalent(instruction: "BasicInstruction",
                        arch_ks: int,
                        arch_cs: int,
                        mode_ks: int,
                        mode_cs: int) -> Optional["BasicInstruction"]:

        if instruction.mnemonic.upper() not in COMPATIBILE_INSTRUCTION:
            return None

        try:
            allowed_registers: Set[str] = ALLOWED_REGISTER[64] if mode_ks == 64 else ALLOWED_REGISTER[32]

            if not set(instruction.regs_read_list).intersection(allowed_registers):
                logger.info(f"Instruction {instruction.uuid} does not have compatible register read")
                return None

            if not set(instruction.regs_write_list).intersection(allowed_registers):
                logger.info(f"Instruction {instruction.uuid} does not have compatible register write")
                return None

            db = INSTRUCTION_EQUIVALENTS_64 if mode_ks == 64 else INSTRUCTION_EQUIVALENTS_32
            instruction_equivalent_str: Optional[str] = EquivalentSwitcher._find_equivalent(instruction, db=db)

            if not instruction_equivalent_str:
                return None
            try:
                new_build: BasicInstruction = InstructionFactoryStatic.create_instruction(
                    ks_arch=arch_ks,
                    ks_mode=mode_ks,
                    arch_cs=arch_cs,
                    mode_cs=mode_cs,
                    asm_str=instruction_equivalent_str
                )

                return new_build
            
            except Exception as e:
                logger.error(traceback.format_exc)
                return None  # placeholder per ora

        except Exception:
            logger.error(traceback.format_exc())
            return None

    #==== FUNZIONE PER IL CONTROLLO PARAMETRI ==========
    @staticmethod
    def _check_params_value() -> None:
        pass

    #==== API PUBBLICA ==========
    @staticmethod
    def switch_equivalent(blocks: OrderedUUIDSet["BasicBlock"],
                          arch_ks: int,
                          arch_cs: int,
                          mode_ks: int,
                          mode_cs: int) -> None:

        for _, block in enumerate(blocks):
            EquivalentSwitcher._switch_equivalent_single(block=block,
                                                         arch_cs=arch_cs, 
                                                         arch_ks=arch_ks,
                                                         mode_cs=mode_cs,
                                                         mode_ks=mode_ks)
            

    @staticmethod
    def _switch_equivalent_single(block: BasicBlock, arch_ks: int,
                          arch_cs: int,
                          mode_ks: int,
                          mode_cs: int) -> None:
        
        if random.random() > PRO_EQUIVALENT_BLOCK:
            logger.info(f"Block {block.uuid} skips in switch_equivalent")
            return

        instructions_selected: List["BasicInstruction"] = [ins for ins in block.instructions if ins.is_equivalent]
        total_instructions: int = int(len(block.instructions) * TOTAL_EQUIVALENT_INSTRUCTION)

        if total_instructions >= len(instructions_selected):
            sample_instr = list(instructions_selected)
        else:
            sample_instr = random.sample(population=instructions_selected, k=total_instructions)

        for instruction in sample_instr:
            if random.random() > PRO_EQUIVALENT_INSTRUCTION:
                logger.info(f"Instruction {instruction.uuid} skips in switch_equivalent")
                continue

            new_instruction: Optional["BasicInstruction"] = EquivalentSwitcher._get_equivalent(
                instruction=instruction,
                arch_cs=arch_cs,
                arch_ks=arch_ks,
                mode_cs=mode_cs,
                mode_ks=mode_ks
            )

            if new_instruction is None:
                continue
            
            block.instructions.add_after_remove(instruction.uuid, new_instruction)
        
        block.ricalcolate_addresses()
