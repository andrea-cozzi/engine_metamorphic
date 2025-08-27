import hashlib
import logging
import random
import traceback
from typing import Dict, Generator, List, Optional, Tuple

import capstone as cap

from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from metamorphic_engine.utils.common_function import are_permutable
from constant_var import SAVE_ASM_CODE_MULTILINE, SAVE_ASM_SHOW_ADDRESS

logger = logging.getLogger(__name__)

LABEL_BLOCK = "label_{:#x}"

class BasicBlock:
    """Rappresenta un blocco di base con istruzioni, terminatore e collegamenti nel CFG."""

    def __init__(self, start_address: int):
        self.start_address: int = start_address
        self.end_address: int = start_address  # indirizzo subito dopo l'ultima istruzione
        self.instructions: OrderedUUIDSet[BasicInstruction] = OrderedUUIDSet()
        self.successors: Dict[str, int] = {}
        self.terminator: Optional[BasicInstruction] = None
        self.terminator_type: Optional[str] = None
        self.is_conditional: bool = False
        self.label = LABEL_BLOCK.format(start_address)

        self.instructions_map_address: Dict[int, BasicInstruction] = {}
        self.instructions_map_uuid: Dict[str, BasicInstruction] = {}

        # UUID del blocco
        self.uuid = hashlib.sha1(f"{self.start_address:x}".encode("utf-8")).hexdigest()

    # === API ===
    def add_instruction(
        self, instruction: cap.CsInsn
    ) -> Optional[Tuple[Optional[str], Optional["BasicInstruction"]]]:
        """Aggiunge un'istruzione al blocco e aggiorna end_address."""
        if not instruction:
            return None

        instruction_form = BasicInstruction(instruction=instruction)
        if not instruction_form:
            raise ValueError(f"Instruction at {instruction.address} cannot be converted to BasicInstruction")

        self.instructions.add(instruction_form)
        self.instructions_map_address[instruction.address] = instruction_form
        self.instructions_map_uuid[instruction_form.uuid] = instruction_form
        self.end_address = instruction.address + instruction.size

        return instruction_form.uuid, instruction_form

    def set_terminator(
        self, 
        instruction: cap.CsInsn, 
        term_type: str, 
        is_conditional: bool = False, 
        add_to_block: bool = False,
        uuid: Optional[str] = None
    ) -> None:
        """Imposta il terminatore del blocco e aggiorna end_address se necessario."""
        self.terminator_type = term_type
        self.is_conditional = is_conditional
        self.end_address = max(self.end_address, instruction.address + instruction.size)

        if add_to_block:
            instruction_form = BasicInstruction(instruction=instruction)
            if not instruction_form:
                raise ValueError(f"Instruction at {instruction.address} cannot be converted to BasicInstruction")
            self.instructions.add(instruction_form)
        elif not add_to_block and uuid and len(uuid) > 0:
            instruction_form = self.instructions.get_by_uuid(uid=uuid)
        else:
            raise ValueError("set_terminator: param configuration is not valid")

        self.terminator = instruction_form

    def get_instruction_addredd(self, address: int) -> Optional["BasicInstruction"]:
        return self.instructions_map_address.get(address)
    
    def get_instruction_uuid(self, uuid: str) -> Optional["BasicInstruction"]:
        if uuid is None or len(uuid) <= 0:
            return None
        return self.instructions.get_by_uuid(uuid)

    def get_block_size(self) -> Optional[int]:
        try:
            # La size è in byte e deve essere calcolata sull'istruzione originale, non sul wrapper
            return sum(instr.original_object.size for instr in self.instructions)
        except Exception:
            logger.error(traceback.format_exc())
            return None
    
    # ==== Funzioni di utilità ====
    def to_dict(self) -> dict:
        return {
            "uuid": self.uuid,
            "start_address": hex(self.start_address),
            "count": len(self.instructions),
            "instructions": [
                {
                    "address": hex(instr.address),
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "bytes": getattr(instr.original_object, 'bytes', b'').hex() if instr.original_object else ""
                }
                for instr in self.instructions
            ],
            "successors": list(self.successors)
        }

    def get_instruction(self) -> List[BasicInstruction]:
        return list(self.instructions)

    def is_block_permutable(self) -> bool:
        if not self.instructions:
            return False
        result = all(instr.is_permutable for instr in list(self.instructions)[:-1])
        return result

    def ricalcolate_addresses(self, base_address: Optional[int] = None, return_end_address: bool = False) -> Optional[int]:
        """Ricalcola gli indirizzi delle istruzioni del blocco."""
        address = base_address if base_address is not None else self.start_address
        if base_address is not None:
            self.start_address = address

        for instruction in self.instructions:
            instruction.address = address
            # la size viene letta dall'oggetto originale capstone, quindi non va aggiornata
            address += instruction.original_object.size

        self.end_address = address
        return self.end_address if return_end_address else None

    def permutate_instructions(self, tries: int = 5) -> None:
        """Permuta due istruzioni permutabili all'interno del blocco."""
        permutables = [ins for ins in self.instructions if ins.is_permutable]
        if len(permutables) < 2:
            return

        tries = max(tries, 1)
        while tries > 0:
            ins1, ins2 = random.sample(permutables, 2)
            if are_permutable(ins1, ins2):
                i1, i2 = self.instructions.index(ins1), self.instructions.index(ins2)
                self.instructions[i1], self.instructions[i2] = self.instructions[i2], self.instructions[i1]
                break
            tries -= 1

        self.ricalcolate_addresses()

    def _add_successor(self, uuids: List[Tuple[str, int]]) -> None:
        if not uuids:
            return
        for uuid, addr in uuids:
            self.successors[uuid] = addr

    def clone(self) -> "BasicBlock":
        """
        Crea e restituisce una copia profonda (un nuovo oggetto) di questo blocco.
        Tutte le istruzioni interne vengono clonate a loro volta.
        """
        new_block = BasicBlock(self.start_address)

        # 2. Copia gli attributi semplici
        new_block.end_address = self.end_address
        new_block.terminator_type = self.terminator_type
        new_block.is_conditional = self.is_conditional
        new_block.label = self.label
        new_block.uuid = self.uuid  
        new_block.successors = self.successors.copy() 

        # 3. Esegui una copia profonda delle istruzioni e popola 
        for instruction in self.instructions:
            cloned_instruction = instruction.clone()
            new_block.instructions.add(cloned_instruction)
            new_block.instructions_map_address[cloned_instruction.address] = cloned_instruction
            new_block.instructions_map_uuid[cloned_instruction.uuid] = cloned_instruction

       
        if self.terminator:
            cloned_terminator = new_block.instructions_map_uuid.get(self.terminator.uuid)
            new_block.terminator = cloned_terminator

        return new_block

    # === Nuova funzione per ottenere codice assembly come stringa ===
    def to_asm(self) -> str:
        def get_lines_generator() -> Generator[str, None, None]:
            yield f"{hex(self.start_address)}:"
            for instr in self.instructions:
                if SAVE_ASM_SHOW_ADDRESS:
                    line = f"{instr.address:#x}:\t{instr.mnemonic} {instr.op_str}"
                else:
                    line = f"{instr.mnemonic}\t{instr.op_str}"
                yield line
                
        return "\n".join(get_lines_generator())