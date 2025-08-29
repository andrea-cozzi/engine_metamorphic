from bisect import bisect_right
import logging
import traceback
from typing import Generator, List, Dict, Optional, Set, Tuple
import capstone as cap
import keystone as ks
import lief as lf

from component.ass_diss import create_disassembler, disassemble_bytes
from metamorphic_engine.model.basic_block import BasicBlock
from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from model.file_model import FileModelBinary
from shared.common_def import is_terminator
from shared.constants import CAPSTONE_TO_KEYSTONE_MAP, INVERT_MAP, TERMINATOR_TYPE

logger = logging.getLogger(__name__)


NON_PERMUTABLE_GROUP = {
        cap.CS_GRP_JUMP,
        cap.CS_GRP_CALL,
        cap.CS_GRP_RET,
        cap.CS_GRP_IRET,
        cap.CS_GRP_INT,
}

# -----------------------------------------------------------------------------
# EngineMeta CFG
# -----------------------------------------------------------------------------
"""
COSTRUIRE UN MECCANISMO CHE SE è UN JUMP/CALL DEVE
ESSERE INSERITA IN QUELLE CHE NON POSSONO ESSERE EQUIVALENTI
"""
class EngineMetaCFG:

    def __init__(self):
        self.blocks: Dict[int, BasicBlock] = {}
        self._start_address_base: Optional[int] = None
        self._all_instructions_unordered: Set[BasicInstruction] = set()
        self._all_blocks_ordered: OrderedUUIDSet[BasicBlock] = OrderedUUIDSet()
        self._map_address_label: Dict[int, str] = {}
        self._map_address_instruction: Dict[int, BasicInstruction] = {}
        self._map_address_uuid: Dict[int, str] = {}
        self.no_equ_set: Set[str] = set()
        self.no_perm_set: Set[str] = set()
        self.created: bool = False
        self._addresses_dirty: bool = True  # indica se bisogna ricalcolare gli indirizzi

    # ---------------- FUNZIONI PRIVATE ----------------

    def _find_terminators(self, instructions: List[cap.CsInsn]) -> Dict[int, TERMINATOR_TYPE]:
        return {instr.address: is_terminator(instr)[0] 
                for instr in instructions if is_terminator(instr)[0] is not None}

    def _create_maps(self) -> None:
        """Popola le mappe interne e i set basandosi sul dizionario self.blocks."""
        # Pulisce le strutture dati prima di ripopolarle per evitare duplicati
        self._all_instructions_unordered.clear()
        self._all_blocks_ordered.clear()
        self._map_address_instruction.clear()
        self._map_address_uuid.clear()

        for block in self.blocks.values():
            self._all_blocks_ordered.add(block)
            for ins in list(block.instructions):
                self._map_address_instruction[ins.address] = ins
                self._map_address_uuid[ins.address] = ins.uuid
                self._all_instructions_unordered.add(ins)
                
                            
    def _create_instruction_sets(self) -> None:
        """Crea sia no_perm_set che no_equ_set in un unico passaggio."""
        for instruction in self._all_instructions_unordered:
            cap_ins = instruction.original_object
            if not cap_ins or not hasattr(cap_ins, "groups"):
                logger.warning(f"Instruction at {instruction.address} missing groups attribute")
                continue

            groups = getattr(cap_ins, "groups", [])
            if any(g in groups for g in NON_PERMUTABLE_GROUP) or instruction.uuid in self.no_perm_set:
                self.no_perm_set.add(instruction.uuid)
                self.no_equ_set.add(instruction.uuid)
                instruction.is_permutable = False
                instruction.is_equivalent = False

   
    def _add_block(self, block: BasicBlock) -> Optional[str]:
        if block.start_address not in self.blocks:
            self.blocks[block.start_address] = block
            return block.uuid
        
        logger.warning(f"Block at {hex(block.start_address)} already exists. Skipping.")
        return None

    def _get_operand_imm(self, op) -> Optional[int]:
        if hasattr(op, "type") and hasattr(op, "imm"):
            if op.type == cap.x86.X86_OP_IMM:
                return op.imm
        if isinstance(op, dict):
            return op.get("imm")
        return None

    def _get_next_block(self, addr: int) -> Optional[BasicBlock]:
        sorted_starts = sorted(self.blocks.keys())
        idx = bisect_right(sorted_starts, addr)
        if idx < len(sorted_starts):
            return self.blocks[sorted_starts[idx]]
        return None

    def _get_block_by_address(self, addr: int) -> Optional[BasicBlock]:
        return self.blocks.get(addr)

    def _get_near_blocks(self, current_block_uuid: str, max_distance: int = 5) -> List[BasicBlock]:
        if not current_block_uuid:
            raise ValueError("A block's uuid is None")
        max_distance = max_distance if max_distance > 0 else 5
        return self._all_blocks_ordered.get_next_from_items(current_block_uuid, max_distance)

    # ---------------- CREAZIONE GRAFO ----------------

    def create_graph(self, file: FileModelBinary, section: str = ".text") -> None:
        if self.created:
            logger.info("Graph already created. No need to recreate")
            return

        try:
            disassembler = create_disassembler(
                file_type=file.type,
                machine_identifier=file.get_machine_type(),
                use_skipdata=False
            )
            if disassembler is None:
                logger.error("Disassembler is None")
                return

            section_binary = file.binary.get_section(section)
            if not section_binary:
                raise ValueError(f"Section {section} not found")

            section_address = file.get_base_address() + section_binary.virtual_address
            if self._start_address_base is None:
                self._start_address_base = section_address

            instructions = disassemble_bytes(
                codes=bytes(section_binary.content),
                start_address=section_address,
                dis=disassembler
            )
            if not instructions:
                raise ValueError("Cannot disassemble the instructions")
            logger.info(f"Found {len(instructions)} instructions")

            block: Optional[BasicBlock] = None
            for instr in instructions:
                term_type, is_conditional = is_terminator(instr)

                if block is None:
                    block = BasicBlock(instr.address)

                unique_uuid, instruction_created = block.add_instruction(instr)
                if unique_uuid is None or instruction_created is None:
                    raise ValueError(f"{instr.address} cannot generate UUID or instruction")
                # Non serve aggiungere a self._all_instructions_unordered qui, verrà fatto da _create_maps

                if term_type is not None:
                    block.set_terminator(instr, term_type, is_conditional, uuid=instruction_created.uuid)
                    self._add_block(block)
                    block = None
            
            # Se l'ultimo blocco non ha un terminatore esplicito (es. finisce il .text)
            if block is not None:
                self._add_block(block)

            self._create_maps()
            self._create_instruction_sets()
            self._link_successors()

            self.created = True
            self._addresses_dirty = True

        except Exception:
            logger.error(traceback.format_exc())
            self.created = False

    # ---------------- SUCCESSORI ----------------

    def _link_successors(self, max_neigh: int = 5) -> None:
        for block in self._all_blocks_ordered:
            instr = block.terminator
            term_type = block.terminator_type
            is_conditional = getattr(block, "is_conditional", False)

            successors: List[Tuple[str, int]] = []
            
            # Se non c'è terminatore, il successore è il blocco successivo
            if term_type is None:
                next_block = self._get_next_block(block.start_address)
                if next_block:
                    successors.append((next_block.uuid, next_block.start_address))
            
            elif term_type == TERMINATOR_TYPE.JUMP:
                target_addr = self._get_operand_imm(instr.operands[0]) if instr.operands else None
                target_block = self._get_block_by_address(target_addr) if target_addr else None
                if target_block:
                    successors.append((target_block.uuid, target_block.start_address))
                # Se il salto è condizionale, aggiungi anche il blocco successivo (fall-through)
                if is_conditional:
                    next_block = self._get_next_block(block.start_address)
                    if next_block:
                        successors.append((next_block.uuid, next_block.start_address))
            
            elif term_type == TERMINATOR_TYPE.CALL:
                # Il successore di una CALL è il blocco immediatamente successivo
                next_block = self._get_next_block(block.start_address)
                if next_block:
                    successors.append((next_block.uuid, next_block.start_address))

            # Per RET, IRET, INT, SYSCALL non ci sono successori calcolabili staticamente
            elif term_type in (TERMINATOR_TYPE.RETURN, TERMINATOR_TYPE.IRET,
                               TERMINATOR_TYPE.INT, TERMINATOR_TYPE.SYSCALL):
                successors = []

            block._add_successor(successors)

    # ---------------- INDIRIZZI E ISTRUZIONI ----------------

    def ricalculate_all_addresses(self) -> None:
        base_address = self._start_address_base
        for block in self._all_blocks_ordered:
            base_address = block.ricalcolate_addresses(base_address=base_address, return_end_address=True)
        self._addresses_dirty = False

    def get_all_instruction(self) -> OrderedUUIDSet[BasicInstruction]:
        self.ricalculate_all_addresses()
        instruction_uuidset: OrderedUUIDSet[BasicInstruction] = OrderedUUIDSet()
        for block in list(self._all_blocks_ordered):
            for ins in list(block.instructions): 
                instruction_uuidset.add(ins)
        return instruction_uuidset


    #TODO: FUNZIONE PER AGGIORNARE GLI INDIRIZZI DEI TERMINATOR
    def resolve_terminator_addresses(self) -> Set[int]:
        """
        Tenta di aggiornare gli indirizzi dei terminatori JMP/CALL.
        Restituisce un set contenente tutti gli indirizzi di destinazione originali
        che non è stato possibile risolvere.
        """
        all_instructions_ordered = self.get_all_instruction()
        map_uuid_to_instruction = {ins.uuid: ins for ins in all_instructions_ordered}
        
        # 1. Crea un set vuoto per raccogliere gli indirizzi
        unresolved_addresses: Set[int] = set()

        for term in (ins for ins in all_instructions_ordered if ins.is_terminator):
            if cap.CS_GRP_JUMP in term.groups or cap.CS_GRP_CALL in term.groups:
                if not term.operands:
                    continue

                original_target_addr = self._get_operand_imm(term.operands[0])
                if original_target_addr is None:
                    continue

                target_uuid = self._map_address_uuid.get(original_target_addr)
                
                if target_uuid is None:
                    # 2. Aggiungi l'indirizzo non risolto al set
                    unresolved_addresses.add(original_target_addr)
                    continue # Passa all'istruzione successiva

                target_instr = map_uuid_to_instruction.get(target_uuid)
                
                if target_instr is None or target_instr.address is None:
                    unresolved_addresses.add(original_target_addr)
                    logger.error(f"ERRORE CRITICO: Trovato UUID per {hex(original_target_addr)} ma l'oggetto istruzione non esiste più!")
                    continue

                term.terminator_new_address = target_instr.address

        # 3. Restituisci il set completo alla fine
        return unresolved_addresses

                        

    # ---------------- UTILITIES ----------------

    def dump(self) -> List[dict]:
        return [blk.to_dict() for blk in sorted(self.blocks.values(), key=lambda x: x.start_address)]

    def to_asm(self) -> str:
        """Restituisce una stringa contenente l'intero programma assembly del CFG."""
        # Ordina i blocchi per indirizzo per garantire un output coerente
        ordered_blocks = sorted(self.blocks.values(), key=lambda b: b.start_address)
        return "\n\n".join(block.to_asm() for block in ordered_blocks)
