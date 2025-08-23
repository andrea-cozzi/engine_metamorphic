import logging
import traceback
from typing import List, Dict, Optional, Set, Tuple
import capstone as cap
import keystone as ks
import lief as lf


from component.ass_diss import create_disassembler, disassemble_bytes
from engine_meta.model.basic_block import BasicBlock
from engine_meta.model.basic_instruction import BasicInstruction
from engine_meta.model.ordered_uuidset import OrderedUUIDSet
from model.file_model import FileModelBinary
from shared.common_def import is_terminator
from shared.constants import CAPSTONE_TO_KEYSTONE_MAP, INVERT_MAP, TERMINATOR_TYPE

logger = logging.getLogger(__name__)

LABEL_BLOCK = "label_{:#x}"

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
        #int --> indirizzo di star del blocco
        self.blocks: Dict[int, BasicBlock] = {}

        #indirizzo base della sezione
        self._start_addres_base : Optional[int] = None


        #Tutte le istruzioni / blocks del grafo
        self._all_instructions_unordered: Set[BasicInstruction] = set()
        self._all_blocks_ordered : OrderedUUIDSet[BasicBlock] = OrderedUUIDSet[BasicBlock]()


        #Mappa delle label dei blocchi
        self._map_address_label: Dict[int, str] = {}

        #Utilie per la ricerca
        self._map_address_instruction: Dict[int, BasicInstruction] = {}
        self._map_address_uuid: Dict[int, str] = {}
        
        #Set di UUID per le istruzioni che non TROVAre EQUIVALENTI
        self.no_equ_set : Set[str] = set()
        self.no_perm_set: Set[str] = set()

        self.created : bool = False


    #----- FUNZIONI PRIVATE ---------------------
    def _find_terminators(self, instructions: List[cap.CsInsn]) -> Dict[int, TERMINATOR_TYPE]:
        terminators = {}
        for _, instr in enumerate(instructions):
            term_type, _= is_terminator(instr)
            if term_type is not None:
                terminators[instr.address] = term_type
        return terminators


    #COSTRUISCO TUTTE LE MAPPE NECESSARIE PER VELOCIZZARE LA RICERCA
    def _create_maps(self) -> None:
        for block in self.blocks.values():   # usa .values() se self.blocks è un dict
            for ins in block.instructions:   # block.instructions è un OrderedUUIDSet, puoi iterarlo
                self._map_address_instruction[ins.address] = ins
                self._map_address_uuid[ins.address] = ins.uuid
                self._all_instructions_unordered.add(ins)

            self._all_blocks_ordered.add(block)



    #COSTRUISCO IL GRUPPO DI ISTRUZIONI CHE NON POSSONO ESSERE PERMUTATE
    def _create_unpermutable_set(self) -> None:
        for _, instruction in enumerate(self._all_instructions_unordered):
            cap_ins : cap.CsInsn = instruction.original_object
            if cap_ins is None or not hasattr(cap_ins, "groups"):
                logger.warning(f"Instructiona at {instruction.address} is None or doesnt have groups attr")
                raise ValueError(f"Instructiona at {instruction.address} is None or doesnt have groups attr")

            groups = getattr(cap_ins, "groups", [])
            if any(group in groups for group in NON_PERMUTABLE_GROUP):
                self.no_perm_set.add(instruction.uuid)
                instruction.is_permutable = False


    #COSTRUISCO IL GRUPPO DI ISTRUZIONI CHE NON POSSO ASSCOARLE UNA EQUIVALENTE
    def _create_unequivalent_set(self) -> None: 
        for _, instruction in enumerate(self._all_instructions_unordered):
            cap_ins: cap.CsInsn = instruction.original_object

            if cap_ins is None or not hasattr(cap_ins, "groups"):
                logger.warning(f"Instruction at {instruction.address} is None or doesn't have groups attr")
                continue

            groups = getattr(cap_ins, "groups", [])

            if any(group in groups for group in NON_PERMUTABLE_GROUP) or instruction.uuid  in self.no_perm_set:
                self.no_equ_set.add(instruction.uuid)
                instruction.is_equivalent = False


    #COSTRUISCO IL SINGOLO BLOCCO 
    def _add_block(self, block: BasicBlock) -> Optional[str]:
        if block.start_address not in self.blocks:
            self.blocks[block.start_address] = block
            self._map_address_label[block.start_address] = LABEL_BLOCK.format(block.start_address)
            return block.uuid
        else:
            logger.warning(f"Block at {hex(block.start_address)} already exists. Skipping.")



    # ----- API DELLA CLASSE -----------------------
    def create_graph(self, file: FileModelBinary, section: str = ".text") -> None:
        try:
            if self.created:
                logger.info("Graph already created. No need to recreate")
                return

            # --- inizializza disassembler ---
            disassembler = create_disassembler(
                file_type=file.type,
                machine_identifier=file.get_machine_type(),
                use_skipdata=False
            )
            if disassembler is None:
                logger.error("Disassembler is None")
                return

            # --- ottieni sezione di codice ---
            section_binary = file.binary.get_section(section)
            if not section_binary:
                raise ValueError(f"Section {section} not found")

            section_address = file.get_base_address() + section_binary.virtual_address
            if self._start_addres_base is None:
                self._start_addres_base = section_address

            section_code = bytes(section_binary.content)

            # --- disassemblaggio istruzioni ---
            instructions: List[cap.CsInsn] = disassemble_bytes(
                codes=section_code,
                start_address=section_address,
                dis=disassembler
            )
            if not instructions:
                raise ValueError("Cannot disassemble the instructions")
            logger.info(f"Found {len(instructions)} instructions")

            # --- crea blocchi e aggiungi istruzioni ---
            block: Optional[BasicBlock] = None

            for instr in instructions:
                term_type, is_conditional = is_terminator(instr)

                # Se non esiste blocco corrente, creane uno nuovo
                if block is None:
                    block = BasicBlock(instr.address)

                # Aggiungi istruzione al blocco
                unique_ud, instruction_created = block.add_instruction(instr)
                if unique_ud is None or instruction_created is None:
                    raise ValueError(f"{instr.address} cannot generate UUID or instruction")
                self._all_instructions_unordered.add(instruction_created)

                # Se istruzione è terminatore, chiudi il blocco
                if term_type is not None:
                    block.set_terminator(instr, term_type, is_conditional, uuid=instruction_created.uuid)
                    block_uuid = self._add_block(block)
                    if block_uuid is None:
                        raise ValueError(f"{block.start_address} UUID is None")
                    self._all_blocks_ordered.add(block)
                    block = None

            # --- crea mappature e set utili ---
            self._create_maps()
            self._create_unequivalent_set()
            self._create_unpermutable_set()

            # --- collega blocchi successori ---
            self._link_successors()

            self.created = True

        except Exception:
            logger.error(traceback.format_exc())
            self.created = False

    


    def _get_operand_imm(self, op) -> Optional[int]:
        """
        Estrae l'indirizzo immediato da un operando.
        Supporta sia oggetti Capstone che dict serializzati.
        """
        # Caso Capstone (X86)
        if hasattr(op, "type") and hasattr(op, "imm"):
            if op.type == cap.x86.X86_OP_IMM:
                return op.imm
            return None
        # Caso dict serializzato
        if isinstance(op, dict):
            return op.get("imm")
        return None


    def _link_successors(self, max_neigh: int = 5) -> None:
        """
        Associa a ogni blocco i suoi successori.
        max_neigh indica il numero massimo di blocchi "vicini" da considerare.
        """
        for block in self._all_blocks_ordered:
            instr = block.terminator
            term_type = block.terminator_type
            is_conditional = getattr(block, "is_conditional", False)

            successors: List[Tuple[str, int]] = []
            near_blocks: List["BasicBlock"] = self._get_near_blocks(block.uuid, max_neigh)

            if term_type == TERMINATOR_TYPE.JUMP:
                if is_conditional:
                    # Jump condizionale: target + fall-through
                    for b in near_blocks:
                        successors.append((b.uuid, b.start_address))
                else:
                    # Jump incondizionale: solo il target immediato
                    target_addr = None
                    if instr.operands:
                        target_addr = self._get_operand_imm(instr.operands[0])

                    if target_addr is not None:
                        for b in near_blocks:
                            if b.start_address == target_addr:
                                successors.append((b.uuid, b.start_address))
            elif term_type == TERMINATOR_TYPE.CALL:
                # Call: il successore naturale è il blocco subito dopo
                for b in near_blocks:
                    if b.start_address > block.end_address:
                        successors.append((b.uuid, b.start_address))
                        break
            elif term_type in (
                TERMINATOR_TYPE.RETURN,
                TERMINATOR_TYPE.IRET,
                TERMINATOR_TYPE.INT,
                TERMINATOR_TYPE.SYSCALL,
            ):
                # Terminatori senza successori diretti
                successors = []
            else:
                # Fallback: considera i blocchi vicini
                for b in near_blocks:
                    successors.append((b.uuid, b.start_address))

            # Aggiungi i successori al blocco
            block._add_successor(successors)



    def _get_next_block(self, addr: int) -> Optional[BasicBlock]:
        """
        Restituisce il blocco con l'indirizzo più piccolo maggiore di addr.
        """
        for block in self._all_blocks_ordered:
            if block.start_address > addr:
                return block
        return None

    def _get_block_by_address(self, addr: int) -> Optional[BasicBlock]:
        """
        Restituisce il blocco che inizia all'indirizzo addr.
        """
        for block in self._all_blocks_ordered:
            if block.start_address == addr:
                return block
        return None


                    
    """
    def get_block_start(self, address: int) -> Optional[int]:
        sorted_starts = sorted(self.blocks.keys())  # meglio se memorizzato già ordinato
        idx = bisect.bisect_right(sorted_starts, address) - 1
        if idx >= 0:
            return sorted_starts[idx]
        return None
    """

    def _get_near_blocks(self, cuurent_block_uuid: str, max_distance: int = 5) -> List[Tuple[str, int]]:
        if cuurent_block_uuid is None or len(cuurent_block_uuid) <=0:
            raise ValueError("A block's uuid is None")
        
        max_distance = max_distance if max_distance > 0 else 5

        return self._all_blocks_ordered.get_next_from_items(cuurent_block_uuid, max_distance)



     


    # FUNXIONE CHE MI RICALCOLA TUTTI GLI ADDRESS DELLE ISTRUZIONI
    def ricalculate_all_addresses(self)-> None:
        base_address: int = self._start_addres_base
        for _, block in enumerate(self._all_blocks_ordered):
           base_address= block.ricalcolate_addresses(base_address=base_address, return_end_address=True)

        
   




    # --- FUNZIONI UTILI -----

    def dump(self) -> List[dict]:
        return [blk.to_dict() for blk in sorted(self.blocks.values(), key=lambda x: x.start_address)]
    

    def to_asm(self) -> str:
        output : str = ""
        for _, block in enumerate(self._all_blocks_ordered):
            output += str(block)

        return output
    
    

"""
FLUSSO DI FUNZIONI

- genrate_mutation() 

    -create graph -->
        => 
        => Individuo e creo set per i TERMINATORI ==> set di indirizzi
        => creo il grafo e suddivdo il codice a blocchi
        => creo il dizionario: Indirizzo_originale-UUID --> Mappa: Indirizzo_orginale - UUID
        => creo set per gli indirizzi puntati da JUMP / CALL --> UUID bloccati per le equivalenze
        => creo mappa per le label: label_{uuid}

        => PERMUTAZIONI
            - capire quanto due istruzioni sono indipendenti
              e se possono essere inveritie
            - invertimento di blocchi
        
        => INSERIMENTO DI GARBAGE CODE --> quando la inserisco --> devo trovare
            la size con un assemlber 

        => RISOLUZIONE DI OPERAZIONI DI JUMP / CALL CHE NON HANNO UNA LABEL
         --> mi ricavo l'indirizzo originale, trovo lo UUID della istruzione, 
         --> e da li vado a calcolare il suo indirizzo sommando tutte le size


        => EQUIVALENZE tra istuzioni





TODO
    - separare le 3 classi del grafo
    

"""