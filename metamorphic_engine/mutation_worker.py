  
from datetime import datetime
import logging
from pathlib import Path
import random
from typing import Any, Dict, Optional, Set
import capstone as cs
import lief as lf

from component.parser import Parser
from constant_var import ALLOW_PERMUTATION_BLOCK, PATH_OUTPUT_EXE, PRO_PERMUTATION_BLOCK, PRO_PERMUTATION_ISTRUCTION, SAVE_ASM_DECODED
from metamorphic_engine.cfg import EngineMetaCFG
from metamorphic_engine.component.equivalent_switcher import EquivalentSwitcher
from metamorphic_engine.component.garbage_generator import GarbageGenerator
from metamorphic_engine.component.permutor import Permutator
from metamorphic_engine.utils.assembler_encoder import AssemblerEncoder
from metamorphic_engine.utils.binary_creator import BinaryCreator
from model.file_model import FileModelBinary
from shared.constants import BinaryType
from shared.save_to_file import FileUtils
logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s',
            filename='engine_metamorphic.log',
            filemode='w'
        )

logger = logging.getLogger(__name__)

class MutationJob:
    """
    Worker completamente autonomo. Carica il file, crea il grafo,
    esegue la mutazione, analizza le feature e restituisce un dizionario.
    """
    def __init__(
        self,
        original_filepath: str,
        file_name: str,
        arch_cs, arch_ks, mode_cs, mode_ks,
        mutation_index: int,
        section: str
    ):
        self.original_filepath = original_filepath
        self.file_name = file_name
        self.graph: Optional[EngineMetaCFG] = None 
        self.arch_cs = arch_cs
        self.arch_ks = arch_ks
        self.mode_cs = mode_cs
        self.mode_ks = mode_ks
        self.mutation_index = mutation_index
        self.section = section 

    #torno le features e nulla, togielere la Optiona[str] e tupla
    def run(self) -> tuple[Optional[Dict[str, Any]], Optional[str]]:

        # 1. CARICO IL FILE BINARIO
        try:
            parser: Parser= Parser()
            executable: FileModelBinary = parser.parse_to_bytes(str(self.original_filepath))
        except Exception as e:
            logger.error(f"Impossibile caricare il file {self.original_filepath} nel worker: {e}")
            return None, None

        # 2. CREO IL GRAFO 
        self.graph = EngineMetaCFG()
        self.graph.create_graph(file=executable, section=self.section)
        
        
        if not self.graph.created:
            logger.error(f"Impossibile creare il grafo per {self.file_name} nel worker.")
            return None, None
        

        # 3. FASE DI MUTAZIONE ED EVENTUALE SALVATAGGIO
        _ = self._mutate_cfg()
        mutated_instructions = self.graph.get_all_instruction()
        variant_name = f"{self.file_name}_mutation_{self.mutation_index}"

        if SAVE_ASM_DECODED:
            output = self.graph.to_asm()
            FileUtils.save_to_assembly(content=output, file_name=f"{variant_name}.asm")


        # 4. RICOSTRUZIONE DELL'ESEGUIBILE
        encoder: AssemblerEncoder =   AssemblerEncoder(
            arch=self.arch_ks, mode = self.mode_ks
        )     
        all_instruction: list[cs.CsInsn] = []
        for ins in list(self.graph.get_all_instruction()):
            all_instruction.append(ins.original_object)

        encoding, size = encoder.encode_instructions(
            instructions=all_instruction,
            base_address=self.graph._start_address_base
        )

        if encoding is None or size <= 0:
            raise ValueError("new bytes is None")
        
        # 4.1 Creazione del nuovo eseguibile
        result_creation : bool = BinaryCreator.create_binary(
            binary=executable.binary,
            new_bytes=encoding,
            filename=executable.file_name
        )

        if not result_creation:
            logger.error("Error while creating new executable mutation")
            return None, None


        # 5. FASE DI ESTRAZIONE FEATURE --> TODO DA RIFARE
        return None, None
        try:
            all_features = BinaryFeatureExtractor._process_single_binary(
                entity=executable,
                arch_cs=self.arch_cs,
                mode_cs=self.mode_cs,
                mutated_instructions=mutated_instructions,
                variant_name=variant_name
            )
            return all_features, variant_name
        except Exception as e:
            logger.error(f"Errore durante l'estrazione feature per {variant_name}: {e}", exc_info=True)
            return None, None
        
  

    def _mutate_cfg(self) -> Optional[Set[int]]:
        self._permutate_algorithm()
        self._garbage_code_mutation()
        self._equivalent_switcher()
        self.graph.ricalculate_all_addresses()
        _ = self.graph.resolve_terminator_addresses()
        return None
        

    def _equivalent_switcher(self):
        EquivalentSwitcher.switch_equivalent(blocks=self.graph._all_blocks_ordered, arch_cs=self.arch_cs, arch_ks=self.arch_ks, mode_cs=self.mode_cs, mode_ks=self.mode_ks)

    def _garbage_code_mutation(self):
        GarbageGenerator.add_garbage_code(blocks=self.graph._all_blocks_ordered, arch_cs=self.arch_cs, arch_ks=self.arch_ks, mode_cs=self.mode_cs, mode_ks=self.mode_ks)

    def _permutate_algorithm(self, max_perm_instruction: Optional[int] = None):
        for block in self.graph._all_blocks_ordered:
            instructions = list(block.instructions)
            total = len(instructions)
            permutables = [ins for ins in instructions if getattr(ins, "is_permutable", False)]
            n_perm = len(permutables)
            if total == 0 or n_perm < 2:
                continue
            factor = n_perm / total
            prob = PRO_PERMUTATION_ISTRUCTION * factor
            if random.random() < prob:
                Permutator.permute_instructions_random(
                    block=block,
                    max_perm_instruction=max_perm_instruction
                )

        if ALLOW_PERMUTATION_BLOCK:
            total_block = len(self.graph._all_blocks_ordered)
            if total_block > 1:
                expected_to_permute = int(total_block * PRO_PERMUTATION_BLOCK)
                if expected_to_permute >= 2:
                    percent_perm = (expected_to_permute / total_block) * 100
                    Permutator.permute_blocks_safe(
                        self.graph._all_blocks_ordered,
                        percent_perm=percent_perm
                    )