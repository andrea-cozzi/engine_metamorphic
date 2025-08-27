import logging
import os
import random
from pathlib import Path
from typing import Dict, Optional, List, Any

from concurrent.futures import ProcessPoolExecutor, as_completed
import capstone as cs

# Assicurati che i percorsi di importazione siano corretti per il tuo progetto
from component.parser import Parser
from feature_extractor.extractor import BinaryFeatureExtractor
from metamorphic_engine.cfg import EngineMetaCFG
from metamorphic_engine.component.equivalent_switcher import EquivalentSwitcher
from metamorphic_engine.component.garbage_generator import GarbageGenerator
from metamorphic_engine.component.permutor import Permutator
from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from metamorphic_engine.utils.common_function import get_component_modes
from shared.save_to_file import FileUtils
from model.file_model import FileModelBinary
from constant_var import *

logger = logging.getLogger(__name__)


class MetamorphicEngine:
    """Motore metamorfico che integra l'estrazione di feature e salva un CSV finale."""

    def __init__(self, model: FileModelBinary):
        if model is None:
            raise ValueError("Il modello passato non può essere None")
        self.file: FileModelBinary = model
        self._graph: Optional[EngineMetaCFG] = None
        componente_mode = get_component_modes(self.file.binary)
        self.cs_arch, self.cs_mode = componente_mode["capstone"]
        self.ks_arch, self.ks_mode = componente_mode["keystone"]

    # _auto_adjust_probabilities non cambia
    def _auto_adjust_probabilities(self, target_mutations: int = 25):
        """Aggiusta dinamicamente le probabilità delle mutazioni."""
        if not self._graph or not self._graph._all_blocks_ordered:
            return

        num_blocks = len(self._graph._all_blocks_ordered)
        avg_instr_per_block = max(
            1,
            sum(len(b.instructions) for b in self._graph._all_blocks_ordered) // num_blocks,
        )
        base = num_blocks * avg_instr_per_block
        scale = target_mutations / base

        def clamp(v: float) -> float:
            return max(0.0, min(1.0, v))

        global PRO_EQUIVALENT_BLOCK, TOTAL_EQUIVALENT_INSTRUCTION, PRO_EQUIVALENT_INSTRUCTION
        global PRO_ADD_DEAD_CODE, PRO_ADD_NOP_INST, PRO_ADD_JUNK_CODE_TERMINATOR, PRO_ADD_OPAQUE_CODE

        PRO_EQUIVALENT_BLOCK = clamp(scale)
        TOTAL_EQUIVALENT_INSTRUCTION = clamp(scale)
        PRO_EQUIVALENT_INSTRUCTION = clamp(scale)
        PRO_ADD_DEAD_CODE = clamp(scale * 0.7)
        PRO_ADD_NOP_INST = clamp(scale * 0.5)
        PRO_ADD_JUNK_CODE_TERMINATOR = clamp(scale * 0.5)
        PRO_ADD_OPAQUE_CODE = clamp(scale * 0.5)

        logger.debug(
            "Probabilità regolate: EQ_BLOCK=%.2f, DEAD=%.2f, NOP=%.2f",
            PRO_EQUIVALENT_BLOCK, PRO_ADD_DEAD_CODE, PRO_ADD_NOP_INST
        )



    def metamorph(
        self,
        section: str = ".text",
        parallel: bool = True,
        max_workers: int = None
    ) -> None:
        """
        Esegue la metamorfosi, estrae le feature per ogni mutazione
        e salva un singolo file CSV con tutti i risultati.
        """
        features_to_save: List[Dict[str, Any]] = []
        
        if ADJ_AUTO_PROB:
            self._auto_adjust_probabilities(target_mutations=25)

        #TODO: inserire varibiabille che decide se analizzare 
        #o meno il l'eseguibile o solo le mutazioni

        # 1. Creazione grafo (solo per il processo principale, non verrà passato)
        self.create_graph_cfg(section=section)
        if self._graph is None or self._graph.created is False:
            raise ValueError("Graph has not been created correctly")


        # 2. Analizza il binario originale
        logger.info(f"Analisi feature per il binario originale: {self.file.file_name}")
        original_features = BinaryFeatureExtractor._process_single_binary(
            entity=self.file, arch_cs=self.cs_arch, mode_cs=self.cs_mode
        )
        if original_features:
            features_to_save.append(original_features)

        # 3. Esecuzione mutazioni e analisi in parallelo
        resolved_workers = self._resolve_max_workers(max_workers)
        
        
        executor_cls = ProcessPoolExecutor if parallel else None

        if parallel and executor_cls:
            logger.info(f"Esecuzione mutazioni e analisi in parallelo con {resolved_workers} PROCESSI")
            with executor_cls(max_workers=resolved_workers) as executor:
                futures = [
                    executor.submit(
                        MutationJob(
                            original_filepath=self.file.file_path,
                            file_name=self.file.file_name,
                            arch_cs=self.cs_arch, arch_ks=self.ks_arch,
                            mode_cs=self.cs_mode, mode_ks=self.ks_mode,
                            mutation_index=i,
                            section=section 
                        ).run
                    )
                    for i in range(NUMBER_MUTATION)
                ]
                for future in as_completed(futures):
                    try:
                        result_features = future.result()
                        if result_features:
                            features_to_save.append(result_features)
                    except Exception as e:
                        logger.error(f"Un job di mutazione/analisi è fallito: {e}", exc_info=True)
        else:
            logger.info("Esecuzione mutazioni e analisi in sequenziale")
            for i in range(NUMBER_MUTATION):
                job = MutationJob(
                    original_filepath=self.file.file_path,
                    file_name=self.file.file_name,
                    arch_cs=self.cs_arch, arch_ks=self.ks_arch,
                    mode_cs=self.cs_mode, mode_ks=self.ks_mode,
                    mutation_index=i,
                    section=section
                )
                result_features = job.run()
                if result_features:
                    features_to_save.append(result_features)

        # 4. Salvataggio del file CSV finale
        if features_to_save:
            output_filename = f"{self.file.file_name}_combined_analysis.csv"
            FileUtils._save_features_to_csv(features_to_save, output_filename)
        else:
            logger.warning("Nessuna feature è stata generata. Nessun file CSV creato.")

    def _resolve_max_workers(self, max_workers: Optional[int]) -> int:
        cpu_count = os.cpu_count() or 1
        default_workers = max(1, cpu_count - 1)
        if max_workers is None:
            return default_workers
        return min(max_workers, cpu_count * 2)

    def create_graph_cfg(self, section: str = ".text") -> None:
        if self._graph is not None:
            raise ValueError("Graph is not None --> errore")
        graph = EngineMetaCFG()
        graph.create_graph(file=self.file, section=section)
        if not graph.created:
            raise RuntimeError("Graph has not been correctly created")
        self._graph = graph


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

    def run(self) -> Optional[Dict[str, Any]]:
        # 1. CARICO IL FILE BINARIO
        try:
            parser: Parser= Parser()
            executable: FileModelBinary = parser.parse_to_bytes(str(self.original_filepath))
        except Exception as e:
            logger.error(f"Impossibile caricare il file {self.original_filepath} nel worker: {e}")
            return None

        # 2. CREO IL GRAFO 
        self.graph = EngineMetaCFG()
        self.graph.create_graph(file=executable, section=self.section)
        if not self.graph.created:
            logger.error(f"Impossibile creare il grafo per {self.file_name} nel worker.")
            return None

        # 3. FASE DI MUTAZIONE
        self._mutate_cfg()
        mutated_instructions = self.graph.get_all_instruction()
        variant_name = f"{self.file_name}_mutation_{self.mutation_index}"

        if SAVE_ASM_DECODED:
            output = self.graph.to_asm()
            FileUtils.save_to_assembly(content=output, file_name=f"{variant_name}.asm")

        # 4. FASE DI ESTRAZIONE FEATURE
        try:
            all_features = BinaryFeatureExtractor._process_single_binary(
                entity=executable,
                arch_cs=self.arch_cs,
                mode_cs=self.mode_cs,
                mutated_instructions=mutated_instructions,
                variant_name=variant_name
            )
            return all_features
        except Exception as e:
            logger.error(f"Errore durante l'estrazione feature per {variant_name}: {e}", exc_info=True)
            return None

    def _mutate_cfg(self):
        self._permutate_algorithm()
        self._garbage_code_mutation()
        self._equivalent_switcher()
        self.graph.ricalculate_all_addresses()

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