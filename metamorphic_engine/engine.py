from datetime import datetime
import logging
import os
import random
from pathlib import Path
from typing import Dict, Optional, List, Any, Set

from concurrent.futures import ProcessPoolExecutor, as_completed
import capstone as cs
import lief as lf

# Assicurati che i percorsi di importazione siano corretti per il tuo progetto
from component.parser import Parser
from feature_extractor.extractor import BinaryFeatureExtractor
from metamorphic_engine.cfg import EngineMetaCFG
from metamorphic_engine.component.equivalent_switcher import EquivalentSwitcher
from metamorphic_engine.component.garbage_generator import GarbageGenerator
from metamorphic_engine.component.permutor import Permutator
from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from metamorphic_engine.mutation_worker import MutationJob
from metamorphic_engine.utils.assembler_encoder import AssemblerEncoder 
from metamorphic_engine.utils.common_function import get_component_modes
from shared.constants import BinaryType
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

        logger.info(
            "Probabilità regolate: EQ_BLOCK=%.2f, DEAD=%.2f, NOP=%.2f",
            PRO_EQUIVALENT_BLOCK, PRO_ADD_DEAD_CODE, PRO_ADD_NOP_INST
        )


    def metamorph(
        self,
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
        self.create_graph_cfg(section=".text")
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
        
        mutated_files_names: List[str] = []
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
                            section=".text" 
                        ).run
                    )
                    for i in range(NUMBER_MUTATION)
                ]
                for future in as_completed(futures):
                    try:
                        result_features , variant_name= future.result()
                        if result_features:
                            features_to_save.append(result_features)

                        if variant_name:
                            mutated_files_names.append(variant_name)

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
                    section=".text"
                )
                result_features, variant_name = job.run()
                if result_features:
                    features_to_save.append(result_features)
                if variant_name:
                            mutated_files_names.append(variant_name)


        if SAVE_MUTATION_REPORT:
                FileUtils.save_mutation_report_json(
                    mutated_files_names=mutated_files_names,
                    original_base_name=self.file.file_name
                )

        # 4. Salvataggio del file CSV finale
        if False:
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

