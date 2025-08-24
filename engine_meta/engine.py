import logging
import random
import json
from pathlib import Path
from typing import Optional, List, Tuple
from engine_meta.cfg import EngineMetaCFG
from engine_meta.component.equivalent_switcher import EquivalentSwitcher
from engine_meta.component.garbage_generator import GarbageGenerator
from engine_meta.component.permutor import Permutator
from engine_meta.model.basic_block import BasicBlock
from engine_meta.utils.common_function import get_component_modes
from engine_meta.utils.save_to_file import FileUtils
from model.file_model import FileModelBinary
from constant_var import *

logger = logging.getLogger(__name__)


class MetamorphicEngine:
    """Motore metamorfico completo per binari."""

    def __init__(self, model: FileModelBinary):
        if model is None:
            raise ValueError("Il modello passato non può essere None")
        
        self.file: FileModelBinary = model
        self._graph: Optional[EngineMetaCFG] = None
        componente_mode = get_component_modes(self.file.binary)
        self.cs_arch, self.cs_mode = componente_mode["capstone"]
        self.ks_arch, self.ks_mode = componente_mode["keystone"]
        self.mutated_files: List[str] = []

    # -----------------------------
    # AUTO PROBABILITIES
    # -----------------------------
    def _auto_adjust_probabilities(self, target_mutations: int = 25):
        if self._graph is None:
            return
        num_blocks = len(self._graph._all_blocks_ordered)
        if num_blocks == 0:
            return
        avg_instr_per_block = max(1, sum(len(b.instructions) for b in self._graph._all_blocks_ordered) // num_blocks)
        base = num_blocks * avg_instr_per_block
        scale = target_mutations / base

        def clamp(v): return max(0.0, min(1.0, v))

        global PRO_EQUIVALENT_BLOCK, TOTAL_EQUIVALENT_INSTRUCTION, PRO_EQUIVALENT_INSTRUCTION
        global PRO_ADD_DEAD_CODE, PRO_ADD_NOP_INST, PRO_ADD_JUNK_CODE_TERMINATOR, PRO_ADD_OPAQUE_CODE

        PRO_EQUIVALENT_BLOCK = clamp(scale)
        TOTAL_EQUIVALENT_INSTRUCTION = clamp(scale)
        PRO_EQUIVALENT_INSTRUCTION = clamp(scale)
        PRO_ADD_DEAD_CODE = clamp(scale * 0.7)
        PRO_ADD_NOP_INST = clamp(scale * 0.5)
        PRO_ADD_JUNK_CODE_TERMINATOR = clamp(scale * 0.5)
        PRO_ADD_OPAQUE_CODE = clamp(scale * 0.5)

    # -----------------------------
    # MAIN METHOD
    # -----------------------------
    def metamorph(self, section: str = ".text") -> None:
        """Esegue la metamorfosi completa sul binario."""
        saved: bool = False
        for index in range(NUMBER_MUTATION):
            self.create_graph_cfg(section=section)
            if SAVE_ASM_DECODED and not saved:
                self.test_save()
                saved = True

            self._auto_adjust_probabilities(target_mutations=25)
            self._mutate_cfg()
            mutated_file = self._save_mutation(index=index)
            self.mutated_files.append(mutated_file)

        self.save_mutation_report_json()
    # -----------------------------
    # CFG
    # -----------------------------
    def create_graph_cfg(self, section: str = ".text") -> None:
        graph = EngineMetaCFG()
        graph.create_graph(file=self.file, section=section)

        if not graph.created:
            raise RuntimeError("Graph non creato correttamente")

        self._graph = graph

        if SAVE_CFG_JSON:
            p = Path(self.file.file_path)
            save_json_filename: str = p.stem
            FileUtils.save_cfg_to_json(graph=self._graph, file_name=save_json_filename)

    # -----------------------------
    # MUTAZIONI
    # -----------------------------
    def _mutate_cfg(self) -> None:
        self._permutate_algorithm()
        self._garbage_code_mutation()
        self._equivalent_switcher()

    def _equivalent_switcher(self) -> None:
        EquivalentSwitcher.switch_equivalent(
            blocks=self._graph._all_blocks_ordered,
            arch_cs=self.cs_arch,
            arch_ks=self.ks_arch,
            mode_cs=self.cs_mode,
            mode_ks=self.ks_mode
        )
        self._graph.ricalculate_all_addresses()

    def _garbage_code_mutation(self) -> None:
        GarbageGenerator.add_garbage_code(
            blocks=self._graph._all_blocks_ordered,
            arch_cs=self.cs_arch,
            arch_ks=self.ks_arch,
            mode_cs=self.cs_mode,
            mode_ks=self.ks_mode
        )
        self._graph.ricalculate_all_addresses()

    def should_permute_block_instructions(self, block: BasicBlock) -> bool:
        instructions = list(block.instructions)
        total = len(instructions)
        permutables = [ins for ins in instructions if getattr(ins, "is_permutable", False)]
        n_perm = len(permutables)

        if total == 0 or n_perm < 2:
            return False

        factor = n_perm / total
        prob = PRO_PERMUTATION_ISTRUCTION * factor
        return random.random() < prob

    def _permutate_algorithm(self, max_perm_instruction: Optional[int] = None) -> None:
        for block in self._graph._all_blocks_ordered:
            if self.should_permute_block_instructions(block):
                Permutator.permute_instructions_random(
                    block=block,
                    max_perm_instruction=max_perm_instruction
                )

        if ALLOW_PERMUTATION_BLOCK:
            total_block = len(self._graph._all_blocks_ordered)
            if total_block > 1:
                expected_to_permute = int(total_block * PRO_PERMUTATION_BLOCK)
                if expected_to_permute >= 2:
                    percent_perm = (expected_to_permute / total_block) * 100
                    Permutator.permute_blocks_safe(self._graph._all_blocks_ordered, percent_perm=percent_perm)

    # -----------------------------
    # SALVATAGGIO
    # -----------------------------
    def _save_mutation(self, index: int = 0) -> str:
        output = "".join(self._graph.to_asm())
        filename = f"{Path(self.file.file_path).stem}_mutation_{index}.asm"
        FileUtils.save_to_assembly(output, file_name=filename)
        return filename

    def test_save(self):
        output = "".join(self._graph.to_asm())
        p = Path(self.file.file_path)
        file_name = f"{p.stem}_NO_MUTATO.asm"
        FileUtils.save_to_assembly(output, file_name=file_name)

    # -----------------------------
    # ANALISI MUTAZIONE JSON
    # -----------------------------
    @staticmethod
    def compare_asm_files(file_original_name: str, file_mutated_name: str) -> Tuple[int, int, int, float]:
        """
        Confronta due file ASM in ASSEMBLY_OUTPUT_PATH e restituisce:
        - numero righe originali
        - righe effettivamente modificate
        - righe aggiunte o rimosse
        - percentuale di modifiche reali rispetto al file originale
        """
        file_original = Path(ASSEMBLY_OUTPUT_PATH) / file_original_name
        file_mutated = Path(ASSEMBLY_OUTPUT_PATH) / file_mutated_name

        with open(file_original, 'r', encoding='utf-8', errors='ignore') as f:
            lines_orig = [line.strip() for line in f if line.strip()]

        with open(file_mutated, 'r', encoding='utf-8', errors='ignore') as f:
            lines_mut = [line.strip() for line in f if line.strip()]

        num_orig = len(lines_orig)
        modificate = 0
        min_len = min(len(lines_orig), len(lines_mut))
        for i in range(min_len):
            if lines_orig[i] != lines_mut[i]:
                modificate += 1

        aggiunte_rimosse = abs(len(lines_orig) - len(lines_mut))
        percent_mod = (modificate / num_orig) * 100 if num_orig > 0 else 0.0

        return num_orig, modificate, aggiunte_rimosse, percent_mod

    def save_mutation_report_json(self):
        """
        Salva un report JSON dei file mutati, con righe modificate, aggiunte/rimosse e percentuale reale.
        """
        if not self.mutated_files:
            return

        p = Path(self.file.file_path)
        original_file = f"{p.stem}_NO_MUTATO.asm"
        report = []

        for f in self.mutated_files:
            num_orig, modificate, aggiunte_rimosse, percent_mod = self.compare_asm_files(original_file, f)
            report.append({
                "file_mutato": f,
                "righe_originali": num_orig,
                "righe_modificate": modificate,
                "righe_aggiunte_o_rimosse": aggiunte_rimosse,
                "percentuale_modificata": percent_mod
            })

        with open(Path(REPORT_JSON_PATH) / FILENAME_JSON_REPORT, "w", encoding="utf-8") as jf:
            json.dump(report, jf, indent=4)

        logger.info(f"Report JSON salvato in {FILENAME_JSON_REPORT}")
