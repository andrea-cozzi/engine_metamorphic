import logging
from pathlib import Path
from typing import Optional
from engine_meta.cfg import EngineMetaCFG
from engine_meta.component.garbage_generator import GarbageGenerator
from engine_meta.component.permutor import Permutator
from engine_meta.model.basic_block import BasicBlock
from engine_meta.utils.common_function import *
from engine_meta.utils.save_to_file import *
from model.file_model import FileModelBinary
from constant_var import PRO_PERMUTATION_ISTRUCTION, PRO_PERMUTATION_BLOCK,ALLOW_PERMUTATION_BLOCK, SAVE_ASM_DECODED, SAVE_CFG_JSON

logger = logging.getLogger(__name__)
ASSEMBLY_PATH = "cache_assembly/"


class MetamorphicEngine:
    """Motore completo per analisi e trasformazioni metamorfica di binari."""

    def __init__(self,  model: FileModelBinary):
        if model is None:
            raise ValueError(f"{model.file_path} cannot be None")
        
        self.file: FileModelBinary = model
        self._graph: Optional[EngineMetaCFG] = None
        componente_mode = get_component_modes(self.file.binary)
        self.cs_arch, self.cs_mode = componente_mode["capstone"]
        self.ks_arch, self.ks_mode = componente_mode["keystone"]

        self._mutation_number : int = 0



    def metamorph(self, section: str = ".text") -> None:
        
        self.create_graph_cfg(section=section)
        
        if SAVE_ASM_DECODED:
            self.test_save()

        self._mutate_cfg()

        self._save_mutation()

    
    # ----------------------------
    # CFG
    # ----------------------------
    def create_graph_cfg(self, section: str = ".text") -> None:
        graph : EngineMetaCFG = EngineMetaCFG()

        graph.create_graph(file=self.file, section=section)

        if graph.created == False:
            raise ValueError("Graph has not been correctly created")

        self._graph = graph

        if SAVE_CFG_JSON:
            p = Path(self.file.file_path)
            save_json_filename: str = p.stem
            FileUtils.save_cfg_to_json(graph=self._graph, file_name=save_json_filename)

        return      


    #QUI DI UTILIZZA DOT.ENV per le variabili
    def _mutate_cfg(self) -> None:

            #Permutazioni
            self._permutate_algorithm()
            

            #AGGIUNTA GARBAGE / DEAD CODE
            self._garbage_code_mutation()

            #SIMILI




    def _garbage_code_mutation(self) -> None:
            GarbageGenerator.add_garbage_code(blocks=self._graph._all_blocks_ordered,
                                              arch_cs=self.cs_arch,
                                              arch_ks=self.ks_arch,
                                              mode_cs=self.cs_mode,
                                              mode_ks=self.ks_mode)
            
            self._graph.ricalculate_all_addresses()
        
    def should_permute_block_instructions(self,
                            block : BasicBlock) -> bool:
        """
        Decide se permutare un blocco in base a:
        - probabilità di base (da .env)
        - numero di istruzioni totali
        - numero di istruzioni permutabili
        """
        instructions = list(block.instructions)
        total = len(instructions)
        
        permutables = [ins for ins in instructions if getattr(ins, "is_permutable", False)]
        n_perm = len(permutables)

        if total == 0 or n_perm < 2:
            return False  # niente da permutare

        factor = n_perm / total

        prob = PRO_PERMUTATION_ISTRUCTION * factor

        return random.random() < prob

    def _permutate_algorithm(self,
                             max_perm_instrucion: Optional[int] = None,
                             ) -> None:
        
        for _, block in enumerate(self._graph._all_blocks_ordered):
            if self.should_permute_block_instructions(block):
                Permutator.permute_instructions_random(
                    block=block,
                    max_perm_instruction=max_perm_instrucion
                    )

        if ALLOW_PERMUTATION_BLOCK:
            total_block: int = len(list(self._graph._all_blocks_ordered))

            if total_block > 1:  
                expected_to_permute = int(total_block * PRO_PERMUTATION_BLOCK)

                if expected_to_permute >= 2:
                    percent_perm = (expected_to_permute / total_block) * 100
                    Permutator.permute_blocks_safe(self._graph._all_blocks_ordered, percent_perm=percent_perm)




    def _save_mutation(self) -> None:
        output = "".join(self._graph.to_asm())
        filename: str = f"{Path(self.file.file_path).stem}_mutation_{self._mutation_number}.asm"
        self._mutation_number+=1
        FileUtils.save_to_assembly(output, file_name=filename)


    def _ricompile(self) -> None:
        pass


    

    # ----------------------------
    #  TESTING
    # ----------------------------


    def test_save(self):
        output = "".join(self._graph.to_asm())
        p = Path(self.file.file_path)
        file_name = f"{p.stem}_NO_MUTATO.asm"
        FileUtils.save_to_assembly(output, file_name=file_name)


    def test_permutation(self):
        block: BasicBlock = list(self._graph._all_blocks_ordered)[1]
        #permutate_instruction_random(block=block)
        output = "".join(self._graph.to_asm())
        FileUtils.save_to_assembly(output, file_name="assembly_prova_permutazione.asm")


