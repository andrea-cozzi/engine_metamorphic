import logging
from pathlib import Path
from typing import Optional
from engine_meta.engine_cfg import EngineMetaCFG
from engine_meta.utils.common_function import *
from engine_meta.utils.save_to_file import *
from model.file_model import FileModelBinary

logger = logging.getLogger(__name__)
ASSEMBLY_PATH = "cache_assembly/"


class MetamorphicEngine:
    """Motore completo per analisi e trasformazioni metamorfica di binari."""

    def __init__(self,  model: FileModelBinary):
        if model is None:
            raise ValueError(f"{model.file_path} cannot be None")
        
        self.file: FileModelBinary = model
        self._graph: Optional[EngineMetaCFG] = None

    
    # ----------------------------
    # CFG
    # ----------------------------
    def create_graph_cfg(self, section: str = ".text", save_on_json: bool = False, save_json_path : str = "output/test_graph.json") -> None:
        graph : EngineMetaCFG = EngineMetaCFG()
        graph.create_graph(file=self.file, section=".text")

        if graph.created == False:
            raise ValueError("Graph has not been correctly created")

        if save_on_json and len(save_json_path) > 0:
            graph.save_to_json("output/test_graph.json")
        self._graph = graph
        return        

    # ----------------------------
    #  TESTING
    # ----------------------------


    def test_equivalce_and_save(self,
                                section: str = ".text",
                                save_on_json: bool = True, 
                                save_json_path : str = "output/test_graph.json",
                                save_on_ass : bool = True, 
                                save_ass_name= ""):

        self.create_graph_cfg(section=section, save_on_json=save_on_json, save_json_path=save_json_path)
        
        if self._graph is None or self._graph.created == False:
            logger.error("self._graph is None")
            return

        instructions_str = str(self._graph)
        p = Path(self.file.file_path)
        file_asembly_path = f"{p.stem}.asm" if len(save_ass_name) <= 0 else save_ass_name
        if save_on_ass:
            save_to_assembly(content=instructions_str, file_name=file_asembly_path, address_label_map=self._graph._map_address_star, insert_address=True)
        out  = ""
        instructions = self._graph.get_code_instruction()

        for i in instructions:
            out +=  get_equivalent(i)
        instructions_str = str(self._graph)
        if save_on_ass: 
            file_asembly_path_copy = f"copy_{file_asembly_path}"
            save_to_assembly(content=instructions_str, file_name=file_asembly_path_copy, address_label_map=self._graph._map_address_star)
        

    def test_save(self):
        output = self._graph.to_asm()
        save_to_assembly(output, file_name="assembly_prova.asm")
