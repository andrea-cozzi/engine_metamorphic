import logging
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from component.disassembler import Disassembler
from engine_meta.engine_cfg import EngineMetaCFG, BasicBlock
from engine_meta.utils.save_to_file import EngineUtil
from model.file_model import FileModelBinary
from shared.common_def import is_terminator
import capstone as cap

logger = logging.getLogger(__name__)
ASSEMBLY_PATH = "cache_assembly/"


class MetamorphicEngine:
    """Motore completo per analisi e trasformazioni metamorfica di binari."""

    def __init__(self,  model: FileModelBinary):
        if model is None:
            raise ValueError(f"{model.file_path} cannot be None")
        
        self.file: FileModelBinary = model
        self.cfg: Optional[EngineMetaCFG] = None

        self.disassembler: Disassembler = Disassembler()
        self.disassembler.create(file_type=self.file.type, use_skipdata=True, machine_identifier=self.file.get_machine_type())
        if self.disassembler.dis is None:
            raise ValueError("Disassembler è NONE")


    # ----------------------------
    # CFG
    # ----------------------------
    def create_graph_cfg(self, section: str = ".text", save_on_json: bool = False, save_json_path : str = "output/test_graph.json") -> Optional[EngineMetaCFG]:
        graph : EngineMetaCFG = EngineMetaCFG()
        graph.create_graph(file=self.file, disassembler=self.disassembler, section=".text")
        if save_on_json and len(save_json_path) > 0:
            graph.save_to_json("output/test_graph.json")
       
        instructions = graph.get_code_instruction()
        logger.info(instructions)
        p = Path(self.file.file_path)
        file_asembly_path = f"{p.stem}.asm"
        logger.info(file_asembly_path)
        EngineUtil.save_to_assembly(instructions=instructions, file_name=file_asembly_path)
