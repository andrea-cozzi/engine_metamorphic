from datetime import datetime
from pathlib import Path
from typing import Generator, List
from capstone import CsInsn
import logging


ASSEMBLY_PATH = Path("./assembly_output/") 
logger = logging.getLogger(__name__)
class EngineUtil:
    
    @staticmethod
    def save_to_assembly(instructions: List[CsInsn], file_name: str, insert_address: bool = False) -> None:
        if not file_name or not instructions:
            logger.warning("Parametri non validi per il salvataggio del file assembly.")
            return

        try:
            target_path = ASSEMBLY_PATH / file_name

            target_path.parent.mkdir(parents=True, exist_ok=True)

            if target_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                target_path = target_path.with_name(f"{target_path.stem}_{timestamp}{target_path.suffix}")


            def generate_lines() -> Generator[str, None, None]:
                if insert_address:
                    for i in instructions:
                        yield f"0x{i.address:x}\t{i.mnemonic}\t{i.op_str}\n"
                else:
                    for i in instructions:
                        yield f"{i.mnemonic}\t{i.op_str}\n"

            with open(target_path, 'w') as file:
                file.writelines(generate_lines())
            
            logger.info(f"File assembly salvato correttamente in {target_path}")

        except Exception:
            logger.error(f"Errore durante il salvataggio del file assembly {file_name}", exc_info=True)