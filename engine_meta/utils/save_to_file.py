from datetime import datetime
import json
from pathlib import Path
import re
from typing import Generator
import logging

from constant_var import ASSEMBLY_OUTPUT_PATH, JSON_CFG_OUTPUT_PATH

from engine_meta.cfg import EngineMetaCFG

# Le costanti e il logger rimangono a livello di modulo
ASSEMBLY_PATH = Path(ASSEMBLY_OUTPUT_PATH)
JSON_CFG_PATH = Path(JSON_CFG_OUTPUT_PATH)

ADDRESS_PATTERN = re.compile(r'\b(call|j\w+)\s+(0x[0-9a-fA-F]+)\b')

logger = logging.getLogger(__name__)


class FileUtils:
    """
    Classe statica che fornisce metodi di utilità per il salvataggio di file,
    come file assembly e configurazioni in formato JSON.
    """

    @staticmethod
    def save_to_assembly(
        content: str | Generator[str, None, None],
        file_name: str,
    ) -> None:
        """
        Salva il contenuto assembly in un file .asm, leggendo e scrivendo
        linea per linea senza caricare tutto in memoria.
        Supporta sia stringhe che generator di righe.
        """
        if not file_name or not content:
            logger.warning("Parametri non validi per il salvataggio del file assembly.")
            return

        try:
            target_path = ASSEMBLY_PATH / file_name
            target_path.parent.mkdir(parents=True, exist_ok=True)

            if target_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                target_path = target_path.with_name(f"{target_path.stem}_{timestamp}{target_path.suffix}")

            # Creiamo un generator uniforme di righe
            if isinstance(content, str):
                lines = (line + "\n" for line in content.splitlines())
            elif isinstance(content, Generator):
                lines = (line if line.endswith("\n") else line + "\n" for line in content)
            else:
                logger.error(f"Tipo di contenuto non supportato: {type(content)}")
                return

            with open(target_path, "w") as f:
                for line in lines:
                    f.write(line)

            logger.info(f"File assembly salvato correttamente in {target_path}")

        except Exception:
            logger.error(f"Errore durante il salvataggio del file assembly")

    @staticmethod
    def save_cfg_to_json(file_name: str,
                        graph: EngineMetaCFG):
            """
            Salva un oggetto EngineMetaCFG in un file JSON.
            """
            if not file_name:
                logger.warning("Parametri per save_cfg_to_json non validi.")
                return

            try:
                target_path = JSON_CFG_PATH / file_name
                target_path.parent.mkdir(parents=True, exist_ok=True)

                if target_path.exists():
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                    target_path = target_path.with_name(f"{target_path.stem}_{timestamp}{target_path.suffix}")

                with open(target_path, 'w') as file:
                    serializable_cfg = {}

                    for _, block in enumerate(graph._all_blocks_ordered):                        
                        codice_identificativo = hex(block.start_address)                        
                        descrizione_completa = block.to_dict()                        
                        serializable_cfg[codice_identificativo] = descrizione_completa

                    json_dump = {
                        "block_number": len(graph.blocks),
                        "created": graph.created,
                        "blocks": serializable_cfg
                    }
                    json.dump(json_dump, file, indent=2)

                logger.info(f"CFG salvato in {target_path}")
            except Exception:
                logger.error(f"Errore durante il salvataggio del CFG in {file_name}", exc_info=True)