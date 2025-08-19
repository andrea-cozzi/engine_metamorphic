from datetime import datetime
from pathlib import Path
import re
from typing import Dict, List, Union, Generator
import logging

from engine_meta.model.basic_instruction import BasicInstruction


ASSEMBLY_PATH = Path("./assembly_output/")
ADDRESS_PATTERN = re.compile(r'\b(call|j\w+)\s+(0x[0-9a-fA-F]+)\b')


logger = logging.getLogger(__name__)



def _resolve_address_stream(input_lines: Generator[str, None, None],
                        address_label_map: Dict[int, str]) -> Generator[str, None, None]:
    """
    Sostituisce in ogni linea assembly gli indirizzi con le etichette presenti in address_label_map.
    Tutti gli indirizzi presenti nella mappa vengono sostituiti.
    """
    for line in input_lines:
        new_line = line
        # Cerca tutti gli indirizzi esadecimali nella linea
        for match in ADDRESS_PATTERN.finditer(line):
            instr, addr_str = match.groups()
            try:
                addr = int(addr_str, 16)
            except ValueError:
                continue  # ignora se non è un esadecimale valido

            label = address_label_map.get(addr)
            if label:
                # sostituisci esattamente il valore esadecimale con la label
                new_line = new_line.replace(addr_str, label)
            else:
                logger.debug(f"Indirizzo {addr_str} non trovato nella mappa")
        yield new_line



#TODO: se passo List[BasicInstruction] stampa solo quelle 

def save_to_assembly(
    content: Union[List[BasicInstruction], str],
    file_name: str,
    address_label_map: Dict[int, str] = None,
    insert_address: bool = False,
    complete: bool = False
) -> None:
    """
    Salva il contenuto assembly in un file .asm, leggendo e scrivendo linea per linea
    senza caricare tutto in memoria.
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

        # Generatore di linee
        if isinstance(content, list):
            def generate_lines() -> Generator[str, None, None]:
                for instr in content:
                    line = str(instr)
                    if insert_address and hasattr(instr, "address"):
                        line = f"; 0x{instr.address:x}\n{line}"
                    yield line
        elif isinstance(content, str):
            # Splitta stringa in righe e genera linee
            def generate_lines() -> Generator[str, None, None]:
                for line in content.splitlines():
                    yield line
        else:
            logger.error(f"Tipo di contenuto non supportato: {type(content)}")
            return

        # Scrive direttamente linea per linea nel file
        with open(target_path, "w") as f:
            if complete:
                for resolved_line in _resolve_address_stream(generate_lines(), address_label_map):
                    f.write(resolved_line + "\n")
            else:
                for lines in generate_lines():
                    f.write(lines + "\n")

        logger.info(f"File assembly salvato correttamente in {target_path}")

    except Exception:
        logger.error(f"Errore durante il salvataggio del file assembly {file_name}", exc_info=True)
