from component.assembler import FasmAssembler
from component.parser import Parser
import logging
import traceback
import lief
from model import file_model
from engine_meta import engine_meta
from datetime import datetime

from check_exe import compare_executables



def main() -> None:

    logging.basicConfig(
        level=logging.INFO,  # Livello minimo dei messaggi da registrare (es. INFO, DEBUG, ERROR)
        format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s', # Formato dei messaggi
        filename='engine_metamorphic.log',  # Nome del file di log
        filemode='w'  # 'w' per sovrascrivere il log a ogni esecuzione, 'a' per aggiungere in coda
    )

    # --- INIZIO ESECUZIONE ---
    start_time = datetime.now()
    print(f"[*] Script started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 40)


    logger = logging.getLogger(__name__)
    try:

        target_file_path = "C:\\Users\\andrea.cozzi\\Desktop\\main_small.exe"
        tagert_file_output = "C:\\Users\\andrea.cozzi\\Desktop\\main_small_modificato.exe"
        print(f"[*] Analisi del file: {target_file_path}")
        
        parser: Parser = Parser()
        file : file_model.FileModelBinary = parser.parse(target_file_path)
        if file is None:
            raise RuntimeError()
        engine = engine_meta.MetamorphicEngine(model=file)
        engine.create_graph_cfg(save_on_json=False)

    except (ValueError, FileNotFoundError) as e: 
        print(f"\nERRORE CRITICO: {e}")
        traceback.print_exc()
    except Exception as e:
        print(f"\nERRORE IMPREVISTO: {e}")
        traceback.print_exc()

    # --- FINE ESECUZIONE ---
    print("-" * 40)
    end_time = datetime.now()
    duration = end_time - start_time
    print(f"[*] Script ended at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"[*] Total execution time: {duration}")

if __name__ == "__main__":
    main()
