import logging
import traceback
import lief
from model import file_model
from engine_meta import engine_meta
from datetime import datetime

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

    try:
        target_file_path = "C:\\Users\\andrea.cozzi\\Desktop\\main_small.exe"
        print(f"[*] Analisi del file: {target_file_path}")
        
        model = file_model.FileModel(target_file_path)
        engine = engine_meta.MetamorphicEngine(model)
        print("[*] Costruzione del Control Flow Graph dalla sezione .text...")
        cfg = engine.create_graph_cfg(section=".text")

        if cfg:
            #engine.save_cfg_to_json(cfg, "output/cfg_iniziale.json")
            # Esegui il test principale che applica la trasformazione e confronta gli hash
            engine.test_and_compare_hashes(cfg, percent=50)
        else:
            print("ERRORE: Impossibile creare il Control Flow Graph. L'analisi non può procedere.")

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
