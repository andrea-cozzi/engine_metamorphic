import logging
import traceback
from datetime import datetime
from pathlib import Path

from component.parser import Parser
from constant_var import DEBUG_MODE
from feature_extractor.extractor import BinaryFeatureExtractor
from metamorphic_engine.engine import MetamorphicEngine
from model import file_model

class Application:

    def __init__(self, executable_path: str):
        self.executable_path = Path(executable_path)
        self._setup_logging()

    def _setup_logging(self) -> None:
        """Configura il sistema di logging in base alla modalità (DEBUG o WARNING)."""
        log_level = logging.INFO if DEBUG_MODE else logging.WARNING
        
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s',
            filename='engine_metamorphic.log',
            filemode='w'
        )
        logging.info("Logging configurato.")

    def run(self) -> None:
        """
        Esegue il flusso principale dell'applicazione: parsing, mutazione e analisi.
        """
        start_time = datetime.now()
        print(f"[*] Script started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print("-" * 40)
        
        try:
            # 1. Parsing del file eseguibile
            print(f"[*] Analisi del file: {self.executable_path}")
            parser = Parser()
            file: file_model.FileModelBinary = parser.parse_to_bytes(str(self.executable_path))
            
            if not file:
                raise FileNotFoundError(f"Impossibile effettuare il parsing o trovare il file: {self.executable_path}")

            # 2. Esecuzione del motore metamorfico
            print("[*] Avvio del motore metamorfico...")
            engine = MetamorphicEngine(model=file)
            mutated_data = engine.metamorph()
            print("[+] Mutazione completata.")

        
        except (ValueError, FileNotFoundError) as e:
            print(f"\nERRORE CRITICO: {e}")
            logging.error(f"Errore critico: {e}", exc_info=True)
            traceback.print_exc()
        except Exception as e:
            print(f"\nERRORE IMPREVISTO: {e}")
            logging.critical(f"Errore imprevisto: {e}", exc_info=True)
            traceback.print_exc()
        finally:
            # --- Blocco eseguito sempre, sia in caso di successo che di errore ---
            print("-" * 40)
            end_time = datetime.now()
            duration = end_time - start_time
            print(f"[*] Script ended at: {end_time.strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"[*] Total execution time: {duration}")