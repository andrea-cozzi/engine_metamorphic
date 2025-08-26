from typing import List
from component.parser import Parser
import logging
import traceback
import lief
from constant_var import PATH_EXE
from feature_extractor.extractor import BinaryFeatureExtractor
from metamorphic_engine.engine import MetamorphicEngine
from model import file_model
from datetime import datetime

from check_exe import compare_executables
from constant_var import DEBUG_MODE

if DEBUG_MODE:
    log_level = logging.INFO
else:
    log_level = logging.WARNING



logging.basicConfig(
    level=log_level, 
    format='%(asctime)s - %(levelname)s - [%(module)s] - %(message)s',
    filename='engine_metamorphic.log',  
    filemode='w' 
)



def main() -> None:

    # --- INIZIO ESECUZIONE ---
    start_time = datetime.now()
    print(f"[*] Script started at: {start_time.strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 40)

    try:
        print(f"[*] Analisi del file: {PATH_EXE}")
        
        parser: Parser = Parser()
        file : file_model.FileModelBinary = parser.parse_to_bytes(PATH_EXE)
        if file is None:
            raise RuntimeError()
        engine: MetamorphicEngine = MetamorphicEngine(model=file)
        
        data= engine.metamorph()
        BinaryFeatureExtractor.run_analysis(original_executable=file,
                                            arch_cs=engine.cs_arch,
                                            mode_cs=engine.cs_mode,
                                            from_mutation=True,
                                            mutated_data=data
                                            )
        
        


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
