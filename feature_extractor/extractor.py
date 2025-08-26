import csv
import logging
import math
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
import lief as lf
import capstone as cs
from concurrent.futures import ThreadPoolExecutor, as_completed

from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from model.file_model import FileModelBinary
from shared.constants import BinaryType
from constant_var import FEATURE_ANALYSIS_PATH 

# Configurazione del logger
logger = logging.getLogger(__name__)

# Definisci un percorso di output di default


class BinaryFeatureExtractor:
    """
    Classe statica per l'estrazione di feature da file binari (PE e ELF).
    Fornisce un'API pubblica per analizzare un eseguibile originale e le sue varianti mutate.
    """

    # ==============================================================================
    # == API PUBBLICA =============================================================
    # ==============================================================================

    @staticmethod
    def run_analysis(
        original_executable: FileModelBinary,
        arch_cs: int,
        mode_cs: int,
        mutated_data: Optional[List[Dict[str, OrderedUUIDSet[BasicInstruction]]]] = None, # <-- AGGIORNATO QUI
        from_mutation: bool = False
    ) -> None:
        
        
        md = cs.Cs(arch_cs, mode_cs)
        md.detail = True

        features_to_save = []

        if not from_mutation:
            features = BinaryFeatureExtractor._process_single_binary(entity=original_executable, md=md)
            features_to_save.append(features)
            output_filename = f"{original_executable.file_name}_original_analysis.csv"
        else:
            if not mutated_data:
                logger.warning("from_mutation è True, ma non sono stati forniti dati mutati.")
                return

            with ThreadPoolExecutor() as executor:
                future_to_variant = {}
                for mutation_dict in mutated_data:
                    for variant_name, instructions in mutation_dict.items():
                        future = executor.submit(
                            BinaryFeatureExtractor._process_single_binary,
                            original_executable, md, instructions, variant_name
                        )
                        future_to_variant[future] = variant_name

                for future in as_completed(future_to_variant):
                    variant_name = future_to_variant[future]
                    try:
                        result = future.result()
                        features_to_save.append(result)
                    except Exception as exc:
                        logger.error(f"La variante {variant_name} ha generato un'eccezione: {exc}")

            output_filename = f"{original_executable.file_name}_mutated_analysis.csv"

        if features_to_save:
            BinaryFeatureExtractor._save_features_to_csv(features_to_save, output_filename)
        else:
            logger.error("Nessuna feature è stata estratta, nessun file CSV verrà creato.")

    # ==============================================================================
    # == METODI PRIVATI DI ORCHESTRAZIONE E SALVATAGGIO ============================
    # ==============================================================================

    @staticmethod
    def _process_single_binary(
        entity: FileModelBinary,
        md: cs.Cs,
        mutated_instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None,
        variant_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """Worker che esegue l'analisi completa su un singolo binario o variante."""
        logger.info(f"Inizio analisi per: {variant_name or entity.file_name}")
        
        lief_features = BinaryFeatureExtractor._extract_lief_features(entity)
        capstone_features = BinaryFeatureExtractor._analyze_instruction_groups(entity.binary, md, mutated_instructions)
        
        all_features = {**lief_features, **capstone_features}
        all_features["filename"] = variant_name or entity.file_name
        
        logger.info(f"Fine analisi per: {variant_name or entity.file_name}")
        return all_features
    
    @staticmethod
    def _save_features_to_csv(features_list: List[Dict[str, Any]], output_filename: str) -> None:
        """Salva una lista di dizionari di feature in un file CSV."""
        if not features_list:
            logger.warning("La lista delle feature da salvare è vuota.")
            return

        output_path = Path(FEATURE_ANALYSIS_PATH) / output_filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        all_keys: Set[str] = set().union(*(d.keys() for d in features_list))
        
        header = sorted(list(all_keys))
        if "filename" in header:
            header.remove("filename")
            header.insert(0, "filename")

        try:
            with open(output_path, 'w', newline='', encoding='utf-8') as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=header)
                writer.writeheader()
                writer.writerows(features_list)
            logger.info(f"Feature salvate con successo in: {output_path}")
        except IOError as e:
            logger.error(f"Errore durante il salvataggio del file CSV {output_path}: {e}")

    # ==============================================================================
    # == METODI PRIVATI DI ANALISI (LIEF & CAPSTONE) ===============================
    # ==============================================================================
    
    @staticmethod
    def _analyze_instruction_groups(
        binary: lf.Binary,
        md: cs.Cs,
        mutated_text_instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None
    ) -> Dict[str, int]:
        """Analizza i gruppi di istruzioni per tutte le sezioni."""
        stats = defaultdict(int)
        for section in binary.sections:
            section_name = section.name.strip('\x00')
            if section_name == ".text" and mutated_text_instructions:
                for instruction in mutated_text_instructions:
                    for gid in instruction.groups:
                        gname = md.group_name(gid) or f"GROUP_{gid}"
                        stats[f"groups_{section_name}_{gname}"] += 1
                continue
            
            code = bytes(section.content)
            if not code:
                continue
            
            for instruction in md.disasm(code, section.virtual_address):
                for gid in instruction.groups:
                    gname = md.group_name(gid) or f"GROUP_{gid}"
                    stats[f"groups_{section_name}_{gname}"] += 1
        return dict(stats)

    @staticmethod
    def _extract_lief_features(file: FileModelBinary) -> Dict[str, Any]:
        """Dispatcher per l'estrazione delle feature statiche."""
        if not file or not file.binary:
            raise ValueError(f"File: {file.file_path} non valido o non parsato.")
        if file.type == BinaryType.WINDOWS:
            return BinaryFeatureExtractor._extract_pe_features(file.binary)
        elif file.type == BinaryType.LINUX:
            return BinaryFeatureExtractor._extract_elf_features(file.binary)
        else:
            raise ValueError(f"Tipo di file non supportato: {file.type}")

    @staticmethod
    def _extract_pe_features(binary: lf.PE.Binary) -> Dict[str, Any]:
        """Estrae feature specifiche per i file PE (Windows)."""
        features = BinaryFeatureExtractor._extract_common_features(binary)
        if binary.has_optional_header:
            features.update({
                "image_base": binary.optional_header.imagebase,
                "subsystem": binary.optional_header.subsystem.name,
                "dll_characteristics": binary.optional_header.dll_characteristics.value,
            })
        features["timestamp"] = binary.header.time_date_stamps
        imported_funcs = {entry.name for imp in binary.imports for entry in imp.entries if entry.name} if binary.has_imports else set()
        features["num_imports"] = len(imported_funcs)
        suspicious_apis = {"VirtualAlloc", "LoadLibraryA", "CreateProcessA", "WriteFile"}
        for api in suspicious_apis:
            features[f"api_{api}"] = 1 if api in imported_funcs else 0
        return features

    @staticmethod
    def _extract_elf_features(binary: lf.ELF.Binary) -> Dict[str, Any]:
        """Estrae feature specifiche per i file ELF (Linux)."""
        features = BinaryFeatureExtractor._extract_common_features(binary)
        features.update({
            "elf_type": binary.header.file_type.name,
            "elf_machine": binary.header.machine_type.name,
        })
        has_rwx_segment = any(
            s.has_perms(lf.ELF.SEGMENT_FLAGS.R) and s.has_perms(lf.ELF.SEGMENT_FLAGS.W) and s.has_perms(lf.ELF.SEGMENT_FLAGS.X)
            for s in binary.segments
        )
        features["has_rwx_segment"] = int(has_rwx_segment)
        imported_funcs = {func for func in binary.imported_functions}
        features["num_imports"] = len(imported_funcs)
        suspicious_apis = {"mmap", "dlopen", "fork", "execve"}
        for api in suspicious_apis:
            features[f"api_{api}"] = 1 if api in imported_funcs else 0
        return features

    @staticmethod
    def _extract_common_features(binary: lf.Binary) -> Dict[str, Any]:
        """Estrae le feature comuni a tutti i tipi di eseguibili."""
        features = {
            "entrypoint": binary.entrypoint,
            "size": binary.virtual_size if hasattr(binary, "virtual_size") else 0,
            "num_sections": len(binary.sections),
        }
        entropies = [BinaryFeatureExtractor._shannon_entropy(bytes(s.content)) for s in binary.sections if s.content]
        features.update({
            "max_entropy": max(entropies) if entropies else 0.0,
            "min_entropy": min(entropies) if entropies else 0.0,
            "avg_entropy": sum(entropies) / len(entropies) if entropies else 0.0,
        })
        return features

    @staticmethod
    def _shannon_entropy(data: bytes) -> float:
        """Calcola l'entropia di Shannon su un buffer di byte."""
        if not data:
            return 0.0
        freq = defaultdict(int)
        for byte in data:
            freq[byte] += 1
        return -sum((count / len(data)) * math.log2(count / len(data)) for count in freq.values())

