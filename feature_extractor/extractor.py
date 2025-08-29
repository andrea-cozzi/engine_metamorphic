import logging
import math
from collections import Counter, defaultdict
import re
from typing import Any, Dict, List, Optional, Set, Iterable

import capstone as cs
import lief as lf

from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from model.file_model import FileModelBinary
from shared.constants import BinaryType

logger = logging.getLogger(__name__)



#TODO: DA RIFARE COMPLETAMENTE
"""
UNA SOLA API CHE MI APRE UN PATH,
LO PARSO IN LIEF E FACCIO L'ANALISI SU TUTTO

"""

class BinaryFeatureExtractor:

    @classmethod
    def run_analysis(
        cls,
        original_executable: FileModelBinary, #SARA DI TIPO LIEF.BINARY
        arch_cs: int, #PASSARLE 
        mode_cs: int, #PASSARLE
        instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None, #NON SERVE
        filename: Optional[str] = None, #NECESSARIO
        from_mutation: bool = False, #NON SERVE
    ) -> Any: # Restituisce una tupla, ma Any è più flessibile
        """
        Punto di ingresso per l'analisi.
        Gestisce la logica per analizzare un file originale o una sua variante mutata.
        """

        #

        if from_mutation:
            if instructions is None or not filename:
                raise ValueError("Per l'analisi di una mutazione sono necessarie le istruzioni e un nome file.")
            
            features = cls._process_single_binary(
                entity=original_executable,
                arch_cs=arch_cs, 
                mode_cs=mode_cs,
                mutated_instructions=instructions,
                variant_name=filename
            )
            return features, None
        
        #NON SERVE
        else: # not from_mutation
            features = cls._process_single_binary(
                entity=original_executable,
                arch_cs=arch_cs,
                mode_cs=mode_cs
            )
            if features:
                output_filename = f"{original_executable.file_name}_original_analysis.csv"
                return features, output_filename
            return None, None


    @classmethod
    def _process_single_binary(
        cls,
        entity: FileModelBinary,
        arch_cs: int,
        mode_cs: int,
        mutated_instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None,
        variant_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        """
        Esegue l'estrazione delle feature da un singolo binario (originale o mutato).
        """
        name_for_log = variant_name or entity.file_name
        logger.info(f"Avvio analisi per: {name_for_log}")

        if not entity.binary:
            logger.error(f"Binario non valido per {name_for_log}")
            return None

        # Estrae le feature strutturali con LIEF (sempre dall'originale, come da requisiti)
        lief_features = cls._extract_lief_features(entity)
        
        # Inizializza Capstone
        md = cs.Cs(arch_cs, mode_cs)
        md.detail = True

        # Analizza i gruppi di istruzioni con Capstone
        capstone_features = cls._analyze_instruction_groups(
            binary=entity.binary, md=md, mutated_text_instructions=mutated_instructions
        )

        all_features = {"filename": name_for_log, **lief_features, **capstone_features}
        logger.info(f"Fine analisi per: {name_for_log}")
        return all_features


    @staticmethod
    def _analyze_instruction_groups(
        binary: lf.Binary,
        md: cs.Cs,
        mutated_text_instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None
    ) -> Dict[str, int]:
       
        stats: Dict[str, Any] = defaultdict(int)
        gid_name_cache: Dict[int, str] = {}

        is_pe = isinstance(binary, lf.PE.Binary)
        is_elf = isinstance(binary, lf.ELF.Binary)

        def get_group_name(gid: int) -> str:
            if gid not in gid_name_cache:
                gid_name_cache[gid] = md.group_name(gid) or f"GROUP_{gid}"
            return gid_name_cache[gid]

        # Pre-calculate the addresses of mutated instructions for efficient lookup
        mutated_addresses: Set[int] = set()
        if mutated_text_instructions:
            mutated_addresses = {instr.address for instr in mutated_text_instructions}

        for section in binary.sections:
            is_executable = (
                (is_pe and section.has_characteristic(lf.PE.Section.CHARACTERISTICS.MEM_EXECUTE))
                or (is_elf and section.has(lf.ELF.Section.FLAGS.X))
            )
            if not is_executable or not section.content:
                continue

            section_name = section.name.strip('\x00')
            content_bytes = bytes(section.content)
            
            mnemonics: List[str] = []
            
            # --- CORRECTED LOGIC ---
            if section_name == ".text" and mutated_text_instructions:
                temp_mnemonics: Dict[int, str] = {}

                # 1. Add statistics and mnemonics from the mutated instructions
                for instruction in mutated_text_instructions:
                    temp_mnemonics[instruction.address] = instruction.mnemonic
                    for gid in instruction.groups:
                        stats[f"groups_{section_name}_{get_group_name(gid)}"] += 1
                
                # 2. Analyze the original instructions, skipping those that were mutated
                try:
                    for insn in md.disasm(content_bytes, section.virtual_address):
                        if insn.address not in mutated_addresses:
                            temp_mnemonics[insn.address] = insn.mnemonic
                            for gid in insn.groups:
                                stats[f"groups_{section_name}_{get_group_name(gid)}"] += 1
                except (cs.CsError, TypeError) as e:
                    logger.warning(f"Capstone failed while analyzing original instructions in {section_name}: {e}")
                
                # Reconstruct the final list of mnemonics in order
                mnemonics = [temp_mnemonics[addr] for addr in sorted(temp_mnemonics)]

            else:
                # Standard behavior for all other sections or for non-mutation analysis
                try:
                    for insn in md.disasm(content_bytes, section.virtual_address):
                        mnemonics.append(insn.mnemonic)
                        for gid in insn.groups:
                            stats[f"groups_{section_name}_{get_group_name(gid)}"] += 1
                except (cs.CsError, TypeError) as e:
                    logger.warning(f"Capstone failed on section {section_name}: {e}")

            # Calculate n-grams for the section after collecting all mnemonics
            if len(mnemonics) > 1:
                bigrams = [tuple(mnemonics[i:i+2]) for i in range(len(mnemonics) - 1)]
                bigram_counts = Counter(bigrams)
                # Save the 10 most common 2-grams for this section
                for (m1, m2), count in bigram_counts.most_common(10):
                    stats[f"2gram_{section_name}_{m1}_{m2}"] = count
        
        return dict(stats)

    @classmethod
    def _extract_lief_features(cls, file: FileModelBinary) -> Dict[str, Any]:
        if not file or not file.binary:
            raise ValueError(f"File non valido: {file.file_path}")

        if file.type == BinaryType.WINDOWS:
            return cls._extract_pe_features(file.binary)
        if file.type == BinaryType.LINUX:
            return cls._extract_elf_features(file.binary)
        
        raise TypeError(f"Tipo file non supportato: {file.type}")

    # ==============================================================================
    # == ESTRATTORI DI FEATURE (PE, ELF, COMUNI) ====================================
    # ==============================================================================

    @classmethod
    def _extract_pe_features(cls, binary: lf.PE.Binary) -> Dict[str, Any]:
        features = cls._extract_common_features(binary)
        features["size"] = getattr(binary, "virtual_size", 0)

        try:
            features["imphash"] = lf.PE.get_imphash(binary)
        except lf.bad_file:
            features["imphash"] = ""

        # 2. Analisi delle Risorse
        if binary.has_resources:
            entropies = [r.entropy for r in binary.resources_manager.entries if r.has_content]
            features["num_resources"] = len(binary.resources_manager.entries)
            features["avg_resource_entropy"] = sum(entropies) / len(entropies) if entropies else 0.0
            langs = {r.lang for r in binary.resources_manager.entries}
            features["has_neutral_lang_resource"] = 1 if "NEUTRAL" in langs else 0
        else:
            features["num_resources"] = 0
            features["avg_resource_entropy"] = 0.0
            features["has_neutral_lang_resource"] = 0

        if hasattr(binary, "optional_header"):
            features.update({
                "image_base": binary.optional_header.imagebase,
                "subsystem": binary.optional_header.subsystem.name,
                "dll_characteristics": int(binary.optional_header.dll_characteristics),
            })
        if hasattr(binary, "header"):
            features["timestamp"] = int(binary.header.time_date_stamps)

        imported_funcs = cls._pe_imported_function_names(binary)
        features["num_imports"] = len(imported_funcs)

        suspicious_apis = {"VirtualAlloc", "LoadLibraryA", "CreateProcessA", "WriteFile"}
        for api in suspicious_apis:
            features[f"api_{api}"] = 1 if api in imported_funcs else 0

        return features

    @staticmethod
    def _pe_imported_function_names(binary: lf.PE.Binary) -> Set[str]:
        if not binary.has_imports:
            return set()
        
        names: Set[str] = set()
        for imp in binary.imports:
            for entry in imp.entries:
                if entry.name:
                    names.add(entry.name)
        return names

    @classmethod
    def _extract_elf_features(cls, binary: lf.ELF.Binary) -> Dict[str, Any]:
        features = cls._extract_common_features(binary)
        features["size"] = getattr(binary, "virtual_size", 0)

        if hasattr(binary, "header"):
            features.update({
                "elf_type": binary.header.file_type.name,
                "elf_machine": binary.header.machine_type.name,
            })

        has_rwx_segment = any(
            s.has(lf.ELF.Segment.FLAGS.R) and s.has(lf.ELF.Segment.FLAGS.W) and s.has(lf.ELF.Segment.FLAGS.X)
            for s in (binary.segments or [])
        )
        features["has_rwx_segment"] = int(has_rwx_segment)

        imported_funcs = set(getattr(binary, "imported_functions", []))
        features["num_imports"] = len(imported_funcs)

        suspicious_apis = {"mmap", "dlopen", "fork", "execve"}
        for api in suspicious_apis:
            features[f"api_{api}"] = 1 if api in imported_funcs else 0

        return features

    @classmethod
    def _extract_common_features(cls, binary: lf.Binary) -> Dict[str, Any]:
        sections = binary.sections or []
        features: Dict[str, Any] = {
            "entrypoint": int(binary.entrypoint),
            "num_sections": len(sections),
        }

        entropies = [cls._shannon_entropy_bytes(s.content) for s in sections if s.content]
        if entropies:
            features.update({
                "max_entropy": max(entropies),
                "min_entropy": min(entropies),
                "avg_entropy": sum(entropies) / len(entropies),
            })
        else:
            features.update({"max_entropy": 0.0, "min_entropy": 0.0, "avg_entropy": 0.0})

        #features.update(cls._extract_string_features(binary))
        return features
    
    @staticmethod
    def _extract_string_features(binary: lf.Binary) -> Dict[str, Any]:
        features = {
            "num_strings": 0,
            "avg_string_len": 0,
            "num_paths": 0,
            "num_urls": 0,
            "num_ips": 0,
        }

        try:
            # Distinzione tra PE ed ELF
            if isinstance(binary, lf.PE.Binary):
                logger.debug("Rilevato PE file")
                raw_bytes = bytes(binary.content)
                # Oltre ad ASCII, nei PE spesso ci sono stringhe UTF-16LE
                ascii_strings = re.findall(rb"[ -~]{4,}", raw_bytes)
                utf16_strings = re.findall(rb"(?:[ -~]\x00){4,}", raw_bytes)
                strings = [s.decode("latin-1", errors="ignore") for s in ascii_strings]
                strings += [s.decode("utf-16le", errors="ignore") for s in utf16_strings]

            elif isinstance(binary, lf.ELF.Binary):
                logger.debug("Rilevato ELF file")
                raw_bytes = bytes(binary.content)
                # Negli ELF di solito bastano le stringhe ASCII
                ascii_strings = re.findall(rb"[ -~]{4,}", raw_bytes)
                strings = [s.decode("latin-1", errors="ignore") for s in ascii_strings]

            else:
                logger.warning("Formato binario non supportato")
                return features

        except Exception as e:
            logger.warning(f"Errore estrazione stringhe: {e}")
            return features

        if not strings:
            return features

        # Pattern comuni
        ip_pattern = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
        url_pattern = re.compile(r"https?://[^\s/$.?#].[^\s]*")
        path_pattern = re.compile(r"[a-zA-Z]:\\[\\\S|*\S].*|\/\w[\w\/.-]*")

        total_len = 0
        for s in strings:
            total_len += len(s)
            if path_pattern.search(s):
                features["num_paths"] += 1
            if url_pattern.search(s):
                features["num_urls"] += 1
            if ip_pattern.search(s):
                features["num_ips"] += 1

        features["num_strings"] = len(strings)
        features["avg_string_len"] = total_len / len(strings)

        return features


    @staticmethod
    def _shannon_entropy_bytes(content: Iterable[int]) -> float:
        try:
            data = bytes(content)
        except (TypeError, ValueError):
            return 0.0
        
        if not data:
            return 0.0

        n = len(data)
        counts = Counter(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())