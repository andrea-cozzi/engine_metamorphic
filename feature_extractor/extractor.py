import logging
import math
from collections import defaultdict, Counter
from typing import Any, Dict, List, Optional, Set, Iterable

import capstone as cs
import lief as lf

from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet
from model.file_model import FileModelBinary
from shared.constants import BinaryType

logger = logging.getLogger(__name__)


class BinaryFeatureExtractor:

    @classmethod
    def run_analysis(
        cls,
        original_executable: FileModelBinary,
        arch_cs: int,
        mode_cs: int,
        intructions: Optional[OrderedUUIDSet[BasicInstruction]] = None,
        filename: Optional[str] = None,
        from_mutation: bool = False,
    ) -> None:
        features_to_save: List[Dict[str, Any]] = []
        output_filename: Optional[str]


        if from_mutation:
            if intructions is None or len(filename) < 0:
                raise ValueError("Configuration is not valid")
            
            features = cls._process_single_binary(
                entity=original_executable,
                arch_cs=arch_cs, 
                mode_cs=mode_cs,
                mutated_instructions=intructions,
                variant_name=filename
            )

            return features, None

        elif not from_mutation:
            features = cls._process_single_binary(
                entity=original_executable,
                arch_cs=arch_cs,
                mode_cs=mode_cs
            )
            if features:
                features_to_save.append(features)
                output_filename = f"{original_executable.file_name}_original_analysis.csv"

            return features, output_filename
        else:
            logger.error("run_analysis configuration not valid")


    # ==============================================================================
    # == WORKER ANALISI BINARIO ====================================================
    # ==============================================================================

    @classmethod
    def _process_single_binary(
        cls,
        entity: FileModelBinary,
        arch_cs: int,
        mode_cs: int,
        mutated_instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None,
        variant_name: Optional[str] = None
    ) -> Optional[Dict[str, Any]]:
        name_for_log = variant_name or entity.file_name
        logger.info(f"Analisi per: {name_for_log}")

        if not entity.binary:
            logger.error(f"Binario non valido per {name_for_log}")
            return None

        md = cs.Cs(arch_cs, mode_cs)
        md.detail = True

        lief_features = cls._extract_lief_features(entity)
        capstone_features = cls._analyze_instruction_groups(
            binary=entity.binary, md=md, mutated_text_instructions=mutated_instructions
        )

        all_features = {"filename": name_for_log, **lief_features, **capstone_features}
        logger.info(f"Fine analisi per: {name_for_log}")
        return all_features

    # ==============================================================================
    # == ANALISI CAPSTONE & LIEF ===================================================
    # ==============================================================================

    @staticmethod
    def _analyze_instruction_groups(
        binary: lf.Binary,
        md: cs.Cs,
        mutated_text_instructions: Optional[OrderedUUIDSet[BasicInstruction]] = None
    ) -> Dict[str, int]:
        stats: Dict[str, int] = defaultdict(int)
        gid_name_cache: Dict[int, str] = {}

        is_pe = isinstance(binary, lf.PE.Binary)
        is_elf = isinstance(binary, lf.ELF.Binary)

        def get_group_name(gid: int) -> str:
            if gid not in gid_name_cache:
                gid_name_cache[gid] = md.group_name(gid) or f"GROUP_{gid}"
            return gid_name_cache[gid]

        for section in binary.sections:
            is_executable = (
                (is_pe and isinstance(section, lf.PE.Section) and section.has_characteristic(lf.PE.Section.CHARACTERISTICS.MEM_EXECUTE))
                or (is_elf and isinstance(section, lf.ELF.Section) and section.has(lf.ELF.Section.FLAGS.X))
            )
            if not is_executable:
                continue

            section_name = section.name.strip('\x00')

            if section_name == ".text" and mutated_text_instructions:
                for instruction in list(mutated_text_instructions):
                    for gid in instruction.groups:
                        stats[f"groups_{section_name}_{get_group_name(gid)}"] += 1
                continue

            content = section.content
            if not content:
                continue

            try:
                for insn in md.disasm(bytes(content), section.virtual_address):
                    for gid in insn.groups:
                        stats[f"groups_{section_name}_{get_group_name(gid)}"] += 1
            except (cs.CsError, TypeError) as e:
                logger.warning(f"Capstone fallito su {section_name}: {e}")

        return dict(stats)

    @classmethod
    def _extract_lief_features(cls, file: FileModelBinary) -> Dict[str, Any]:
        if not file or not file.binary:
            raise ValueError(f"File: {file.file_path} non valido.")

        if file.type == BinaryType.WINDOWS:
            return cls._extract_pe_features(file.binary)
        elif file.type == BinaryType.LINUX:
            return cls._extract_elf_features(file.binary)
        else:
            raise TypeError(f"Tipo file non supportato: {file.type}")

    # --------------------------- PE FEATURES --------------------------------------

    @classmethod
    def _extract_pe_features(cls, binary: lf.PE.Binary) -> Dict[str, Any]:
        features = cls._extract_common_features(binary)
        features["size"] = getattr(binary, "virtual_size", 0)

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
        if not getattr(binary, "has_imports", False):
            return set()

        imports_attr = getattr(binary, "imports", None)
        imports_iter = imports_attr() if callable(imports_attr) else imports_attr
        if not imports_iter:
            return set()

        names: Set[str] = set()
        for imp in imports_iter:
            for entry in getattr(imp, "entries", []) or []:
                if name := getattr(entry, "name", None):
                    names.add(name)
        return names

    # --------------------------- ELF FEATURES -------------------------------------

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

        imported_funcs = set(getattr(binary, "imported_functions", []) or [])
        features["num_imports"] = len(imported_funcs)

        suspicious_apis = {"mmap", "dlopen", "fork", "execve"}
        for api in suspicious_apis:
            features[f"api_{api}"] = 1 if api in imported_funcs else 0

        return features

    # --------------------------- COMUNI -------------------------------------------

    @classmethod
    def _extract_common_features(cls, binary: lf.Binary) -> Dict[str, Any]:
        sections = getattr(binary, "sections", []) or []
        features: Dict[str, Any] = {
            "entrypoint": int(getattr(binary, "entrypoint", 0)),
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

        return features

    @staticmethod
    def _shannon_entropy_bytes(content: Iterable[int]) -> float:
        try:
            data = bytes(content)
        except (TypeError, ValueError):
            return 0.0
        if not data:
            return 0.0

        counts = Counter(data)
        n = len(data)
        return -sum((c / n) * math.log2(c / n) for c in counts.values())