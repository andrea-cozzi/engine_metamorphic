import csv
from datetime import datetime
import json
from pathlib import Path
import re
from typing import Any, Dict, Generator, List, Tuple
import logging

from constant_var import (
    ASSEMBLY_OUTPUT_PATH,
    FEATURE_ANALYSIS_PATH,
    FILENAME_JSON_REPORT,
    JSON_CFG_OUTPUT_PATH,
    REPORT_JSON_PATH,
)
from metamorphic_engine.cfg import EngineMetaCFG


# Costanti e logger
ASSEMBLY_PATH = Path(ASSEMBLY_OUTPUT_PATH)
JSON_CFG_PATH = Path(JSON_CFG_OUTPUT_PATH)

ADDRESS_PATTERN = re.compile(r"\b(call|j\w+)\s+(0x[0-9a-fA-F]+)\b")

logger = logging.getLogger(__name__)


class FileUtils:
    """
    Classe di utilità per salvataggio e analisi di file assembly e CFG.
    """

    # -----------------------------
    # UTILS
    # -----------------------------
    @staticmethod
    def _ensure_extension(file_name: str, expected_ext: str) -> str:
        """
        Garantisce che il nome file abbia l'estensione corretta.
        Se manca o è diversa, viene forzata a `expected_ext`.
        """
        ext = expected_ext.lower()
        path = Path(file_name)

        if path.suffix.lower() != ext:
            path = path.with_suffix(ext)

        return str(path)

    # -----------------------------
    # SALVATAGGIO FILE
    # -----------------------------
    @staticmethod
    def save_to_assembly(content: str | Generator[str, None, None], file_name: str) -> None:
        """
        Salva contenuto assembly in un file .asm.
        Supporta stringhe e generatori di righe.
        """
        if not file_name or not content:
            logger.warning("Parametri non validi per il salvataggio del file assembly.")
            return

        try:
            file_name = FileUtils._ensure_extension(file_name, ".asm")
            target_path = ASSEMBLY_PATH / file_name
            target_path.parent.mkdir(parents=True, exist_ok=True)

            # Evita sovrascrittura → aggiunge timestamp
            if target_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                target_path = target_path.with_name(
                    f"{target_path.stem}_{timestamp}{target_path.suffix}"
                )

            # Normalizza le righe
            if isinstance(content, str):
                lines = (line + "\n" for line in content.splitlines())
            elif isinstance(content, Generator):
                lines = (line if line.endswith("\n") else line + "\n" for line in content)
            else:
                logger.error(f"Tipo di contenuto non supportato: {type(content)}")
                return

            with open(target_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

            logger.info(f"File assembly salvato correttamente in {target_path}")

        except Exception:
            logger.error("Errore durante il salvataggio del file assembly", exc_info=True)

    @staticmethod
    def save_cfg_to_json(file_name: str, graph: EngineMetaCFG) -> None:
        """
        Salva un oggetto EngineMetaCFG in un file JSON.
        """
        if not file_name:
            logger.warning("Parametri per save_cfg_to_json non validi.")
            return

        try:
            file_name = FileUtils._ensure_extension(file_name, ".json")
            target_path = JSON_CFG_PATH / file_name
            target_path.parent.mkdir(parents=True, exist_ok=True)

            if target_path.exists():
                timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
                target_path = target_path.with_name(
                    f"{target_path.stem}_{timestamp}{target_path.suffix}"
                )

            serializable_cfg = {
                hex(block.start_address): block.to_dict()
                for block in graph._all_blocks_ordered
            }

            json_dump = {
                "block_number": len(graph.blocks),
                "created": graph.created,
                "blocks": serializable_cfg,
            }

            with open(target_path, "w", encoding="utf-8") as file:
                json.dump(json_dump, file, indent=2)

            logger.info(f"CFG salvato in {target_path}")

        except Exception:
            logger.error(
                f"Errore durante il salvataggio del CFG in {file_name}", exc_info=True
            )

    # -----------------------------
    # LETTURA FILE
    # -----------------------------
    @staticmethod
    def _read_asm_lines(file_path: Path) -> List[str]:
        """
        Legge un file assembly restituendo le righe non vuote.
        """
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.strip() for line in f if line.strip()]
        except FileNotFoundError:
            logger.error(f"File non trovato: {file_path}")
            return []
        except Exception:
            logger.error(f"Errore in lettura file: {file_path}", exc_info=True)
            return []

    # -----------------------------
    # ANALISI MUTAZIONE JSON
    # -----------------------------
    @staticmethod
    def compare_asm_files(
        original_path: Path, mutated_path: Path
    ) -> Tuple[int, int, int, int, float]:
        """
        Confronta due file assembly e ritorna:
        (righe_originali, righe_sostituite, righe_aggiunte_o_rimosse, modifiche_totali, percentuale)
        """
        lines_orig = FileUtils._read_asm_lines(original_path)
        lines_mut = FileUtils._read_asm_lines(mutated_path)

        num_righe_originali = len(lines_orig)
        if num_righe_originali == 0:
            return (
                0,
                0,
                len(lines_mut),
                len(lines_mut),
                100.0 if len(lines_mut) > 0 else 0.0,
            )

        righe_sostituite = sum(
            1 for orig_line, mut_line in zip(lines_orig, lines_mut) if orig_line != mut_line
        )
        righe_aggiunte_rimosse = abs(len(lines_orig) - len(lines_mut))
        modifiche_totali = righe_sostituite + righe_aggiunte_rimosse
        percentuale_modifiche = (modifiche_totali / num_righe_originali) * 100

        return (
            num_righe_originali,
            righe_sostituite,
            righe_aggiunte_rimosse,
            modifiche_totali,
            percentuale_modifiche,
        )

    @staticmethod
    def save_mutation_report_json(mutated_files_names: list[str], original_base_name: str) -> None:
        """
        Salva un report JSON dei file mutati, confrontandoli con il file originale.
        """
        if not mutated_files_names:
            logger.warning("Nessun file mutato fornito, il report non sarà generato.")
            return

        output_dir = ASSEMBLY_PATH
        output_dir.mkdir(parents=True, exist_ok=True)

        # 🔹 Forza estensione corretta
        original_base_name = Path(FileUtils._ensure_extension(original_base_name, ".asm")).stem
        original_path = output_dir / f"{original_base_name}"

        if not original_path.is_file():
            logger.error(f"File originale per il confronto non trovato: {original_path}")
            return

        report_data = []
        for mutated_file_name in mutated_files_names:
            mutated_file_name = FileUtils._ensure_extension(mutated_file_name, ".asm")
            mutated_path = output_dir / mutated_file_name
            mutated_path.parent.mkdir(parents=True, exist_ok=True)

            if not mutated_path.is_file():
                logger.warning(f"File mutato non trovato, saltato: {mutated_path}")
                continue

            num_orig, sostituite, agg_rim, totali, percent_mod = FileUtils.compare_asm_files(
                original_path, mutated_path
            )

            report_data.append(
                {
                    "file_mutato": mutated_file_name,
                    "righe_originali": num_orig,
                    "righe_sostituite": sostituite,
                    "righe_aggiunte_o_rimosse": agg_rim,
                    "modifiche_totali": totali,
                    "percentuale_modificata": f"{percent_mod:.2f}%",
                }
            )

        report_dir = Path(REPORT_JSON_PATH)
        report_dir.mkdir(parents=True, exist_ok=True)
        output_report_path = report_dir / FileUtils._ensure_extension(FILENAME_JSON_REPORT, ".json")

        try:
            with open(output_report_path, "w", encoding="utf-8") as jf:
                json.dump(report_data, jf, indent=4)

            logger.info(f"Report JSON salvato correttamente in: {output_report_path}")
        except Exception:
            logger.error("Errore durante il salvataggio del report JSON", exc_info=True)


    @staticmethod
    def _save_features_to_csv(features_list: List[Dict[str, Any]], output_filename: str) -> None:
        if not features_list:
            logger.warning("Lista feature vuota, CSV non creato.")
            return

        output_path = Path(FEATURE_ANALYSIS_PATH) / output_filename
        output_path.parent.mkdir(parents=True, exist_ok=True)

        header = sorted({k for d in features_list for k in d})
        if "filename" in header:
            header.remove("filename")
            header.insert(0, "filename")

        try:
            with output_path.open('w', newline='', encoding='utf-8') as f:
                writer = csv.DictWriter(f, fieldnames=header, extrasaction="ignore")
                writer.writeheader()
                writer.writerows(features_list)
            logger.info(f"Feature salvate in {output_path}")
        except IOError as e:
            logger.error(f"Errore scrittura CSV {output_path}: {e}")