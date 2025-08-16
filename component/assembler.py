import logging
import re
import subprocess
from typing import List

from capstone import Cs, CS_ARCH_X86, CS_MODE_64, CsInsn

# (L'eccezione AssemblyError e la classe base astratta rimangono le stesse)
class AssemblyError(Exception):
    """Eccezione sollevata quando si verifica un errore durante l'assemblaggio."""
    def __init__(self, message: str, source_code: str = "", stderr: str = ""):
        super().__init__(message)
        self.source_code = source_code
        self.stderr = stderr

    def __str__(self):
        return f"{super().__str__()}\n--- Source Code ---:\n{self.source_code}\n--- Stderr ---\n{self.stderr}"

class FasmAssembler:
    """
    Versione ottimizzata di un Assembler che usa FASM via stdin/stdout.
    """
    _PTR_CLEANER = re.compile(
        r'\b(byte|word|dword|qword|tword|xword|yword|zword)\s+ptr\b',
        re.IGNORECASE
    )

    def __init__(self, fasm_path: str = 'fasm'):
        self.fasm_path = fasm_path

    @staticmethod
    def _clean_instruction_string(instruction_line: str) -> str:
        return FasmAssembler._PTR_CLEANER.sub(r'\1', instruction_line)

    def assemble(self, instructions: List[CsInsn], bits: int = 64) -> bytes:
        if not instructions:
            raise ValueError("La lista di istruzioni non può essere vuota.")

        if not (bits == 64 or bits == 32):
            raise ValueError(f"{bits} non è un valore accettabile")

        asm_code = self._prepare_asm_code(instructions, bits)
        command = [self.fasm_path, '-', '-']

        try:
            result = subprocess.run(
                command,
                input=asm_code.encode('utf-8'),
                capture_output=True,
                check=True
            )
            return result.stdout

        except FileNotFoundError:
            raise FileNotFoundError(
                f"L'eseguibile di FASM non è stato trovato in '{self.fasm_path}'. "
                "Assicurati che sia nel PATH di sistema."
            )

        except subprocess.CalledProcessError as e:
            stderr_output = e.stderr.decode('utf-8', errors='ignore')
            error_message = f"FASM ha fallito con codice di uscita {e.returncode}."
            raise AssemblyError(error_message, source_code=asm_code, stderr=stderr_output)
    
    def assemble_to_file(self, instructions: List[CsInsn], output_path: str, bits: int = 64) -> None:
        if not (bits == 64 or bits == 32):
            raise ValueError(f"{bits} non è un valore accettabile")
        
        asm_code = self._prepare_asm_code(instructions, bits)        
        command = [self.fasm_path, '-', output_path]
        
        try:
            subprocess.run(
                command,
                input=asm_code.encode('utf-8'),
                capture_output=True, 
                check=True
            )
        except FileNotFoundError:
            raise FileNotFoundError(f"L'eseguibile FASM non è stato trovato in '{self.fasm_path}'.")
        except subprocess.CalledProcessError as e:
            raise AssemblyError(f"FASM ha fallito nel creare '{output_path}'.", source_code=asm_code, stderr=e.stderr.decode())

    def _prepare_asm_code(self, instructions, bits):
        header = "use64\n" if bits == 64 else "use32\n"
        asm_lines = [self._clean_instruction_string(f"{insn.mnemonic} {insn.op_str}".strip()) for insn in instructions]
        return header + "\n".join(asm_lines)