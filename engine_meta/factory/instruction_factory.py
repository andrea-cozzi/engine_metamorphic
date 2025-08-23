import logging
from typing import List, Optional, Union
import keystone as ks
import capstone as cs
from engine_meta.model.basic_instruction import BasicInstruction

logger = logging.getLogger(__name__)


class InstructionFactoryStatic:
    """
    Factory statica per generare istruzioni x86/x64 in formato binario.
    Crea sempre un nuovo engine Keystone ad ogni chiamata.
    """

    @staticmethod
    def _create_assebmler(arch: int = ks.KS_ARCH_X86, mode: int = ks.KS_MODE_64) -> Optional[ks.Ks]:
        """Crea un nuovo engine Keystone e lo restituisce."""
        try:
            return ks.Ks(arch, mode)
        except ks.KsError as e:
            logger.error(f"Errore creazione Keystone engine: {e}")
            return None
        
    @staticmethod
    def _create_dissassembler(arch: int = cs.CS_ARCH_X86, mode: int = cs.CS_MODE_64) -> Optional[cs.Cs]:
        """Crea un nuovo engine Capstone e lo restituisce."""
        try:
            md = cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
            md.detail = True
            return md
        except cs.CsError as e:
            logger.error(f"Errore creazione Capstone engine: {e}")
            return None

    @staticmethod
    def assemble(asm_code: str, arch: int = ks.KS_ARCH_X86, mode: int = ks.KS_MODE_64, addr: int = 0) -> Optional[bytes]:
        """
        Assembla una singola istruzione.
        Restituisce i byte o None se fallisce.
        """
        engine = InstructionFactoryStatic._create_assebmler(arch, mode)
        if not engine:
            logger.error("Keystone engine non disponibile")
            return None

        try:
            encoding, _ = engine.asm(asm_code, addr)
            return bytes(encoding)
        except ks.KsError as e:
            logger.warning(f"Errore assembly '{asm_code}': {e}")
            return None

    @staticmethod
    def assemble_block(asm_lines: List[str], arch: int = ks.KS_ARCH_X86, mode: int = ks.KS_MODE_64, addr: int = 0) -> List[bytes]:
        """
        Assembla una lista di istruzioni.
        Restituisce lista di blocchi in formato bytes.
        """
        result: List[bytes] = []
        for line in asm_lines:
            encoded = InstructionFactoryStatic.assemble(line, arch, mode, addr)
            if encoded is not None:
                result.append(encoded)
        return result
    

    @staticmethod 
    def _process_single_instruction(
        assembler: ks.Ks,
        disassembler: cs.Cs,
        asm_str: str,
        address: int
    ) -> BasicInstruction:
        """Metodo di supporto per processare una singola istruzione e restituire un oggetto BasicInstruction."""
        encoding, count = assembler.asm(asm_str, address)
        
        if count <= 0 or not encoding:
            raise ValueError(f"Assemblaggio di '{asm_str}' fallito.")

        disassembled_instructions = list(disassembler.disasm(bytes(encoding), address))
        
        if not disassembled_instructions:
            raise ValueError(f"Disassemblaggio di '{asm_str}' fallito.")
        
        cp_ins = disassembled_instructions[0]
        basic_ins = BasicInstruction(instruction=cp_ins, address=cp_ins.address)
        
        return basic_ins


    @staticmethod
    def create_instruction(
        ks_mode: int,
        ks_arch: int,
        cp_mode: int,
        cp_arch: int,
        asm_str: Union[str, List[str]],
        address: int = 0x1000
    ) -> Union[BasicInstruction, List[BasicInstruction]]:
        
        assembler = InstructionFactoryStatic._create_assebmler(ks_arch, ks_mode)
        if assembler is None:
            raise RuntimeError("Assembler non disponibile.")
        
        disassembler = InstructionFactoryStatic._create_dissassembler(cp_arch, cp_mode)
        if disassembler is None:
            raise RuntimeError("Disassembler non disponibile.")

        if isinstance(asm_str, str):
            return InstructionFactoryStatic._process_single_instruction(
                assembler, disassembler, asm_str, address
            )
        
        elif isinstance(asm_str, List):
            return_instr: List[BasicInstruction] = []
            current_address: int = address
            
            for line in asm_str:
                try:
                    basic_ins: BasicInstruction = InstructionFactoryStatic._process_single_instruction(
                        assembler, disassembler, line, current_address
                    )

                    if basic_ins is None:
                        raise ValueError(f"Cannot created {line}: _process_single_instruction returned None")

                    return_instr.append(basic_ins)
                    current_address += basic_ins.size
                except ValueError as e:
                    logger.error(e)

            return return_instr
        
        else:
            raise TypeError(f"Tipo non supportato per asm_str: {type(asm_str)}")



    
