import logging
import traceback
import re
from typing import List, Optional, Tuple, Union
from keystone import Ks, KS_ARCH_X86, KS_MODE_64, KS_MODE_32, KsError
import capstone as cs

from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet

logger = logging.getLogger(__name__)

class AssemblerEncoder:
    """
    Encoder assembler robusto per architetture x86 e x64.
    Gestisce la conversione di BasicInstruction (Capstone wrapped) in bytecode.
    """

    _INVERSE_CONDITIONS = {
        "je": "jne", "jne": "je", "jz": "jnz", "jnz": "jz",
        "ja": "jbe", "jae": "jb", "jb": "jae", "jbe": "ja",
        "jg": "jle", "jge": "jl", "jl": "jge", "jle": "jg",
        "jp": "jnp", "jnp": "jp", "jpe": "jpo", "jpo": "jpe",
        "jo": "jno", "jno": "jo", "js": "jns", "jns": "js",
        "jc": "jnc", "jnc": "jc", "jecxz": None, "jrcxz": None,
        "loop": None, "loope": None, "loopne": None
    }

    _SIZE_MAP = {
        1: "byte ptr",
        2: "word ptr",
        4: "dword ptr",
        6: "fword ptr",
        8: "qword ptr",
        10: "tbyte ptr",  # 80-bit FPU
        16: "xmmword ptr",
        32: "ymmword ptr",
        64: "zmmword ptr",
    }

    _SEGMENT_PREFIXES = re.compile(r'\b(?:cs|ds|es|fs|gs|ss):', re.IGNORECASE)
    
    def __init__(self, arch: int, mode: int = KS_MODE_64):
        """
        Inizializza l'encoder.
        
        Args:
            mode: KS_MODE_32 o KS_MODE_64
        """
        if arch != KS_ARCH_X86:
            raise ValueError("Errore architettura non valida")

        self.mode = mode
        self.ks = Ks(KS_ARCH_X86, mode)
        
        if mode == KS_MODE_64:
            self.reg_rip = "rip"
            self.reg_ax = "rax"
            self.reg_cx = "rcx"
            self.ptr_size = 8
        else:
            self.reg_rip = "eip"
            self.reg_ax = "eax"
            self.reg_cx = "ecx"
            self.ptr_size = 4

    # =========================================================
    # API PRINCIPALE
    # =========================================================
    def encode_instructions(self, instructions:  OrderedUUIDSet[BasicInstruction], base_address: int = 0) -> Tuple[bytes, List[int]]:
        """
        Codifica una lista di BasicInstruction in bytecode.
        
        Args:
            instructions: Lista di BasicInstruction
            base_address: Indirizzo base per il calcolo dei salti
            
        Returns:
            Tupla (bytecode, lista_offset_per_istruzione)
        """
        result = bytearray()
        offsets = []
        current_address = base_address
        
        for inst in list(instructions):
            offsets.append(len(result))
            
            try:
                encoded = self._encode_single_instruction(inst, current_address)
                if encoded:
                    result.extend(encoded)
                    current_address += len(encoded)
                else:
                    # Fallback: usa i bytes originali se disponibili
                    if hasattr(inst.original_object, 'bytes') and inst.original_object.bytes:
                        result.extend(inst.original_object.bytes)
                        current_address += len(inst.original_object.bytes)
                    else:
                        logger.error(f"Failed to encode instruction at 0x{inst.address:x}: {inst.mnemonic} {inst.op_str}")
            except Exception as e:
                logger.error(f"Exception encoding instruction at 0x{inst.address:x}: {e}")
                # Usa bytes originali come fallback
                if hasattr(inst.original_object, 'bytes') and inst.original_object.bytes:
                    result.extend(inst.original_object.bytes)
                    current_address += len(inst.original_object.bytes)
        
        return bytes(result), offsets

    # =========================================================
    # GESTIONE ISTRUZIONI
    # =========================================================
    def _encode_single_instruction(self, inst: BasicInstruction, current_address: int) -> Optional[bytes]:
        """
        Codifica una singola BasicInstruction.
        """
        mnemonic = inst.mnemonic.lower()
        
        # Gestione speciale per istruzioni di branch
        if self._is_branch_instruction(inst.groups):
            return self._encode_branch(inst, current_address)
        
        # Gestione speciale per istruzioni FPU
        elif mnemonic.startswith('f') and mnemonic not in ['fence', 'fxch']:
            return self._encode_fpu(inst, current_address)
        
        # Gestione speciale per istruzioni con memoria
        elif self._has_memory_operand(inst.original_object):
            return self._encode_with_memory(inst, current_address)
        
        # Tentativo standard
        else:
            return self._encode_standard(inst, current_address)

    def _is_branch_instruction(self, groups) -> bool:
        """Verifica se l'istruzione è un salto o chiamata."""
        return (cs.CS_GRP_JUMP in groups or 
                cs.CS_GRP_CALL in groups or
                cs.CS_GRP_BRANCH_RELATIVE in groups)

    def _has_memory_operand(self, inst: cs.CsInsn) -> bool:
        """Verifica se l'istruzione ha operandi di memoria."""
        for op in inst.operands:
            if op.type == cs.x86.X86_OP_MEM:
                return True
        return False

    # =========================================================
    # BRANCH / JUMP / CALL --> solo qui dovrebbe Capitare instruction.terminator_new_address
    # =========================================================
    def _encode_branch(self, instruction: BasicInstruction, current_address: int) -> Optional[bytes]:
        """Codifica istruzioni di salto e chiamata."""
        
        mnemonic = instruction.mnemonic.lower()
        inst = instruction.original_object
        
        # Estrai destinazione
        dest = None
        if instruction.is_terminator and instruction.terminator_new_address is not None:
            dest = instruction.terminator_new_address
        elif inst.operands and inst.operands[0].type == cs.x86.X86_OP_IMM:
            dest = inst.operands[0].imm
        
        if dest is None:
            # Salto indiretto o registro
            return self._encode_standard(instruction, current_address)
        
        # Salto condizionale
        if mnemonic in self._INVERSE_CONDITIONS:
            return self._encode_conditional_jump(mnemonic, dest, current_address)
        
        # JMP o CALL assoluto
        if mnemonic in ['jmp', 'call']:
            return self._encode_jmp_call(mnemonic, dest, current_address)
        
        # Altri salti (loop, jecxz, etc.)
        return self._encode_standard(instruction, current_address)

    def _encode_conditional_jump(self, mnemonic: str, dest: int, current_address: int) -> Optional[bytes]:
        """Codifica salti condizionali."""
        try:
            encoding, _ = self.ks.asm(f"{mnemonic} 0x{dest:x}", addr=current_address)
            return bytes(encoding)
        except KsError:
            inverse = self._INVERSE_CONDITIONS.get(mnemonic)
            if not inverse:
                return None
            
            try:
                skip_bytes = 7 if self.mode == KS_MODE_32 else 12
                skip_addr = current_address + 2 + skip_bytes
                
                result = bytearray()
                inv_enc, _ = self.ks.asm(f"{inverse} 0x{skip_addr:x}", addr=current_address)
                result.extend(inv_enc)
                
                jmp_addr = current_address + len(inv_enc)
                jmp_enc = self._encode_jmp_call("jmp", dest, jmp_addr)
                if jmp_enc:
                    result.extend(jmp_enc)
                    return bytes(result)
            except KsError:
                pass
        
        return None

    def _encode_jmp_call(self, mnemonic: str, dest: int, current_address: int) -> Optional[bytes]:
        """Codifica JMP e CALL."""
        try:
            encoding, _ = self.ks.asm(f"{mnemonic} 0x{dest:x}", addr=current_address)
            return bytes(encoding)
        except KsError:
            try:
                result = bytearray()
                mov_enc, _ = self.ks.asm(f"mov {self.reg_ax}, 0x{dest:x}", addr=current_address)
                result.extend(mov_enc)
                op_enc, _ = self.ks.asm(f"{mnemonic} {self.reg_ax}", addr=current_address + len(mov_enc))
                result.extend(op_enc)
                return bytes(result)
            except KsError:
                return None

    # =========================================================
    # FPU / MEMORY / STANDARD
    # =========================================================
    def _encode_fpu(self, instruction: BasicInstruction, current_address: int) -> Optional[bytes]:
        inst = instruction.original_object
        mnemonic = inst.mnemonic.lower()
        op_str = self._prepare_operand_string(inst, preserve_size=True)
        
        if not op_str:
            asm_str = mnemonic
        else:
            if '[' in op_str and not any(ptr in op_str.lower() for ptr in ['ptr', 'word', 'byte', 'dword', 'qword', 'tbyte']):
                size_hint = self._get_fpu_size_hint(inst)
                if size_hint:
                    op_str = op_str.replace('[', f'{size_hint} [', 1)
            asm_str = f"{mnemonic} {op_str}"
        
        try:
            encoding, _ = self.ks.asm(asm_str, addr=current_address)
            return bytes(encoding)
        except KsError:
            return self._try_alternative_encodings(instruction, current_address)

    def _encode_with_memory(self, instruction: BasicInstruction, current_address: int) -> Optional[bytes]:
        inst = instruction.original_object
        mnemonic = inst.mnemonic.lower()
        op_str = self._prepare_operand_string(inst)
        
        attempts = []
        attempts.append(f"{mnemonic} {op_str}" if op_str else mnemonic)
        
        if self._needs_size_directive(inst) and '[' in op_str:
            size_dir = self._get_size_directive(inst)
            if size_dir:
                sized_op = op_str.replace('[', f'{size_dir} [', 1)
                attempts.append(f"{mnemonic} {sized_op}")
        
        if inst.op_str and inst.op_str != op_str:
            attempts.append(f"{mnemonic} {inst.op_str}")
        
        for asm_str in attempts:
            try:
                encoding, _ = self.ks.asm(asm_str, addr=current_address)
                return bytes(encoding)
            except KsError:
                continue
        
        return None

    def _encode_standard(self, instruction: BasicInstruction, current_address: int) -> Optional[bytes]:
        inst = instruction.original_object
        mnemonic = inst.mnemonic.lower()
        
        #NOTA: NON DOVREBBE MAI CAPITARE
        if instruction.is_terminator and instruction.terminator_new_address is not None:
            asm_str : str = f"{mnemonic} {instruction.terminator_new_address}"
        
        else:   
            op_str = self._prepare_operand_string(inst)
            asm_str = f"{mnemonic} {op_str}" if op_str else mnemonic
        
        try:
            encoding, _ = self.ks.asm(asm_str, addr=current_address)
            return bytes(encoding)
        except KsError:
            return self._try_alternative_encodings(instruction, current_address)

    # =========================================================
    # UTILS
    # =========================================================
    def _prepare_operand_string(self, inst: cs.CsInsn, preserve_size: bool = False) -> str:
        if not inst.op_str:
            return ""
        
        op_str = inst.op_str.strip()
        op_str = self._SEGMENT_PREFIXES.sub('', op_str)
        
        if not preserve_size:
            for size in ['xmmword ptr', 'ymmword ptr', 'zmmword ptr', 'oword ptr', 'zword ptr']:
                op_str = re.sub(r'\b' + re.escape(size) + r'\b', '', op_str, flags=re.IGNORECASE)
        
        op_str = ' '.join(op_str.split())
        
        if self.mode == KS_MODE_64 and 'rip' in op_str.lower():
            op_str = self._fix_rip_relative(op_str)
        
        return op_str

    def _fix_rip_relative(self, op_str: str) -> str:
        return op_str

    def _needs_size_directive(self, inst: cs.CsInsn) -> bool:
        mnemonic = inst.mnemonic.lower()
        
        if mnemonic in ['movzx', 'movsx', 'movsxd', 'cwde', 'cdqe', 'cwd', 'cdq', 'cqo']:
            return True
        
        has_imm = any(op.type == cs.x86.X86_OP_IMM for op in inst.operands)
        has_mem = any(op.type == cs.x86.X86_OP_MEM for op in inst.operands)
        
        if has_imm and has_mem:
            if mnemonic in ['mov', 'add', 'sub', 'and', 'or', 'xor', 'cmp', 'test']:
                return True
        
        return False

    def _get_size_directive(self, inst: cs.CsInsn) -> str:
        for op in inst.operands:
            if op.type == cs.x86.X86_OP_MEM:
                return self._SIZE_MAP.get(op.size, "")
        return ""

    def _get_fpu_size_hint(self, inst: cs.CsInsn) -> str:
        mnemonic = inst.mnemonic.lower()
        fpu_sizes = {
            'fld': 'tbyte ptr',
            'fstp': 'tbyte ptr',
            'fild': 'qword ptr',
            'fistp': 'qword ptr',
            'fldcw': 'word ptr',
            'fstcw': 'word ptr',
            'fldenv': 'dword ptr',
            'fstenv': 'dword ptr',
        }
        
        for op in inst.operands:
            if op.type == cs.x86.X86_OP_MEM and op.size:
                return self._SIZE_MAP.get(op.size, fpu_sizes.get(mnemonic, 'tbyte ptr'))
        
        return fpu_sizes.get(mnemonic, 'tbyte ptr')

    def _try_alternative_encodings(self, instruction: BasicInstruction, current_address: int) -> Optional[bytes]:
        mnemonic = instruction.mnemonic.lower()
        inst = instruction.original_object
        
        alternatives = []
        
        if instruction.is_terminator and instruction.terminator_new_address is not None:
            alternatives.append(f"{mnemonic} {instruction.terminator_new_address}")
        elif inst.op_str:
            alternatives.append(f"{mnemonic} {inst.op_str}")
        
        if inst.op_str and '[' in inst.op_str:
            for size in ['dword ptr', 'qword ptr', 'word ptr', 'byte ptr']:
                sized = inst.op_str.replace('[', f'{size} [', 1)
                alternatives.append(f"{mnemonic} {sized}")
        
        if inst.op_str:
            cleaned = re.sub(r'\b\w+\s+ptr\b', '', inst.op_str, flags=re.IGNORECASE)
            cleaned = ' '.join(cleaned.split())
            if cleaned != inst.op_str:
                alternatives.append(f"{mnemonic} {cleaned}")
        
        for asm_str in alternatives:
            try:
                encoding, _ = self.ks.asm(asm_str, addr=current_address)
                return bytes(encoding)
            except KsError:
                logger.warning(traceback.format_exc())
                continue
        
        if hasattr(inst, 'bytes') and inst.bytes:
            logger.warning(f"Using original bytes for: {mnemonic} {inst.op_str}")
            return bytes(inst.bytes)
        
        return None
