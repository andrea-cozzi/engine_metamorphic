import hashlib
import logging
from typing import List, Optional

import capstone as cs

logger = logging.getLogger(__name__)

class BasicInstruction:
    def __init__(self, instruction: cs.CsInsn):
        """
        Inizializza un'istruzione a partire da un oggetto CsInsn di Capstone.
        L'input deve essere un oggetto disassemblato da Capstone.
        """
        if not isinstance(instruction, cs.CsInsn):
            raise TypeError("L'input deve essere un oggetto capstone.CsInsn")

        # Memorizza l'oggetto originale e imposta gli attributi principali
        self.original_object: cs.CsInsn = instruction
        self.istr_equivalent: str = f"{instruction.mnemonic} {instruction.op_str}"
        logger.debug(f"Istruzione originale: {self.original_object}")
        
        self.mnemonic: str = self.original_object.mnemonic
        self.id: int = self.original_object.id
        self.address: int = self.original_object.address
        self._size: int = self.original_object.size
        self.op_str: str = self.original_object.op_str

        # Questi attributi dipendono dall'opzione detail=True in Capstone
        self.groups: List[int] = getattr(self.original_object, "groups", [])
        self.regs_read: List[int] = getattr(self.original_object, "regs_read", [])
        self.regs_write: List[int] = getattr(self.original_object, "regs_write", [])
        self.eflags: Optional[int] = getattr(self.original_object, "eflags", None)

        # Flag per analisi successive (valori di default)
        self.is_permutable: bool = True
        self.is_equivalent: bool = True
        
        # Calcola l'UUID
        self.uuid = self.get_uuid()

        # Estrazione dettagliata degli operandi
        self.operands = []
        self._extract_operands()

    def get_uuid(self) -> str:
        """Genera un UUID per l'istruzione basato su mnemonico e operandi."""
        data = f"{self.mnemonic}:{self.op_str}"
        return hashlib.md5(data.encode()).hexdigest()

    def _extract_operands(self):
        """Estrai e formatta gli operandi se disponibili."""
        if not hasattr(self.original_object, "operands"):
            return

        for op in self.original_object.operands:
            operand_detail = {"type": op.type, "reg": None, "imm": None, "mem": None}
            if op.type == cs.CS_OP_REG:
                operand_detail["reg"] = self.original_object.reg_name(op.reg)
            elif op.type == cs.CS_OP_IMM:
                operand_detail["imm"] = op.imm
            elif op.type == cs.CS_OP_MEM:
                operand_detail["mem"] = {
                    "base": self.original_object.reg_name(op.mem.base) if op.mem.base != 0 else None,
                    "index": self.original_object.reg_name(op.mem.index) if op.mem.index != 0 else None,
                    "scale": op.mem.scale,
                    "disp": op.mem.disp,
                }
            self.operands.append(operand_detail)
            
    def size(self) -> int:
        """Restituisce la dimensione in byte dell'istruzione."""
        return self._size
        
    def regs_read_list(self) -> List[str]:
        """Restituisce la lista dei nomi dei registri letti dall'istruzione."""
        if not self.regs_read:
            return []
        return [self.original_object.reg_name(r) for r in self.regs_read]

    def regs_write_list(self) -> List[str]:
        """Restituisce la lista dei nomi dei registri scritti dall'istruzione."""
        if not self.regs_write:
            return []
        return [self.original_object.reg_name(r) for r in self.regs_write]

    def __str__(self) -> str:
        return f"{self.mnemonic} {self.op_str}" if self.op_str else self.mnemonic

    def __repr__(self) -> str:
        return f"<BasicInstruction @ 0x{self.address:x} | {self}>"
    
    def clone(self) -> "BasicInstruction":
        return BasicInstruction(self.original_object)