import hashlib
import logging
from typing import List, Optional, Union

import capstone as cs
import keystone as ks

logger = logging.getLogger(__name__)

class BasicInstruction:
    def __init__(self,
                 instruction: Union[cs.CsInsn, str],
                 address: int = 0x0):
        
        self.custom_created: bool = False
        self.istr_equivalent: str = ""
        self.original_object: Optional[cs.CsInsn] = None

        if isinstance(instruction, str):
            self.custom_created = True
            self.istr_equivalent = instruction
            try:             
                # qui potresti assemblare se vuoi subito i bytes
                # es. engine = ks.Ks(ks.KS_ARCH_X86, ks.KS_MODE_32)
                # encoding, _ = engine.asm(instruction)
                pass
            except ks.KsError as e:
                logger.error(f"Errore di Keystone nell'assemblare '{instruction}': {e}")
                raise ValueError(f"Impossibile assemblare l'istruzione: '{instruction}'") from e

        elif isinstance(instruction, cs.CsInsn):
            self.original_object = instruction
            self.istr_equivalent = f"{instruction.mnemonic} {instruction.op_str}"
            logger.debug(f"Istruzione originale: {self.original_object}")
        else:
            raise TypeError("L'input deve essere una stringa assembly o un oggetto capstone.CsInsn")

        if self.original_object:
            self.mnemonic: str = self.original_object.mnemonic
            self.id: int = self.original_object.id
            self.address: int = self.original_object.address
            self._size: int = self.original_object.size
            self.op_str: str = self.original_object.op_str

            # Questi attributi potrebbero non esserci se detail=False
            self.groups: List[int] = getattr(self.original_object, "groups", [])
            self.regs_read: List[int] = getattr(self.original_object, "regs_read", [])
            self.regs_write: List[int] = getattr(self.original_object, "regs_write", [])
            self.eflags: Optional[int] = getattr(self.original_object, "eflags", None)
        else:
            # caso custom (stringa assembly senza disassembly ancora)
            self.mnemonic = instruction.split()[0]
            self.id = -1
            self.address = address
            self._size = 0
            self.op_str = " ".join(instruction.split()[1:])
            self.groups = []
            self.regs_read = []
            self.regs_write = []
            self.eflags = None

        # Flag per analisi successive (valori di default)
        self.is_permutable: bool = True
        self.is_equivalent: bool = True

        def get_uuid() -> str:
            data = f"{self.mnemonic}:{self.op_str}"
            return hashlib.md5(data.encode()).hexdigest()
        self.uuid = get_uuid()

        # Estrazione dettagliata degli operandi (se disponibile)
        self._extract_operands()

    def _extract_operands(self):
        """Estrai e formatta gli operandi se disponibili."""
        self.operands = []
        if not self.original_object or not hasattr(self.original_object, "operands"):
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
            
    @property
    def size(self) -> int:
        return self._size
       
    @property
    def regs_read_list(self) -> List[str]:
        if not self.regs_read or not self.original_object:
            return []
        return [self.original_object.reg_name(r) for r in self.regs_read]

    @property
    def regs_write_list(self) -> List[str]:
        if not self.regs_write or not self.original_object:
            return []
        return [self.original_object.reg_name(r) for r in self.regs_write]

    def __str__(self) -> str:
        return f"{self.mnemonic} {self.op_str}" if self.op_str else self.mnemonic

    def __repr__(self) -> str:
        return f"<BasicInstruction @ 0x{self.address:x} | {self}>"
