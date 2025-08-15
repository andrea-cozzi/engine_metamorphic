from typing import Optional
import capstone as cap

from engine_meta.cfg import BasicBlock, ControlFlowGraph

class EngineMetaFunction:
    def __init__(self, arch: int, mode: int, cfg: ControlFlowGraph = None):
        self.arch = arch
        self.mode = mode
        self.cgf = cfg

    def set_cfg(self, cfg: ControlFlowGraph = None) -> None:
        if cfg is None:
            return 
        self.cgf = cfg
        

    def block_indipendent(self, block1: Optional[BasicBlock] = None, block2 : Optional[BasicBlock] = None) -> Optional[bool]:
        if block1 is None or block2 is None:
            return False
        
        if block1.instructions.count() <= 0 or block2.instructions.count() <= 0:
            return True
        
        try:
            indi: bool = False

        
            return indi
        except Exception as e:
            return None
        
    def __get_mem_address_str(self, instruction: cap.CsInsn, op: cap.x86.X86Op) -> str:
        addr = "MEM["
        if op.mem.base != 0:
            addr += instruction.reg_name(op.mem.base)
        if op.mem.index != 0:
            addr += f"+{instruction.reg_name(op.mem.index)}*{op.mem.scale}"
        if op.mem.disp != 0:
            addr += f"+{op.mem.disp:#x}"
        addr += "]"
        return addr
    

    def __read_entity_ist__(self, instruction: cap.CsInsn) -> set:
        use_set = set()
        
        read_regs, _ = instruction.regs_access()
        for r in read_regs:
            use_set.add(instruction.reg_name(r))

        for op in instruction.operands:
            if op.type == cap.x86.CS_OP_MEM:
                if op.mem.base != 0:
                    use_set.add(instruction.reg_name(op.mem.base))
                if op.mem.index != 0:
                    use_set.add(instruction.reg_name(op.mem.index))
                
                if op.access & cap.CS_AC_READ:
                    addr_str = self.__get_mem_address_str(instruction, op)
                    use_set.add(addr_str)
                    
        return use_set
    
    """
        # Le istruzioni sono dipendenti se:
        # 1. ist2 legge ciò che ist1 scrive (RAW)
        # 2. ist1 legge ciò che ist2 scrive (WAR)
        # 3. ist1 e ist2 scrivono nella stessa locazione (WAW)
    """
    
    def __write_entity_ist__(self, instruction: cap.CsInsn) -> set:
        def_set = set()
        
        _, write_regs = instruction.regs_access()
        for r in write_regs:
            def_set.add(instruction.reg_name(r))

        for op in instruction.operands:
            if op.type == cap.x86.CS_OP_MEM:
                if op.access & cap.CS_AC_WRITE:
                    addr_str = self.__get_mem_address_str(instruction, op)
                    def_set.add(addr_str)
                    
        return def_set
    
    

    def instruction_indipendent(self, ist1: cap.CsInsn = None, ist2 : cap.CsInsn = None) -> bool:
        if ist1 is None or ist2 is None:
            return False
        
        # tutto ciò che legge DA l'istruzione --> memoria address + registri
        use1 = self.__read_entity_ist__(ist1)
        # tutto ciò che scrive IN l'istruzione --> memoria address + registri 
        def1 = self.__write_entity_ist__(ist1)

        use2 = self.__read_entity_ist__(ist2)
        def2 = self.__write_entity_ist__(ist2)

        is_dependent = bool((def1 & use2) or (use1 & def2) or (def1 & def2))
        return not is_dependent
