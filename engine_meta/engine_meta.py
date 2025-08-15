import itertools
import pprint
from typing import Dict, List, Optional, Set, Tuple

import lief
from engine_meta.cfg import TERMINATOR_TYPE, BasicBlock, ControlFlowGraph, is_terminator
from engine_meta.instruction.engine_meta_function import EngineMetaFunction
from model import file_model
import capstone as cap
import json


class MetamorphicEngine:
    def __init__(self, file: file_model.FileModel):
        if file is None:
            return
        self.file = file
        self.engine_function : EngineMetaFunction = EngineMetaFunction(arch=self.file.arch, mode=self.file.arch)

    def __get_base_address__(self):
        binary = self.file.binary
        if self.file.type == file_model.BinaryType.WINDOWS:
            return binary.optional_header.imagebase

        elif self.file.type == file_model.BinaryType.LINUX:
            min_addr = float('inf')
            found_load_segment = False
            for segment in binary.segments:
                if segment.type == lief.ELF.SEGMENT_TYPES.LOAD:
                    found_load_segment = True
                    min_addr = min(min_addr, segment.virtual_address)
            return min_addr if found_load_segment else 0
        else:
            raise ValueError("File type not supported")


    def create_graph_cfg(self, section : str = ".text", 
                        save_ass_out: Optional[str] = None,
                        save_cfg_out : Optional[str] = None
                        ) -> Optional[ControlFlowGraph]:
        
        text_section =self.file.binary.get_section(section)
        if not text_section:
            return None

        code_bytes = bytes(text_section.content)
        section_address = self.__get_base_address__()+text_section.virtual_address
        md = cap.Cs(self.file.arch, self.file.mode)
        md.detail = True

        instructions = list(md.disasm(code_bytes, section_address))
       
        if save_ass_out is not None and len(save_ass_out)>0:
            self.__save_assembly_to_file__(instructions=instructions, output_path=save_ass_out)

        cfg : Optional[ControlFlowGraph] = self.__analyze__(
            ins=instructions
        )

        if cfg is None:
            return None
        
        if save_cfg_out is not None and len(save_cfg_out) > 0:
            self.__saveCFG__(
                file_path=save_cfg_out,
                chain= cfg
            )

        self.engine_function.set_cfg(cfg=cfg)

        return cfg
        



    def __save_assembly_to_file__(self, instructions: list[cap.CsInsn] = [], output_path: str = ""):
        with open(output_path, 'w') as out:
            for ist in instructions:
                line = f"0x{ist.address:x}:\tmem: {ist.mnemonic}\t{ist.op_str}\n"
                out.write(line)
    

    def __analyze__(self, ins: List[cap.CsInsn]) -> Optional[ControlFlowGraph]:
        if not ins:
            return None

        cfg = ControlFlowGraph()
        leaders: Set[int] = set()
        addr_to_idx: Dict[int, int] = {instr.address: i for i, instr in enumerate(ins)}

        # --- PASSATA 1: Identificazione dei Leader ---
        leaders.add(ins[0].address)

        for i, instr in enumerate(ins):
            term_type, is_conditional = is_terminator(instr)
            if term_type is None:
                continue

            # Target di un salto o call è un leader
            if instr.operands and instr.operands[0].type == cap.x86.X86_OP_IMM:
                target_addr = instr.operands[0].imm
                if target_addr in addr_to_idx:
                    leaders.add(target_addr)

            # Istruzione successiva a un salto condizionale o call è un leader
            if is_conditional or term_type == TERMINATOR_TYPE.CALL:
                if i + 1 < len(ins):
                    leaders.add(ins[i + 1].address)

        # --- PASSATA 2: Creazione e Collegamento dei Blocchi ---
        sorted_leaders = sorted(list(leaders))
        leader_set = set(sorted_leaders) # Usiamo un set per ricerche veloci O(1)

        for i, start_addr in enumerate(sorted_leaders):
            block = BasicBlock(start_addr)
            
            # Popola il blocco
            next_leader_addr = sorted_leaders[i + 1] if i + 1 < len(sorted_leaders) else float('inf')
            current_idx = addr_to_idx[start_addr]
            while current_idx < len(ins) and ins[current_idx].address < next_leader_addr:

                block.add_instruction(ins[current_idx])
                current_idx += 1
            
            cfg.add_block(block)

            # --- LOGICA DI COLLEGAMENTO CORRETTA ---
            if not block.instructions:
                continue # Salta blocchi vuoti se mai dovessero crearsi

            last_instr = block.instructions[-1]
            term_type, is_conditional = is_terminator(last_instr)

            # 1. Aggiungi il successore del salto (se esiste)
            if term_type == TERMINATOR_TYPE.JUMP or term_type == TERMINATOR_TYPE.CALL:
                if last_instr.operands and last_instr.operands[0].type == cap.x86.X86_OP_IMM:
                    target_addr = last_instr.operands[0].imm
                    if target_addr in leader_set: # Controlla se il target è l'inizio di un blocco valido
                        block.successors.append(target_addr)

            # 2. Aggiungi il successore "fall-through" (se applicabile)
            # Un fall-through esiste se il flusso non è interrotto incondizionatamente
            is_unconditional_end = (term_type == TERMINATOR_TYPE.RETURN) or \
                                (term_type == TERMINATOR_TYPE.IRET) or \
                                (term_type == TERMINATOR_TYPE.JUMP and not is_conditional)

            if not is_unconditional_end:
                fall_through_addr = last_instr.address + last_instr.size
                if fall_through_addr in leader_set:
                    block.successors.append(fall_through_addr)
                    
        return cfg

    
    def __saveCFG__(self, file_path: str= "", chain: ControlFlowGraph = None):
        serializable_data = {
            "count": len(chain.blocks.items()),
            "blocks": {}
        }

        for start_addr, block in chain.blocks.items():
            serializable_block = {
                "start_address": hex(block.start_address),
                "end_address": hex(block.end_address),
                "successors": [hex(s) for s in block.successors],
                "instructions": []
            }

            REG_TYPE = 1
            IMM_TYPE = 2
            MEM_TYPE = 3

            for instr in block.instructions:
                
                operand_list =[]
                for op in instr.operands:
                    operand_info = {
                        "type": op.type, #tipo di operando
                        "reg": instr.reg_name(op.reg) if op.type == REG_TYPE else None, # Se è un operazione di registro contene il nome del registro
                        "imm": op.imm if op.type == IMM_TYPE else None, #Se IMM_TYPE, contiene il valore immediato --> valore costante scritto nel codice 
                        # Se è un accesso in memoria --> scoposizione dell'indirizzo a cui si accede
                        "mem": {
                            "base": instr.reg_name(op.mem.base) if MEM_TYPE else None, #Registro baso usato per il calcolo
                            "index": instr.reg_name(op.mem.index) if op.type == cap.x86.X86_OP_MEM else None, #registro di index utilizzato 
                            "scale": op.mem.scale if op.type == cap.x86.X86_OP_MEM else None,#valore da moltiplicare index
                            "disp": op.mem.disp if op.type == cap.x86.X86_OP_MEM else None,# offset indirizzo
                        } if op.type == cap.x86.X86_OP_MEM else None
                    },
                
                    operand_list.append(operand_info)

                serializable_instr = {
                    "address": hex(instr.address),
                    "mnemonic": instr.mnemonic,
                    "op_str": instr.op_str,
                    "size": instr.size,
                    "bytes": instr.bytes.hex(),
                    "operand_info": operand_list
                }
                serializable_block["instructions"].append(serializable_instr)
            
            serializable_data["blocks"][hex(start_addr)] = serializable_block

        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(serializable_data, f, indent=4)


    def analyze_assembly(self, ins: List[cap.CsInsn], file_path: Optional[str] = None) -> None:
        should_return_chain = file_path is not None and len(file_path) > 0
        chain = self.__analyze__(ins)

        if should_return_chain and chain is not None:
            self.__saveChain__(file_path, chain)





    # ===================== FUNZIONI DI TEST DELLE SINGOLE FUNZIONI ========================       

    def test_indipendent_istruction(self, CODE):
        md = cap.Cs(self.file.arch, self.file.mode)
        md.detail = True

        instructions = list(md.disasm(CODE, 0x1000))
        instruction_pairs = itertools.combinations(instructions, 2)


        with open("output/test_istruzioni_indipendenti.txt", 'w') as file:
            for inst1, inst2 in instruction_pairs:
                are_independent = self.engine_function.instruction_indipendent(inst1, inst2)
                result_text = "Indipendenti" if are_independent else "NOT Indipendenti"
                line1 = f"{inst1.mnemonic} {inst1.op_str}"
                line2 = f"{inst2.mnemonic} {inst2.op_str}"

                file.write(f"{line1}\t {line2}\t{result_text}\n")
    
