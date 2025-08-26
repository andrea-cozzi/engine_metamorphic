import logging
import random
import re
import traceback
from typing import List, Optional, Set, Tuple, Sequence

from metamorphic_engine.factory.instruction_factory import InstructionFactoryStatic
from metamorphic_engine.model.basic_block import BasicBlock
from constant_var import (
    MAX_BLOCK_OBFUSCATION,
    PRO_ADD_DEAD_CODE,
    PRO_ADD_JUNK_CODE_AFTER_TERMINATOR,
    PRO_ADD_NOP_INST,
    PRO_ADD_OPAQUE_CODE,
    MIN_NOP_INSTRUCTION_BLOCK,
    MAX_NOP_INSTRUCTION_BLOCK,
)
from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet

logger = logging.getLogger("garbage_generator")


class GarbageGenerator:
    """Utility per inserire codice spazzatura/obfuscation in BasicBlock."""
    _tot_dead_code_added_to_block: int = 0

    # -----------------------
    # Helpers interni
    # -----------------------
    @staticmethod
    def _normalize_to_list(obj) -> List[BasicInstruction]:
        if isinstance(obj, BasicInstruction):
            return [obj]
        if isinstance(obj, list):
            if not all(isinstance(x, BasicInstruction) for x in obj):
                raise TypeError("InstructionFactory returned a list with non-BasicInstruction elements")
            return obj
        raise TypeError(f"Unsupported instruction object type: {type(obj)}")

    @staticmethod
    def _try_factory(asm, arch_ks, mode_ks, arch_cs, mode_cs):
        try:
            return InstructionFactoryStatic.create_instruction(
                asm_str=asm, ks_mode=mode_ks, ks_arch=arch_ks, cp_arch=arch_cs, cp_mode=mode_cs
            ), None
        except Exception as e:
            return None, e

    @staticmethod
    def _assemble(asm: Sequence[str] | str, arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> List[BasicInstruction]:
        """
        Chiama la factory e ritorna sempre una lista di BasicInstruction.
        In caso di errore prova alcune correzioni heuristics e riloggare errori dettagliati.
        """
        # Normalizziamo: vogliamo passare o una lista di stringhe o una singola stringa
        tried_variants = []

        def _log_and_raise(orig_asm, exc):
            logger.error("Assembly failed for asm=%r ; exception=%s", orig_asm, exc)
            # rilanciamo con maggior contesto
            raise RuntimeError(f"assembly failed for {orig_asm!r}: {exc}") from exc

        # 1) prova originale
        tried_variants.append(("original", asm))
        res, err = GarbageGenerator._try_factory(asm, arch_ks, mode_ks, arch_cs, mode_cs)
        if res is not None:
            return GarbageGenerator._normalize_to_list(res)

        # Se fallisce, loggalo (ma non ancora raise)
        logger.debug("First assembly attempt failed for %r: %s", asm, err)

        # 2) Se asm è stringa che contiene ';' o '\n', trasformala in lista separata
        if isinstance(asm, str):
            if ";" in asm:
                v = [s.strip() for s in asm.split(";") if s.strip()]
                tried_variants.append(("split_semicolon", v))
                res2, err2 = GarbageGenerator._try_factory(v, arch_ks, mode_ks, arch_cs, mode_cs)
                if res2 is not None:
                    return GarbageGenerator._normalize_to_list(res2)
            if "\n" in asm:
                v = [s.strip() for s in asm.splitlines() if s.strip()]
                tried_variants.append(("split_newline", v))
                res2, err2 = GarbageGenerator._try_factory(v, arch_ks, mode_ks, arch_cs, mode_cs)
                if res2 is not None:
                    return GarbageGenerator._normalize_to_list(res2)

        # 3) Se è lista/tuple di stringhe, assicurati sia list e riprova
        if isinstance(asm, (list, tuple)):
            v = list(asm)
            tried_variants.append(("as_list", v))
            res2, err2 = GarbageGenerator._try_factory(v, arch_ks, mode_ks, arch_cs, mode_cs)
            if res2 is not None:
                return GarbageGenerator._normalize_to_list(res2)

        # 4) Heuristics su pattern noti: imul reg, reg -> imul reg, reg, 1
        def _fix_imul(seq):
            changed = False
            out = []
            for s in seq:
                m = re.match(r"^\s*imul\s+([er]?(?:[abcd]x|[sd]i|[sb]p|r\d+)?),\s*([er]?(?:[abcd]x|[sd]i|[sb]p|r\d+)?)\s*$", s, re.I)
                if m:
                    out.append(s + ", 1")
                    changed = True
                else:
                    out.append(s)
            return out if changed else None

        # prepare a list form to run fixes on
        seq = list(asm) if isinstance(asm, (list, tuple)) else [asm]

        imul_fixed = _fix_imul(seq)
        if imul_fixed is not None:
            tried_variants.append(("imul_fixed", imul_fixed))
            res3, err3 = GarbageGenerator._try_factory(imul_fixed, arch_ks, mode_ks, arch_cs, mode_cs)
            if res3 is not None:
                return GarbageGenerator._normalize_to_list(res3)

        # 5) split accidental "push reg, push reg" patterns (commas inside single item)
        def _split_commas_in_items(seq):
            out = []
            changed = False
            for s in seq:
                parts = [p.strip() for p in s.split(",") if p.strip()]
                # se sembra due istruzioni (es: "push rax, push rax")
                if len(parts) >= 2 and any(p.lower().startswith(("push ", "pop ", "mov ", "xor ", "add ", "sub ")) for p in parts):
                    # non provare a ricomporre con comma: usiamo newline-splitting heuristic
                    # ricomponiamo come istruzioni separate (ma se erano operandi con comma, attenzione)
                    # tentiamo di riconoscere "push rax, push rax" => ["push rax", "push rax"]
                    maybe_instrs = []
                    for p in parts:
                        # se contiene spazio (likely instr), mantieni
                        if " " in p:
                            maybe_instrs.append(p)
                        else:
                            # fallback: trattalo come singolo operando
                            maybe_instrs.append(p)
                    if len(maybe_instrs) > 1:
                        out.extend(maybe_instrs)
                        changed = True
                        continue
                out.append(s)
            return out if changed else None

        comma_fixed = _split_commas_in_items(seq)
        if comma_fixed is not None:
            tried_variants.append(("comma_fixed", comma_fixed))
            res4, err4 = GarbageGenerator._try_factory(comma_fixed, arch_ks, mode_ks, arch_cs, mode_cs)
            if res4 is not None:
                return GarbageGenerator._normalize_to_list(res4)

        # 6) ultima chance: prova a chiamare la factory con ogni singola riga separatamente e concatenare
        single_results = []
        any_ok = False
        for idx, line in enumerate(seq):
            try:
                r, e = GarbageGenerator._try_factory(line, arch_ks, mode_ks, arch_cs, mode_cs)
                if r is None:
                    logger.debug("line-level assembly failed for %r: %s", line, e)
                    single_results = []
                    any_ok = False
                    break
                else:
                    single_results.extend(GarbageGenerator._normalize_to_list(r))
                    any_ok = True
            except Exception as e:
                logger.debug("line-level assembly exception for %r: %s", line, e)
                single_results = []
                any_ok = False
                break
        if any_ok and single_results:
            return single_results

        # Se siamo qui, tutto ha fallito: logga dettagli di debug e rilancia un errore esplicito
        logger.error("Assembly failed for all attempted variants. Tried: %s", tried_variants)
        # preferiamo mostrare l'errore originale se esistente
        final_exc = err or (err2 if 'err2' in locals() else None)
        raise RuntimeError(f"assembly failed for {asm!r}: {final_exc}") from final_exc 

    # -----------------------
    # Dati dipendenti da arch
    # -----------------------
    @staticmethod
    def _get_arch_constants(mode_ks: int):
        """Ritorna registri e costanti arch dipendenti (32 vs 64 bit).
        Template sicuri per keystone: nessun 'mul reg, imm' o 'div reg, imm' e
        nessuna istruzione con '$+5' come jump relativo fragile.
        """
        if mode_ks == 32:
            allow_register = {"eax", "ebx", "ecx", "edx"}
            dead_code_constants = [
                ("PUSH {reg}", "POP {reg}"),
                ("MOV {reg}, {reg}", ""),
                ("XOR {reg}, {reg}", "OR {reg}, 0"),    # OR reg,0 è accettato ma inutile — ok come no-op pair
                ("ADD {reg}, 0", ""),
                ("SUB {reg}, 0", ""),
                ("INC {reg}", "DEC {reg}"),
                ("ADD {reg}, 10", "SUB {reg}, 10"),
                ("SHL {reg}, 0", "SHR {reg}, 0"),
                ("AND {reg}, 0xFFFFFFFF", ""),
                # evita MUL/DIV con immediati: usa IMUL a 3-operand o rimuovi entirely
                ("IMUL {reg}, {reg}, 1", ""),  # IMUL reg, reg, imm è supportato; equivalente no-op
                # se vuoi sequenza push/push, definiscila come due template separati
                ("PUSH {reg}", "PUSH {reg}"),
            ]
            # Opaque predicates: non usare relative-jump $+5; usa sequenze senza jump o IMUL/TEST
            opaque_predicates = [
                ["cmp eax, eax"],                   # comparazione innocua
                ["test eax, eax"],                  # test reg,reg (setta flags)
                ["and eax, 1", "cmp eax, 2"],       # lascia stare i jump: qui solo istruzioni
            ]
            junk_before_term = [
                "mov eax, 0x12345678",
                "push eax",
                "pop ecx",
                "xor ebx, ebx",
            ]
            junk_after_term = [
                "mov eax, 0xDEADBEEF",
                "xor ebx, ebx",
                "push ecx",
                "pop ecx",
            ]
        else:
            allow_register = {"rax", "rbx", "rcx", "rdx"}
            dead_code_constants = [
                ("PUSH {reg}", "POP {reg}"),
                ("MOV {reg}, {reg}", ""),
                ("XOR {reg}, {reg}", "OR {reg}, 0"),
                ("ADD {reg}, 0", ""),
                ("SUB {reg}, 0", ""),
                ("INC {reg}", "DEC {reg}"),
                ("ADD {reg}, 10", "SUB {reg}, 10"),
                ("SHL {reg}, 0", "SHR {reg}, 0"),
                ("AND {reg}, 0xFFFFFFFFFFFFFFFF", ""),
                ("IMUL {reg}, {reg}, 1", ""),   # forma IMUL a 3-operand per compatibilità
                ("PUSH {reg}", "PUSH {reg}"),
            ]
            opaque_predicates = [
                ["cmp rax, rax"],
                ["test rax, rax"],
                ["and rax, 1", "cmp rax, 2"],
            ]
            junk_before_term = [
                "mov rax, 0x12345678",
                "push rax",
                "pop rcx",
                "xor rbx, rbx",
            ]
            junk_after_term = [
                "mov rax, 0xDEADBEEF",
                "xor rbx, rbx",
                "push rcx",
                "pop rcx",
            ]
        return allow_register, dead_code_constants, opaque_predicates, junk_before_term, junk_after_term

    @staticmethod
    def _can_add(instructions_registered: Set[str], allow_register: Set[str]) -> Tuple[bool, Optional[Set[str]]]:
        if not instructions_registered:
            return True, set(allow_register)
        diff = allow_register.difference(instructions_registered)
        return (True, diff) if diff else (False, None)

    # -----------------------
    # Trasformazioni
    # -----------------------
    @staticmethod
    def _add_dead_code(block: BasicBlock, arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> None:
        if not block or len(block.instructions) == 0:
            return

        allow_register, dead_code_constants, _, _, _ = GarbageGenerator._get_arch_constants(mode_ks)

        all_used_regs = set()
        for instruction in block.instructions:
            # Questi attributi si presume siano liste/insiemi di stringhe
            all_used_regs.update(getattr(instruction, "regs_read_list", []) or [])
            all_used_regs.update(getattr(instruction, "regs_write_list", []) or [])

        can_add_dead_code, available_regs = GarbageGenerator._can_add(all_used_regs, allow_register)
        if not (can_add_dead_code and available_regs):
            logger.debug("No available registers for dead code addition.")
            return

        # Evita di esagerare con gli inserimenti
        max_insertions = max(1, len(block.instructions) // 2)
        num_insertions = random.randint(1, max_insertions)
        logger.debug("Adding %d dead code insertion(s).", num_insertions)

        # Prepara le posizioni di inserimento (escludi l’ultima se è il terminatore)
        safe_instrs = list(block.instructions)
        if len(safe_instrs) > 1:
            safe_instrs = safe_instrs[:-1]  # evita di spezzare il terminatore

        if not safe_instrs:
            return

        instructions_to_add: List[Tuple[str, BasicInstruction]] = []

        for _ in range(num_insertions):
            selected_reg = random.choice(list(available_regs))
            inst_tpl = random.choice(dead_code_constants)

            # Crea 1 o 2 istruzioni a seconda del template
            asm_list = [inst_tpl[0].format(reg=selected_reg)]
            if inst_tpl[1]:
                asm_list.append(inst_tpl[1].format(reg=selected_reg))

            try:
                new_instructions = GarbageGenerator._assemble(
                    asm=asm_list, arch_ks=arch_ks, mode_ks=mode_ks, arch_cs=arch_cs, mode_cs=mode_cs
                )
                # Scegli un punto di inserimento casuale (dopo)
                target_instruction = random.choice(safe_instrs)
                for ins in new_instructions:
                    instructions_to_add.append((target_instruction.uuid, ins))
                    target_instruction = ins
            except Exception as e:
                logger.error(traceback.format_exc())
                logger.error("Failed to create dead code instruction: %s", e)

        # Applica gli inserimenti
        for uuid_after, ins in instructions_to_add:
            block.instructions.add_after(after_uuid=uuid_after, item=ins)

        # Ricalcola indirizzi solo una volta alla fine
        if instructions_to_add:
            block.ricalcolate_addresses()

    @staticmethod
    def _add_nop_instruction(block: BasicBlock, arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> None:
        block_len = len(block.instructions)
        if block_len == 0 or random.random() > PRO_ADD_NOP_INST:
            return

        # Escludi il terminatore (ultima istruzione)
        uuids = [instr.uuid for instr in list(block.instructions)[:-1]] if block_len > 1 else []
        if not uuids:
            return

        # Numero massimo di NOP consentiti
        max_insertable = min(len(uuids), MAX_NOP_INSTRUCTION_BLOCK)
        if max_insertable <= 0:
            return

        if MIN_NOP_INSTRUCTION_BLOCK >= max_insertable:
            num_nop_insertions = max_insertable
        else:
            num_nop_insertions = random.randint(MIN_NOP_INSTRUCTION_BLOCK, max_insertable)

        logger.debug("Adding %d NOP(s).", num_nop_insertions)

        try:
            nop_ins_list = GarbageGenerator._assemble(
                asm="nop", arch_ks=arch_ks, mode_ks=mode_ks, arch_cs=arch_cs, mode_cs=mode_cs
            )
            if len(nop_ins_list) != 1:
                raise RuntimeError("NOP assembly returned multiple instructions unexpectedly")
            nop_ins_prototype = nop_ins_list[0]
        
        except Exception as e:
            logger.error(traceback.format_exc())
            return

        for uuid_after in random.sample(uuids, k=num_nop_insertions):
            try:
                new_nop = GarbageGenerator._assemble(
                    asm="nop", arch_ks=arch_ks, mode_ks=mode_ks, arch_cs=arch_cs, mode_cs=mode_cs
                )[0]
                block.instructions.add_after(after_uuid=uuid_after, item=new_nop)
            except Exception as e:
                logger.error(traceback.format_exc())
                continue

        block.ricalcolate_addresses()

    @staticmethod
    def _add_opaque_predicate(block: BasicBlock, arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> None:
        if random.random() > PRO_ADD_OPAQUE_CODE or len(block.instructions) < 2:
            return

        _, _, opaque_preds, junk_before_term, _ = GarbageGenerator._get_arch_constants(mode_ks)
        pred_seq = random.choice(opaque_preds)  # già lista di istruzioni
        asm_list = pred_seq + junk_before_term

        try:
            new_ins = GarbageGenerator._assemble(
                asm=asm_list, arch_ks=arch_ks, mode_ks=mode_ks, arch_cs=arch_cs, mode_cs=mode_cs
            )
            # Inserisci prima del terminatore (dopo la penultima)
            prev_uuid = (list(block.instructions)[:-1])[-1].uuid
            for ins in new_ins:
                block.instructions.add_after(after_uuid=prev_uuid, item=ins)
                prev_uuid = ins.uuid
            block.ricalcolate_addresses()
        except Exception as e:
            logger.error(traceback.format_exc())


    @staticmethod
    def _add_junk_code_after_terminator(block: BasicBlock, arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> None:
        if len(block.instructions) == 0:
            return

        _, _, _, _, junk_after_term = GarbageGenerator._get_arch_constants(mode_ks)

        term : BasicInstruction = block.terminator
        if term is None:
            return

        term_mn = term.mnemonic.lower()
        if term_mn not in {"jmp", "ret", "retf", "iret", "iretd", "iretq", "hlt", "ud2"}:
            return

        try:
            junk_ins = GarbageGenerator._assemble(
                asm=junk_after_term, arch_ks=arch_ks, mode_ks=mode_ks, arch_cs=arch_cs, mode_cs=mode_cs
            )
            uuid_after = term.uuid
            for ins in junk_ins:
                block.instructions.add_after(after_uuid=uuid_after, item=ins)
                uuid_after = ins.uuid
            block.ricalcolate_addresses()
        except Exception as e:
            logger.error(traceback.format_exc())

    @staticmethod
    def _execute_obfuscation(block: BasicBlock, arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> None:
        """Esegue le trasformazioni con le probabilità configurate."""
        try:
            if random.random() < PRO_ADD_DEAD_CODE:
                GarbageGenerator._add_dead_code(block, arch_ks, mode_ks, arch_cs, mode_cs)
            if random.random() < PRO_ADD_NOP_INST:
                GarbageGenerator._add_nop_instruction(block, arch_ks, mode_ks, arch_cs, mode_cs)
            if random.random() < PRO_ADD_OPAQUE_CODE:
                GarbageGenerator._add_opaque_predicate(block, arch_ks, mode_ks, arch_cs, mode_cs)
            if random.random() < PRO_ADD_JUNK_CODE_AFTER_TERMINATOR:
                GarbageGenerator._add_junk_code_after_terminator(block, arch_ks, mode_ks, arch_cs, mode_cs)
        except Exception as e:
            logger.error(traceback.format_exc())

    # -----------------------
    # API pubblica
    # -----------------------
    @staticmethod
    def add_garbage_code(blocks: OrderedUUIDSet[BasicBlock], arch_ks: int, mode_ks: int, arch_cs: int, mode_cs: int) -> None:
        num_blocks = len(blocks)
        if num_blocks == 0:
            return

        # Determina i blocchi da offuscare
        if MAX_BLOCK_OBFUSCATION == -1:
            blocks_to_obfuscate = list(blocks)
        elif MAX_BLOCK_OBFUSCATION > 0:
            if MAX_BLOCK_OBFUSCATION >= 1:
                count = int(min(MAX_BLOCK_OBFUSCATION, num_blocks))
            else:
                count = max(1, int(num_blocks * MAX_BLOCK_OBFUSCATION))
            # random.sample richiede una sequence; OrderedUUIDSet è iterabile
            blocks_to_obfuscate = random.sample(list(blocks), k=count)
        else:
            raise ValueError(f"Invalid MAX_BLOCK_OBFUSCATION {MAX_BLOCK_OBFUSCATION}")

        for block in blocks_to_obfuscate:
            GarbageGenerator._execute_obfuscation(block, arch_ks, mode_ks, arch_cs, mode_cs)
            logger.debug("Obfuscation done for block %s", getattr(block, "uuid", "?"))
