

import logging
import random
from typing import List, Optional, Set

from engine_meta.model.basic_block import BasicBlock
from engine_meta.model.basic_instruction import BasicInstruction
from engine_meta.model.ordered_uuidset import OrderedUUIDSet
from engine_meta.utils.common_function import are_permutable


logger = logging.getLogger(__name__)

NO_PERM_INSTRUCTION : Optional[Set[str]] = None

def permutate(no_perm_instruction: Set[str],
              percent_perm_block: int = 40,
              percent_perm_istruction: int = 50,
              max_perm_block: Optional[int] = None,
              max_perm_instrunction: Optional[int] = None
              ) -> None:
    try:
        NO_PERM_INSTRUCTION = no_perm_instruction




    except Exception as e:
        raise e
    

def permute_block_safely(instructions: List["BasicInstruction"]) -> List["BasicInstruction"]:
    """
    Prende una lista di istruzioni ordinate e restituisce una nuova lista
    in cui le istruzioni permutabili sono mischiate in modo sicuro.
    """
    if not instructions:
        return []

    permuted_block: List["BasicInstruction"] = []
    permutable_group: List["BasicInstruction"] = []

    def flush_group():
        """Mescola e svuota il gruppo permutabile nella lista finale in modo sicuro."""
        if permutable_group:
            # Mischia rispettando le dipendenze tra istruzioni
            shuffled = []
            while permutable_group:
                for i, instr in enumerate(permutable_group):
                    # Se può essere aggiunta senza conflitti con l'ultima inserita
                    if not shuffled or are_permutable(shuffled[-1], instr):
                        shuffled.append(instr)
                        permutable_group.pop(i)
                        break
                else:
                    # Se nessuna istruzione è permutabile con l'ultima, inserisci in ordine
                    shuffled.append(permutable_group.pop(0))
            permuted_block.extend(shuffled)

    for instr in instructions:
        if getattr(instr, "is_permutable", False):
            permutable_group.append(instr)
        else:
            flush_group()
            permuted_block.append(instr)

    flush_group()
    return permuted_block


def permutate_instruction_random(block: "BasicBlock",
                                 percent_perm_instruction: int = 50,
                                 max_perm_instruction: Optional[int] = None):
    """
    Permuta in sicurezza le istruzioni di un blocco, rispettando i conflitti
    tra registri e memoria.
    """
    if not block or not block.instructions:
        logger.warning("Cannot permutate: block or instructions is None")
        return

    instructions: List[BasicInstruction] = list(block.instructions)

    # Escludiamo il terminator dalla permutazione
    if block.terminator and instructions[-1].address == block.terminator.address:
        permutables = instructions[:-1]
    else:
        permutables = instructions[:]

    # Manteniamo solo le istruzioni permutabili
    permutables = [ins for ins in permutables if getattr(ins, "is_permutable", False)]
    if len(permutables) < 2:
        logger.info(f"{block.uuid} cannot permutate: less than 2 permutable instructions")
        return

    # Limitiamo il numero di istruzioni da permutare
    n_to_permute = max(2, int(len(permutables) * percent_perm_instruction / 100))
    if max_perm_instruction is not None:
        n_to_permute = min(n_to_permute, max_perm_instruction, len(permutables))

    # Selezioniamo casualmente le istruzioni da permutare
    selected = random.sample(permutables, n_to_permute)
    selected_indices = [instructions.index(ins) for ins in selected]

    # Costruiamo la lista di istruzioni permutabili
    permutable_group = [instructions[i] for i in selected_indices]

    # Mischiamo la lista rispettando le dipendenze
    shuffled_group = permute_block_safely(permutable_group)

    # Inseriamo le istruzioni permutate nel blocco originale usando swap sicuro
    for current, new_instr in zip(permutable_group, shuffled_group):
        if current.uuid != new_instr.uuid:
            try:
                block.instructions.swap(current.uuid, new_instr.uuid)
            except ValueError as e:
                logger.warning(f"Swap skipped due to conflict: {e}")

    # Ricalcoliamo gli indirizzi
    block.end_address = block.ricalcolate_addresses(
        base_address=block.start_address,
        return_end_address=True
    )

# PERMUTAZIONE DI BLOCCHI
import networkx as nx

def build_dependency_graph(blocks: list[BasicBlock]) -> nx.DiGraph:
    """
    Costruisce un grafo di dipendenza tra blocchi.
    Un arco da B1 a B2 significa che B2 dipende da B1.
    """
    G = nx.DiGraph()
    for b in blocks:
        G.add_node(b.uuid, block=b)

    for i, b1 in enumerate(blocks):
        regs_read1 = set().union(*(ins.regs_read for ins in b1.instructions))
        regs_write1 = set().union(*(ins.regs_write for ins in b1.instructions))
        mem_read1 = set().union(*(getattr(ins, "mem_read", []) for ins in b1.instructions))
        mem_write1 = set().union(*(getattr(ins, "mem_write", []) for ins in b1.instructions))
        flags1 = set().union(*(getattr(ins, "flags_read", []) + getattr(ins, "flags_write", []) for ins in b1.instructions))

        for j, b2 in enumerate(blocks):
            if i == j:
                continue
            regs_read2 = set().union(*(ins.regs_read for ins in b2.instructions))
            regs_write2 = set().union(*(ins.regs_write for ins in b2.instructions))
            mem_read2 = set().union(*(getattr(ins, "mem_read", []) for ins in b2.instructions))
            mem_write2 = set().union(*(getattr(ins, "mem_write", []) for ins in b2.instructions))
            flags2 = set().union(*(getattr(ins, "flags_read", []) + getattr(ins, "flags_write", []) for ins in b2.instructions))

            # Conflitto => aggiungi arco
            if (regs_write1 & (regs_read2 | regs_write2) or
                regs_write2 & (regs_read1 | regs_write1) or
                mem_write1 & (mem_read2 | mem_write2) or
                mem_write2 & (mem_read1 | mem_write1) or
                flags1 & flags2):
                G.add_edge(b1.uuid, b2.uuid)
    return G


def permute_blocks_safe(blocks: list[BasicBlock], percent_perm: int = 50):
    """
    Permuta blocchi in sicurezza usando il grafo di dipendenza.
    """
    G = build_dependency_graph(blocks)
    independent_blocks = [b for b in blocks if G.in_degree(b.uuid) == 0 and G.out_degree(b.uuid) == 0]

    if len(independent_blocks) < 2:
        return  # niente da permutare

    n_to_permute = max(2, int(len(independent_blocks) * percent_perm / 100))
    selected = random.sample(independent_blocks, n_to_permute)
    shuffled = selected[:]
    random.shuffle(shuffled)

    # Swap sicuro dei blocchi nell’ordine originale
    for orig_block, new_block in zip(selected, shuffled):
        if orig_block.uuid != new_block.uuid:
            # Presuppone che `blocks` sia un OrderedUUIDSet-like
            blocks.swap(orig_block.uuid, new_block.uuid)
