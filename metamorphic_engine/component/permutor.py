import logging
import random
from typing import Optional, Set

import networkx as nx

from metamorphic_engine.model.basic_block import BasicBlock
from metamorphic_engine.model.basic_instruction import BasicInstruction
from metamorphic_engine.utils.common_function import are_permutable
from metamorphic_engine.model.ordered_uuidset import OrderedUUIDSet

logger = logging.getLogger(__name__)


class Permutator:
    # ==========================
    # PERMUTAZIONE ISTRUZIONI
    # ==========================
    @staticmethod
    def permute_block_instruction(instructions: list[BasicInstruction]) -> list[BasicInstruction]:
        """Esegue una permutazione sicura con random topological sort."""
        if not instructions:
            return []

        graph = {ins.uuid: set() for ins in instructions}
        indegree = {ins.uuid: 0 for ins in instructions}
        instr_map = {ins.uuid: ins for ins in instructions}

        # Costruzione grafo dipendenze
        for a in instructions:
            for b in instructions:
                if a.uuid == b.uuid:
                    continue
                if not are_permutable(a, b):  # conflitto → arco a→b
                    if b.uuid not in graph[a.uuid]:
                        graph[a.uuid].add(b.uuid)
                        indegree[b.uuid] += 1

        # Randomized topological sort
        queue = [u for u, deg in indegree.items() if deg == 0]
        random.shuffle(queue)
        result = []

        while queue:
            node = queue.pop()
            result.append(instr_map[node])
            for neighbor in graph[node]:
                indegree[neighbor] -= 1
                if indegree[neighbor] == 0:
                    queue.append(neighbor)
            if len(queue) > 1:
                random.shuffle(queue)

        if len(result) != len(instructions):
            logger.info("Cycle detected in instruction dependencies")
            remaining = [instr_map[u] for u, deg in indegree.items() if deg > 0]
            result.extend(remaining)

        return result

    @staticmethod
    def permute_instructions_random(
        block: BasicBlock,
        max_perm_instruction: Optional[int] = None
    ):
        """Permuta in sicurezza le istruzioni di un blocco usando solo swap."""
        if not block or not block.instructions:
            return

        instructions = list(block.instructions)

        # Ultima istruzione = terminator → non si tocca
        if not block.terminator or instructions[-1].uuid != block.terminator.uuid:
            raise ValueError("Last instruction is invalid or mismatched terminator")
        permutables = [ins for ins in instructions[:-1] if ins.is_permutable]

        if len(permutables) < 2:
            return

        n_to_permute = int(len(permutables))
        if max_perm_instruction is not None:
            n_to_permute = min(n_to_permute, max_perm_instruction, len(permutables))

        # Seleziona un sottoinsieme
        selected = random.sample(permutables, n_to_permute)

        # Permutazione sicura
        shuffled_group = Permutator.permute_block_instruction(selected)
        count: int = 0
        for i, desired in enumerate(shuffled_group):
            current = selected[i]
            if current.uuid != desired.uuid:
                try:
                    block.instructions.swap(current.uuid, desired.uuid)
                    count+=1
                except Exception as e:
                    logger.warning(f"Swap skipped ({current.uuid} ↔ {desired.uuid}): {e}")

        # Ricalcolo indirizzi
        try:
            block.end_address = block.ricalcolate_addresses(
                base_address=block.start_address,
                return_end_address=True
            )

            logger.info(f"Block: {block.uuid} swapped {count} instructions")
        except Exception as e:
            logger.error(f"Failed to recalc addresses for {block.uuid}: {e}")


    # ==========================
    # PERMUTAZIONE BLOCCHI
    # ==========================
    @staticmethod
    def build_dependency_graph(blocks: OrderedUUIDSet[BasicBlock]) -> nx.DiGraph:
        G = nx.DiGraph()
        for b in blocks:
            G.add_node(b.uuid, block=b)

        block_data = {
            b.uuid: {
                "regs_r": set().union(*(ins.regs_read for ins in b.instructions)),
                "regs_w": set().union(*(ins.regs_write for ins in b.instructions)),
                "mem_r": set().union(*(getattr(ins, "mem_read", []) for ins in b.instructions)),
                "mem_w": set().union(*(getattr(ins, "mem_write", []) for ins in b.instructions)),
                "flags": set().union(*(getattr(ins, "flags_read", []) + getattr(ins, "flags_write", []) for ins in b.instructions)),
            }
            for b in blocks
        }

        for b1 in blocks:
            d1 = block_data[b1.uuid]
            for b2 in blocks:
                if b1.uuid == b2.uuid:
                    continue
                d2 = block_data[b2.uuid]
                if (
                    d1["regs_w"] & (d2["regs_r"] | d2["regs_w"]) or
                    d1["mem_w"] & (d2["mem_r"] | d2["mem_w"]) or
                    d1["flags"] & d2["flags"]
                ):
                    G.add_edge(b1.uuid, b2.uuid)
        return G

    @staticmethod
    def permute_blocks_safe(blocks: OrderedUUIDSet[BasicBlock], percent_perm: int = 50):
        """Permuta i blocchi indipendenti rispettando le dipendenze."""
        if not blocks:
            return

        G = Permutator.build_dependency_graph(blocks)

        try:
            topo_sorted = list(nx.topological_sort(G))
        except nx.NetworkXUnfeasible:
            logger.info("Cycle detected in block dependencies, skipping permutation")
            return

        independent = [
            G.nodes[u]["block"]
            for u in topo_sorted
            if G.in_degree(u) == 0 and G.out_degree(u) == 0
        ]

        if len(independent) < 2:
            return

        n_to_permute = max(2, int(len(independent) * percent_perm / 100))
        selected = random.sample(independent, n_to_permute)

        shuffled = selected[:]
        random.shuffle(shuffled)
        mapping = dict(zip((b.uuid for b in selected), shuffled))

        new_order = [mapping.get(u, G.nodes[u]["block"]) for u in topo_sorted]

        # 🔹 Ricostruzione usando solo swap
        for i, desired in enumerate(new_order):
            current = blocks[i]
            if current.uuid != desired.uuid:
                try:
                    blocks.swap(current.uuid, desired.uuid)
                except Exception as e:
                    logger.warning(f"Swap skipped ({current.uuid} ↔ {desired.uuid}): {e}")
