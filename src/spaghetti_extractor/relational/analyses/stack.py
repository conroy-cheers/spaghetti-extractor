from __future__ import annotations

import json
from collections import defaultdict, deque
from typing import Any

from ...stage_binary import StageABinary
from ..extraction import _semantic_memory_reads
from ..model import _stack_window_transfer_claims
from .external import _register_offset_witness, _semantic_external_target_identity




def _attach_return_write_address_separations(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    original_bin: StageABinary,
    candidate_bin: StageABinary,
) -> dict[str, Any]:
    refined = json.loads(json.dumps(contract))

    def inside_image(binary: StageABinary, address: int) -> bool:
        return (
            binary.image_base <= address
            < binary.image_base + binary.pe.OPTIONAL_HEADER.SizeOfImage
            and address < 2**32
        )

    for region, behavior_pair in zip(
        refined.get("regions", []), behaviors, strict=True
    ):
        original = behavior_pair.get("original_ir") or {}
        candidate = behavior_pair.get("candidate_ir") or {}
        original_outcome = original.get("outcome") or {}
        candidate_outcome = candidate.get("outcome") or {}
        if (
            original_outcome.get("op") != "returned"
            or candidate_outcome.get("op") != "returned"
        ):
            continue
        original_writes = original.get("writes") or []
        candidate_writes = candidate.get("writes") or []
        original_stack = _semantic_read32_after_writes_address(
            original_outcome.get("target") or {}, original_writes
        )
        candidate_stack = _semantic_read32_after_writes_address(
            candidate_outcome.get("target") or {}, candidate_writes
        )
        if original_stack is None or candidate_stack is None:
            continue
        original_slot_result = _register_offset_witness(original_stack, "esp")
        candidate_slot_result = _register_offset_witness(candidate_stack, "esp")
        if original_slot_result is None or candidate_slot_result is None:
            continue
        original_requirements = _constant_return_write_requirements(
            original, int(original_slot_result[1])
        )
        candidate_requirements = _constant_return_write_requirements(
            candidate, int(candidate_slot_result[1])
        )
        if not original_requirements or not candidate_requirements:
            continue
        if (
            any(
                offset >= 2**32 or not inside_image(original_bin, address)
                for offset, address in original_requirements
            )
            or any(
                offset >= 2**32 or not inside_image(candidate_bin, address)
                for offset, address in candidate_requirements
            )
        ):
            continue
        original_rows = sorted(original_requirements)
        candidate_rows = sorted(candidate_requirements)
        row_count = max(len(original_rows), len(candidate_rows))
        separations = region.setdefault("address_separations", [])
        existing = {
            (
                str(row["original_register"]),
                str(row["candidate_register"]),
                int(row["original_offset"]),
                int(row["candidate_offset"]),
                int(row["original_address"]),
                int(row["candidate_address"]),
            )
            for row in separations
        }
        for index in range(row_count):
            original_offset, original_address = original_rows[
                index % len(original_rows)
            ]
            candidate_offset, candidate_address = candidate_rows[
                index % len(candidate_rows)
            ]
            key = (
                "esp", "esp", original_offset, candidate_offset,
                original_address, candidate_address,
            )
            if key in existing:
                continue
            separations.append({
                "original_register": "esp",
                "candidate_register": "esp",
                "original_offset": original_offset,
                "candidate_offset": candidate_offset,
                "original_address": original_address,
                "candidate_address": candidate_address,
                "source": "return_after_static_write_separation",
            })
            existing.add(key)
        separations.sort(key=lambda row: (
            str(row["original_register"]), str(row["candidate_register"]),
            int(row["original_offset"]), int(row["candidate_offset"]),
            int(row["original_address"]), int(row["candidate_address"]),
        ))
    return refined

def _reachable_weighted_nonzero_cycle_nodes(
    adjacency: dict[int, list[tuple[int, int]]],
    roots: set[int],
) -> set[int]:
    """Find reachable SCCs whose edge weights cannot have one node potential."""
    reachable: set[int] = set()
    pending = list(sorted(roots, reverse=True))
    while pending:
        node = pending.pop()
        if node in reachable:
            continue
        reachable.add(node)
        pending.extend(
            target for target, _ in reversed(adjacency.get(node, []))
            if target not in reachable
        )

    order: list[int] = []
    visited: set[int] = set()
    for start in sorted(reachable):
        if start in visited:
            continue
        stack: list[tuple[int, bool]] = [(start, False)]
        while stack:
            node, expanded = stack.pop()
            if expanded:
                order.append(node)
                continue
            if node in visited:
                continue
            visited.add(node)
            stack.append((node, True))
            stack.extend(
                (target, False)
                for target, _ in reversed(adjacency.get(node, []))
                if target in reachable and target not in visited
            )

    reverse: dict[int, list[int]] = defaultdict(list)
    for source in reachable:
        for target, _ in adjacency.get(source, []):
            if target in reachable:
                reverse[target].append(source)

    result: set[int] = set()
    assigned: set[int] = set()
    for start in reversed(order):
        if start in assigned:
            continue
        component: set[int] = set()
        pending = [start]
        assigned.add(start)
        while pending:
            node = pending.pop()
            component.add(node)
            for predecessor in reverse.get(node, []):
                if predecessor not in assigned:
                    assigned.add(predecessor)
                    pending.append(predecessor)

        potential = {start: 0}
        pending = [start]
        inconsistent = False
        while pending:
            source = pending.pop()
            for target, weight in adjacency.get(source, []):
                if target not in component:
                    continue
                expected = potential[source] + weight
                if target not in potential:
                    potential[target] = expected
                    pending.append(target)
                elif potential[target] != expected:
                    inconsistent = True
        if inconsistent:
            result.update(component)
    return result

def _attach_stack_window_invariants(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    register_relations: dict[str, Any],
    original_bin: StageABinary,
    candidate_bin: StageABinary,
) -> tuple[dict[str, Any], dict[str, Any]]:
    refined = json.loads(json.dumps(contract))
    regions = refined.get("regions", [])
    requirements: dict[tuple[int, str, str], tuple[int, int]] = {}
    seed_sources: dict[tuple[int, str, str], set[str]] = {}

    def inside_image(binary: StageABinary, address: int) -> bool:
        return binary.image_base <= address < binary.image_base + binary.pe.OPTIONAL_HEADER.SizeOfImage

    def register_offset(expression: Any) -> tuple[str, int] | None:
        if not isinstance(expression, dict):
            return None
        if expression.get("op") == "input_reg":
            return str(expression.get("reg")), 0
        operation = expression.get("op")
        if operation not in {"add", "sub"}:
            return None
        left = expression.get("left") or {}
        right = expression.get("right") or {}
        if operation == "add" and left.get("op") == "constant":
            left, right = right, left
        if right.get("op") != "constant":
            return None
        value = int(right.get("value", -1))
        if not 0 <= value < 2**32:
            return None
        prior = register_offset(left)
        if prior is None:
            return None
        register, prior_offset = prior
        word_offset = (
            prior_offset + value if operation == "add" else prior_offset - value
        ) % 2**32
        signed_offset = (
            word_offset if word_offset < 2**31 else word_offset - 2**32
        )
        return register, signed_offset

    def access_window(offset: int, width: int) -> tuple[int, int] | None:
        end = offset + width
        if width <= 0 or not -(2**31) < offset < 2**31 or not -(2**31) < end < 2**31:
            return None
        return max(-offset, 0), max(end, 0)

    def add_requirement(
        region_index: int, original_register: str, candidate_register: str,
        bytes_above: int, source: str, bytes_below: int = 0,
    ) -> None:
        # A live stack pointer must have headroom for a checked positive ESP
        # adjustment; otherwise an IA-32 add can wrap at the top of memory.
        bytes_above = max(bytes_above, 1)
        if (
            original_register != "esp"
            or candidate_register != "esp"
            or not 0 <= bytes_below < 2**32
            or not 0 <= bytes_above < 2**32
            or bytes_below + bytes_above == 0
        ):
            return
        key = (region_index, original_register, candidate_register)
        prior_below, prior_above = requirements.get(key, (0, 0))
        requirements[key] = (
            max(prior_below, bytes_below), max(prior_above, bytes_above)
        )
        seed_sources.setdefault(key, set()).add(source)

    def stack_delta(expression: Any, register: str) -> int | None:
        affine = register_offset(expression)
        if affine is None or affine[0] != register:
            return None
        return affine[1]

    machine_contracts_by_target = {
        (
            str(item["import"]["dll"]).lower(),
            "symbol" if "symbol" in item["import"] else "ordinal",
            item["import"].get("symbol", item["import"].get("ordinal")),
        ): item
        for item in refined.get("machine_import_call_contracts", [])
    }

    for region_index, region in enumerate(regions):
        for separation in region.get("address_separations", []):
            original_register = str(separation["original_register"])
            candidate_register = str(separation["candidate_register"])
            original_offset = int(separation["original_offset"])
            candidate_offset = int(separation["candidate_offset"])
            if (
                original_register != "esp"
                or candidate_register != "esp"
                or original_offset >= 2**31
                or candidate_offset >= 2**31
                or not inside_image(original_bin, int(separation["original_address"]))
                or not inside_image(candidate_bin, int(separation["candidate_address"]))
            ):
                continue
            key = (region_index, original_register, candidate_register)
            prior_below, prior_above = requirements.get(key, (0, 0))
            requirements[key] = (
                prior_below,
                max(prior_above, original_offset + 1, candidate_offset + 1),
            )
            seed_sources.setdefault(key, set()).add("address_separation_seed")

    relation_rows = register_relations.get("regions", [])
    for region_index, behavior in enumerate(behaviors):
        region = regions[region_index]
        relation_row = (
            relation_rows[region_index]
            if region_index < len(relation_rows)
            else {}
        )
        for location in relation_row.get("return_slot_offsets", []):
            original_register = str(
                location.get("original_register", "esp")
            )
            candidate_register = str(
                location.get("candidate_register", "esp")
            )
            original_window = access_window(int(location["original"]), 4)
            candidate_window = access_window(int(location["candidate"]), 4)
            if original_window is None or candidate_window is None:
                continue
            add_requirement(
                region_index, original_register, candidate_register,
                max(original_window[1], candidate_window[1]),
                "runtime_return_frame_seed",
                max(original_window[0], candidate_window[0]),
            )
        original_reads = {
            tuple(read["path"]): read
            for read in _semantic_memory_reads(behavior["original_ir"])
        }
        candidate_reads = {
            tuple(read["path"]): read
            for read in _semantic_memory_reads(behavior["candidate_ir"])
        }
        for path in sorted(original_reads.keys() & candidate_reads.keys()):
            original_read = original_reads[path]
            candidate_read = candidate_reads[path]
            width = original_read.get("width")
            if not isinstance(width, int) or width != candidate_read.get("width"):
                continue
            original_address = register_offset(original_read.get("address"))
            candidate_address = register_offset(candidate_read.get("address"))
            if original_address is None or candidate_address is None:
                continue
            original_window = access_window(original_address[1], width)
            candidate_window = access_window(candidate_address[1], width)
            if original_window is None or candidate_window is None:
                continue
            add_requirement(
                region_index, original_address[0], candidate_address[0],
                max(original_window[1], candidate_window[1]),
                "paired_memory_read_seed",
                max(original_window[0], candidate_window[0]),
            )
        original_outcome = behavior["original_ir"].get("outcome") or {}
        candidate_outcome = behavior["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") == "external_jump"
            and candidate_outcome.get("op") == "external_jump"
        ):
            original_target = _semantic_external_target_identity(
                original_outcome.get("import")
            )
            candidate_target = _semantic_external_target_identity(
                candidate_outcome.get("import")
            )
            machine_contract = machine_contracts_by_target.get(original_target)
            if (
                original_target is not None
                and original_target == candidate_target
                and machine_contract is not None
            ):
                argument_windows = [
                    access_window(4 + int(offset), 4)
                    for offset in machine_contract.get(
                        "stack_argument_offsets", []
                    )
                ]
                if all(window is not None for window in argument_windows):
                    add_requirement(
                        region_index,
                        "esp",
                        "esp",
                        max(
                            (
                                window[1] for window in argument_windows
                                if window is not None
                            ),
                            default=0,
                        ),
                        "import_thunk_boundary_seed",
                        max(
                            (
                                window[0] for window in argument_windows
                                if window is not None
                            ),
                            default=0,
                        ),
                    )
                    # The normalized call boundary advances ESP past the saved
                    # return address. Retain one byte of headroom above that
                    # boundary so the checked affine transfer also proves that
                    # the 32-bit addition cannot wrap.
                    add_requirement(
                        region_index,
                        "esp",
                        "esp",
                        5,
                        "import_thunk_return_slot_seed",
                        0,
                    )
        if (
            original_outcome.get("op") == "indirect_call"
            and candidate_outcome.get("op") == "indirect_call"
        ):
            original_target = original_outcome.get("target") or {}
            candidate_target = candidate_outcome.get("target") or {}
            import_matches = [
                relation for relation in region.get("input_import_relations", [])
                if original_target == {
                    "op": "input_reg", "reg": relation["original"],
                }
                and candidate_target == {
                    "op": "input_reg", "reg": relation["candidate"],
                }
            ]
            if len(import_matches) == 1:
                imported = import_matches[0]["import"]
                identity = (
                    str(imported["dll"]).lower(),
                    "symbol" if "symbol" in imported else "ordinal",
                    imported.get("symbol", imported.get("ordinal")),
                )
                machine_contract = machine_contracts_by_target.get(identity)
                original_delta = stack_delta(
                    (behavior["original_ir"].get("registers") or {}).get("esp"),
                    "esp",
                )
                candidate_delta = stack_delta(
                    (behavior["candidate_ir"].get("registers") or {}).get("esp"),
                    "esp",
                )
                if (
                    machine_contract is not None
                    and original_delta is not None
                    and original_delta == candidate_delta
                ):
                    restored_delta = original_delta + 4
                    argument_windows = [
                        access_window(restored_delta + int(offset), 4)
                        for offset in machine_contract.get(
                            "stack_argument_offsets", []
                        )
                    ]
                    if all(window is not None for window in argument_windows):
                        add_requirement(
                            region_index,
                            "esp",
                            "esp",
                            max(
                                (window[1] for window in argument_windows
                                 if window is not None),
                                default=1,
                            ),
                            "register_import_argument_seed",
                            max(
                                (window[0] for window in argument_windows
                                 if window is not None),
                                default=0,
                            ),
                        )
        if original_outcome.get("op") == candidate_outcome.get("op") == "returned":
            original_delta = stack_delta(
                (behavior["original_ir"].get("registers") or {}).get("esp"), "esp"
            )
            candidate_delta = stack_delta(
                (behavior["candidate_ir"].get("registers") or {}).get("esp"), "esp"
            )
            if (
                original_delta is not None
                and original_delta == candidate_delta
                and original_delta > 0
            ):
                add_requirement(
                    region_index, "esp", "esp", original_delta + 1,
                    "return_stack_no_wrap_seed",
                )
        original_writes = behavior["original_ir"].get("writes") or []
        candidate_writes = behavior["candidate_ir"].get("writes") or []
        if len(original_writes) == len(candidate_writes):
            for original_write, candidate_write in zip(
                original_writes, candidate_writes, strict=True
            ):
                original_address = register_offset(original_write.get("address"))
                candidate_address = register_offset(candidate_write.get("address"))
                if original_address is None or candidate_address is None:
                    continue
                original_window = access_window(original_address[1], 4)
                candidate_window = access_window(candidate_address[1], 4)
                if original_window is None or candidate_window is None:
                    continue
                add_requirement(
                    region_index, original_address[0], candidate_address[0],
                    max(original_window[1], candidate_window[1]),
                    "paired_memory_write_seed",
                    max(original_window[0], candidate_window[0]),
                )

    incoming: dict[int, list[dict[str, Any]]] = {}
    for edge in register_relations.get("edges", []):
        incoming.setdefault(int(edge["target_region_index"]), []).append(edge)
    region_index_by_target_id = {
        int(region.get("numeric_id", index)): index
        for index, region in enumerate(regions)
    }
    direct_call_continuations: dict[int, list[dict[str, Any]]] = defaultdict(list)
    direct_call_edges_by_source = {
        int(edge["source_region_index"]): edge
        for edge in register_relations.get("edges", [])
        if edge.get("direct_call_push_claim") is not None
    }
    stack_window_return_summary_by_source = {
        int(summary["callsite_region_index"]): summary
        for summary in (
            register_relations.get("return_slot_analysis", {})
            .get("call_summary_analysis", {})
            .get("summaries", [])
        )
        if summary.get("stack_window_return_status")
            == "candidate_requires_local_lean_replay"
    }
    for source_index, behavior in enumerate(behaviors):
        original_outcome = behavior["original_ir"].get("outcome") or {}
        candidate_outcome = behavior["candidate_ir"].get("outcome") or {}
        if (
            original_outcome.get("op") != "call"
            or candidate_outcome.get("op") != "call"
            or original_outcome.get("target") != candidate_outcome.get("target")
            or original_outcome.get("continuation")
                != candidate_outcome.get("continuation")
        ):
            continue
        callee_index = region_index_by_target_id.get(
            int(original_outcome["target"])
        )
        continuation_index = region_index_by_target_id.get(
            int(original_outcome["continuation"])
        )
        if callee_index is None or continuation_index is None:
            continue
        original_delta = stack_delta(
            (behavior["original_ir"].get("registers") or {}).get("esp"), "esp"
        )
        candidate_delta = stack_delta(
            (behavior["candidate_ir"].get("registers") or {}).get("esp"), "esp"
        )
        if original_delta is None or original_delta != candidate_delta:
            continue
        call_edge = direct_call_edges_by_source.get(source_index)
        return_stack_deltas = {
            4 + int(claim["pop_bytes"])
            for claim in (
                call_edge.get("return_slot_call_summary_claims", [])
                if call_edge is not None
                else []
            )
        }
        static_return_summary = stack_window_return_summary_by_source.get(source_index)
        if static_return_summary is not None:
            return_stack_deltas.add(
                int(static_return_summary["stack_window_return_delta"])
            )
        callee_original_outcome = behaviors[callee_index]["original_ir"].get(
            "outcome"
        ) or {}
        callee_candidate_outcome = behaviors[callee_index]["candidate_ir"].get(
            "outcome"
        ) or {}
        callee_original_target = _semantic_external_target_identity(
            callee_original_outcome.get("import")
        )
        callee_candidate_target = _semantic_external_target_identity(
            callee_candidate_outcome.get("import")
        )
        callee_machine_contract = machine_contracts_by_target.get(
            callee_original_target
        )
        if (
            callee_original_outcome.get("op") == "external_jump"
            and callee_candidate_outcome.get("op") == "external_jump"
            and callee_original_target is not None
            and callee_original_target == callee_candidate_target
            and callee_machine_contract is not None
        ):
            return_stack_deltas.add(
                4 + int(callee_machine_contract["stack_result_delta"])
            )
        direct_call_continuations[continuation_index].append({
            "source_region_index": source_index,
            "callee_region_index": callee_index,
            "entry_stack_delta": original_delta,
            "return_stack_delta": (
                next(iter(return_stack_deltas))
                if len(return_stack_deltas) == 1
                else None
            ),
        })
    call_window_adjacency = {
        continuation: {
            int(call["callee_region_index"]) for call in calls
        }
        for continuation, calls in direct_call_continuations.items()
    }

    def call_window_path_exists(start: int, target: int) -> bool:
        pending = [start]
        seen: set[int] = set()
        while pending:
            node = pending.pop()
            if node == target:
                return True
            if node in seen:
                continue
            seen.add(node)
            pending.extend(call_window_adjacency.get(node, set()) - seen)
        return False

    for continuation, calls in direct_call_continuations.items():
        for call in calls:
            call["recursive"] = int(call_window_path_exists(
                int(call["callee_region_index"]), continuation,
            ))
    def edge_stack_delta(
        edge: dict[str, Any], original_register: str, candidate_register: str,
    ) -> tuple[int | None, str | None]:
        source_index = int(edge["source_region_index"])
        original_expression = (
            behaviors[source_index]["original_ir"].get("registers") or {}
        ).get(original_register) or {}
        candidate_expression = (
            behaviors[source_index]["candidate_ir"].get("registers") or {}
        ).get(candidate_register) or {}
        original_delta = stack_delta(original_expression, original_register)
        candidate_delta = stack_delta(candidate_expression, candidate_register)
        environment_delta = 0
        if edge.get("environment_barrier"):
            original_outcome = behaviors[source_index]["original_ir"].get(
                "outcome"
            ) or {}
            candidate_outcome = behaviors[source_index]["candidate_ir"].get(
                "outcome"
            ) or {}
            original_target = _semantic_external_target_identity(
                original_outcome.get("import")
            )
            candidate_target = _semantic_external_target_identity(
                candidate_outcome.get("import")
            )
            machine_contract = machine_contracts_by_target.get(original_target)
            if (
                original_outcome.get("op") != "external_call"
                or candidate_outcome.get("op") != "external_call"
                or original_target is None
                or original_target != candidate_target
                or machine_contract is None
            ):
                return None, "unsupported_environment_stack_transfer"
            environment_delta = int(machine_contract["stack_result_delta"])
        if (
            original_delta is None
            or candidate_delta is None
            or original_delta + environment_delta
                != candidate_delta + environment_delta
        ):
            return None, "non_identity_or_environment_stack_transfer"
        return original_delta + environment_delta, None

    unbounded_cycle_nodes: dict[tuple[str, str], set[int]] = {}
    for original_register, candidate_register in sorted({
        (original_register, candidate_register)
        for _, original_register, candidate_register in requirements
    }):
        adjacency: dict[int, list[tuple[int, int]]] = defaultdict(list)
        for target_index, target_edges in incoming.items():
            for edge in target_edges:
                delta, _ = edge_stack_delta(
                    edge, original_register, candidate_register
                )
                if delta is not None:
                    adjacency[target_index].append((
                        int(edge["source_region_index"]), delta,
                    ))
        if original_register == "esp" and candidate_register == "esp":
            for continuation, calls in direct_call_continuations.items():
                for call in calls:
                    return_stack_delta = call.get("return_stack_delta")
                    if (
                        not bool(call.get("recursive"))
                        and isinstance(return_stack_delta, int)
                    ):
                        adjacency[continuation].append((
                            int(call["callee_region_index"]),
                            return_stack_delta,
                        ))
        for edges in adjacency.values():
            edges.sort()
        roots = {
            region_index
            for region_index, source_original, source_candidate in requirements
            if source_original == original_register
            and source_candidate == candidate_register
        }
        unbounded_cycle_nodes[(original_register, candidate_register)] = (
            _reachable_weighted_nonzero_cycle_nodes(adjacency, roots)
        )

    frontier: list[dict[str, Any]] = []
    frontier_keys: set[tuple[tuple[str, Any], ...]] = set()
    duplicate_frontier_observations = 0
    propagation_steps = 0
    requirement_updates = 0

    def add_frontier(row: dict[str, Any]) -> None:
        nonlocal duplicate_frontier_observations
        key = tuple(sorted(row.items()))
        if key in frontier_keys:
            duplicate_frontier_observations += 1
            return
        frontier_keys.add(key)
        frontier.append(row)

    queue = deque(sorted(requirements))
    queued = set(queue)
    while queue:
        target_key = queue.popleft()
        propagation_steps += 1
        queued.discard(target_key)
        target_index, original_register, candidate_register = target_key
        bytes_below, bytes_above = requirements[target_key]
        if target_index in unbounded_cycle_nodes.get(
            (original_register, candidate_register), set()
        ):
            add_frontier({
                "region_index": target_index,
                "original_register": original_register,
                "candidate_register": candidate_register,
                "bytes_below": bytes_below,
                "bytes_above": bytes_above,
                "reason": "nonzero_stack_delta_cycle_requires_relational_frame",
            })
            continue
        if original_register == "esp" and candidate_register == "esp":
            for call in direct_call_continuations.get(target_index, []):
                if bool(call.get("recursive")):
                    add_frontier({
                        "region_index": target_index,
                        "source_region_index": int(call["source_region_index"]),
                        "callee_region_index": int(call["callee_region_index"]),
                        "original_register": original_register,
                        "candidate_register": candidate_register,
                        "bytes_below": bytes_below,
                        "bytes_above": bytes_above,
                        "reason": "recursive_call_window_requires_inductive_frame",
                    })
                    continue
                return_stack_delta = call.get("return_stack_delta")
                if not isinstance(return_stack_delta, int):
                    add_frontier({
                        "region_index": target_index,
                        "source_region_index": int(call["source_region_index"]),
                        "callee_region_index": int(call["callee_region_index"]),
                        "original_register": original_register,
                        "candidate_register": candidate_register,
                        "bytes_below": bytes_below,
                        "bytes_above": bytes_above,
                        "reason": "direct_call_window_requires_return_summary",
                    })
                    continue
                callee_key = (
                    int(call["callee_region_index"]),
                    original_register,
                    candidate_register,
                )
                callee_below = max(bytes_below - return_stack_delta, 0)
                callee_above = max(bytes_above + return_stack_delta, 1)
                prior_below, prior_above = requirements.get(callee_key, (0, 0))
                required = (
                    max(prior_below, callee_below),
                    max(prior_above, callee_above),
                )
                if required != (prior_below, prior_above):
                    requirements[callee_key] = required
                    seed_sources.setdefault(callee_key, set()).add(
                        "direct_call_continuation_window"
                    )
                    requirement_updates += 1
                    if callee_key not in queued:
                        queue.append(callee_key)
                        queued.add(callee_key)
        edges = incoming.get(target_index, [])
        if not edges:
            add_frontier({
                "region_index": target_index,
                "original_register": original_register,
                "candidate_register": candidate_register,
                "bytes_below": bytes_below,
                "bytes_above": bytes_above,
                "reason": "no_checked_incoming_edge",
            })
            continue
        for edge in edges:
            source_index = int(edge["source_region_index"])
            original_delta, transfer_issue = edge_stack_delta(
                edge, original_register, candidate_register
            )
            if original_delta is None:
                add_frontier({
                    "region_index": target_index,
                    "source_region_index": source_index,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                    "bytes_below": bytes_below,
                    "bytes_above": bytes_above,
                    "reason": transfer_issue,
                })
                continue
            source_below = max(bytes_below - original_delta, 0)
            source_above = max(bytes_above + original_delta, 1)
            source_key = (source_index, original_register, candidate_register)
            prior_below, prior_above = requirements.get(source_key, (0, 0))
            required = (
                max(prior_below, source_below), max(prior_above, source_above)
            )
            if required != (prior_below, prior_above):
                requirements[source_key] = required
                requirement_updates += 1
                if source_key not in queued:
                    queue.append(source_key)
                    queued.add(source_key)

    windows_by_region: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for (region_index, original_register, candidate_register), (
        bytes_below, bytes_above,
    ) in sorted(requirements.items()):
        windows_by_region[region_index].append({
            "range_id": 0,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "bytes_below": bytes_below,
            "bytes_above": bytes_above,
            "source": (
                "+".join(sorted(seed_sources[
                    (region_index, original_register, candidate_register)
                ]))
                if (region_index, original_register, candidate_register)
                    in seed_sources
                else "backward_identity_stack_window"
            ),
        })

    for region_index, region in enumerate(regions):
        windows = windows_by_region.get(region_index, [])
        region["stack_windows"] = windows
        claims = []
        for separation in region.get("address_separations", []):
            matches = [
                window for window in windows
                if window["original_register"] == separation["original_register"]
                and window["candidate_register"] == separation["candidate_register"]
                and int(separation["original_offset"]) < int(window["bytes_above"])
                and int(separation["candidate_offset"]) < int(window["bytes_above"])
            ]
            if len(matches) == 1:
                claims.append({"window": matches[0], "separation": separation})
        region["stack_address_separation_claims"] = claims

    return refined, {
        "format": "stage-a-relational-stack-windows-v1",
        "status": "proposal_requires_lean_replay",
        "range_profile": "paired-stack-range-v1",
        "regions_with_windows": sum(bool(region.get("stack_windows")) for region in regions),
        "windows": sum(len(region.get("stack_windows", [])) for region in regions),
        "separation_claims": sum(
            len(region.get("stack_address_separation_claims", [])) for region in regions
        ),
        "propagation_steps": propagation_steps,
        "requirement_updates": requirement_updates,
        "nonzero_stack_delta_cycle_nodes": sum(
            len(nodes) for nodes in unbounded_cycle_nodes.values()
        ),
        "duplicate_frontier_observations": duplicate_frontier_observations,
        "frontier": frontier,
    }

def _direct_call_push_claim(
    region: dict[str, Any],
    behavior_pair: dict[str, Any],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> dict[str, Any] | None:
    original = behavior_pair.get("original_ir") or {}
    candidate = behavior_pair.get("candidate_ir") or {}
    original_outcome = original.get("outcome") or {}
    candidate_outcome = candidate.get("outcome") or {}
    if (
        original_outcome.get("op") != "call"
        or candidate_outcome.get("op") != "call"
        or original_outcome != candidate_outcome
    ):
        return None
    callee_id = int(original_outcome["target"])
    continuation_id = int(original_outcome["continuation"])
    local_targets = region.get("code_targets", [])
    callees = [item for item in local_targets if int(item["id"]) == callee_id]
    continuations = [
        item for item in local_targets if int(item["id"]) == continuation_id
    ]
    if len(callees) != 1 or len(continuations) != 1:
        return None
    original_writes = original.get("writes", [])
    candidate_writes = candidate.get("writes", [])
    if not original_writes or not candidate_writes:
        return None
    original_last = original_writes[-1]
    candidate_last = candidate_writes[-1]
    original_stack = (original.get("registers") or {}).get("esp")
    candidate_stack = (candidate.get("registers") or {}).get("esp")
    continuation = continuations[0]
    original_return = original_last.get("value")
    candidate_return = candidate_last.get("value")
    original_rvas = {
        int(continuation["original_rva"]),
        *(int(rva) for rva in continuation.get("original_aliases", [])),
    }
    candidate_rvas = {
        int(continuation["candidate_rva"]),
        *(int(rva) for rva in continuation.get("candidate_aliases", [])),
    }
    if (
        original_stack is None
        or candidate_stack is None
        or original_last.get("address") != original_stack
        or candidate_last.get("address") != candidate_stack
        or not isinstance(original_return, dict)
        or original_return.get("op") != "constant"
        or int(original_return.get("value", -1)) - original_image_base
            not in original_rvas
        or not isinstance(candidate_return, dict)
        or candidate_return.get("op") != "constant"
        or int(candidate_return.get("value", -1)) - candidate_image_base
            not in candidate_rvas
    ):
        return None
    return {
        "profile": "mapped_direct_call_push_v1",
        "callee_target_id": callee_id,
        "continuation_target_id": continuation_id,
        "continuation_region_index": int(continuation["region_index"]),
        "original_return_address": int(original_return["value"]),
        "candidate_return_address": int(candidate_return["value"]),
        "original_stack_address": original_stack,
        "candidate_stack_address": candidate_stack,
    }


def _indirect_call_push_claim(
    region: dict[str, Any],
    behavior_pair: dict[str, Any],
    *,
    original_image_base: int,
    candidate_image_base: int,
) -> dict[str, Any] | None:
    original = behavior_pair.get("original_ir") or {}
    candidate = behavior_pair.get("candidate_ir") or {}
    original_outcome = original.get("outcome") or {}
    candidate_outcome = candidate.get("outcome") or {}
    if (
        original_outcome.get("op") != "indirect_call"
        or candidate_outcome.get("op") != "indirect_call"
        or original_outcome.get("continuation")
            != candidate_outcome.get("continuation")
    ):
        return None
    continuation_id = int(original_outcome["continuation"])
    continuations = [
        item for item in region.get("code_targets", [])
        if int(item["id"]) == continuation_id
    ]
    if len(continuations) != 1:
        return None
    original_writes = original.get("writes", [])
    candidate_writes = candidate.get("writes", [])
    if not original_writes or not candidate_writes:
        return None
    original_last = original_writes[-1]
    candidate_last = candidate_writes[-1]
    original_stack = (original.get("registers") or {}).get("esp")
    candidate_stack = (candidate.get("registers") or {}).get("esp")
    continuation = continuations[0]
    original_return = original_last.get("value")
    candidate_return = candidate_last.get("value")
    original_rvas = {
        int(continuation["original_rva"]),
        *(int(rva) for rva in continuation.get("original_aliases", [])),
    }
    candidate_rvas = {
        int(continuation["candidate_rva"]),
        *(int(rva) for rva in continuation.get("candidate_aliases", [])),
    }
    if (
        original_stack is None
        or candidate_stack is None
        or original_last.get("address") != original_stack
        or candidate_last.get("address") != candidate_stack
        or not isinstance(original_return, dict)
        or original_return.get("op") != "constant"
        or int(original_return.get("value", -1)) - original_image_base
            not in original_rvas
        or not isinstance(candidate_return, dict)
        or candidate_return.get("op") != "constant"
        or int(candidate_return.get("value", -1)) - candidate_image_base
            not in candidate_rvas
    ):
        return None
    return {
        "profile": "mapped_indirect_call_push_v1",
        "continuation_target_id": continuation_id,
        "continuation_region_index": int(continuation["region_index"]),
        "original_return_address": int(original_return["value"]),
        "candidate_return_address": int(candidate_return["value"]),
        "original_stack_address": original_stack,
        "candidate_stack_address": candidate_stack,
    }

def _semantic_read8_after_writes(
    address: dict[str, Any], writes: list[dict[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {"op": "read8", "address": address}
    for write in writes:
        result = {
            "op": "read8_after_write",
            "address": address,
            "write_address": write["address"],
            "write_value": write["value"],
            "prior": result,
        }
    return result

def _semantic_read32_after_writes(
    address: dict[str, Any], writes: list[dict[str, Any]],
) -> dict[str, Any]:
    def byte_address(offset: int) -> dict[str, Any]:
        if offset == 0:
            return address
        return {
            "op": "add",
            "left": address,
            "right": {"op": "constant", "value": offset},
        }

    byte_reads = [
        _semantic_read8_after_writes(byte_address(offset), writes)
        for offset in range(4)
    ]
    shifted = [
        byte_reads[0],
        {"op": "shift_left", "value": byte_reads[1], "amount": 8},
        {"op": "shift_left", "value": byte_reads[2], "amount": 16},
        {"op": "shift_left", "value": byte_reads[3], "amount": 24},
    ]
    return {
        "op": "bit_or",
        "left": {"op": "bit_or", "left": shifted[0], "right": shifted[1]},
        "right": {"op": "bit_or", "left": shifted[2], "right": shifted[3]},
    }

def _semantic_read32_after_writes_address(
    target: dict[str, Any], writes: list[dict[str, Any]],
) -> dict[str, Any] | None:
    left = target.get("left") or {}
    first_byte = left.get("left") or {}
    if first_byte.get("op") not in {"read8", "read8_after_write"}:
        return None
    address = first_byte.get("address")
    if not isinstance(address, dict):
        return None
    return address if target == _semantic_read32_after_writes(address, writes) else None

def _constant_return_write_requirements(
    behavior: dict[str, Any], stack_offset: int,
) -> set[tuple[int, int]] | None:
    requirements: set[tuple[int, int]] = set()
    writes = behavior.get("writes") or []
    if not writes:
        return None
    for write in writes:
        address = write.get("address") or {}
        if address.get("op") != "constant":
            return None
        write_address = int(address.get("value", -1))
        if not 0 <= write_address < 2**32 or write_address + 4 > 2**32:
            return None
        for word_byte in range(4):
            for write_byte in range(4):
                requirements.add((
                    stack_offset + word_byte,
                    write_address + write_byte,
                ))
    return requirements

def _return_write_separations_cover(
    region: dict[str, Any] | None,
    original_requirements: set[tuple[int, int]],
    candidate_requirements: set[tuple[int, int]],
) -> bool:
    if region is None:
        return False
    separations = region.get("address_separations") or []
    original_available = {
        (int(row["original_offset"]), int(row["original_address"]))
        for row in separations
        if row.get("original_register") == "esp"
    }
    candidate_available = {
        (int(row["candidate_offset"]), int(row["candidate_address"]))
        for row in separations
        if row.get("candidate_register") == "esp"
    }
    return (
        original_requirements <= original_available
        and candidate_requirements <= candidate_available
    )

def _return_pop_claim(
    behavior_pair: dict[str, Any],
    *,
    region: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    original = behavior_pair.get("original_ir") or {}
    candidate = behavior_pair.get("candidate_ir") or {}
    original_outcome = original.get("outcome") or {}
    candidate_outcome = candidate.get("outcome") or {}
    if (
        original_outcome.get("op") != "returned"
        or candidate_outcome.get("op") != "returned"
    ):
        return None
    original_target = original_outcome.get("target") or {}
    candidate_target = candidate_outcome.get("target") or {}
    original_writes = original.get("writes") or []
    candidate_writes = candidate.get("writes") or []
    if (
        original_target.get("op") == "read32"
        and candidate_target.get("op") == "read32"
    ):
        profile = "esp_relative_return_pop_v1"
        original_stack = original_target.get("address")
        candidate_stack = candidate_target.get("address")
    else:
        profile = "esp_relative_return_after_static_writes_v1"
        original_stack = _semantic_read32_after_writes_address(
            original_target, original_writes
        )
        candidate_stack = _semantic_read32_after_writes_address(
            candidate_target, candidate_writes
        )
        if original_stack is None or candidate_stack is None:
            return None

    original_slot_result = _register_offset_witness(original_stack)
    candidate_slot_result = _register_offset_witness(candidate_stack)
    original_output_result = _register_offset_witness(
        (original.get("registers") or {}).get("esp")
    )
    candidate_output_result = _register_offset_witness(
        (candidate.get("registers") or {}).get("esp")
    )
    if any(result is None for result in (
        original_slot_result, candidate_slot_result,
        original_output_result, candidate_output_result,
    )):
        return None
    assert original_slot_result is not None
    assert candidate_slot_result is not None
    assert original_output_result is not None
    assert candidate_output_result is not None
    original_slot_witness, original_slot = original_slot_result
    candidate_slot_witness, candidate_slot = candidate_slot_result
    original_output_witness, original_output = original_output_result
    candidate_output_witness, candidate_output = candidate_output_result
    original_delta = (int(original_output) - int(original_slot)) % 2**32
    candidate_delta = (int(candidate_output) - int(candidate_slot)) % 2**32
    if (
        original_delta != candidate_delta
        or not 4 <= original_delta <= 4 + 65535
    ):
        return None
    if profile == "esp_relative_return_after_static_writes_v1":
        original_requirements = _constant_return_write_requirements(
            original, int(original_slot)
        )
        candidate_requirements = _constant_return_write_requirements(
            candidate, int(candidate_slot)
        )
        if (
            original_requirements is None
            or candidate_requirements is None
            or not _return_write_separations_cover(
                region, original_requirements, candidate_requirements
            )
        ):
            return None
    return {
        "profile": profile,
        "original_stack_address": original_stack,
        "candidate_stack_address": candidate_stack,
        "original_stack_witness": original_slot_witness,
        "candidate_stack_witness": candidate_slot_witness,
        "original_stack_offset": original_slot,
        "candidate_stack_offset": candidate_slot,
        "original_output_witness": original_output_witness,
        "candidate_output_witness": candidate_output_witness,
        "original_output_offset": original_output,
        "candidate_output_offset": candidate_output,
        "pop_bytes": original_delta - 4,
    }

def _discover_static_call_return_summaries(
    relation_rows: list[dict[str, Any]],
    edges: list[dict[str, Any]],
) -> dict[str, Any]:
    region_count = len(relation_rows)
    ordinary_successors: list[set[int]] = [set() for _ in relation_rows]
    call_edges: dict[int, dict[str, Any]] = {}
    unsupported_exit = [False] * region_count
    for edge in edges:
        source = int(edge["source_region_index"])
        if edge.get("direct_call_push_claim") is not None:
            call_edges[source] = edge
            continue
        if (
            edge["environment_barrier"]
            or edge["requires_call_stack_proof"]
            or edge.get("indirect_target_profile")
            or edge["kind"] == "call"
        ):
            unsupported_exit[source] = True
            continue
        ordinary_successors[source].add(int(edge["target_region_index"]))

    reverse_dependencies: list[set[int]] = [set() for _ in relation_rows]
    for source, successors in enumerate(ordinary_successors):
        for target in successors:
            reverse_dependencies[target].add(source)
    for source, edge in call_edges.items():
        callee = int(edge["target_region_index"])
        continuation = int(edge["direct_call_push_claim"]["continuation_region_index"])
        reverse_dependencies[callee].add(source)
        reverse_dependencies[continuation].add(source)

    return_sets: list[set[int]] = [
        {index} if row.get("is_return") else set()
        for index, row in enumerate(relation_rows)
    ]
    pending = deque(range(region_count))
    queued = set(range(region_count))
    return_updates = 0
    while pending:
        source = pending.popleft()
        queued.discard(source)
        if relation_rows[source].get("is_return"):
            continue
        proposed: set[int] = set()
        if source in call_edges:
            edge = call_edges[source]
            callee = int(edge["target_region_index"])
            continuation = int(
                edge["direct_call_push_claim"]["continuation_region_index"]
            )
            if return_sets[callee]:
                proposed.update(return_sets[continuation])
        else:
            for target in ordinary_successors[source]:
                proposed.update(return_sets[target])
        if not proposed.issubset(return_sets[source]):
            return_sets[source].update(proposed)
            return_updates += 1
            for predecessor in reverse_dependencies[source]:
                if predecessor not in queued:
                    queued.add(predecessor)
                    pending.append(predecessor)

    closed = [True] * region_count
    changed = True
    closure_iterations = 0
    while changed:
        changed = False
        closure_iterations += 1
        for source, row in enumerate(relation_rows):
            if row.get("is_return"):
                next_closed = not unsupported_exit[source]
            elif unsupported_exit[source]:
                next_closed = False
            elif source in call_edges:
                edge = call_edges[source]
                callee = int(edge["target_region_index"])
                continuation = int(
                    edge["direct_call_push_claim"]["continuation_region_index"]
                )
                next_closed = closed[callee] and closed[continuation]
            else:
                successors = ordinary_successors[source]
                next_closed = bool(successors) and all(closed[target] for target in successors)
            if closed[source] and not next_closed:
                closed[source] = False
                changed = True

    summaries = []
    for source, edge in sorted(call_edges.items()):
        callee = int(edge["target_region_index"])
        continuation = int(edge["direct_call_push_claim"]["continuation_region_index"])
        returns = sorted(return_sets[callee])
        summaries.append({
            "callsite_region_index": source,
            "callee_region_index": callee,
            "continuation_region_index": continuation,
            "return_region_indices": returns,
            "closed": bool(closed[callee]),
            "status": (
                "candidate_requires_return_slot_replay"
                if closed[callee] and returns
                else "incomplete"
            ),
            "blocker": (
                None
                if closed[callee] and returns
                else "callee has an unsupported exit or no statically reachable return"
            ),
        })
    return {
        "profile": "static_pushdown_return_summary_v1",
        "return_updates": return_updates,
        "closure_iterations": closure_iterations,
        "closed_regions": sum(closed),
        "summaries": summaries,
    }

def _attach_return_slot_contracts(
    behaviors: list[dict[str, Any]],
    relation_rows: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    machine_import_call_contracts: list[dict[str, Any]] | None = None,
    disjunction_budget: int = 8,
) -> dict[str, Any]:
    FrameLocation = tuple[str, int, str, int]

    def location_payload(location: FrameLocation) -> dict[str, Any]:
        original_register, original_offset, candidate_register, candidate_offset = location
        return {
            "original_register": original_register,
            "original": original_offset,
            "candidate_register": candidate_register,
            "candidate": candidate_offset,
        }

    locations: list[set[FrameLocation]] = [set() for _ in relation_rows]
    overflow_regions: set[int] = set()
    seed_edges = 0
    for edge in edges:
        edge["return_slot_seed"] = None
        edge["return_slot_transfer_claims"] = []
        edge["return_slot_frame_transfer_claims"] = []
        edge["return_slot_call_summary_claims"] = []
        push_claim = (
            edge.get("direct_call_push_claim")
            or edge.get("indirect_call_push_claim")
        )
        if push_claim is None:
            continue
        target_index = int(edge["target_region_index"])
        zero_location: FrameLocation = ("esp", 0, "esp", 0)
        locations[target_index].add(zero_location)
        edge["return_slot_seed"] = {
            "profile": (
                "direct_call_runtime_frame_seed_v1"
                if edge.get("direct_call_push_claim") is not None
                else "indirect_call_runtime_frame_seed_v1"
            ),
            "target_region_index": target_index,
            "offsets": location_payload(zero_location),
        }
        seed_edges += 1

    def behavior_transfer_witnesses(
        source: int, source_location: FrameLocation,
    ) -> list[tuple[FrameLocation, dict[str, Any], dict[str, Any]]]:
        original_source_register, original_source_offset, \
            candidate_source_register, candidate_source_offset = source_location
        transfers = []
        for rule in behavior_transfer_rules(source):
            if (
                rule["original_source_register"] != original_source_register
                or rule["candidate_source_register"] != candidate_source_register
            ):
                continue
            target_location: FrameLocation = (
                str(rule["original_target_register"]),
                (original_source_offset - int(rule["original_delta"])) % 2**32,
                str(rule["candidate_target_register"]),
                (candidate_source_offset - int(rule["candidate_delta"])) % 2**32,
            )
            transfers.append((
                target_location,
                rule["original_output_witness"],
                rule["candidate_output_witness"],
            ))
        return transfers

    transfer_rule_cache: dict[int, list[dict[str, Any]]] = {}
    machine_contracts_by_target = {
        (
            str(item["import"]["dll"]).lower(),
            "symbol" if "symbol" in item["import"] else "ordinal",
            item["import"].get("symbol", item["import"].get("ordinal")),
        ): item
        for item in (machine_import_call_contracts or [])
    }

    def behavior_transfer_rules(source: int) -> list[dict[str, Any]]:
        cached = transfer_rule_cache.get(source)
        if cached is not None:
            return cached
        original = behaviors[source].get("original_ir") or {}
        candidate = behaviors[source].get("candidate_ir") or {}
        rules: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        source_relations: list[dict[str, Any]] = []
        source_pairs: set[tuple[str, str]] = set()
        for family in (
            "inputs", "outputs", "runtime_frame_inputs", "runtime_frame_outputs",
        ):
            for relation in relation_rows[source].get(family, []):
                pair = (str(relation["original"]), str(relation["candidate"]))
                if pair in source_pairs:
                    continue
                source_pairs.add(pair)
                source_relations.append(relation)
        for input_relation in source_relations:
            original_source_register = str(input_relation["original"])
            candidate_source_register = str(input_relation["candidate"])
            for output_relation in relation_rows[source].get("outputs", []):
                original_target_register = str(output_relation["original"])
                candidate_target_register = str(output_relation["candidate"])
                key = (
                    original_source_register, candidate_source_register,
                    original_target_register, candidate_target_register,
                )
                if key in seen:
                    continue
                original_result = _register_offset_witness(
                    (original.get("registers") or {}).get(
                        original_target_register
                    ),
                    original_source_register,
                )
                candidate_result = _register_offset_witness(
                    (candidate.get("registers") or {}).get(
                        candidate_target_register
                    ),
                    candidate_source_register,
                )
                if original_result is None or candidate_result is None:
                    continue
                seen.add(key)
                original_witness, original_delta = original_result
                candidate_witness, candidate_delta = candidate_result
                rules.append({
                    "profile": "return_slot_affine_transfer_rule_v1",
                    "original_source_register": original_source_register,
                    "candidate_source_register": candidate_source_register,
                    "original_target_register": original_target_register,
                    "candidate_target_register": candidate_target_register,
                    "original_output_witness": original_witness,
                    "candidate_output_witness": candidate_witness,
                    "original_delta": original_delta,
                    "candidate_delta": candidate_delta,
                })
        transfer_rule_cache[source] = rules
        return rules

    external_transfer_rule_cache: dict[int, list[dict[str, Any]]] = {}

    def word_offsets_disjoint(left: int, right: int) -> bool:
        return all(
            (left + left_byte) % 2**32 != (right + right_byte) % 2**32
            for left_byte in range(4)
            for right_byte in range(4)
        )

    def write_address_witnesses(
        behavior: dict[str, Any], register: str, frame_offset: int,
    ) -> list[dict[str, Any]] | None:
        witnesses = []
        for write in behavior.get("writes") or []:
            result = _register_offset_witness(write.get("address"), register)
            if result is None:
                return None
            witness, write_offset = result
            if not word_offsets_disjoint(frame_offset, int(write_offset)):
                return None
            witnesses.append(witness)
        return witnesses

    def external_transfer_rules(source: int) -> list[dict[str, Any]]:
        cached = external_transfer_rule_cache.get(source)
        if cached is not None:
            return cached
        original = behaviors[source].get("original_ir") or {}
        candidate = behaviors[source].get("candidate_ir") or {}
        original_outcome = original.get("outcome") or {}
        candidate_outcome = candidate.get("outcome") or {}
        original_identity = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        contract = machine_contracts_by_target.get(original_identity)
        if (
            original_outcome.get("op") != "external_call"
            or candidate_outcome.get("op") != "external_call"
            or original_identity is None
            or original_identity != candidate_identity
            or contract is None
        ):
            external_transfer_rule_cache[source] = []
            return []
        source_relations: list[dict[str, Any]] = []
        source_pairs: set[tuple[str, str]] = set()
        for family in (
            "inputs", "outputs", "runtime_frame_inputs", "runtime_frame_outputs",
        ):
            for relation in relation_rows[source].get(family, []):
                pair = (str(relation["original"]), str(relation["candidate"]))
                if pair in source_pairs:
                    continue
                source_pairs.add(pair)
                source_relations.append(relation)
        preserved = set(str(item) for item in contract["preserved_registers"])
        stack_delta = int(contract["stack_result_delta"])
        rules: list[dict[str, Any]] = []
        seen: set[tuple[str, str, str, str]] = set()
        for input_relation in source_relations:
            original_source_register = str(input_relation["original"])
            candidate_source_register = str(input_relation["candidate"])
            for output_relation in relation_rows[source].get("outputs", []):
                original_target_register = str(output_relation["original"])
                candidate_target_register = str(output_relation["candidate"])
                if (
                    original_target_register == "esp"
                    and candidate_target_register == "esp"
                ):
                    original_environment_delta = stack_delta
                    candidate_environment_delta = stack_delta
                elif (
                    original_target_register in preserved
                    and candidate_target_register in preserved
                ):
                    original_environment_delta = 0
                    candidate_environment_delta = 0
                else:
                    continue
                key = (
                    original_source_register, candidate_source_register,
                    original_target_register, candidate_target_register,
                )
                if key in seen:
                    continue
                original_result = _register_offset_witness(
                    (original.get("registers") or {}).get(
                        original_target_register
                    ),
                    original_source_register,
                )
                candidate_result = _register_offset_witness(
                    (candidate.get("registers") or {}).get(
                        candidate_target_register
                    ),
                    candidate_source_register,
                )
                if original_result is None or candidate_result is None:
                    continue
                seen.add(key)
                original_witness, original_internal_delta = original_result
                candidate_witness, candidate_internal_delta = candidate_result
                rules.append({
                    "profile": "external_return_slot_affine_transfer_rule_v1",
                    "machine_contract_id": int(contract["id"]),
                    "original_source_register": original_source_register,
                    "candidate_source_register": candidate_source_register,
                    "original_target_register": original_target_register,
                    "candidate_target_register": candidate_target_register,
                    "original_output_witness": original_witness,
                    "candidate_output_witness": candidate_witness,
                    "original_internal_delta": int(original_internal_delta),
                    "candidate_internal_delta": int(candidate_internal_delta),
                    "original_environment_delta": original_environment_delta,
                    "candidate_environment_delta": candidate_environment_delta,
                    "original_delta": (
                        int(original_internal_delta) + original_environment_delta
                    ) % 2**32,
                    "candidate_delta": (
                        int(candidate_internal_delta) + candidate_environment_delta
                    ) % 2**32,
                })
        external_transfer_rule_cache[source] = rules
        return rules

    def external_transfer_claims(source: int) -> list[dict[str, Any]]:
        original = behaviors[source].get("original_ir") or {}
        candidate = behaviors[source].get("candidate_ir") or {}
        claims = []
        for source_location in sorted(locations[source]):
            original_source_register, original_source_offset, \
                candidate_source_register, candidate_source_offset = source_location
            original_write_witnesses = write_address_witnesses(
                original, original_source_register, original_source_offset
            )
            candidate_write_witnesses = write_address_witnesses(
                candidate, candidate_source_register, candidate_source_offset
            )
            if (
                original_write_witnesses is None
                or candidate_write_witnesses is None
            ):
                continue
            for rule in external_transfer_rules(source):
                if (
                    rule["original_source_register"] != original_source_register
                    or rule["candidate_source_register"] != candidate_source_register
                ):
                    continue
                internal_location: FrameLocation = (
                    str(rule["original_target_register"]),
                    (
                        original_source_offset
                        - int(rule["original_internal_delta"])
                    ) % 2**32,
                    str(rule["candidate_target_register"]),
                    (
                        candidate_source_offset
                        - int(rule["candidate_internal_delta"])
                    ) % 2**32,
                )
                target_location: FrameLocation = (
                    internal_location[0],
                    (
                        internal_location[1]
                        - int(rule["original_environment_delta"])
                    ) % 2**32,
                    internal_location[2],
                    (
                        internal_location[3]
                        - int(rule["candidate_environment_delta"])
                    ) % 2**32,
                )
                claims.append({
                    "profile": "external_return_slot_transfer_claim_v1",
                    "machine_contract_id": int(rule["machine_contract_id"]),
                    "source": location_payload(source_location),
                    "internal_target": location_payload(internal_location),
                    "target": location_payload(target_location),
                    "internal_rule": {
                        "original_source_register": original_source_register,
                        "candidate_source_register": candidate_source_register,
                        "original_target_register": internal_location[0],
                        "candidate_target_register": internal_location[2],
                        "original_output_witness": rule["original_output_witness"],
                        "candidate_output_witness": rule["candidate_output_witness"],
                        "original_delta": int(rule["original_internal_delta"]),
                        "candidate_delta": int(rule["candidate_internal_delta"]),
                    },
                    "result_rule": {
                        "source": location_payload(internal_location),
                        "target": location_payload(target_location),
                        "original_delta": int(rule["original_environment_delta"]),
                        "candidate_delta": int(rule["candidate_environment_delta"]),
                    },
                    "memory_claim": {
                        "offsets": location_payload(source_location),
                        "original_write_witnesses": original_write_witnesses,
                        "candidate_write_witnesses": candidate_write_witnesses,
                    },
                })
        return claims

    def transfer_witnesses(
        edge: dict[str, Any], source_location: FrameLocation,
    ) -> list[tuple[FrameLocation, dict[str, Any], dict[str, Any]]]:
        has_checked_call_push = (
            edge.get("direct_call_push_claim") is not None
            or edge.get("indirect_call_push_claim") is not None
        )
        if (
            edge["environment_barrier"]
            or edge["requires_call_stack_proof"]
            or (edge["kind"] == "call" and not has_checked_call_push)
            or (edge.get("indirect_target_profile") and not has_checked_call_push)
        ):
            return []
        return behavior_transfer_witnesses(
            int(edge["source_region_index"]), source_location
        )

    def propagate_ordinary_once() -> bool:
        changed = False
        for edge in edges:
            source = int(edge["source_region_index"])
            target = int(edge["target_region_index"])
            if source in overflow_regions or not locations[source]:
                continue
            proposed = {
                target_location
                for source_location in locations[source]
                for target_location, _, _ in transfer_witnesses(
                    edge, source_location
                )
            }
            joined = locations[target] | proposed
            if len(joined) > disjunction_budget:
                if target not in overflow_regions:
                    overflow_regions.add(target)
                    changed = True
                continue
            if joined != locations[target]:
                locations[target] = joined
                changed = True
        return changed

    max_iterations = max(1, len(relation_rows) * (disjunction_budget + 1))
    converged = False
    for iteration in range(max_iterations):
        changed = propagate_ordinary_once()
        if not changed:
            converged = True
            break
    else:
        iteration = max_iterations - 1

    total_iterations = iteration + 1
    call_summary_analysis = _discover_static_call_return_summaries(
        relation_rows, edges
    )
    direct_call_edge_by_source = {
        int(edge["source_region_index"]): edge
        for edge in edges
        if edge.get("direct_call_push_claim") is not None
    }

    def replayable_call_summary(summary: dict[str, Any]) -> dict[str, Any] | None:
        if not summary["closed"] or not summary["return_region_indices"]:
            return None
        callsite = int(summary["callsite_region_index"])
        call_edge = direct_call_edge_by_source.get(callsite)
        if call_edge is None:
            return None
        original = behaviors[callsite].get("original_ir") or {}
        candidate = behaviors[callsite].get("candidate_ir") or {}
        original_call_result = _register_offset_witness(
            (original.get("registers") or {}).get("esp")
        )
        candidate_call_result = _register_offset_witness(
            (candidate.get("registers") or {}).get("esp")
        )
        if original_call_result is None or candidate_call_result is None:
            return None
        original_call_witness, original_call_delta = original_call_result
        candidate_call_witness, candidate_call_delta = candidate_call_result
        summary_deltas: set[tuple[int, int]] = set()
        return_rows = []
        for return_index in summary["return_region_indices"]:
            row = relation_rows[int(return_index)]
            return_claim = row.get("return_pop_claim")
            if return_claim is None:
                return None
            expected = (
                "esp",
                int(return_claim["original_stack_offset"]),
                "esp",
                int(return_claim["candidate_stack_offset"]),
            )
            if expected not in locations[int(return_index)]:
                return None
            delta = (
                (
                    original_call_delta + 4 + int(return_claim["pop_bytes"])
                ) % 2**32,
                (
                    candidate_call_delta + 4 + int(return_claim["pop_bytes"])
                ) % 2**32,
            )
            summary_deltas.add(delta)
            return_rows.append({
                "return_region_index": int(return_index),
                "return_claim": return_claim,
            })
        if len(summary_deltas) != 1:
            return None
        summary_delta = next(iter(summary_deltas))
        return {
            "original_call_witness": original_call_witness,
            "candidate_call_witness": candidate_call_witness,
            "summary_delta": {
                "original": summary_delta[0],
                "candidate": summary_delta[1],
            },
            "returns": return_rows,
        }

    summary_rounds = 0
    max_summary_rounds = max(1, len(direct_call_edge_by_source) + 1)
    while summary_rounds < max_summary_rounds:
        summary_rounds += 1
        summary_changed = False
        for summary in call_summary_analysis["summaries"]:
            if summary["closed"]:
                continuation = int(summary["continuation_region_index"])
                nested_return_targets: set[FrameLocation] = set()
                for return_index_value in summary["return_region_indices"]:
                    return_index = int(return_index_value)
                    return_claim = relation_rows[return_index].get(
                        "return_pop_claim"
                    )
                    if return_claim is None:
                        continue
                    active_location: FrameLocation = (
                        "esp",
                        int(return_claim["original_stack_offset"]),
                        "esp",
                        int(return_claim["candidate_stack_offset"]),
                    )
                    for source_location in locations[return_index]:
                        if source_location == active_location:
                            continue
                        nested_return_targets.update(
                            target_location
                            for target_location, _, _ in
                                behavior_transfer_witnesses(
                                    return_index, source_location
                                )
                        )
                joined_nested = locations[continuation] | nested_return_targets
                if len(joined_nested) > disjunction_budget:
                    overflow_regions.add(continuation)
                elif joined_nested != locations[continuation]:
                    locations[continuation] = joined_nested
                    summary_changed = True
            replay = replayable_call_summary(summary)
            if replay is None:
                continue
            callsite = int(summary["callsite_region_index"])
            continuation = int(summary["continuation_region_index"])
            if callsite in overflow_regions or not locations[callsite]:
                continue
            original_delta = int(replay["summary_delta"]["original"])
            candidate_delta = int(replay["summary_delta"]["candidate"])
            proposed = {
                (
                    "esp",
                    (original_source - original_delta) % 2**32,
                    "esp",
                    (candidate_source - candidate_delta) % 2**32,
                )
                for original_register, original_source,
                    candidate_register, candidate_source in locations[callsite]
                if original_register == "esp" and candidate_register == "esp"
            }
            joined = locations[continuation] | proposed
            if len(joined) > disjunction_budget:
                overflow_regions.add(continuation)
                continue
            if joined != locations[continuation]:
                locations[continuation] = joined
                summary_changed = True
        if not summary_changed:
            break
        for ordinary_iteration in range(max_iterations):
            ordinary_changed = propagate_ordinary_once()
            total_iterations += 1
            if not ordinary_changed:
                break

    call_summary_claim_count = 0
    replayable_call_summaries = 0
    for summary in call_summary_analysis["summaries"]:
        replay = replayable_call_summary(summary)
        summary["return_slot_status"] = "incomplete"
        summary["return_slot_claims"] = []
        if replay is None:
            continue
        callsite = int(summary["callsite_region_index"])
        continuation = int(summary["continuation_region_index"])
        call_edge = direct_call_edge_by_source[callsite]
        claims = []
        for source_location in sorted(locations[callsite]):
            original_register, original_source, candidate_register, \
                candidate_source = source_location
            if original_register != "esp" or candidate_register != "esp":
                continue
            target_location: FrameLocation = (
                "esp",
                (
                    original_source - int(replay["summary_delta"]["original"])
                ) % 2**32,
                "esp",
                (
                    candidate_source - int(replay["summary_delta"]["candidate"])
                ) % 2**32,
            )
            if target_location not in locations[continuation]:
                continue
            for return_row in replay["returns"]:
                return_claim = return_row["return_claim"]
                claims.append({
                    "profile": "return_slot_call_summary_v1",
                    "source": location_payload(source_location),
                    "target": location_payload(target_location),
                    "return_region_index": return_row["return_region_index"],
                    "original_call_witness": replay["original_call_witness"],
                    "candidate_call_witness": replay["candidate_call_witness"],
                    "original_return_slot_witness": return_claim[
                        "original_stack_witness"
                    ],
                    "candidate_return_slot_witness": return_claim[
                        "candidate_stack_witness"
                    ],
                    "original_return_output_witness": return_claim[
                        "original_output_witness"
                    ],
                    "candidate_return_output_witness": return_claim[
                        "candidate_output_witness"
                    ],
                    "pop_bytes": int(return_claim["pop_bytes"]),
                })
        if claims:
            summary["return_slot_status"] = "candidate_requires_lean_replay"
            summary["return_slot_claims"] = claims
            call_edge["return_slot_call_summary_claims"].extend(claims)
            call_summary_claim_count += len(claims)
            replayable_call_summaries += 1

    transfer_claim_count = 0
    frame_transfer_claim_count = 0
    transfer_rule_count = 0
    external_transfer_rule_count = 0
    external_transfer_claim_count = 0
    for edge in edges:
        source = int(edge["source_region_index"])
        has_checked_call_push = (
            edge.get("direct_call_push_claim") is not None
            or edge.get("indirect_call_push_claim") is not None
        )
        edge["return_slot_transfer_rules"] = (
            behavior_transfer_rules(source)
            if not edge["environment_barrier"]
            and not edge["requires_call_stack_proof"]
            and (edge["kind"] != "call" or has_checked_call_push)
            and (not edge.get("indirect_target_profile") or has_checked_call_push)
            else []
        )
        edge["return_slot_external_transfer_rules"] = (
            external_transfer_rules(source)
            if edge["environment_barrier"] else []
        )
        edge["return_slot_external_transfer_claims"] = (
            external_transfer_claims(source)
            if edge["environment_barrier"] else []
        )
        transfer_rule_count += len(edge["return_slot_transfer_rules"])
        external_transfer_rule_count += len(
            edge["return_slot_external_transfer_rules"]
        )
        external_transfer_claim_count += len(
            edge["return_slot_external_transfer_claims"]
        )
        claims = []
        frame_claims = []
        original = behaviors[source].get("original_ir") or {}
        candidate = behaviors[source].get("candidate_ir") or {}
        for source_location in sorted(locations[source]):
            original_write_witnesses = write_address_witnesses(
                original, source_location[0], source_location[1]
            )
            candidate_write_witnesses = write_address_witnesses(
                candidate, source_location[2], source_location[3]
            )
            for target_location, original_witness, candidate_witness in \
                    transfer_witnesses(edge, source_location):
                transfer_claim = {
                    "profile": "return_slot_affine_transfer_v2",
                    "source": location_payload(source_location),
                    "target": location_payload(target_location),
                    "original_output_witness": original_witness,
                    "candidate_output_witness": candidate_witness,
                }
                claims.append(transfer_claim)
                if (
                    original_write_witnesses is not None
                    and candidate_write_witnesses is not None
                ):
                    frame_claims.append({
                        "profile": "return_slot_frame_transfer_v1",
                        "transfer": transfer_claim,
                        "memory": {
                            "offsets": location_payload(source_location),
                            "original_write_witnesses": original_write_witnesses,
                            "candidate_write_witnesses": candidate_write_witnesses,
                        },
                    })
        edge["return_slot_transfer_claims"] = claims
        edge["return_slot_frame_transfer_claims"] = frame_claims
        transfer_claim_count += len(claims)
        frame_transfer_claim_count += len(frame_claims)

    return_transfer_claim_count = 0
    return_transfer_rule_count = 0
    for region_index, row in enumerate(relation_rows):
        row["return_slot_return_transfer_claims"] = []
        row["return_slot_return_transfer_rules"] = []
        if row.get("return_pop_claim") is None:
            continue
        row["return_slot_return_transfer_rules"] = behavior_transfer_rules(
            region_index
        )
        return_transfer_rule_count += len(
            row["return_slot_return_transfer_rules"]
        )
        claims = []
        for source_location in sorted(locations[region_index]):
            for target_location, original_witness, candidate_witness in \
                    behavior_transfer_witnesses(region_index, source_location):
                claims.append({
                    "profile": "return_slot_return_affine_transfer_v1",
                    "source": location_payload(source_location),
                    "target": location_payload(target_location),
                    "original_output_witness": original_witness,
                    "candidate_output_witness": candidate_witness,
                })
        row["return_slot_return_transfer_claims"] = claims
        return_transfer_claim_count += len(claims)

    local_transfer_rule_count = 0
    for region_index, row in enumerate(relation_rows):
        row["return_slot_local_transfer_rules"] = behavior_transfer_rules(
            region_index
        )
        local_transfer_rule_count += len(
            row["return_slot_local_transfer_rules"]
        )

    aligned_returns = 0
    partially_aligned_returns = 0
    for region_index, row in enumerate(relation_rows):
        row["return_slot_offsets"] = [
            location_payload(location)
            for location in sorted(locations[region_index])
        ]
        row["return_pop_frame_claims"] = []
        row["return_slot_status"] = (
            "incomplete_disjunction_budget"
            if region_index in overflow_regions
            else "not_a_return"
        )
        return_claim = row.get("return_pop_claim")
        if return_claim is None:
            if row.get("is_return") and region_index not in overflow_regions:
                row["return_slot_status"] = "incomplete_return_pop"
            continue
        expected = (
            "esp",
            int(return_claim["original_stack_offset"]),
            "esp",
            int(return_claim["candidate_stack_offset"]),
        )
        if expected in locations[region_index]:
            row["return_pop_frame_claims"] = [{
                "profile": "return_pop_runtime_frame_v1",
                "offsets": location_payload(expected),
                "original_slot_witness": return_claim["original_stack_witness"],
                "candidate_slot_witness": return_claim["candidate_stack_witness"],
            }]
        if not locations[region_index]:
            row["return_slot_status"] = "incomplete_no_checked_call_path"
        elif locations[region_index] == {expected}:
            row["return_slot_status"] = "satisfied"
            aligned_returns += 1
        elif expected in locations[region_index]:
            row["return_slot_status"] = "incomplete_ambiguous_path_offsets"
            partially_aligned_returns += 1
        else:
            row["return_slot_status"] = "incomplete_slot_offset_mismatch"

    stack_window_return_summaries = 0
    for summary in call_summary_analysis["summaries"]:
        return_deltas = {
            4 + int(relation_rows[int(return_index)]["return_pop_claim"]["pop_bytes"])
            for return_index in summary["return_region_indices"]
            if relation_rows[int(return_index)].get("return_slot_status") == "satisfied"
            and relation_rows[int(return_index)].get("return_pop_claim") is not None
        }
        all_returns_checked = (
            bool(summary["return_region_indices"])
            and all(
                relation_rows[int(return_index)].get("return_slot_status") == "satisfied"
                for return_index in summary["return_region_indices"]
            )
        )
        summary["stack_window_return_status"] = "incomplete"
        summary["stack_window_return_delta"] = None
        if summary["closed"] and all_returns_checked and len(return_deltas) == 1:
            summary["stack_window_return_status"] = (
                "candidate_requires_local_lean_replay"
            )
            summary["stack_window_return_delta"] = next(iter(return_deltas))
            stack_window_return_summaries += 1

    return {
        "profile": "bounded_return_slot_dataflow_v1",
        "status": "proposal_requires_generated_lean_replay",
        "disjunction_budget": disjunction_budget,
        "converged": converged,
        "iterations": total_iterations,
        "seed_edges": seed_edges,
        "transfer_claims": transfer_claim_count,
        "frame_transfer_claims": frame_transfer_claim_count,
        "transfer_rules": transfer_rule_count,
        "external_transfer_rules": external_transfer_rule_count,
        "external_transfer_claims": external_transfer_claim_count,
        "return_transfer_claims": return_transfer_claim_count,
        "return_transfer_rules": return_transfer_rule_count,
        "local_transfer_rules": local_transfer_rule_count,
        "regions_with_offsets": sum(bool(items) for items in locations),
        "overflow_regions": sorted(overflow_regions),
        "aligned_returns": aligned_returns,
        "partially_aligned_returns": partially_aligned_returns,
        "call_summary_rounds": summary_rounds,
        "replayable_call_summaries": replayable_call_summaries,
        "call_summary_claims": call_summary_claim_count,
        "stack_window_return_summaries": stack_window_return_summaries,
        "call_summary_analysis": call_summary_analysis,
        "trust": {
            "role": "analysis_and_certificate_proposal_only",
            "acceptance_rule": (
                "Lean must reconstruct every affine register expression and prove each seed, "
                "transfer, and return-slot use against decoded behavior"
            ),
        },
    }
