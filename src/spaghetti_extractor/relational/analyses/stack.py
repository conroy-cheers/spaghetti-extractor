from __future__ import annotations

import json
from collections import Counter, defaultdict, deque
from typing import Any

from ...stage_binary import StageABinary
from ..extraction import _semantic_memory_reads
from ..model import _stack_window_transfer_claims
from .external import _register_offset_witness, _semantic_external_target_identity


REGISTER_NAMES = frozenset({
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
})


def _stack_read32_adjustment(
    expression: object,
) -> tuple[str, str, int, dict[str, Any]] | None:
    if not isinstance(expression, dict) or expression.get("op") != "read32":
        return None
    address = expression.get("address")
    if not isinstance(address, dict):
        return None
    if address.get("op") == "input_reg":
        register = address.get("reg")
        if isinstance(register, str):
            return register, "identity", 0, address
        return None
    operation = address.get("op")
    if operation not in {"add", "sub"}:
        return None
    register = address.get("left")
    constant = address.get("right")
    if operation == "add" and isinstance(register, dict) and register.get(
        "op"
    ) == "constant":
        register, constant = constant, register
    if (
        not isinstance(register, dict)
        or register.get("op") != "input_reg"
        or not isinstance(register.get("reg"), str)
        or not isinstance(constant, dict)
        or constant.get("op") != "constant"
    ):
        return None
    value = constant.get("value")
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**32:
        return None
    if operation == "sub":
        return str(register["reg"]), "subtract", value, address
    if value < 2**31:
        return str(register["reg"]), "add", value, address
    return str(register["reg"]), "subtract", 2**32 - value, address


def _stack_bound_window_matches(
    window: dict[str, Any],
    original: tuple[str, str, int, dict[str, Any]],
    candidate: tuple[str, str, int, dict[str, Any]],
) -> bool:
    if (
        original[1:3] != candidate[1:3]
        or window.get("original_register") != original[0]
        or window.get("candidate_register") != candidate[0]
    ):
        return False
    kind, amount = original[1], original[2]
    above = int(window.get("bytes_above", -1))
    below = int(window.get("bytes_below", -1))
    if kind == "identity":
        return 4 <= above
    if kind == "add":
        return amount % 4 == 0 and amount + 4 <= above
    return 4 <= amount and amount % 4 == 0 and amount <= below


def _attach_checked_stack_index_bounds(
    regions: list[dict[str, Any]], behaviors: list[dict[str, Any]],
) -> dict[str, Any]:
    accepted: list[dict[str, Any]] = []
    rejected: list[dict[str, Any]] = []
    for region_index, region in enumerate(regions):
        behavior_pair = behaviors[region_index] if region_index < len(behaviors) else {}
        region["stack_index_bound_claims"] = []
        requests = [
            (bound_index, bound, bound.get("stack_bound_request"))
            for bound_index, bound in enumerate(region.get("bounds", []))
            if isinstance(bound, dict)
            and isinstance(bound.get("stack_bound_request"), dict)
        ]
        request_keys = Counter(
            json.dumps(request, sort_keys=True, separators=(",", ":"))
            for _, _, request in requests
        )
        for bound_index, bound, request in requests:
            assert isinstance(request, dict)

            def reject(reason: str) -> None:
                bound.pop("original_expression", None)
                bound.pop("candidate_expression", None)
                bound.pop("expression_source", None)
                bound.pop("stack_bound_predicate", None)
                rejected.append({
                    "region_index": region_index,
                    "bound_index": bound_index,
                    "reason": reason,
                })

            request_key = json.dumps(
                request, sort_keys=True, separators=(",", ":")
            )
            if request_keys[request_key] != 1:
                reject("ambiguous_stack_bound_request")
                continue
            original_expression = request.get("original_expression")
            candidate_expression = request.get("candidate_expression")
            original = _stack_read32_adjustment(original_expression)
            candidate = _stack_read32_adjustment(candidate_expression)
            if original is None or candidate is None or original[1:3] != candidate[1:3]:
                reject("stack_read32_shape_mismatch")
                continue
            original_behavior = behavior_pair.get("original_ir")
            candidate_behavior = behavior_pair.get("candidate_ir")
            if not isinstance(original_behavior, dict) or not isinstance(
                candidate_behavior, dict
            ):
                reject("decoded_behavior_missing")
                continue
            if original_behavior.get("writes") != [] or candidate_behavior.get(
                "writes"
            ) != []:
                reject("decoded_write_clobber")
                continue
            original_register = bound.get("original")
            candidate_register = bound.get("candidate")
            if (
                not isinstance(original_register, str)
                or not isinstance(candidate_register, str)
                or (original_behavior.get("registers") or {}).get(original_register)
                != original_expression
                or (candidate_behavior.get("registers") or {}).get(candidate_register)
                != candidate_expression
            ):
                reject("decoded_register_load_mismatch")
                continue
            matches = [
                window
                for window in region.get("stack_windows", [])
                if isinstance(window, dict)
                and _stack_bound_window_matches(window, original, candidate)
            ]
            if len(matches) != 1:
                reject(
                    "stack_window_missing"
                    if not matches
                    else "stack_window_ambiguous"
                )
                continue
            upper = bound.get("unsigned_lt")
            if (
                not isinstance(upper, int)
                or isinstance(upper, bool)
                or not 0 < upper < 2**32
            ):
                reject("runtime_upper_bound_invalid")
                continue
            predicate = {
                "original": {
                    "op": "unsigned_less",
                    "left": original_expression,
                    "right": {"op": "constant", "value": upper},
                },
                "candidate": {
                    "op": "unsigned_less",
                    "left": candidate_expression,
                    "right": {"op": "constant", "value": upper},
                },
                "exact_memory_reads": [{
                    "original_address": original[3],
                    "candidate_address": candidate[3],
                    "bytes": 4,
                }],
                "source": "checked_stack_register_bound_v1",
            }
            predicates = region.setdefault("state_predicates", [])
            if predicate not in predicates:
                predicates.append(predicate)
            adjustment = {"kind": original[1], "amount": original[2]}
            claim = {
                "profile": "checked_stack_register_bound_v1",
                "original_register": original_register,
                "candidate_register": candidate_register,
                "upper_exclusive": upper,
                "original_index_expression": original_expression,
                "candidate_index_expression": candidate_expression,
                "window": matches[0],
                "adjustment": adjustment,
                "predicate": predicate,
            }
            region["stack_index_bound_claims"].append(claim)
            bound["original_expression"] = original_expression
            bound["candidate_expression"] = candidate_expression
            bound["expression_source"] = "checked_stack_register_bound_v1"
            bound["stack_bound_predicate"] = predicate
            accepted.append({
                "region_index": region_index,
                "bound_index": bound_index,
                "adjustment": adjustment,
            })
    return {
        "format": "stage-a-checked-stack-register-bounds-v1",
        "status": "proposal_requires_generated_lean_replay",
        "acceptance_authority": False,
        "accepted_count": len(accepted),
        "rejected_count": len(rejected),
        "accepted": accepted,
        "rejected": rejected,
    }


def _discover_direct_call_stack_return_summaries(
    regions: list[dict[str, Any]],
    behaviors: list[dict[str, Any]],
    relation_rows: list[dict[str, Any]],
    edges: list[dict[str, Any]],
    *,
    additional_entries: tuple[int, ...] = (),
) -> dict[str, Any]:
    """Propose reusable affine-return summaries from closed decoded paths.

    Direct-call destinations are discovered from the edge inventory. Other
    machine entry surfaces, such as loader callbacks, may request the same
    checked summary through ``additional_entries`` without manufacturing a
    synthetic call edge.
    """
    region_count = len(regions)
    outgoing: dict[int, list[dict[str, Any]]] = defaultdict(list)
    direct_edges_by_source: dict[int, list[dict[str, Any]]] = defaultdict(list)
    for edge in edges:
        source = int(edge.get("source_region_index", -1))
        if not 0 <= source < region_count:
            continue
        outgoing[source].append(edge)
        if isinstance(edge.get("direct_call_push_claim"), dict):
            direct_edges_by_source[source].append(edge)
    for source_edges in outgoing.values():
        source_edges.sort(key=lambda edge: (
            int(edge.get("target_region_index", -1)), str(edge.get("kind", "")),
        ))

    target_id_by_region = {
        index: int(region.get("numeric_id", index))
        for index, region in enumerate(regions)
    }

    def affine_esp_offset(expression: Any) -> int | None:
        if not isinstance(expression, dict):
            return None
        if expression.get("op") == "input_reg":
            return 0 if expression.get("reg") == "esp" else None
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
        prior = affine_esp_offset(left)
        if prior is None:
            return None
        result = (prior + value if operation == "add" else prior - value) % 2**32
        return result if result < 2**31 else result - 2**32

    def paired_behavior_stack_delta(
        behavior_pair: dict[str, Any],
    ) -> int | None:
        original = behavior_pair.get("original_ir") or {}
        candidate = behavior_pair.get("candidate_ir") or {}
        original_delta = affine_esp_offset(
            (original.get("registers") or {}).get("esp")
        )
        candidate_delta = affine_esp_offset(
            (candidate.get("registers") or {}).get("esp")
        )
        if original_delta is None or original_delta != candidate_delta:
            return None
        return original_delta

    def stack_access_window(
        behavior_pair: dict[str, Any],
        *,
        call_push_checked: bool,
        relation_preservation_checked: bool,
        return_claim: dict[str, Any] | None,
    ) -> tuple[int, int] | None:
        original = behavior_pair.get("original_ir") or {}
        candidate = behavior_pair.get("candidate_ir") or {}
        original_writes = original.get("writes") or []
        candidate_writes = candidate.get("writes") or []
        if len(original_writes) != len(candidate_writes):
            return None
        if original_writes and not (
            call_push_checked
            or relation_preservation_checked
            or (
                isinstance(return_claim, dict)
                and return_claim.get("profile")
                    == "esp_relative_return_after_static_writes_v1"
            )
        ):
            return None

        low = 0
        high = 0
        static_return_writes = (
            isinstance(return_claim, dict)
            and return_claim.get("profile")
                == "esp_relative_return_after_static_writes_v1"
        )
        for original_write, candidate_write in zip(
            original_writes, candidate_writes, strict=True
        ):
            original_offset = affine_esp_offset(original_write.get("address"))
            candidate_offset = affine_esp_offset(candidate_write.get("address"))
            if original_offset is None or candidate_offset is None:
                if static_return_writes:
                    continue
                return None
            if original_offset != candidate_offset:
                return None
            low = min(low, original_offset)
            high = max(high, original_offset + 4)

        def read_footprint(behavior: dict[str, Any]) -> Counter[tuple[int, int]]:
            result: Counter[tuple[int, int]] = Counter()
            for read in _semantic_memory_reads(behavior):
                width = read.get("width")
                offset = affine_esp_offset(read.get("address"))
                if isinstance(width, int) and width > 0 and offset is not None:
                    result[(offset, width)] += 1
            return result

        original_reads = read_footprint(original)
        candidate_reads = read_footprint(candidate)
        if original_reads != candidate_reads:
            return None
        for (offset, width), _ in original_reads.items():
            low = min(low, offset)
            high = max(high, offset + width)
        return low, high

    def decoded_ordinary_targets(
        behavior_pair: dict[str, Any],
    ) -> set[int] | None:
        original = (behavior_pair.get("original_ir") or {}).get("outcome") or {}
        candidate = (behavior_pair.get("candidate_ir") or {}).get("outcome") or {}
        if original.get("op") != candidate.get("op"):
            return None
        operation = original.get("op")
        fields = {
            "jump": ("target",),
            "branch": ("taken", "fallthrough"),
            "checked_continue": ("continuation",),
        }.get(str(operation))
        if fields is None:
            return None
        original_targets = {int(original[field]) for field in fields}
        candidate_targets = {int(candidate[field]) for field in fields}
        return original_targets if original_targets == candidate_targets else None

    def decoded_direct_call(
        source: int, edge: dict[str, Any],
    ) -> tuple[int, int] | None:
        if not 0 <= source < len(behaviors):
            return None
        target = int(edge.get("target_region_index", -1))
        claim = edge.get("direct_call_push_claim")
        if not isinstance(claim, dict) or not 0 <= target < region_count:
            return None
        continuation = int(claim.get("continuation_region_index", -1))
        if not 0 <= continuation < region_count:
            return None
        original = (behaviors[source].get("original_ir") or {}).get("outcome") or {}
        candidate = (behaviors[source].get("candidate_ir") or {}).get("outcome") or {}
        expected_target = target_id_by_region[target]
        expected_continuation = target_id_by_region[continuation]
        if (
            original.get("op") != "call"
            or candidate.get("op") != "call"
            or int(original.get("target", -1)) != expected_target
            or int(candidate.get("target", -1)) != expected_target
            or int(original.get("continuation", -1)) != expected_continuation
            or int(candidate.get("continuation", -1)) != expected_continuation
            or paired_behavior_stack_delta(behaviors[source]) is None
        ):
            return None
        return target, continuation

    complete_entries: dict[int, dict[str, Any]] = {}
    entry_blockers: dict[int, str] = {}

    def analyze_entry(entry: int) -> tuple[dict[str, Any] | None, str]:
        if not (
            0 <= entry < region_count
            and len(behaviors) == region_count
            and len(relation_rows) == region_count
        ):
            return None, "callee_region_inventory_incomplete"
        offsets = {entry: 0}
        pending = [entry]
        reachable: set[int] = set()
        adjacency: dict[int, set[int]] = defaultdict(set)
        returns: list[tuple[int, int]] = []
        window_low = 0
        window_high = 0

        while pending:
            source = pending.pop()
            if source in reachable:
                continue
            reachable.add(source)
            behavior_pair = behaviors[source]
            stack_delta = paired_behavior_stack_delta(behavior_pair)
            if stack_delta is None:
                return None, "non_affine_or_unpaired_esp_transfer"
            source_offset = offsets[source]
            source_edges = outgoing.get(source, [])
            relation_row = relation_rows[source]
            return_claim = relation_row.get("return_pop_claim")
            if relation_row.get("is_return"):
                original_outcome = (
                    behavior_pair.get("original_ir") or {}
                ).get("outcome") or {}
                candidate_outcome = (
                    behavior_pair.get("candidate_ir") or {}
                ).get("outcome") or {}
                if (
                    source_edges
                    or not isinstance(return_claim, dict)
                    or original_outcome.get("op") != "returned"
                    or candidate_outcome.get("op") != "returned"
                    or source_offset + int(
                        return_claim.get("original_stack_offset", 2**32)
                    ) != 0
                    or source_offset + int(
                        return_claim.get("candidate_stack_offset", 2**32)
                    ) != 0
                ):
                    return None, "return_slot_restoration_unproved"
                local_window = stack_access_window(
                    behavior_pair,
                    call_push_checked=False,
                    relation_preservation_checked=False,
                    return_claim=return_claim,
                )
                if local_window is None:
                    return None, "return_memory_preservation_unproved"
                window_low = min(window_low, source_offset + local_window[0])
                window_high = max(window_high, source_offset + local_window[1])
                returns.append((source, source_offset + stack_delta))
                continue

            if not source_edges:
                return None, "reachable_non_return_terminal"

            direct_edges = [
                edge for edge in source_edges
                if isinstance(edge.get("direct_call_push_claim"), dict)
            ]
            if direct_edges:
                if len(source_edges) != 1 or len(direct_edges) != 1:
                    return None, "ambiguous_nested_call_edge"
                edge = direct_edges[0]
                decoded = decoded_direct_call(source, edge)
                if decoded is None:
                    return None, "nested_call_decode_mismatch"
                nested_entry, continuation = decoded
                nested_summary = complete_entries.get(nested_entry)
                if nested_summary is None:
                    return None, "nested_call_return_summary_incomplete"
                local_window = stack_access_window(
                    behavior_pair,
                    call_push_checked=True,
                    relation_preservation_checked=False,
                    return_claim=None,
                )
                if local_window is None:
                    return None, "nested_call_memory_preservation_unproved"
                nested_offset = source_offset + stack_delta
                window_low = min(
                    window_low,
                    source_offset + local_window[0],
                    nested_offset - int(nested_summary["bytes_below"]),
                )
                window_high = max(
                    window_high,
                    source_offset + local_window[1],
                    nested_offset + int(nested_summary["bytes_above"]),
                )
                target = continuation
                target_offset = nested_offset + int(nested_summary["return_delta"])
                next_rows = [(target, target_offset)]
            else:
                if any(
                    edge.get("environment_barrier")
                    or edge.get("requires_call_stack_proof")
                    or edge.get("indirect_target_profile")
                    or edge.get("kind") == "call"
                    for edge in source_edges
                ):
                    return None, "unsupported_reachable_exit"
                decoded_targets = decoded_ordinary_targets(behavior_pair)
                edge_target_ids = {
                    target_id_by_region.get(
                        int(edge.get("target_region_index", -1)), -1
                    )
                    for edge in source_edges
                }
                if decoded_targets is None or edge_target_ids != decoded_targets:
                    return None, "ordinary_successor_decode_mismatch"
                relation_preservation_checked = all(
                    edge.get("relation_preservation_proposed") is True
                    for edge in source_edges
                )
                local_window = stack_access_window(
                    behavior_pair,
                    call_push_checked=False,
                    relation_preservation_checked=relation_preservation_checked,
                    return_claim=None,
                )
                if local_window is None:
                    return None, "paired_memory_preservation_unproved"
                window_low = min(window_low, source_offset + local_window[0])
                window_high = max(window_high, source_offset + local_window[1])
                next_rows = [
                    (int(edge["target_region_index"]), source_offset + stack_delta)
                    for edge in source_edges
                ]

            for target, target_offset in next_rows:
                if not 0 <= target < region_count:
                    return None, "successor_region_missing"
                if not -(2**31) < target_offset < 2**31:
                    return None, "stack_offset_range_ambiguous"
                prior = offsets.get(target)
                if prior is not None and prior != target_offset:
                    return None, "ambiguous_path_esp_offset"
                adjacency[source].add(target)
                if prior is None:
                    offsets[target] = target_offset
                    pending.append(target)

        if not returns:
            return None, "no_reachable_return"
        reverse: dict[int, set[int]] = defaultdict(set)
        for source, targets in adjacency.items():
            for target in targets:
                reverse[target].add(source)
        reaches_return = {source for source, _ in returns}
        pending = list(reaches_return)
        while pending:
            target = pending.pop()
            for source in reverse.get(target, set()):
                if source not in reaches_return:
                    reaches_return.add(source)
                    pending.append(source)
        if reaches_return != reachable:
            return None, "reachable_path_without_return"
        if not (
            -(2**31) < window_low <= 0
            and 0 <= window_high < 2**31
        ):
            return None, "stack_window_range_ambiguous"

        return_deltas = {delta for _, delta in returns}
        if len(return_deltas) != 1:
            return None, "ambiguous_return_esp_restoration"
        return_delta = next(iter(return_deltas))
        if not 4 <= return_delta <= 4 + 65535:
            return None, "return_esp_restoration_out_of_range"
        return {
            "return_delta": return_delta,
            "return_region_indices": sorted(source for source, _ in returns),
            "reachable_region_indices": sorted(reachable),
            "bytes_below": max(-window_low, 0),
            "bytes_above": max(window_high, 1),
        }, ""

    callee_entries = sorted({
        int(edge.get("target_region_index", -1))
        for source_edges in direct_edges_by_source.values()
        for edge in source_edges
        if 0 <= int(edge.get("target_region_index", -1)) < region_count
    } | {
        int(entry) for entry in additional_entries
        if 0 <= int(entry) < region_count
    })
    rounds = 0
    for _ in range(len(callee_entries) + 1):
        rounds += 1
        changed = False
        for entry in callee_entries:
            if entry in complete_entries:
                continue
            summary, blocker = analyze_entry(entry)
            entry_blockers[entry] = blocker
            if summary is not None:
                complete_entries[entry] = summary
                changed = True
        if not changed:
            break

    summaries = []
    for source, source_edges in sorted(direct_edges_by_source.items()):
        if len(source_edges) != 1:
            summaries.append({
                "callsite_region_index": source,
                "status": "incomplete",
                "blocker": "ambiguous_direct_call_edge",
            })
            continue
        edge = source_edges[0]
        decoded = decoded_direct_call(source, edge)
        if decoded is None:
            summaries.append({
                "callsite_region_index": source,
                "status": "incomplete",
                "blocker": "direct_call_decode_mismatch",
            })
            continue
        callee, continuation = decoded
        entry_summary = complete_entries.get(callee)
        if entry_summary is None:
            summaries.append({
                "callsite_region_index": source,
                "callee_region_index": callee,
                "continuation_region_index": continuation,
                "status": "incomplete",
                "blocker": entry_blockers.get(
                    callee, "callee_return_summary_incomplete"
                ),
            })
            continue
        summaries.append({
            "profile": "decoded_affine_stack_return_summary_v1",
            "callsite_region_index": source,
            "callee_region_index": callee,
            "continuation_region_index": continuation,
            "status": "candidate_requires_local_lean_replay",
            **entry_summary,
            "blocker": None,
        })
    return {
        "profile": "decoded_affine_stack_return_summary_v1",
        "rounds": rounds,
        "complete_callee_entries": len(complete_entries),
        "entry_summaries": [
            {"entry_region_index": entry, **summary}
            for entry, summary in sorted(complete_entries.items())
        ],
        "entry_blockers": [
            {"entry_region_index": entry, "blocker": blocker}
            for entry, blocker in sorted(entry_blockers.items())
            if entry not in complete_entries
        ],
        "complete_summaries": sum(
            summary.get("status") == "candidate_requires_local_lean_replay"
            for summary in summaries
        ),
        "summaries": summaries,
    }



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
    adjacency: dict[tuple[int, str, str], list[tuple[tuple[int, str, str], int]]],
    roots: set[tuple[int, str, str]],
) -> set[tuple[int, str, str]]:
    """Find reachable SCCs whose edge weights cannot have one node potential."""
    reachable: set[tuple[int, str, str]] = set()
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

    order: list[tuple[int, str, str]] = []
    visited: set[tuple[int, str, str]] = set()
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

    reverse: dict[tuple[int, str, str], list[tuple[int, str, str]]] = defaultdict(list)
    for source in reachable:
        for target, _ in adjacency.get(source, []):
            if target in reachable:
                reverse[target].append(source)

    result: set[tuple[int, str, str]] = set()
    assigned: set[tuple[int, str, str]] = set()
    for start in reversed(order):
        if start in assigned:
            continue
        component: set[tuple[int, str, str]] = set()
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
    tls_callback_target_ids = [
        int(target_id)
        for target_id in (refined.get("launch") or {}).get(
            "tls_callback_target_ids", []
        )
    ]
    # pe32-console-launch-v2 materializes a return address followed by the
    # three machine-level TLS callback arguments.  Exact-word preservation
    # checks may need any of those words even when an earlier local analysis
    # only requested the frame base itself.
    tls_launch_frame_span = 16 if tls_callback_target_ids else 4
    image_separation_span = 16 if tls_callback_target_ids else 1

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
            original_register not in REGISTER_NAMES
            or candidate_register not in REGISTER_NAMES
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
        for relation in region.get("input_dynamic_stack_range_relations", []):
            window = relation.get("window") or {}
            add_requirement(
                region_index,
                str(window.get("original_register")),
                str(window.get("candidate_register")),
                int(window.get("bytes_above", 0)),
                "declared_dynamic_stack_range_seed",
                int(window.get("bytes_below", 0)),
            )
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
                max(
                    prior_above,
                    original_offset + image_separation_span,
                    candidate_offset + image_separation_span,
                ),
            )
            seed_sources.setdefault(key, set()).add(
                "tls_launch_frame_address_separation_seed"
                if tls_callback_target_ids else "address_separation_seed"
            )

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
            original_window = access_window(
                int(location["original"]), tls_launch_frame_span
            )
            candidate_window = access_window(
                int(location["candidate"]), tls_launch_frame_span
            )
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
        output_pairs = [
            (str(pair["original"]), str(pair["candidate"]))
            for pair in region.get("outputs", [])
        ]
        original_output_counts = Counter(pair[0] for pair in output_pairs)
        candidate_output_counts = Counter(pair[1] for pair in output_pairs)
        output_register_map = {
            original_register: candidate_register
            for original_register, candidate_register in output_pairs
            if original_output_counts[original_register] == 1
            and candidate_output_counts[candidate_register] == 1
        }

        # A related input register that is advanced by the same aligned amount
        # on both sides can be represented by a checked paired stack range.
        # Seed the source range here; backward propagation then sizes the range
        # across ordinary edges and checked call/return continuations.  This is
        # proposal logic only: Lean rechecks range membership, affine syntax,
        # non-wrap, alignment, and the resulting related-word claim.
        original_registers = behavior["original_ir"].get("registers") or {}
        candidate_registers = behavior["candidate_ir"].get("registers") or {}
        for output_relation in relation_row.get("outputs", []):
            original_output = str(output_relation.get("original"))
            candidate_output = str(output_relation.get("candidate"))
            architectural_stack_pointer = (
                original_output == "esp" and candidate_output == "esp"
            )
            if (
                output_relation.get("relation") != "related_word"
                and not architectural_stack_pointer
            ):
                continue
            affine_sources: list[tuple[str, str, int]] = []
            for input_relation in relation_row.get("inputs", []):
                if (
                    input_relation.get("relation") != "related_word"
                    and not architectural_stack_pointer
                ):
                    continue
                original_input = str(input_relation.get("original"))
                candidate_input = str(input_relation.get("candidate"))
                original_delta = stack_delta(
                    original_registers.get(original_output), original_input
                )
                candidate_delta = stack_delta(
                    candidate_registers.get(candidate_output), candidate_input
                )
                if (
                    original_delta is not None
                    and original_delta == candidate_delta
                    and original_delta != 0
                    and original_delta % 4 == 0
                ):
                    affine_sources.append(
                        (original_input, candidate_input, original_delta)
                    )
            if len(affine_sources) != 1:
                continue
            original_input, candidate_input, delta = affine_sources[0]
            if delta > 0:
                add_requirement(
                    region_index,
                    original_input,
                    candidate_input,
                    delta + 1,
                    "related_word_affine_output_seed",
                )
            else:
                add_requirement(
                    region_index,
                    original_input,
                    candidate_input,
                    1,
                    "related_word_affine_output_seed",
                    -delta,
                )

        def paired_access_is_dynamic(
            original_address: Any, candidate_address: Any, width: int,
        ) -> bool:
            original_affine = register_offset(original_address)
            candidate_affine = register_offset(candidate_address)
            if original_affine is None or candidate_affine is None or width <= 0:
                return False
            for relation in region.get("input_dynamic_range_relations", []):
                if (
                    original_affine[0] != str(relation.get("original"))
                    or candidate_affine[0] != str(relation.get("candidate"))
                ):
                    continue
                original_offset = (
                    int(relation.get("original_offset", 0)) + original_affine[1]
                )
                candidate_offset = (
                    int(relation.get("candidate_offset", 0)) + candidate_affine[1]
                )
                if original_offset != candidate_offset:
                    continue
                if any(
                    int(word.get("offset", -1)) <= original_offset
                    and original_offset + width <= int(word.get("offset", -1)) + 4
                    for word in relation.get("required_words", [])
                ):
                    return True
            return False

        def candidate_read_path(path: tuple[str, ...]) -> tuple[str, ...]:
            if len(path) >= 2 and path[0] == "registers":
                return (
                    path[0], output_register_map.get(path[1], path[1]), *path[2:]
                )
            return path

        for path in sorted(original_reads):
            original_read = original_reads[path]
            candidate_read = candidate_reads.get(candidate_read_path(path))
            if candidate_read is None:
                continue
            width = original_read.get("width")
            if not isinstance(width, int) or width != candidate_read.get("width"):
                continue
            if paired_access_is_dynamic(
                original_read.get("address"), candidate_read.get("address"), width,
            ):
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
                if paired_access_is_dynamic(
                    original_write.get("address"), candidate_write.get("address"), 4,
                ):
                    continue
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
    tls_callback_region_indices = tuple(
        region_index_by_target_id[target_id]
        for target_id in tls_callback_target_ids
        if target_id in region_index_by_target_id
    )
    checked_call_continuations: dict[int, list[dict[str, Any]]] = defaultdict(list)
    checked_call_edges_by_source = {
        int(edge["source_region_index"]): edge
        for edge in register_relations.get("edges", [])
        if (
            edge.get("direct_call_push_claim") is not None
            or (
                edge.get("indirect_call_push_claim") is not None
                and edge.get("indirect_target_profile") in {
                    "immutable_relocated_function_pointer_call_v1",
                    "fixed_static_function_pointer_call_v1",
                    "inductive_fixed_code_pointer_register_call_v1",
                }
            )
        )
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
    direct_call_return_summary_analysis = (
        _discover_direct_call_stack_return_summaries(
            regions,
            behaviors,
            relation_rows,
            register_relations.get("edges", []),
            additional_entries=tls_callback_region_indices,
        )
    )
    direct_call_return_summary_by_source = {
        int(summary["callsite_region_index"]): summary
        for summary in direct_call_return_summary_analysis["summaries"]
        if summary.get("status") == "candidate_requires_local_lean_replay"
    }
    affine_return_summary_by_entry = {
        int(summary["entry_region_index"]): summary
        for summary in direct_call_return_summary_analysis.get(
            "entry_summaries", []
        )
    }
    for source_index, behavior in enumerate(behaviors):
        original_outcome = behavior["original_ir"].get("outcome") or {}
        candidate_outcome = behavior["candidate_ir"].get("outcome") or {}
        call_edge = checked_call_edges_by_source.get(source_index)
        if call_edge is None:
            continue
        direct_claim = call_edge.get("direct_call_push_claim")
        indirect_claim = call_edge.get("indirect_call_push_claim")
        if direct_claim is not None:
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
        else:
            target_claim = call_edge.get("indirect_target_claim") or {}
            expected_target_id = int(target_claim.get("target_id", -1))
            expected_continuation = int(
                (indirect_claim or {}).get("continuation_target_id", -1)
            )
            if (
                original_outcome.get("op") != "indirect_call"
                or candidate_outcome.get("op") != "indirect_call"
                or int(original_outcome.get("continuation", -2))
                    != expected_continuation
                or int(candidate_outcome.get("continuation", -2))
                    != expected_continuation
                or expected_target_id < 0
                or expected_target_id
                    != int(regions[int(call_edge["target_region_index"])].get(
                        "numeric_id", call_edge["target_region_index"]
                    ))
            ):
                continue
            callee_index = int(call_edge["target_region_index"])
            continuation_index = region_index_by_target_id.get(expected_continuation)
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
        direct_return_summary = direct_call_return_summary_by_source.get(source_index)
        if direct_return_summary is not None:
            return_stack_deltas.add(int(direct_return_summary["return_delta"]))
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
            if callee_machine_contract.get("disposition") == "terminates":
                # The decoded call still names the syntactic next instruction,
                # but a checked non-returning import has no runtime continuation.
                # Adding that impossible return edge can manufacture a weighted
                # stack cycle through linker padding or a following function.
                continue
            return_stack_deltas.add(
                4 + int(callee_machine_contract["stack_result_delta"])
            )
        checked_call_continuations[continuation_index].append({
            "source_region_index": source_index,
            "callee_region_index": callee_index,
            "entry_stack_delta": original_delta,
            "return_stack_delta": (
                next(iter(return_stack_deltas))
                if len(return_stack_deltas) == 1
                else None
            ),
            "return_summary_bytes_below": (
                int(direct_return_summary["bytes_below"])
                if direct_return_summary is not None
                else 0
            ),
            "return_summary_bytes_above": (
                int(direct_return_summary["bytes_above"])
                if direct_return_summary is not None
                else 0
            ),
            "return_predecessors": (
                [
                    {
                        "region_index": return_index,
                        "stack_delta": stack_delta(
                            (
                                behaviors[return_index]["original_ir"].get(
                                    "registers"
                                )
                                or {}
                            ).get("esp"),
                            "esp",
                        ),
                    }
                    for return_index in direct_return_summary.get(
                        "return_region_indices", []
                    )
                ]
                if direct_return_summary is not None
                else []
            ),
        })
    call_window_adjacency = {
        continuation: {
            int(call["callee_region_index"]) for call in calls
        }
        for continuation, calls in checked_call_continuations.items()
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

    for continuation, calls in checked_call_continuations.items():
        for call in calls:
            call["recursive"] = int(call_window_path_exists(
                int(call["callee_region_index"]), continuation,
            ))

    entry_region_indices = [
        index for index, region in enumerate(regions)
        if bool(region.get("root"))
    ]
    if tls_callback_target_ids and len(entry_region_indices) == 1:
        continuation_target_ids = [
            *tls_callback_target_ids[1:],
            int(regions[entry_region_indices[0]].get(
                "numeric_id", entry_region_indices[0]
            )),
        ]
        for callback_position, (
            callback_target_id, continuation_target_id,
        ) in enumerate(zip(
            tls_callback_target_ids, continuation_target_ids, strict=True
        )):
            callback_index = region_index_by_target_id.get(callback_target_id)
            continuation_index = region_index_by_target_id.get(
                continuation_target_id
            )
            if callback_index is None or continuation_index is None:
                continue
            # The bounded console launch profile materializes one 16-byte
            # frame for this callback and every remaining continuation. Keep
            # their complete return slot and three loader arguments inside the
            # proved stack range while the callback executes.
            add_requirement(
                callback_index, "esp", "esp",
                16 * (len(tls_callback_target_ids) - callback_position),
                "pe32_tls_launch_frame_span",
            )
            return_summary = affine_return_summary_by_entry.get(callback_index)
            if return_summary is None:
                continue
            checked_call_continuations[continuation_index].append({
                "source_region_index": callback_index,
                "callee_region_index": callback_index,
                "entry_stack_delta": 0,
                "return_stack_delta": int(return_summary["return_delta"]),
                "return_summary_bytes_below": int(
                    return_summary["bytes_below"]
                ),
                "return_summary_bytes_above": int(
                    return_summary["bytes_above"]
                ),
                "return_predecessors": [
                    {
                        "region_index": int(return_index),
                        "stack_delta": stack_delta(
                            (
                                behaviors[int(return_index)]["original_ir"].get(
                                    "registers"
                                )
                                or {}
                            ).get("esp"),
                            "esp",
                        ),
                    }
                    for return_index in return_summary[
                        "return_region_indices"
                    ]
                ],
                "recursive": 0,
                "source": "pe32_tls_launch_continuation",
            })
    def edge_stack_transfer(
        edge: dict[str, Any], original_register: str, candidate_register: str,
    ) -> tuple[tuple[str, str, int] | None, str | None]:
        source_index = int(edge["source_region_index"])
        original_expression = (
            behaviors[source_index]["original_ir"].get("registers") or {}
        ).get(original_register) or {}
        candidate_expression = (
            behaviors[source_index]["candidate_ir"].get("registers") or {}
        ).get(candidate_register) or {}
        original_affine = register_offset(original_expression)
        candidate_affine = register_offset(candidate_expression)
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
            # Machine cleanup changes architectural ESP, not preserved frame
            # or general-register windows that happen to cross the call edge.
            if original_register == candidate_register == "esp":
                environment_delta = int(machine_contract["stack_result_delta"])
        if (
            original_affine is None
            or candidate_affine is None
            or original_affine[1] + environment_delta
                != candidate_affine[1] + environment_delta
        ):
            return None, "non_identity_or_environment_stack_transfer"
        return (
            original_affine[0], candidate_affine[0],
            original_affine[1] + environment_delta,
        ), None

    transfer_adjacency: dict[
        tuple[int, str, str],
        list[tuple[tuple[int, str, str], int]],
    ] = defaultdict(list)
    transfer_pending = list(sorted(requirements, reverse=True))
    transfer_seen: set[tuple[int, str, str]] = set()
    while transfer_pending:
        target_key = transfer_pending.pop()
        if target_key in transfer_seen:
            continue
        transfer_seen.add(target_key)
        target_index, original_register, candidate_register = target_key
        for edge in incoming.get(target_index, []):
            transfer, _ = edge_stack_transfer(
                edge, original_register, candidate_register
            )
            if transfer is None:
                continue
            source_original, source_candidate, delta = transfer
            source_key = (
                int(edge["source_region_index"]), source_original, source_candidate,
            )
            transfer_adjacency[target_key].append((source_key, delta))
            if source_key not in transfer_seen:
                transfer_pending.append(source_key)
        if original_register == "esp" and candidate_register == "esp":
            for call in checked_call_continuations.get(target_index, []):
                return_stack_delta = call.get("return_stack_delta")
                if (
                    not bool(call.get("recursive"))
                    and isinstance(return_stack_delta, int)
                ):
                    source_key = (
                        int(call["callee_region_index"]), "esp", "esp",
                    )
                    transfer_adjacency[target_key].append((
                        source_key, return_stack_delta,
                    ))
                    if source_key not in transfer_seen:
                        transfer_pending.append(source_key)
                    for predecessor in call.get("return_predecessors", []):
                        predecessor_delta = predecessor.get("stack_delta")
                        if not isinstance(predecessor_delta, int):
                            continue
                        predecessor_key = (
                            int(predecessor["region_index"]), "esp", "esp",
                        )
                        transfer_adjacency[target_key].append((
                            predecessor_key, predecessor_delta,
                        ))
                        if predecessor_key not in transfer_seen:
                            transfer_pending.append(predecessor_key)
    for transfers in transfer_adjacency.values():
        transfers.sort()
    unbounded_cycle_nodes = _reachable_weighted_nonzero_cycle_nodes(
        transfer_adjacency, set(requirements)
    )
    stack_anchored = {
        key for key in transfer_seen | set(requirements)
        if key[1] == "esp" and key[2] == "esp"
    }
    changed = True
    while changed:
        changed = False
        for target_key, transfers in transfer_adjacency.items():
            if (
                target_key not in stack_anchored
                and any(source_key in stack_anchored for source_key, _ in transfers)
            ):
                stack_anchored.add(target_key)
                changed = True
    unproven_stack_seeds = {
        key: requirements[key]
        for key in requirements.keys() - stack_anchored
    }
    requirements = {
        key: value for key, value in requirements.items()
        if key in stack_anchored
    }

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

    for (region_index, original_register, candidate_register), (
        bytes_below, bytes_above,
    ) in sorted(unproven_stack_seeds.items()):
        add_frontier({
            "region_index": region_index,
            "original_register": original_register,
            "candidate_register": candidate_register,
            "bytes_below": bytes_below,
            "bytes_above": bytes_above,
            "reason": "stack_anchor_provenance_unresolved",
        })

    queue = deque(sorted(requirements))
    queued = set(queue)
    while queue:
        target_key = queue.popleft()
        propagation_steps += 1
        queued.discard(target_key)
        target_index, original_register, candidate_register = target_key
        bytes_below, bytes_above = requirements[target_key]
        if target_key in unbounded_cycle_nodes:
            add_frontier({
                "region_index": target_index,
                "original_register": original_register,
                "candidate_register": candidate_register,
                "bytes_below": bytes_below,
                "bytes_above": bytes_above,
                "reason": "nonzero_stack_delta_cycle_requires_relational_frame",
            })
            continue
        has_checked_return_predecessor = False
        if original_register == "esp" and candidate_register == "esp":
            for call in checked_call_continuations.get(target_index, []):
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
                has_checked_return_predecessor = True
                callee_key = (
                    int(call["callee_region_index"]),
                    original_register,
                    candidate_register,
                )
                callee_below = max(
                    bytes_below - return_stack_delta,
                    int(call.get("return_summary_bytes_below", 0)),
                    0,
                )
                callee_above = max(
                    bytes_above + return_stack_delta,
                    int(call.get("return_summary_bytes_above", 0)),
                    1,
                )
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
                for predecessor in call.get("return_predecessors", []):
                    predecessor_delta = predecessor.get("stack_delta")
                    if not isinstance(predecessor_delta, int):
                        add_frontier({
                            "region_index": target_index,
                            "source_region_index": int(call["source_region_index"]),
                            "callee_region_index": int(call["callee_region_index"]),
                            "return_region_index": int(predecessor["region_index"]),
                            "original_register": original_register,
                            "candidate_register": candidate_register,
                            "bytes_below": bytes_below,
                            "bytes_above": bytes_above,
                            "reason": "return_predecessor_stack_delta_unsupported",
                        })
                        continue
                    predecessor_key = (
                        int(predecessor["region_index"]),
                        original_register,
                        candidate_register,
                    )
                    predecessor_required = (
                        max(bytes_below - predecessor_delta, 0),
                        max(bytes_above + predecessor_delta, 1),
                    )
                    prior_below, prior_above = requirements.get(
                        predecessor_key, (0, 0)
                    )
                    required = (
                        max(prior_below, predecessor_required[0]),
                        max(prior_above, predecessor_required[1]),
                    )
                    if required != (prior_below, prior_above):
                        requirements[predecessor_key] = required
                        seed_sources.setdefault(predecessor_key, set()).add(
                            "direct_call_return_predecessor_window"
                        )
                        requirement_updates += 1
                        if predecessor_key not in queued:
                            queue.append(predecessor_key)
                            queued.add(predecessor_key)
        edges = incoming.get(target_index, [])
        if not edges:
            if has_checked_return_predecessor:
                continue
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
            transfer, transfer_issue = edge_stack_transfer(
                edge, original_register, candidate_register
            )
            if transfer is None:
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
            source_original, source_candidate, original_delta = transfer
            source_below = max(bytes_below - original_delta, 0)
            source_above = max(bytes_above + original_delta, 1)
            source_key = (source_index, source_original, source_candidate)
            if source_key not in stack_anchored:
                add_frontier({
                    "region_index": target_index,
                    "source_region_index": source_index,
                    "original_register": original_register,
                    "candidate_register": candidate_register,
                    "bytes_below": bytes_below,
                    "bytes_above": bytes_above,
                    "reason": "stack_anchor_provenance_unresolved",
                })
                continue
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

    stack_index_bound_analysis = _attach_checked_stack_index_bounds(
        regions, behaviors
    )

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
            1 for _ in unbounded_cycle_nodes
        ),
        "unproven_stack_address_seeds": len(unproven_stack_seeds),
        "duplicate_frontier_observations": duplicate_frontier_observations,
        "direct_call_return_summary_analysis": direct_call_return_summary_analysis,
        "stack_index_bounds": stack_index_bound_analysis,
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
    machine_import_call_contracts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    region_count = len(relation_rows)
    ordinary_successors: list[set[int]] = [set() for _ in relation_rows]
    call_edges: dict[int, dict[str, Any]] = {}
    unsupported_exit = [False] * region_count
    returning_machine_contract_ids = {
        int(contract["id"])
        for contract in machine_import_call_contracts or []
        if (
            isinstance(contract, dict)
            and isinstance(contract.get("id"), int)
            and not isinstance(contract.get("id"), bool)
            and contract.get("disposition") == "returns"
        )
    }

    def call_push_claim(edge: dict[str, Any]) -> dict[str, Any] | None:
        claim = (
            edge.get("direct_call_push_claim")
            or edge.get("indirect_call_push_claim")
        )
        return claim if isinstance(claim, dict) else None

    def returning_external_thunk(edge: dict[str, Any]) -> bool:
        contract_id = edge.get("returning_external_thunk_contract_id")
        return isinstance(contract_id, int) and not isinstance(contract_id, bool)

    def returning_external_call(edge: dict[str, Any]) -> bool:
        contract_id = edge.get("machine_contract_id")
        return (
            edge.get("kind") == "external_call"
            and edge.get("environment_barrier") is True
            and isinstance(contract_id, int)
            and not isinstance(contract_id, bool)
            and int(contract_id) in returning_machine_contract_ids
        )

    for edge in edges:
        source = int(edge["source_region_index"])
        if call_push_claim(edge) is not None:
            call_edges[source] = edge
            continue
        if returning_external_call(edge):
            ordinary_successors[source].add(int(edge["target_region_index"]))
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
        claim = call_push_claim(edge)
        assert claim is not None
        continuation = int(claim["continuation_region_index"])
        if not returning_external_thunk(edge):
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
            claim = call_push_claim(edge)
            assert claim is not None
            continuation = int(claim["continuation_region_index"])
            if returning_external_thunk(edge):
                proposed.update(return_sets[continuation])
            elif return_sets[callee]:
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
                claim = call_push_claim(edge)
                assert claim is not None
                continuation = int(claim["continuation_region_index"])
                next_closed = (
                    closed[continuation]
                    if returning_external_thunk(edge)
                    else closed[callee] and closed[continuation]
                )
            else:
                successors = ordinary_successors[source]
                next_closed = bool(successors) and all(closed[target] for target in successors)
            if closed[source] and not next_closed:
                closed[source] = False
                changed = True

    summaries = []
    for source, edge in sorted(call_edges.items()):
        if returning_external_thunk(edge):
            continue
        callee = int(edge["target_region_index"])
        claim = call_push_claim(edge)
        assert claim is not None
        continuation = int(claim["continuation_region_index"])
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
        "profile": "static_pushdown_return_summary_v2",
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
        edge["return_slot_external_call_summary_claims"] = []
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

    transfer_rule_cache: dict[
        tuple[int, tuple[tuple[str, str], ...]], list[dict[str, Any]]
    ] = {}
    machine_contracts_by_target = {
        (
            str(item["import"]["dll"]).lower(),
            "symbol" if "symbol" in item["import"] else "ordinal",
            item["import"].get("symbol", item["import"].get("ordinal")),
        ): item
        for item in (machine_import_call_contracts or [])
    }

    def behavior_transfer_rules(source: int) -> list[dict[str, Any]]:
        runtime_pairs = tuple(sorted({
            (location[0], location[2]) for location in locations[source]
        }))
        cache_key = (source, runtime_pairs)
        cached = transfer_rule_cache.get(cache_key)
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
        for original_register, candidate_register in runtime_pairs:
            if (original_register, candidate_register) in source_pairs:
                continue
            source_pairs.add((original_register, candidate_register))
            source_relations.append({
                "original": original_register,
                "candidate": candidate_register,
            })
        target_relations = list(relation_rows[source].get("outputs", []))
        target_pairs = {
            (str(relation["original"]), str(relation["candidate"]))
            for relation in target_relations
        }
        for original_register, candidate_register in runtime_pairs:
            if (original_register, candidate_register) in target_pairs:
                continue
            target_pairs.add((original_register, candidate_register))
            target_relations.append({
                "original": original_register,
                "candidate": candidate_register,
            })
        for input_relation in source_relations:
            original_source_register = str(input_relation["original"])
            candidate_source_register = str(input_relation["candidate"])
            for output_relation in target_relations:
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
        transfer_rule_cache[cache_key] = rules
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
        relation_rows, edges, machine_import_call_contracts
    )
    checked_call_edge_by_source = {
        int(edge["source_region_index"]): edge
        for edge in edges
        if (
            edge.get("direct_call_push_claim") is not None
            or (
                edge.get("indirect_call_push_claim") is not None
                and edge.get("indirect_target_profile") in {
                    "immutable_relocated_function_pointer_call_v1",
                    "fixed_static_function_pointer_call_v1",
                    "inductive_fixed_code_pointer_register_call_v1",
                }
            )
        )
    }

    machine_contracts_by_id: dict[int, dict[str, Any]] = {}
    ambiguous_machine_contract_ids: set[int] = set()
    for contract in machine_import_call_contracts or []:
        contract_id = contract.get("id") if isinstance(contract, dict) else None
        if not isinstance(contract_id, int) or isinstance(contract_id, bool):
            continue
        if contract_id in machine_contracts_by_id:
            ambiguous_machine_contract_ids.add(contract_id)
            machine_contracts_by_id.pop(contract_id, None)
        elif contract_id not in ambiguous_machine_contract_ids:
            machine_contracts_by_id[contract_id] = contract

    def external_call_summary_basis(
        call_edge: dict[str, Any],
    ) -> dict[str, Any] | None:
        """Return exact evidence for a checked returning import-thunk call.

        This is proposal generation only.  The generated Lean checker replays
        the direct call, thunk decode, import identity, contract selection, and
        offset arithmetic before the summary can participate in composition.
        """

        call_push = call_edge.get("direct_call_push_claim")
        contract_id = call_edge.get("returning_external_thunk_contract_id")
        if (
            not isinstance(call_push, dict)
            or not isinstance(contract_id, int)
            or isinstance(contract_id, bool)
            or contract_id in ambiguous_machine_contract_ids
        ):
            return None
        contract = machine_contracts_by_id.get(contract_id)
        if contract is None or contract.get("disposition") != "returns":
            return None
        thunk_index = int(call_edge["target_region_index"])
        if not 0 <= thunk_index < len(behaviors):
            return None
        original_thunk = behaviors[thunk_index].get("original_ir") or {}
        candidate_thunk = behaviors[thunk_index].get("candidate_ir") or {}
        original_outcome = original_thunk.get("outcome") or {}
        candidate_outcome = candidate_thunk.get("outcome") or {}
        original_identity = _semantic_external_target_identity(
            original_outcome.get("import")
        )
        candidate_identity = _semantic_external_target_identity(
            candidate_outcome.get("import")
        )
        imported = contract.get("import") or {}
        contract_identity = (
            str(imported.get("dll", "")).lower(),
            "symbol" if "symbol" in imported else "ordinal",
            imported.get("symbol", imported.get("ordinal")),
        )
        if (
            original_outcome.get("op") != "external_jump"
            or candidate_outcome.get("op") != "external_jump"
            or original_identity is None
            or original_identity != candidate_identity
            or original_identity != contract_identity
        ):
            return None
        callsite = int(call_edge["source_region_index"])
        original_call = behaviors[callsite].get("original_ir") or {}
        candidate_call = behaviors[callsite].get("candidate_ir") or {}
        original_result = _register_offset_witness(
            (original_call.get("registers") or {}).get("esp"), "esp"
        )
        candidate_result = _register_offset_witness(
            (candidate_call.get("registers") or {}).get("esp"), "esp"
        )
        if original_result is None or candidate_result is None:
            return None
        original_witness, original_delta = original_result
        candidate_witness, candidate_delta = candidate_result
        original_thunk_result = _register_offset_witness(
            (original_thunk.get("registers") or {}).get("esp"), "esp"
        )
        candidate_thunk_result = _register_offset_witness(
            (candidate_thunk.get("registers") or {}).get("esp"), "esp"
        )
        if original_thunk_result is None or candidate_thunk_result is None:
            return None
        original_thunk_witness, original_thunk_delta = original_thunk_result
        candidate_thunk_witness, candidate_thunk_delta = candidate_thunk_result
        stack_delta = contract.get("stack_result_delta")
        if (
            not isinstance(stack_delta, int)
            or isinstance(stack_delta, bool)
            or not 0 <= stack_delta < 2**32
        ):
            return None
        continuation = call_push.get("continuation_region_index")
        if (
            not isinstance(continuation, int)
            or isinstance(continuation, bool)
            or not 0 <= continuation < len(relation_rows)
        ):
            return None
        return {
            "machine_contract_id": contract_id,
            "thunk_region_index": thunk_index,
            "continuation_region_index": continuation,
            "original_call_witness": original_witness,
            "candidate_call_witness": candidate_witness,
            "original_call_delta": int(original_delta),
            "candidate_call_delta": int(candidate_delta),
            "original_thunk_witness": original_thunk_witness,
            "candidate_thunk_witness": candidate_thunk_witness,
            "original_thunk_delta": int(original_thunk_delta),
            "candidate_thunk_delta": int(candidate_thunk_delta),
            "stack_result_delta": stack_delta,
        }

    def external_call_summary_claim(
        call_edge: dict[str, Any], source_location: FrameLocation,
    ) -> dict[str, Any] | None:
        basis = external_call_summary_basis(call_edge)
        if basis is None:
            return None
        if source_location[0] != "esp" or source_location[2] != "esp":
            return None
        suspended_location: FrameLocation = (
            "esp",
            (source_location[1] - int(basis["original_call_delta"])) % 2**32,
            "esp",
            (source_location[3] - int(basis["candidate_call_delta"])) % 2**32,
        )
        internal_location: FrameLocation = (
            "esp",
            (
                suspended_location[1] - int(basis["original_thunk_delta"])
            ) % 2**32,
            "esp",
            (
                suspended_location[3] - int(basis["candidate_thunk_delta"])
            ) % 2**32,
        )
        boundary_location: FrameLocation = (
            "esp",
            (internal_location[1] - 4) % 2**32,
            "esp",
            (internal_location[3] - 4) % 2**32,
        )
        target_location: FrameLocation = (
            "esp",
            (
                boundary_location[1] - int(basis["stack_result_delta"])
            ) % 2**32,
            "esp",
            (
                boundary_location[3] - int(basis["stack_result_delta"])
            ) % 2**32,
        )
        thunk_index = int(basis["thunk_region_index"])
        original_write_witnesses = write_address_witnesses(
            behaviors[thunk_index].get("original_ir") or {},
            "esp",
            suspended_location[1],
        )
        candidate_write_witnesses = write_address_witnesses(
            behaviors[thunk_index].get("candidate_ir") or {},
            "esp",
            suspended_location[3],
        )
        if (
            original_write_witnesses is None
            or candidate_write_witnesses is None
        ):
            return None
        return {
            "profile": "external_return_slot_call_summary_v1",
            "machine_contract_id": int(basis["machine_contract_id"]),
            "thunk_region_index": int(basis["thunk_region_index"]),
            "continuation_region_index": int(
                basis["continuation_region_index"]
            ),
            "source": location_payload(source_location),
            "suspended": location_payload(suspended_location),
            "target": location_payload(target_location),
            "original_call_witness": basis["original_call_witness"],
            "candidate_call_witness": basis["candidate_call_witness"],
            "thunk_transfer": {
                "source": location_payload(suspended_location),
                "internal_target": location_payload(internal_location),
                "boundary_target": location_payload(boundary_location),
                "internal_rule": {
                    "original_source_register": "esp",
                    "candidate_source_register": "esp",
                    "original_target_register": "esp",
                    "candidate_target_register": "esp",
                    "original_output_witness": basis[
                        "original_thunk_witness"
                    ],
                    "candidate_output_witness": basis[
                        "candidate_thunk_witness"
                    ],
                    "original_delta": int(basis["original_thunk_delta"]),
                    "candidate_delta": int(basis["candidate_thunk_delta"]),
                },
                "result_rule": {
                    "source": location_payload(boundary_location),
                    "target": location_payload(target_location),
                    "original_delta": int(basis["stack_result_delta"]),
                    "candidate_delta": int(basis["stack_result_delta"]),
                },
                "memory_claim": {
                    "offsets": location_payload(suspended_location),
                    "original_write_witnesses": original_write_witnesses,
                    "candidate_write_witnesses": candidate_write_witnesses,
                },
            },
        }

    def replayable_call_summary(summary: dict[str, Any]) -> dict[str, Any] | None:
        if not summary["closed"] or not summary["return_region_indices"]:
            return None
        callsite = int(summary["callsite_region_index"])
        call_edge = checked_call_edge_by_source.get(callsite)
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
    max_summary_rounds = max(1, len(checked_call_edge_by_source) + 1)
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
        for call_edge in checked_call_edge_by_source.values():
            basis = external_call_summary_basis(call_edge)
            if basis is None:
                continue
            callsite = int(call_edge["source_region_index"])
            continuation = int(basis["continuation_region_index"])
            proposed = {
                location_key
                for source_location in locations[callsite]
                for claim in [external_call_summary_claim(call_edge, source_location)]
                if claim is not None
                for location_key in [(
                    str(claim["target"]["original_register"]),
                    int(claim["target"]["original"]),
                    str(claim["target"]["candidate_register"]),
                    int(claim["target"]["candidate"]),
                )]
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
    external_call_summary_claim_count = 0
    replayable_call_summaries = 0
    for summary in call_summary_analysis["summaries"]:
        replay = replayable_call_summary(summary)
        summary["return_slot_status"] = "incomplete"
        summary["return_slot_claims"] = []
        if replay is None:
            continue
        callsite = int(summary["callsite_region_index"])
        continuation = int(summary["continuation_region_index"])
        call_edge = checked_call_edge_by_source[callsite]
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

    for call_edge in checked_call_edge_by_source.values():
        claims = [
            claim
            for source_location in sorted(
                locations[int(call_edge["source_region_index"])]
            )
            for claim in [external_call_summary_claim(call_edge, source_location)]
            if claim is not None
        ]
        call_edge["return_slot_external_call_summary_claims"] = claims
        external_call_summary_claim_count += len(claims)

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
        "external_call_summary_claims": external_call_summary_claim_count,
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
