"""Untrusted state-predicate pullback proposals checked by Lean."""

from __future__ import annotations

import copy
import hashlib
import json
from typing import Any

from ..contract import _semantic_expr_is_pure


_SUPPORTED_FLAG_BITS = {0, 2, 4, 6, 7, 10, 11}
_FLAG_FIELDS = {
    0: "carry",
    2: "parity",
    4: "auxiliary",
    6: "zero",
    7: "sign",
    11: "overflow",
}


def _semantic_identity(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _predicate_semantics(predicate: dict[str, Any]) -> dict[str, Any]:
    return {
        "original": predicate.get("original"),
        "candidate": predicate.get("candidate"),
        "exact_memory_reads": predicate.get("exact_memory_reads", []),
    }


def _bound_predicate(bound: object) -> dict[str, Any] | None:
    if not isinstance(bound, dict):
        return None
    upper = bound.get("unsigned_lt")
    if not isinstance(upper, int) or isinstance(upper, bool) or upper <= 0:
        return None
    stack_predicate = bound.get("stack_bound_predicate")
    if bound.get("expression_source") == "checked_stack_register_bound_v1":
        if _checked_stack_bound_predicate(stack_predicate, upper):
            return copy.deepcopy(stack_predicate)
        return None
    expressions: dict[str, dict[str, Any]] = {}
    for side in ("original", "candidate"):
        expression = bound.get(f"{side}_expression")
        if expression is None:
            register = bound.get(side)
            if not isinstance(register, str):
                return None
            expression = {"op": "input_reg", "reg": register}
        if not isinstance(expression, dict) or not _semantic_expr_is_pure(expression):
            return None
        expressions[side] = copy.deepcopy(expression)
    return {
        "original": {
            "op": "unsigned_less",
            "left": expressions["original"],
            "right": {"op": "constant", "value": upper},
        },
        "candidate": {
            "op": "unsigned_less",
            "left": expressions["candidate"],
            "right": {"op": "constant", "value": upper},
        },
        "exact_memory_reads": [],
        "source": "cfg_bound_invariant",
    }


def _checked_stack_bound_predicate(predicate: object, upper: int | None = None) -> bool:
    if not isinstance(predicate, dict):
        return False
    reads = predicate.get("exact_memory_reads")
    if not isinstance(reads, list) or len(reads) != 1:
        return False
    read = reads[0]
    if not isinstance(read, dict) or read.get("bytes") != 4:
        return False
    for side in ("original", "candidate"):
        expression = predicate.get(side)
        address = read.get(f"{side}_address")
        if (
            not isinstance(expression, dict)
            or expression.get("op") != "unsigned_less"
            or expression.get("left")
            != {"op": "read32", "address": address}
        ):
            return False
        right = expression.get("right")
        if (
            not isinstance(right, dict)
            or right.get("op") != "constant"
            or not isinstance(right.get("value"), int)
            or isinstance(right.get("value"), bool)
            or int(right["value"]) <= 0
            or (upper is not None and int(right["value"]) != upper)
        ):
            return False
    return True


def _bool_expression_is_pure(expression: object) -> bool:
    if not isinstance(expression, dict):
        return False
    operation = expression.get("op")
    if operation == "bool_constant":
        return isinstance(expression.get("value"), bool)
    if operation == "input_flag":
        return int(expression.get("index", -1)) in _SUPPORTED_FLAG_BITS
    if operation in {"equal", "unsigned_less"}:
        return _semantic_expr_is_pure(expression.get("left")) and _semantic_expr_is_pure(
            expression.get("right")
        )
    if operation in {"msb", "bit"}:
        return _semantic_expr_is_pure(expression.get("value"))
    if operation == "not":
        return _bool_expression_is_pure(expression.get("value"))
    if operation in {"and", "or", "xor"}:
        return _bool_expression_is_pure(expression.get("left")) and _bool_expression_is_pure(
            expression.get("right")
        )
    if operation == "division_valid":
        return all(
            _semantic_expr_is_pure(expression.get(field))
            for field in ("high", "low", "divisor")
        )
    return False


def _substitute_expression(
    expression: dict[str, Any], registers: dict[str, Any]
) -> dict[str, Any]:
    if expression.get("op") == "input_reg":
        return copy.deepcopy(registers[expression["reg"]])
    result: dict[str, Any] = {"op": expression.get("op")}
    for key, value in expression.items():
        if key == "op":
            continue
        result[key] = (
            _substitute_expression(value, registers)
            if isinstance(value, dict) and "op" in value
            else copy.deepcopy(value)
        )
    return result


def _substitute_flag(index: int, flags: object) -> dict[str, Any]:
    field = _FLAG_FIELDS.get(index)
    if field is None or not isinstance(flags, dict) or flags.get(field) is None:
        return {"op": "input_flag", "index": index}
    return copy.deepcopy(flags[field])


def _substitute_bool_expression(
    expression: dict[str, Any], registers: dict[str, Any], flags: object
) -> dict[str, Any]:
    operation = expression.get("op")
    if operation == "input_flag":
        return _substitute_flag(int(expression["index"]), flags)
    if operation == "bool_constant":
        return copy.deepcopy(expression)
    result: dict[str, Any] = {"op": operation}
    for key, value in expression.items():
        if key == "op":
            continue
        if isinstance(value, dict) and "op" in value:
            result[key] = (
                _substitute_bool_expression(value, registers, flags)
                if value.get("op") in {
                    "bool_constant", "equal", "not", "and", "or", "xor",
                    "unsigned_less", "msb", "bit", "input_flag",
                    "division_valid",
                }
                else _substitute_expression(value, registers)
            )
        else:
            result[key] = copy.deepcopy(value)
    return result


def _read8_after_writes(
    address: dict[str, Any], writes: object,
) -> dict[str, Any] | None:
    if not isinstance(writes, list):
        return None
    prior: dict[str, Any] = {
        "op": "read8",
        "address": copy.deepcopy(address),
    }
    for write in writes:
        if not isinstance(write, dict):
            return None
        write_address = write.get("address")
        write_value = write.get("value")
        if not isinstance(write_address, dict) or not isinstance(write_value, dict):
            return None
        prior = {
            "op": "read8_after_write",
            "address": copy.deepcopy(address),
            "write_address": copy.deepcopy(write_address),
            "write_value": copy.deepcopy(write_value),
            "prior": prior,
        }
    return prior


def _read32_after_writes(
    address: dict[str, Any], writes: object,
) -> dict[str, Any] | None:
    bytes_: list[dict[str, Any]] = []
    for offset in range(4):
        byte_address = (
            copy.deepcopy(address)
            if offset == 0
            else {
                "op": "add",
                "left": copy.deepcopy(address),
                "right": {"op": "constant", "value": offset},
            }
        )
        byte = _read8_after_writes(byte_address, writes)
        if byte is None:
            return None
        bytes_.append(
            byte
            if offset == 0
            else {"op": "shift_left", "value": byte, "amount": offset * 8}
        )
    return {
        "op": "bit_or",
        "left": {"op": "bit_or", "left": bytes_[0], "right": bytes_[1]},
        "right": {"op": "bit_or", "left": bytes_[2], "right": bytes_[3]},
    }


def _pullback_memory_expression(
    expression: object,
    behavior: dict[str, Any],
    *,
    preserve_direct_reads: bool = False,
) -> dict[str, Any] | None:
    if not isinstance(expression, dict):
        return None
    operation = expression.get("op")
    if operation == "input_reg":
        register = expression.get("reg")
        value = behavior.get("registers", {}).get(register)
        return copy.deepcopy(value) if isinstance(value, dict) else None
    if operation in {"input_fs_base", "constant", "undefined"}:
        return copy.deepcopy(expression)
    if operation == "input_flag_value":
        # Lean supports this case, but the semantic JSON expression vocabulary
        # does not yet expose BoolExpr.toWord. Keep the proposal fail-closed.
        return None
    if operation in {"input_x87_control", "input_x87_status"}:
        return None
    if operation in {"read8", "read32"}:
        address = _pullback_memory_expression(
            expression.get("address"),
            behavior,
            preserve_direct_reads=preserve_direct_reads,
        )
        if address is None:
            return None
        if preserve_direct_reads and behavior.get("writes") == []:
            return {"op": operation, "address": address}
        if operation == "read8":
            return _read8_after_writes(address, behavior.get("writes"))
        return _read32_after_writes(address, behavior.get("writes"))
    if operation == "read8_after_write":
        fields = {}
        for field in ("address", "write_address", "write_value", "prior"):
            value = _pullback_memory_expression(
                expression.get(field),
                behavior,
                preserve_direct_reads=preserve_direct_reads,
            )
            if value is None:
                return None
            fields[field] = value
        return {"op": operation, **fields}
    if operation not in {
        "add", "sub", "bit_and", "bit_xor", "bit_not", "extract_byte",
        "shift_left", "shift_right", "shift_left_by", "shift_right_by",
        "shift_arithmetic_right_by", "bit_or", "if_equal",
        "unsigned_less_value", "bit_value", "multiply",
        "multiply_high_unsigned", "multiply_high_signed", "divide_quotient",
        "divide_remainder", "division_valid_value", "lowest_set_bit",
        "highest_set_bit",
    }:
        return None
    result: dict[str, Any] = {"op": operation}
    for key, value in expression.items():
        if key == "op":
            continue
        if isinstance(value, dict) and "op" in value:
            pulled = _pullback_memory_expression(
                value,
                behavior,
                preserve_direct_reads=preserve_direct_reads,
            )
            if pulled is None:
                return None
            result[key] = pulled
        else:
            result[key] = copy.deepcopy(value)
    return result


def _pullback_bool_expression(
    expression: object, behavior: dict[str, Any]
) -> dict[str, Any] | None:
    if not isinstance(expression, dict):
        return None
    operation = expression.get("op")
    if operation == "bool_constant":
        return copy.deepcopy(expression)
    if operation == "input_flag":
        index = expression.get("index")
        if not isinstance(index, int) or index not in _SUPPORTED_FLAG_BITS:
            return None
        return _substitute_flag(index, behavior.get("flags"))
    expression_fields = {
        "equal": ("left", "right"),
        "unsigned_less": ("left", "right"),
        "msb": ("value",),
        "bit": ("value",),
        "division_valid": ("high", "low", "divisor"),
    }
    boolean_fields = {
        "not": ("value",),
        "and": ("left", "right"),
        "or": ("left", "right"),
        "xor": ("left", "right"),
    }
    if operation in expression_fields:
        result = {"op": operation}
        for field in expression_fields[operation]:
            pulled = _pullback_memory_expression(
                expression.get(field), behavior, preserve_direct_reads=True
            )
            if pulled is None:
                return None
            result[field] = pulled
        for field, value in expression.items():
            if field not in {"op", *expression_fields[operation]}:
                result[field] = copy.deepcopy(value)
        return result
    if operation in boolean_fields:
        result = {"op": operation}
        for field in boolean_fields[operation]:
            pulled = _pullback_bool_expression(expression.get(field), behavior)
            if pulled is None:
                return None
            result[field] = pulled
        return result
    return None


def _pullback_predicate(
    predicate: object,
    original_behavior: dict[str, Any],
    candidate_behavior: dict[str, Any],
) -> dict[str, Any] | None:
    if not isinstance(predicate, dict):
        return None
    original = predicate.get("original")
    candidate = predicate.get("candidate")
    reads = predicate.get("exact_memory_reads", [])
    memory_predicate = _checked_stack_bound_predicate(predicate)
    if not isinstance(reads, list) or (
        not memory_predicate
        and (
            not _bool_expression_is_pure(original)
            or not _bool_expression_is_pure(candidate)
        )
    ):
        return None
    pulled_reads: list[dict[str, Any]] = []
    for read in reads:
        if not isinstance(read, dict):
            return None
        original_address = _pullback_memory_expression(
            read.get("original_address"), original_behavior
        )
        candidate_address = _pullback_memory_expression(
            read.get("candidate_address"), candidate_behavior
        )
        byte_count = read.get("bytes")
        if (
            original_address is None
            or candidate_address is None
            or not isinstance(byte_count, int)
            or isinstance(byte_count, bool)
        ):
            return None
        pulled_reads.append({
            "original_address": original_address,
            "candidate_address": candidate_address,
            "bytes": byte_count,
        })
    if memory_predicate:
        pulled_original = _pullback_bool_expression(original, original_behavior)
        pulled_candidate = _pullback_bool_expression(candidate, candidate_behavior)
        if pulled_original is None or pulled_candidate is None:
            return None
    else:
        try:
            pulled_original = _substitute_bool_expression(
                original,
                original_behavior.get("registers", {}),
                original_behavior.get("flags"),
            )
            pulled_candidate = _substitute_bool_expression(
                candidate,
                candidate_behavior.get("registers", {}),
                candidate_behavior.get("flags"),
            )
        except (KeyError, TypeError, ValueError):
            return None
    return {
        "original": pulled_original,
        "candidate": pulled_candidate,
        "exact_memory_reads": pulled_reads,
        "source": "no_write_state_predicate_pullback",
    }


def _negate_normalized(expression: dict[str, Any]) -> dict[str, Any]:
    if expression.get("op") == "not" and isinstance(expression.get("value"), dict):
        return copy.deepcopy(expression["value"])
    return {"op": "not", "value": copy.deepcopy(expression)}


def _true_guard() -> dict[str, Any]:
    zero = {"op": "constant", "value": 0}
    return {"op": "equal", "left": zero, "right": copy.deepcopy(zero)}


def _guarded_pullback(
    predicate: dict[str, Any],
    original_guard: dict[str, Any] | None,
    candidate_guard: dict[str, Any] | None,
) -> dict[str, Any]:
    if original_guard is None or candidate_guard is None:
        return predicate
    return {
        **predicate,
        "original": {
            "op": "or",
            "left": _negate_normalized(original_guard),
            "right": predicate["original"],
        },
        "candidate": {
            "op": "or",
            "left": _negate_normalized(candidate_guard),
            "right": predicate["candidate"],
        },
        "source": "no_write_state_predicate_edge_pullback",
    }


def _constant_value(expression: object) -> int | None:
    if not isinstance(expression, dict) or expression.get("op") != "constant":
        return None
    value = expression.get("value")
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _strictly_above_clause(
    expression: object,
) -> tuple[dict[str, Any], int] | None:
    if not isinstance(expression, dict) or expression.get("op") != "and":
        return None
    less_child = expression.get("left")
    unequal_child = expression.get("right")
    if not isinstance(less_child, dict) or less_child.get("op") != "not":
        return None
    less = less_child.get("value")
    if not isinstance(less, dict) or less.get("op") != "unsigned_less":
        return None
    value = less.get("left")
    threshold = _constant_value(less.get("right"))
    if not isinstance(value, dict) or threshold is None:
        return None
    if not isinstance(unequal_child, dict) or unequal_child.get("op") != "not":
        return None
    equal = unequal_child.get("value")
    if not isinstance(equal, dict) or equal.get("op") != "equal":
        return None
    equal_left, equal_right = equal.get("left"), equal.get("right")
    if _constant_value(equal_right) != 0 or not isinstance(equal_left, dict):
        return None
    if (
        equal_left.get("op") == "sub"
        and equal_left.get("left") == value
        and _constant_value(equal_left.get("right")) == threshold
    ):
        return value, threshold
    return None


def _stack_upper_bound_tautology(expression: object) -> bool:
    if not isinstance(expression, dict) or expression.get("op") != "or":
        return False
    above = _strictly_above_clause(expression.get("left"))
    bound = expression.get("right")
    if (
        above is None
        or not isinstance(bound, dict)
        or bound.get("op") != "unsigned_less"
        or bound.get("left") != above[0]
    ):
        return False
    upper = _constant_value(bound.get("right"))
    return upper is not None and 0 <= above[1] < upper < 2**32


def _pulled_predicate_directly_supported(
    source: dict[str, Any], pulled: dict[str, Any]
) -> bool:
    if not _stack_upper_bound_tautology(
        pulled.get("original")
    ) or not _stack_upper_bound_tautology(pulled.get("candidate")):
        return False
    source_reads = [
        read
        for predicate in source.get("state_predicates", [])
        if isinstance(predicate, dict)
        for read in predicate.get("exact_memory_reads", [])
        if isinstance(read, dict)
    ]
    return all(
        sum(read == source_read for source_read in source_reads) == 1
        for read in pulled.get("exact_memory_reads", [])
    )


def _paired_no_write_edges(
    pair: object,
) -> tuple[tuple[int, dict[str, Any] | None, dict[str, Any] | None], ...]:
    if not isinstance(pair, dict):
        return ()
    original = pair.get("original_ir")
    candidate = pair.get("candidate_ir")
    if not isinstance(original, dict) or not isinstance(candidate, dict):
        return ()
    if original.get("writes") != [] or candidate.get("writes") != []:
        return ()
    original_outcome = original.get("outcome")
    candidate_outcome = candidate.get("outcome")
    if not isinstance(original_outcome, dict) or not isinstance(candidate_outcome, dict):
        return ()
    operation = original_outcome.get("op")
    if operation != candidate_outcome.get("op"):
        return ()
    if operation == "jump":
        fields = (("target", None, None),)
    elif operation == "branch":
        original_condition = original_outcome.get("condition")
        candidate_condition = candidate_outcome.get("condition")
        if not isinstance(original_condition, dict) or not isinstance(
            candidate_condition, dict
        ):
            return ()
        if original_outcome.get("taken") == original_outcome.get("fallthrough"):
            fields = (("taken", _true_guard(), _true_guard()),)
        else:
            fields = (
                ("taken", original_condition, candidate_condition),
                (
                    "fallthrough",
                    _negate_normalized(original_condition),
                    _negate_normalized(candidate_condition),
                ),
            )
    else:
        return ()
    edges: list[tuple[int, dict[str, Any] | None, dict[str, Any] | None]] = []
    for field, original_guard, candidate_guard in fields:
        original_target = original_outcome.get(field)
        candidate_target = candidate_outcome.get(field)
        if (
            not isinstance(original_target, int)
            or isinstance(original_target, bool)
            or original_target != candidate_target
        ):
            return ()
        if all(edge[0] != original_target for edge in edges):
            edges.append((original_target, original_guard, candidate_guard))
    return tuple(edges)


def _edge_for_target(
    pair: dict[str, Any], target: dict[str, Any]
) -> tuple[dict[str, Any] | None, dict[str, Any] | None] | None:
    target_id = target.get("numeric_id")
    if not isinstance(target_id, int) or isinstance(target_id, bool):
        return None
    matches = [
        (original_guard, candidate_guard)
        for edge_target, original_guard, candidate_guard in _paired_no_write_edges(pair)
        if edge_target == target_id
    ]
    return matches[0] if len(matches) == 1 else None


def _strongly_connected_components(
    node_count: int, edges: list[tuple[int, int]]
) -> list[int]:
    adjacency: list[list[int]] = [[] for _ in range(node_count)]
    reverse: list[list[int]] = [[] for _ in range(node_count)]
    for source, target in edges:
        adjacency[source].append(target)
        reverse[target].append(source)
    visited = [False] * node_count
    order: list[int] = []
    for node in range(node_count):
        if visited[node]:
            continue
        stack: list[tuple[int, bool]] = [(node, False)]
        while stack:
            current, expanded = stack.pop()
            if expanded:
                order.append(current)
                continue
            if visited[current]:
                continue
            visited[current] = True
            stack.append((current, True))
            stack.extend(
                (target, False)
                for target in reversed(adjacency[current])
                if not visited[target]
            )
    components = [-1] * node_count
    component_count = 0
    for node in reversed(order):
        if components[node] >= 0:
            continue
        components[node] = component_count
        stack = [node]
        while stack:
            current = stack.pop()
            for target in reverse[current]:
                if components[target] < 0:
                    components[target] = component_count
                    stack.append(target)
        component_count += 1
    return components


def state_predicate_pullback_supported(
    source: dict[str, Any],
    target: dict[str, Any],
    pair: dict[str, Any],
) -> bool:
    target_predicates = target.get("state_predicates", [])
    if not target_predicates:
        return True
    original = pair.get("original_ir")
    candidate = pair.get("candidate_ir")
    if (
        not isinstance(original, dict)
        or not isinstance(candidate, dict)
        or original.get("writes") != []
        or candidate.get("writes") != []
    ):
        return False
    source_ids = {
        _semantic_identity(_predicate_semantics(predicate))
        for predicate in source.get("state_predicates", [])
        if isinstance(predicate, dict)
    }
    edge = _edge_for_target(pair, target)
    if edge is None:
        return False
    original_guard, candidate_guard = edge
    for predicate in target_predicates:
        pulled = _pullback_predicate(predicate, original, candidate)
        if pulled is not None:
            pulled = _guarded_pullback(pulled, original_guard, candidate_guard)
        if (
            pulled is None
            or (
                _semantic_identity(_predicate_semantics(pulled)) not in source_ids
                and not _pulled_predicate_directly_supported(source, pulled)
            )
        ):
            return False
    return True


def bound_edge_pullback_supported(
    source: dict[str, Any],
    target: dict[str, Any],
    pair: dict[str, Any],
) -> bool:
    """Check that every target bound has an exact edge weakest precondition.

    This only recognizes predicates that the generated Lean checker reconstructs
    from the target bound and decoded source behavior. Static table extent is not
    consulted here and therefore cannot become an unchecked runtime bound.
    """
    target_bounds = target.get("bounds", [])
    if not target_bounds:
        return True
    source_ids = {
        _semantic_identity(_predicate_semantics(predicate))
        for predicate in source.get("state_predicates", [])
        if isinstance(predicate, dict)
    }
    edge = _edge_for_target(pair, target)
    if edge is None:
        return False
    original_guard, candidate_guard = edge
    original = pair.get("original_ir")
    candidate = pair.get("candidate_ir")
    if not isinstance(original, dict) or not isinstance(candidate, dict):
        return False
    for bound in target_bounds:
        predicate = _bound_predicate(bound)
        if predicate is None:
            return False
        pulled = _pullback_predicate(predicate, original, candidate)
        if pulled is not None:
            pulled = _guarded_pullback(pulled, original_guard, candidate_guard)
        if (
            pulled is None
            or (
                _semantic_identity(_predicate_semantics(pulled)) not in source_ids
                and not _pulled_predicate_directly_supported(source, pulled)
            )
        ):
            return False
    return True


def attach_no_write_bound_edge_pullbacks(
    contract: dict[str, Any], behaviors: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Attach checked-proposal weakest preconditions for successor bounds.

    Cyclic propagation remains unsupported here. A loop bound requires an
    explicit inductive certificate rather than assuming its own weakest
    precondition around the cycle.
    """
    regions = contract.get("regions", [])
    target_to_index = {
        int(region["numeric_id"]): index
        for index, region in enumerate(regions)
        if isinstance(region, dict) and isinstance(region.get("numeric_id"), int)
    }
    edges: list[
        tuple[int, int, dict[str, Any] | None, dict[str, Any] | None]
    ] = []
    for source_index, pair in enumerate(behaviors):
        for target_id, original_guard, candidate_guard in _paired_no_write_edges(pair):
            target_index = target_to_index.get(target_id)
            if target_index is not None:
                edges.append(
                    (source_index, target_index, original_guard, candidate_guard)
                )
    graph_edges = [(source, target) for source, target, _, _ in edges]
    components = _strongly_connected_components(len(regions), graph_edges)
    component_sizes: dict[int, int] = {}
    for component in components:
        component_sizes[component] = component_sizes.get(component, 0) + 1
    cyclic_components = {
        component for component, size in component_sizes.items() if size > 1
    }
    cyclic_components.update(
        components[source]
        for source, target in graph_edges
        if source == target
    )

    claims: list[dict[str, Any]] = []
    skipped_cycles: set[tuple[int, int, int]] = set()
    unsupported: list[dict[str, Any]] = []
    lowered_stack_bounds: list[dict[str, int]] = []
    for source_index, target_index, original_guard, candidate_guard in edges:
        target = regions[target_index]
        if not target.get("bounds"):
            continue
        source = regions[source_index]
        pair = behaviors[source_index]
        original = pair.get("original_ir")
        candidate = pair.get("candidate_ir")
        if not isinstance(original, dict) or not isinstance(candidate, dict):
            continue
        raw_source_predicates = source.get("state_predicates", [])
        source_predicates = (
            raw_source_predicates if isinstance(raw_source_predicates, list) else []
        )
        source_ids = {
            _semantic_identity(_predicate_semantics(predicate))
            for predicate in source_predicates
            if isinstance(predicate, dict)
        }
        for bound_index, bound in enumerate(target.get("bounds", [])):
            if (
                isinstance(bound, dict)
                and bound.get("expression_source")
                == "checked_stack_register_bound_v1"
            ):
                lowered_stack_bounds.append({
                    "target_region_index": target_index,
                    "bound_index": bound_index,
                })
                continue
            predicate = _bound_predicate(bound)
            pulled = (
                _pullback_predicate(predicate, original, candidate)
                if predicate is not None else None
            )
            if pulled is None:
                unsupported.append({
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "bound_index": bound_index,
                    "reason": "bound_expression_pullback_unsupported",
                })
                continue
            pulled = _guarded_pullback(
                pulled, original_guard, candidate_guard
            )
            identity = _semantic_identity(_predicate_semantics(pulled))
            if identity in source_ids:
                continue
            if components[source_index] in cyclic_components:
                skipped_cycles.add((source_index, target_index, bound_index))
                continue
            if "state_predicates" not in source:
                source["state_predicates"] = source_predicates
            source_predicates.append(pulled)
            source_ids.add(identity)
            claims.append({
                "source_region_index": source_index,
                "target_region_index": target_index,
                "bound_index": bound_index,
                "predicate_sha256": hashlib.sha256(
                    identity.encode("utf-8")
                ).hexdigest(),
            })
    return contract, {
        "format": "stage-a-no-write-bound-edge-pullbacks-v1",
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "eligible_edge_count": sum(
            bool(regions[target].get("bounds")) for _, target, _, _ in edges
        ),
        "attached_predicate_count": len(claims),
        "skipped_cycle_edge_count": len(skipped_cycles),
        "unsupported_bound_count": len(unsupported),
        "lowered_stack_bound_count": len(lowered_stack_bounds),
        "claims": claims,
        "lowered_stack_bounds": lowered_stack_bounds,
        "unsupported": unsupported,
    }


def attach_no_write_state_predicate_pullbacks(
    contract: dict[str, Any], behaviors: list[dict[str, Any]],
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Pull successor predicates back across acyclic paired no-write control."""
    regions = contract.get("regions", [])
    target_to_index = {
        int(region["numeric_id"]): index
        for index, region in enumerate(regions)
        if isinstance(region, dict) and isinstance(region.get("numeric_id"), int)
    }
    edges: list[
        tuple[int, int, dict[str, Any] | None, dict[str, Any] | None]
    ] = []
    for source_index, pair in enumerate(behaviors):
        for target_id, original_guard, candidate_guard in _paired_no_write_edges(pair):
            target_index = target_to_index.get(target_id)
            if target_index is not None:
                edges.append(
                    (source_index, target_index, original_guard, candidate_guard)
                )
    graph_edges = [(source, target) for source, target, _, _ in edges]
    components = _strongly_connected_components(len(regions), graph_edges)
    component_sizes: dict[int, int] = {}
    for component in components:
        component_sizes[component] = component_sizes.get(component, 0) + 1
    cyclic_components = {
        component
        for component, size in component_sizes.items()
        if size > 1
    }
    cyclic_components.update(
        components[source]
        for source, target in graph_edges
        if source == target
    )
    skipped_cycles: list[dict[str, int]] = []
    claims: list[dict[str, Any]] = []
    changed = True
    while changed:
        changed = False
        for source_index, target_index, original_guard, candidate_guard in reversed(edges):
            source = regions[source_index]
            target = regions[target_index]
            pair = behaviors[source_index]
            original = pair["original_ir"]
            candidate = pair["candidate_ir"]
            raw_source_predicates = source.get("state_predicates", [])
            source_predicates = (
                raw_source_predicates if isinstance(raw_source_predicates, list) else []
            )
            source_ids = {
                _semantic_identity(_predicate_semantics(predicate))
                for predicate in source_predicates
                if isinstance(predicate, dict)
            }
            for predicate in target.get("state_predicates", []):
                pulled = _pullback_predicate(predicate, original, candidate)
                if pulled is None:
                    continue
                pulled = _guarded_pullback(
                    pulled, original_guard, candidate_guard
                )
                if _pulled_predicate_directly_supported(source, pulled):
                    continue
                identity = _semantic_identity(_predicate_semantics(pulled))
                if identity in source_ids:
                    continue
                if components[source_index] in cyclic_components:
                    skipped_cycles.append({
                        "source_region_index": source_index,
                        "target_region_index": target_index,
                    })
                    continue
                if "state_predicates" not in source:
                    source["state_predicates"] = source_predicates
                source_predicates.append(pulled)
                source_ids.add(identity)
                changed = True
                claims.append({
                    "source_region_index": source_index,
                    "target_region_index": target_index,
                    "predicate_sha256": hashlib.sha256(identity.encode("utf-8")).hexdigest(),
                })
    return contract, {
        "format": "stage-a-no-write-state-predicate-pullbacks-v1",
        "status": "untrusted_proposal_requires_lean_replay",
        "acceptance_authority": False,
        "eligible_edge_count": len(edges),
        "attached_predicate_count": len(claims),
        "skipped_cycle_edge_count": len({
            (item["source_region_index"], item["target_region_index"])
            for item in skipped_cycles
        }),
        "claims": claims,
    }


__all__ = [
    "attach_no_write_bound_edge_pullbacks",
    "attach_no_write_state_predicate_pullbacks",
    "bound_edge_pullback_supported",
    "state_predicate_pullback_supported",
]
