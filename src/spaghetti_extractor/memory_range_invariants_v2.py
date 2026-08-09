"""Checked address ranges for ordinary counted-loop memory accesses.

The recognizer in this module is untrusted proposal logic. It identifies a
small, common natural-loop shape and submits range, congruence, and flag
relation facts to the generic SCC invariant checker. Address bounds are
exported only from facts accepted by that independent replay.
"""

from __future__ import annotations

import copy
from collections import defaultdict
from collections.abc import Mapping, Sequence
from typing import Any

from .analysis.scc_worklist import strongly_connected_components
from .artifact_identity_v2 import canonical_sha256
from .exception_invariants_v2 import (
    check_exception_invariant_certificate_v2,
    synthesize_exception_invariant_certificate_v2,
)


MEMORY_RANGE_INVARIANTS_V2_FORMAT = (
    "spaghetti-extractor-memory-range-invariants-v2"
)
CHECKED_MEMORY_ADDRESS_RANGE_V2_FORMAT = (
    "stage-a-checked-memory-address-range-v2"
)
_UINT32_LIMIT = 1 << 32
_VALIDATION_CACHE: dict[
    tuple[str, str, str, str], dict[str, Mapping[str, Any]]
] = {}


def derive_memory_range_invariants_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    binary_sha256: str,
    machine_ir_sha256: str,
    solver_timeout_ms: int = 5_000,
) -> dict[str, Any]:
    """Prove address bounds for recognized positive count-up loops."""

    by_id, by_rva = _unit_indexes(units)
    edges = _direct_edges(by_id, by_rva)
    adjacency: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    predecessors: dict[str, set[str]] = {unit_id: set() for unit_id in by_id}
    conditions: dict[tuple[str, str], list[Mapping[str, Any]]] = defaultdict(list)
    for source, target, condition in edges:
        adjacency[source].add(target)
        predecessors[target].add(source)
        conditions[(source, target)].append(condition)

    certificates: list[dict[str, Any]] = []
    checked_facts: list[dict[str, Any]] = []
    address_ranges: list[dict[str, Any]] = []
    frontiers: list[dict[str, Any]] = []
    for members in strongly_connected_components(adjacency):
        member_set = frozenset(members)
        if not _cyclic(members, adjacency):
            continue
        proposal = _natural_loop_proposal(
            members=members,
            member_set=member_set,
            by_id=by_id,
            adjacency=adjacency,
            predecessors=predecessors,
            conditions=conditions,
        )
        if proposal is None:
            if _scc_has_symbolic_memory(members, by_id):
                frontiers.append({
                    "status": "incomplete",
                    "code": "memory_loop_shape_not_recognized",
                    "member_unit_ids": list(members),
                })
            continue
        synthesis = synthesize_exception_invariant_certificate_v2(
            units=units,
            member_ids=members,
            binary_sha256=binary_sha256,
            machine_ir_sha256=machine_ir_sha256,
            requested_facts=proposal["requested_facts"],
            candidate_budget=max(128, proposal["requested_fact_count"] * 4),
            solver_timeout_ms=solver_timeout_ms,
        )
        certificate = synthesis["certificate"]
        report = check_exception_invariant_certificate_v2(
            certificate,
            units=units,
            binary_sha256=binary_sha256,
            machine_ir_sha256=machine_ir_sha256,
            solver_timeout_ms=solver_timeout_ms,
        )
        certificate_row = {
            "id": "memory-range-scc:" + canonical_sha256(certificate),
            "members": list(members),
            "recognition": proposal["recognition"],
            "synthesis_status": synthesis["status"],
            "certificate": certificate,
            "check": report,
        }
        certificates.append(certificate_row)
        if report["status"] != "complete":
            frontiers.append({
                "status": report["status"],
                "code": "memory_loop_invariant_not_proved",
                "member_unit_ids": list(members),
                "issues": copy.deepcopy(report["issues"]),
            })
            continue
        exports = [
            copy.deepcopy(row)
            for row in report["checked_invariants"]
            if isinstance(row, Mapping)
        ]
        checked_facts.extend(exports)
        address_ranges.extend(_address_range_facts(
            members=members,
            by_id=by_id,
            checked_facts=exports,
            certificate_id=certificate_row["id"],
        ))

    issues = sorted(frontiers, key=lambda row: (
        str(row.get("code")), tuple(row.get("member_unit_ids", ()))
    ))
    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues
        else "complete"
    )
    payload = {
        "format": MEMORY_RANGE_INVARIANTS_V2_FORMAT,
        "status": status,
        "binary_sha256": binary_sha256,
        "machine_ir_sha256": machine_ir_sha256,
        "certificates": sorted(certificates, key=lambda row: row["id"]),
        "checked_invariant_facts": sorted(
            checked_facts,
            key=lambda row: (str(row.get("unit_id")), str(row.get("authority_id"))),
        ),
        "checked_address_ranges": sorted(
            address_ranges,
            key=lambda row: (
                str(row["unit_id"]), int(row["event_index"]), str(row["id"])
            ),
        ),
        "counts": {
            "cyclic_sccs": sum(
                _cyclic(component, adjacency)
                for component in strongly_connected_components(adjacency)
            ),
            "checked_sccs": sum(
                row["check"].get("status") == "complete" for row in certificates
            ),
            "checked_invariant_facts": len(checked_facts),
            "checked_address_ranges": len(address_ranges),
            "frontiers": len(frontiers),
        },
        "issues": issues,
    }
    return {**payload, "analysis_sha256": canonical_sha256(payload)}


def validate_memory_range_invariants_v2(
    analysis: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    binary_sha256: str,
    machine_ir_sha256: str,
    solver_timeout_ms: int = 5_000,
) -> dict[str, Mapping[str, Any]]:
    """Replay submitted SCC certificates and exact event-range bindings."""

    expected_fields = {
        "format",
        "status",
        "binary_sha256",
        "machine_ir_sha256",
        "certificates",
        "checked_invariant_facts",
        "checked_address_ranges",
        "counts",
        "issues",
        "analysis_sha256",
    }
    if not isinstance(analysis, Mapping) or set(analysis) != expected_fields:
        raise ValueError("memory-range invariant artifact has noncanonical fields")
    body = {key: copy.deepcopy(value) for key, value in analysis.items() if key != "analysis_sha256"}
    if analysis.get("analysis_sha256") != canonical_sha256(body):
        raise ValueError("memory-range invariant artifact digest is stale")
    if (
        analysis.get("format") != MEMORY_RANGE_INVARIANTS_V2_FORMAT
        or analysis.get("binary_sha256") != binary_sha256
        or analysis.get("machine_ir_sha256") != machine_ir_sha256
    ):
        raise ValueError("memory-range invariant artifact binding is stale")
    cache_key = (
        str(analysis["analysis_sha256"]),
        binary_sha256,
        machine_ir_sha256,
        canonical_sha256(list(units)),
    )
    cached = _VALIDATION_CACHE.get(cache_key)
    if cached is not None:
        return dict(cached)
    by_id, _by_rva = _unit_indexes(units)
    certificates = analysis.get("certificates")
    if not isinstance(certificates, list):
        raise ValueError("memory-range certificate inventory is malformed")
    expected_facts: list[dict[str, Any]] = []
    expected_ranges: list[dict[str, Any]] = []
    seen_certificate_ids: set[str] = set()
    for row in certificates:
        if not isinstance(row, Mapping):
            raise ValueError("memory-range certificate is malformed")
        certificate = row.get("certificate")
        members = row.get("members")
        if not isinstance(certificate, Mapping) or not isinstance(members, list):
            raise ValueError("memory-range certificate payload is malformed")
        identity = "memory-range-scc:" + canonical_sha256(certificate)
        if row.get("id") != identity or identity in seen_certificate_ids:
            raise ValueError("memory-range certificate identity is stale or duplicated")
        seen_certificate_ids.add(identity)
        report = check_exception_invariant_certificate_v2(
            certificate,
            units=units,
            binary_sha256=binary_sha256,
            machine_ir_sha256=machine_ir_sha256,
            solver_timeout_ms=solver_timeout_ms,
        )
        if row.get("check") != report:
            raise ValueError("memory-range certificate replay is stale")
        if report["status"] != "complete":
            continue
        if any(member not in by_id for member in members):
            raise ValueError("memory-range certificate names an unknown unit")
        exports = [copy.deepcopy(value) for value in report["checked_invariants"]]
        expected_facts.extend(exports)
        expected_ranges.extend(_address_range_facts(
            members=members,
            by_id=by_id,
            checked_facts=exports,
            certificate_id=identity,
        ))
    expected_facts.sort(
        key=lambda row: (str(row.get("unit_id")), str(row.get("authority_id")))
    )
    expected_ranges.sort(key=lambda row: (
        str(row["unit_id"]), int(row["event_index"]), str(row["id"])
    ))
    if analysis.get("checked_invariant_facts") != expected_facts:
        raise ValueError("memory-range checked-fact inventory is stale")
    if analysis.get("checked_address_ranges") != expected_ranges:
        raise ValueError("memory-range checked-address inventory is stale")
    result: dict[str, Mapping[str, Any]] = {}
    for row in expected_ranges:
        event_id = f"event:{row['unit_id']}:{row['event_index']}"
        if event_id in result:
            raise ValueError("memory-range facts duplicate an exact event")
        result[event_id] = row
    result = dict(sorted(result.items()))
    if len(_VALIDATION_CACHE) >= 8:
        _VALIDATION_CACHE.pop(next(iter(_VALIDATION_CACHE)))
    _VALIDATION_CACHE[cache_key] = dict(result)
    return result


def _natural_loop_proposal(
    *,
    members: Sequence[str],
    member_set: frozenset[str],
    by_id: Mapping[str, Mapping[str, Any]],
    adjacency: Mapping[str, set[str]],
    predecessors: Mapping[str, set[str]],
    conditions: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
) -> dict[str, Any] | None:
    incoming = sorted(
        (source, target)
        for target in members
        for source in predecessors[target]
        if source not in member_set
    )
    headers = {target for _source, target in incoming}
    if len(headers) != 1 or not incoming:
        return None
    header = next(iter(headers))
    latches = sorted(
        source for source in members
        if header in adjacency[source] and source != header
    )
    if len(latches) != 1:
        return None
    latch = latches[0]
    order = _single_body_order(header, latch, member_set, adjacency)
    if order is None or set(order) != member_set:
        return None

    incoming_constants: dict[str, int] = {}
    for source, target in incoming:
        if target != header:
            return None
        for register, value in _constant_register_writes(by_id[source]).items():
            prior = incoming_constants.setdefault(register, value)
            if prior != value:
                return None

    updates: list[tuple[str, str, int]] = []
    for unit_id in members:
        for register, expression in _register_writes(by_id[unit_id]).items():
            step = _positive_self_increment(expression, register)
            if step is not None:
                updates.append((unit_id, register, step))
    for update_unit, register, step in updates:
        base = incoming_constants.get(register)
        if base is None:
            continue
        comparison = _signed_loop_comparison(
            latch=latch,
            header=header,
            register=register,
            order=order,
            by_id=by_id,
            conditions=conditions,
        )
        if comparison is None:
            continue
        bound, flag_producer, branch_relation = comparison
        if not (0 <= base <= bound < 0x8000_0000 and base + step <= bound):
            continue
        if (bound - base) % step:
            continue
        if any(
            register in _register_writes(by_id[unit_id])
            and unit_id != update_unit
            for unit_id in members
        ):
            continue
        requested = _loop_requested_facts(
            order=order,
            by_id=by_id,
            induction_register=register,
            base=base,
            bound=bound,
            step=step,
            branch_relation=branch_relation,
            flag_producer=flag_producer,
            latch=latch,
        )
        if requested is None:
            continue
        return {
            "requested_facts": requested,
            "requested_fact_count": sum(len(rows) for rows in requested.values()),
            "recognition": {
                "kind": "positive-count-up-natural-loop-v2",
                "header_unit_id": header,
                "latch_unit_id": latch,
                "flag_producer_unit_id": flag_producer,
                "update_unit_id": update_unit,
                "induction_register": register,
                "base": base,
                "bound": bound,
                "step": step,
            },
        }
    return None


def _loop_requested_facts(
    *,
    order: Sequence[str],
    by_id: Mapping[str, Mapping[str, Any]],
    induction_register: str,
    base: int,
    bound: int,
    step: int,
    branch_relation: Mapping[str, Any],
    flag_producer: str,
    latch: str,
) -> dict[str, list[dict[str, Any]]] | None:
    intervals: dict[str, tuple[int, int]] = {
        induction_register: (base, bound - step)
    }
    result: dict[str, list[dict[str, Any]]] = {}
    relation_active = False
    for unit_id in order:
        relevant = _memory_address_registers(by_id[unit_id]) | {induction_register}
        facts = [
            _range_fact(register, *intervals[register])
            for register in sorted(relevant & intervals.keys())
        ]
        induction_range = intervals.get(induction_register)
        if induction_range is not None:
            facts.append({
                "kind": "congruence",
                "expression": _reg(induction_register),
                "modulus": step,
                "remainder": base % step,
            })
        if relation_active or unit_id == latch:
            facts.append({
                "kind": "predicate",
                "expression": copy.deepcopy(dict(branch_relation)),
            })
        result[unit_id] = _unique_facts(facts)
        post = _apply_interval_writes(by_id[unit_id], intervals)
        if post is None:
            return None
        intervals = post
        if unit_id == flag_producer:
            relation_active = True
    return result


def _signed_loop_comparison(
    *,
    latch: str,
    header: str,
    register: str,
    order: Sequence[str],
    by_id: Mapping[str, Mapping[str, Any]],
    conditions: Mapping[tuple[str, str], Sequence[Mapping[str, Any]]],
) -> tuple[int, str, dict[str, Any]] | None:
    loop_conditions = conditions.get((latch, header), ())
    if len(loop_conditions) != 1:
        return None
    branch = copy.deepcopy(dict(loop_conditions[0]))
    if not _xor_flags(branch, "sf", "of"):
        return None
    latch_index = order.index(latch)
    for unit_id in reversed(order[: latch_index + 1]):
        flags = _flag_writes(by_id[unit_id])
        sf = flags.get("sf")
        of = flags.get("of")
        bound = _cmp_bound(sf, of, register)
        if bound is None:
            if flags:
                return None
            continue
        relation = {
            "op": "eq_bool",
            "args": [
                branch,
                {"op": "ult32", "args": [_reg(register), _const(bound)]},
            ],
        }
        return bound, unit_id, relation
    return None


def _cmp_bound(sf: Any, of: Any, register: str) -> int | None:
    if not isinstance(sf, Mapping) or sf.get("op") != "msb":
        return None
    sf_args = sf.get("args")
    if not isinstance(sf_args, list) or len(sf_args) != 2 or sf_args[0] != 32:
        return None
    subtraction = sf_args[1]
    if not _register_minus_constant(subtraction, register):
        return None
    assert isinstance(subtraction, Mapping)
    sub_args = subtraction["args"]
    bound = _constant(sub_args[1])
    if bound is None or not isinstance(of, Mapping) or of.get("op") != "sub_overflow":
        return None
    of_args = of.get("args")
    if (
        not isinstance(of_args, list)
        or len(of_args) != 4
        or of_args[0] != 32
        or of_args[1] != sub_args[0]
        or of_args[2] != sub_args[1]
        or of_args[3] != subtraction
    ):
        return None
    return bound


def _address_range_facts(
    *,
    members: Sequence[str],
    by_id: Mapping[str, Mapping[str, Any]],
    checked_facts: Sequence[Mapping[str, Any]],
    certificate_id: str,
) -> list[dict[str, Any]]:
    facts_by_unit: dict[str, list[Mapping[str, Any]]] = defaultdict(list)
    for row in checked_facts:
        unit_id = row.get("unit_id")
        fact = row.get("fact")
        if isinstance(unit_id, str) and isinstance(fact, Mapping):
            facts_by_unit[unit_id].append(row)
    result: list[dict[str, Any]] = []
    for unit_id in members:
        intervals, dependencies = _fact_intervals(facts_by_unit.get(unit_id, ()))
        semantics = _semantics(by_id[unit_id])
        events = semantics.get("memory_events")
        if not isinstance(events, list):
            continue
        for event_index, raw in enumerate(events):
            if not isinstance(raw, Mapping):
                continue
            width = raw.get("width")
            if (
                raw.get("kind") not in {"read", "write", "read_write"}
                or not isinstance(width, int)
                or isinstance(width, bool)
                or not 0 < width <= 4096
            ):
                continue
            span = _interval_expression(raw.get("address"), intervals)
            if span is None or span[1] + width > _UINT32_LIMIT:
                continue
            base = {
                "format": CHECKED_MEMORY_ADDRESS_RANGE_V2_FORMAT,
                "status": "complete",
                "unit_id": unit_id,
                "event_index": event_index,
                "memory_kind": raw.get("kind"),
                "width_bytes": width,
                "address_expression": copy.deepcopy(raw.get("address")),
                "minimum_address": span[0],
                "maximum_address": span[1],
                "invariant_authority_ids": sorted(dependencies),
                "certificate_id": certificate_id,
            }
            identity = "memory-address-range:" + canonical_sha256(base)[:20]
            result.append({
                **base,
                "id": identity,
                "fact_sha256": canonical_sha256({**base, "id": identity}),
            })
    return result


def _fact_intervals(
    rows: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, tuple[int, int]], set[str]]:
    intervals: dict[str, tuple[int, int]] = {}
    dependencies: set[str] = set()
    for row in rows:
        fact = row.get("fact")
        authority_id = row.get("authority_id")
        if not isinstance(fact, Mapping) or not isinstance(authority_id, str):
            continue
        expression = fact.get("expression")
        register = _register_name(expression)
        if register is None:
            continue
        if fact.get("kind") == "range":
            minimum, maximum = fact.get("minimum"), fact.get("maximum")
        elif fact.get("kind") == "finite_values":
            values = fact.get("values")
            if not isinstance(values, list) or not values:
                continue
            minimum, maximum = min(values), max(values)
        else:
            continue
        if not _u32(minimum) or not _u32(maximum) or minimum > maximum:
            continue
        intervals[register] = (int(minimum), int(maximum))
        dependencies.add(authority_id)
    return intervals, dependencies


def _apply_interval_writes(
    unit: Mapping[str, Any], intervals: Mapping[str, tuple[int, int]]
) -> dict[str, tuple[int, int]] | None:
    output = dict(intervals)
    for register, expression in _register_writes(unit).items():
        value = _interval_expression(expression, intervals)
        if value is None:
            output.pop(register, None)
        else:
            output[register] = value
    return output


def _interval_expression(
    expression: Any, intervals: Mapping[str, tuple[int, int]]
) -> tuple[int, int] | None:
    constant = _constant(expression)
    if constant is not None:
        return constant, constant
    register = _register_name(expression)
    if register is not None:
        return intervals.get(register)
    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    args = expression.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    if op in {"add", "add32"}:
        for base_expression, delta_expression in (args, reversed(args)):
            delta = _constant(delta_expression)
            base_interval = _interval_expression(base_expression, intervals)
            if delta is None or base_interval is None:
                continue
            signed_delta = delta - _UINT32_LIMIT if delta >= 0x8000_0000 else delta
            minimum = base_interval[0] + signed_delta
            maximum = base_interval[1] + signed_delta
            return (
                (minimum, maximum)
                if 0 <= minimum <= maximum < _UINT32_LIMIT
                else None
            )
    if op in {"sub", "sub32"}:
        delta = _constant(args[1])
        base_interval = _interval_expression(args[0], intervals)
        if delta is not None and base_interval is not None:
            signed_delta = delta - _UINT32_LIMIT if delta >= 0x8000_0000 else delta
            minimum = base_interval[0] - signed_delta
            maximum = base_interval[1] - signed_delta
            return (
                (minimum, maximum)
                if 0 <= minimum <= maximum < _UINT32_LIMIT
                else None
            )
    left = _interval_expression(args[0], intervals)
    right = _interval_expression(args[1], intervals)
    if left is None or right is None:
        return None
    if op in {"add", "add32"}:
        minimum, maximum = left[0] + right[0], left[1] + right[1]
    elif op in {"sub", "sub32"}:
        minimum, maximum = left[0] - right[1], left[1] - right[0]
    elif op in {"mul", "mul32"} and min(*left, *right) >= 0:
        products = [a * b for a in left for b in right]
        minimum, maximum = min(products), max(products)
    else:
        return None
    if not (0 <= minimum <= maximum < _UINT32_LIMIT):
        return None
    return minimum, maximum


def _single_body_order(
    header: str,
    latch: str,
    members: frozenset[str],
    adjacency: Mapping[str, set[str]],
) -> list[str] | None:
    order: list[str] = []
    current = header
    while current not in order:
        order.append(current)
        if current == latch:
            return order
        successors = sorted(adjacency[current] & members)
        if len(successors) != 1:
            return None
        current = successors[0]
    return None


def _direct_edges(
    by_id: Mapping[str, Mapping[str, Any]],
    by_rva: Mapping[int, str],
) -> list[tuple[str, str, Mapping[str, Any]]]:
    result: list[tuple[str, str, Mapping[str, Any]]] = []
    for unit_id, unit in sorted(by_id.items()):
        semantics = _semantics(unit)
        rows = semantics.get("edge_conditions")
        if not isinstance(rows, list):
            continue
        for row in rows:
            if not isinstance(row, Mapping):
                continue
            target = by_rva.get(row.get("target_rva"))
            condition = row.get("condition")
            if target is not None and isinstance(condition, Mapping):
                result.append((unit_id, target, copy.deepcopy(dict(condition))))
    return result


def _unit_indexes(
    units: Sequence[Mapping[str, Any]],
) -> tuple[dict[str, Mapping[str, Any]], dict[int, str]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    by_rva: dict[int, str] = {}
    for unit in units:
        unit_id = unit.get("id") if isinstance(unit, Mapping) else None
        source = unit.get("source") if isinstance(unit, Mapping) else None
        original = source.get("original") if isinstance(source, Mapping) else None
        rva = original.get("rva_start") if isinstance(original, Mapping) else None
        if (
            not isinstance(unit_id, str)
            or not unit_id
            or unit_id in by_id
            or not isinstance(rva, int)
            or isinstance(rva, bool)
            or rva in by_rva
        ):
            raise ValueError("memory-range analysis received malformed machine IR")
        by_id[unit_id] = unit
        by_rva[rva] = unit_id
    return by_id, by_rva


def _register_writes(unit: Mapping[str, Any]) -> dict[str, Any]:
    writes = _semantics(unit).get("register_writes")
    return {
        str(row["register"]): row.get("value")
        for row in writes if isinstance(writes, list) and isinstance(row, Mapping)
        if isinstance(row.get("register"), str)
    }


def _constant_register_writes(unit: Mapping[str, Any]) -> dict[str, int]:
    return {
        register: value
        for register, expression in _register_writes(unit).items()
        if (value := _constant(expression)) is not None
    }


def _flag_writes(unit: Mapping[str, Any]) -> dict[str, Any]:
    writes = _semantics(unit).get("flag_writes")
    return {
        str(row["flag"]): row.get("value")
        for row in writes if isinstance(writes, list) and isinstance(row, Mapping)
        if isinstance(row.get("flag"), str)
    }


def _semantics(unit: Mapping[str, Any]) -> Mapping[str, Any]:
    value = unit.get("semantics")
    return value if isinstance(value, Mapping) else {}


def _positive_self_increment(expression: Any, register: str) -> int | None:
    if not isinstance(expression, Mapping) or expression.get("op") not in {"add", "add32"}:
        return None
    args = expression.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    for reg_value, constant_value in (args, reversed(args)):
        if _register_name(reg_value) == register:
            value = _constant(constant_value)
            if value is not None and 0 < value < 0x8000_0000:
                return value
    return None


def _register_minus_constant(expression: Any, register: str) -> bool:
    if not isinstance(expression, Mapping) or expression.get("op") not in {"sub", "sub32"}:
        return False
    args = expression.get("args")
    return (
        isinstance(args, list)
        and len(args) == 2
        and _register_name(args[0]) == register
        and _constant(args[1]) is not None
    )


def _xor_flags(expression: Any, left: str, right: str) -> bool:
    if not isinstance(expression, Mapping) or expression.get("op") != "xor_bool":
        return False
    args = expression.get("args")
    return isinstance(args, list) and len(args) == 2 and {
        _flag_name(args[0]), _flag_name(args[1])
    } == {left, right}


def _constant(expression: Any) -> int | None:
    if not isinstance(expression, Mapping) or expression.get("op") not in {"const", "constant"}:
        return None
    value = expression.get("value")
    return value if _u32(value) else None


def _register_name(expression: Any) -> str | None:
    if not isinstance(expression, Mapping) or expression.get("op") not in {"reg", "register", "input_reg"}:
        return None
    value = expression.get("name", expression.get("reg"))
    return str(value) if isinstance(value, str) and value else None


def _flag_name(expression: Any) -> str | None:
    if not isinstance(expression, Mapping) or expression.get("op") != "flag":
        return None
    value = expression.get("name")
    return str(value) if isinstance(value, str) and value else None


def _memory_address_registers(unit: Mapping[str, Any]) -> set[str]:
    result: set[str] = set()
    events = _semantics(unit).get("memory_events")
    for event in events if isinstance(events, list) else ():
        if isinstance(event, Mapping):
            _collect_registers(event.get("address"), result)
    return result


def _collect_registers(expression: Any, result: set[str]) -> None:
    register = _register_name(expression)
    if register is not None:
        result.add(register)
        return
    if isinstance(expression, Mapping):
        for value in expression.values():
            _collect_registers(value, result)
    elif isinstance(expression, list):
        for value in expression:
            _collect_registers(value, result)


def _scc_has_symbolic_memory(
    members: Sequence[str], by_id: Mapping[str, Mapping[str, Any]]
) -> bool:
    return any(_memory_address_registers(by_id[member]) for member in members)


def _range_fact(register: str, minimum: int, maximum: int) -> dict[str, Any]:
    return {
        "kind": "range",
        "expression": _reg(register),
        "minimum": minimum,
        "maximum": maximum,
    }


def _reg(name: str) -> dict[str, Any]:
    return {"op": "reg", "name": name, "width": 32}


def _const(value: int) -> dict[str, Any]:
    return {"op": "const", "value": value, "width": 32}


def _unique_facts(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    by_digest = {canonical_sha256(row): copy.deepcopy(dict(row)) for row in rows}
    return [by_digest[digest] for digest in sorted(by_digest)]


def _cyclic(
    members: Sequence[str], adjacency: Mapping[str, set[str]]
) -> bool:
    return len(members) > 1 or bool(members and members[0] in adjacency[members[0]])


def _u32(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value < _UINT32_LIMIT
    )


__all__ = [
    "CHECKED_MEMORY_ADDRESS_RANGE_V2_FORMAT",
    "MEMORY_RANGE_INVARIANTS_V2_FORMAT",
    "derive_memory_range_invariants_v2",
    "validate_memory_range_invariants_v2",
]
