"""Checked cutpoint invariants for machine-IR control and fault closure.

The same invariant kernel supports cyclic exceptional-control SCCs and finite
acyclic regions ending at an explicitly declared indirect-control frontier.
Both forms are checked against exact machine-IR records using initiation and
one-step preservation; neither uses bounded path or predecessor enumeration.
"""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from typing import Any, Mapping, Sequence

from .reconstruction_validation import check_straight_line_semantic_claim


EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT = (
    "stage-a-scc-exception-invariant-certificate-v2"
)
EXCEPTION_INVARIANT_CHECK_V2_FORMAT = "stage-a-scc-exception-invariant-check-v2"
EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT = (
    "stage-a-scc-exception-invariant-proposal-v2"
)
CONTROL_INVARIANT_CERTIFICATE_V2_FORMAT = (
    "stage-a-control-invariant-certificate-v2"
)
CONTROL_INVARIANT_CHECK_V2_FORMAT = "stage-a-control-invariant-check-v2"
CONTROL_INVARIANT_PROPOSAL_V2_FORMAT = "stage-a-control-invariant-proposal-v2"
SUPPORTED_SEH_INVENTORY_V2_FORMAT = "stage-a-supported-seh-target-inventory-v2"

_DIGEST_LENGTH = 64
_LOCAL_QF_BV_FAULTS = frozenset({"divide_error"})


class ExceptionInvariantV2Error(ValueError):
    """A caller option, rather than certificate evidence, is invalid."""


def canonical_sha256(value: Any) -> str:
    """Return the canonical JSON SHA-256 used by all v2 bindings."""

    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        ).encode("ascii")
    ).hexdigest()


def exception_invariant_unit_binding(unit: Mapping[str, Any]) -> dict[str, str]:
    """Bind one exact canonical machine-IR unit and both source digests."""

    unit_id = unit.get("id")
    source = unit.get("source")
    if not isinstance(unit_id, str) or not unit_id or not isinstance(source, Mapping):
        raise ExceptionInvariantV2Error("machine-IR unit identity/source is malformed")
    contract = source.get("contract_sha256")
    instruction = source.get("instruction_bytes_sha256")
    if not _digest(contract) or not _digest(instruction):
        raise ExceptionInvariantV2Error("machine-IR unit source digests are malformed")
    return {
        "unit_id": unit_id,
        "unit_sha256": canonical_sha256(unit),
        "contract_sha256": str(contract),
        "instruction_bytes_sha256": str(instruction),
    }


def derive_exception_scc_inventory(
    units: Sequence[Mapping[str, Any]], member_ids: Sequence[str]
) -> dict[str, Any]:
    """Derive the exact internal-edge and normal/terminal-exit inventory."""

    by_id, by_rva = _unit_indexes(units)
    members = tuple(sorted(member_ids))
    if not members or len(set(members)) != len(members):
        raise ExceptionInvariantV2Error("SCC members must be nonempty and unique")
    if any(member not in by_id for member in members):
        raise ExceptionInvariantV2Error("SCC member is absent from machine IR")
    member_set = frozenset(members)
    all_edges: list[dict[str, Any]] = []
    exits: list[dict[str, Any]] = []
    incomplete: list[str] = []
    for unit in units:
        source_id = str(unit["id"])
        edges, terminal, reason = _unit_control(unit, by_rva)
        all_edges.extend(edges)
        if source_id in member_set:
            exits.extend(
                edge for edge in edges if edge.get("target_unit_id") not in member_set
            )
            if terminal is not None:
                exits.append(terminal)
            if reason is not None:
                incomplete.append(f"{source_id}:{reason}")
    internal = [
        edge
        for edge in all_edges
        if edge["source_unit_id"] in member_set
        and edge.get("target_unit_id") in member_set
    ]
    incoming = [
        edge
        for edge in all_edges
        if edge["source_unit_id"] not in member_set
        and edge.get("target_unit_id") in member_set
    ]
    return {
        "members": list(members),
        "edges": sorted(internal, key=_edge_key),
        "incoming": sorted(incoming, key=_edge_key),
        "exits": sorted(exits, key=_exit_key),
        "incomplete_reasons": sorted(incomplete),
    }


def derive_control_region_inventory(
    units: Sequence[Mapping[str, Any]],
    member_ids: Sequence[str],
    frontier_member_ids: Sequence[str],
) -> dict[str, Any]:
    """Derive a finite region whose declared sinks have indirect control.

    An indirect exit is permitted only at an exact declared frontier member.
    The frontier declaration does not resolve that exit; it merely allows a
    checked invariant at the member's entry to be reused by the separate
    indirect-exit certificate.
    """

    inventory = derive_exception_scc_inventory(units, member_ids)
    members = frozenset(inventory["members"])
    frontiers = tuple(sorted(frontier_member_ids))
    if len(set(frontiers)) != len(frontiers) or any(
        frontier not in members for frontier in frontiers
    ):
        raise ExceptionInvariantV2Error(
            "control-region frontiers must be unique region members"
        )
    expected = {
        reason.removesuffix(":indirect_or_unknown_control")
        for reason in inventory["incomplete_reasons"]
        if reason.endswith(":indirect_or_unknown_control")
    }
    if set(frontiers) != expected:
        raise ExceptionInvariantV2Error(
            "control-region frontiers do not match indirect-control sinks"
        )
    remaining = [
        reason
        for reason in inventory["incomplete_reasons"]
        if not reason.endswith(":indirect_or_unknown_control")
    ]
    return {
        **inventory,
        "frontier_members": list(frontiers),
        "incomplete_reasons": remaining,
    }


def synthesize_exception_invariant_certificate_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    member_ids: Sequence[str],
    binary_sha256: str,
    machine_ir_sha256: str,
    root_assumptions: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    requested_facts: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    finite_value_budget: int = 32,
    candidate_budget: int = 128,
    solver_timeout_ms: int = 5_000,
) -> dict[str, Any]:
    """Propose, but never authorize, one replayable SCC certificate.

    Candidates come only from exact edge guards, caller-supplied root facts,
    requested facts, and exact constant register writes in the supplied
    machine IR. Requested facts are untrusted guidance and are exported only
    after the independent checker proves initiation and inductive preservation.
    Local QF_BV checks prune candidates before that authority replay.

    The synthesis is deliberately bounded and fail-closed.  Unsupported
    predicates, candidate overflow, and faults that cannot be shown infeasible
    produce an ``incomplete`` proposal and an explicit-incomplete fault claim.
    It never performs bounded path or predecessor enumeration.
    """

    return _synthesize_invariant_certificate_v2(
        units=units,
        member_ids=member_ids,
        binary_sha256=binary_sha256,
        machine_ir_sha256=machine_ir_sha256,
        root_assumptions=root_assumptions,
        finite_value_budget=finite_value_budget,
        candidate_budget=candidate_budget,
        solver_timeout_ms=solver_timeout_ms,
        certificate_format=EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT,
        proposal_format=EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT,
        region_key="scc",
        require_cyclic=True,
        frontier_member_ids=(),
        requested_facts=requested_facts,
        include_faults=True,
    )


def synthesize_control_invariant_certificate_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    member_ids: Sequence[str],
    frontier_member_ids: Sequence[str],
    requested_facts: Mapping[str, Sequence[Mapping[str, Any]]],
    binary_sha256: str,
    machine_ir_sha256: str,
    root_assumptions: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    finite_value_budget: int = 32,
    candidate_budget: int = 128,
    solver_timeout_ms: int = 5_000,
) -> dict[str, Any]:
    """Propose replayable facts at finite indirect-control cutpoints.

    ``requested_facts`` is untrusted synthesis guidance. The replay checker
    independently proves each retained fact from exact incoming transitions.
    """

    return _synthesize_invariant_certificate_v2(
        units=units,
        member_ids=member_ids,
        binary_sha256=binary_sha256,
        machine_ir_sha256=machine_ir_sha256,
        root_assumptions=root_assumptions,
        finite_value_budget=finite_value_budget,
        candidate_budget=candidate_budget,
        solver_timeout_ms=solver_timeout_ms,
        certificate_format=CONTROL_INVARIANT_CERTIFICATE_V2_FORMAT,
        proposal_format=CONTROL_INVARIANT_PROPOSAL_V2_FORMAT,
        region_key="region",
        require_cyclic=False,
        frontier_member_ids=frontier_member_ids,
        requested_facts=requested_facts,
        include_faults=False,
    )


def _synthesize_invariant_certificate_v2(
    *,
    units: Sequence[Mapping[str, Any]],
    member_ids: Sequence[str],
    binary_sha256: str,
    machine_ir_sha256: str,
    root_assumptions: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    finite_value_budget: int,
    candidate_budget: int,
    solver_timeout_ms: int,
    certificate_format: str,
    proposal_format: str,
    region_key: str,
    require_cyclic: bool,
    frontier_member_ids: Sequence[str],
    requested_facts: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    include_faults: bool,
) -> dict[str, Any]:
    if not _digest(binary_sha256) or not _digest(machine_ir_sha256):
        raise ExceptionInvariantV2Error("binary bindings must be SHA-256 digests")
    for name, value in (
        ("finite-value", finite_value_budget),
        ("candidate", candidate_budget),
        ("solver timeout", solver_timeout_ms),
    ):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise ExceptionInvariantV2Error(f"{name} budget must be a positive integer")

    by_id, _by_rva = _unit_indexes(units)
    members = tuple(sorted(member_ids))
    inventory = (
        derive_exception_scc_inventory(units, members)
        if require_cyclic
        else derive_control_region_inventory(units, members, frontier_member_ids)
    )
    member_set = frozenset(members)
    assumptions = _normalize_root_assumptions(root_assumptions, member_set)
    requested = _normalize_requested_facts(
        requested_facts,
        member_set,
        finite_value_budget=finite_value_budget,
    )
    issues: list[dict[str, str]] = []

    if inventory["incomplete_reasons"]:
        issues.extend(
            _issue("incomplete", "control_effect_unknown", str(reason))
            for reason in inventory["incomplete_reasons"]
        )
    if require_cyclic and not _is_cyclic_strong_component(members, inventory["edges"]):
        issues.append(_issue("incomplete", "members_do_not_form_cyclic_scc"))

    candidates: dict[str, list[dict[str, Any]]] = {
        member: [] for member in members
    }
    incoming_by_target = _edges_by_target(
        [*inventory["incoming"], *inventory["edges"]]
    )
    for member in members:
        for predicate in assumptions.get(member, ()):
            _extend_candidate_facts(
                candidates[member],
                predicate,
                finite_value_budget=finite_value_budget,
                issues=issues,
                detail=f"root:{member}",
            )
        for edge in incoming_by_target.get(member, ()):
            source = by_id[str(edge["source_unit_id"])]
            for fact in _facts_preserved_across_edge(
                edge["condition"], source, finite_value_budget, issues
            ):
                _append_unique_fact(candidates[member], fact)
            for fact in _constant_post_write_facts(source):
                _append_unique_fact(candidates[member], fact)
        for fact in requested.get(member, ()):
            _append_unique_fact(candidates[member], fact)

    total_candidates = sum(len(values) for values in candidates.values())
    if total_candidates > candidate_budget:
        issues.append(
            _issue(
                "incomplete",
                "invariant_candidate_budget_exceeded",
                f"{total_candidates}>{candidate_budget}",
            )
        )
        candidates = _truncate_candidate_facts(candidates, candidate_budget)

    # Facts are removed to a deterministic fixed point.  A fact may depend on
    # facts retained at predecessor cutpoints, but cannot appear solely because
    # it was submitted: every incoming transition or root initiation is checked.
    changed = True
    while changed:
        changed = False
        predicates = {
            member: _predicate_for_facts(facts)
            for member, facts in candidates.items()
        }
        for member in members:
            kept: list[dict[str, Any]] = []
            for fact in candidates[member]:
                conclusion = _invariant_predicate(
                    {"unit_id": member, "facts": [fact]}
                )
                if _candidate_is_inductive(
                    member,
                    conclusion,
                    inventory=inventory,
                    incoming_by_target=incoming_by_target,
                    by_id=by_id,
                    member_set=member_set,
                    source_predicates=predicates,
                    root_assumptions=assumptions,
                    timeout=solver_timeout_ms,
                ):
                    kept.append(fact)
                else:
                    changed = True
            candidates[member] = kept

    invariants = [
        {"unit_id": member, "facts": candidates[member]}
        for member in members
    ]
    retained_requested: dict[str, list[dict[str, Any]]] = {}
    for unit_id, facts in requested.items():
        retained_digests = {
            canonical_sha256(fact) for fact in candidates.get(unit_id, ())
        }
        retained_requested[unit_id] = [
            fact for fact in facts if canonical_sha256(fact) in retained_digests
        ]
        for fact in facts:
            if canonical_sha256(fact) not in retained_digests:
                issues.append(
                    _issue(
                        "incomplete",
                        "requested_control_fact_not_synthesized",
                        f"{unit_id}:{canonical_sha256(fact)}",
                    )
                )

    initiation = _synthesized_initiation(inventory, assumptions, members)
    if not initiation:
        issues.append(_issue("incomplete", "initiation_not_synthesized"))

    predicates = {
        row["unit_id"]: _invariant_predicate(row) for row in invariants
    }
    faults: list[dict[str, Any]] = []
    for key, fault in (
        sorted(_fault_inventory(by_id, members).items()) if include_faults else ()
    ):
        claim = {
            "source_unit_id": key[0],
            "fault_index": key[1],
            "fault_sha256": canonical_sha256(fault),
            "outcome": {"kind": "incomplete"},
        }
        predicate = predicates.get(key[0])
        condition = fault.get("condition")
        if (
            predicate is not None
            and fault.get("kind") in _LOCAL_QF_BV_FAULTS
            and isinstance(condition, Mapping)
        ):
            result = _check_implication(
                [predicate, condition], _false(), solver_timeout_ms
            )
            if result["status"] == "complete":
                claim["outcome"] = {"kind": "checked_infeasible"}
            else:
                issues.append(
                    _issue(
                        "incomplete",
                        "fault_infeasibility_not_synthesized",
                        f"{key[0]}:{key[1]}",
                    )
                )
        else:
            issues.append(
                _issue(
                    "incomplete",
                    "fault_predicate_not_synthesizable",
                    f"{key[0]}:{key[1]}",
                )
            )
        faults.append(claim)

    certificate = {
        "format": certificate_format,
        "bindings": {
            "binary_sha256": binary_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "units": [exception_invariant_unit_binding(by_id[member]) for member in members],
        },
        region_key: {
            "members": list(members),
            "edges": inventory["edges"],
            "exits": inventory["exits"],
            **(
                {"frontier_members": inventory["frontier_members"]}
                if not require_cyclic
                else {}
            ),
        },
        "invariants": invariants,
        "preservation": inventory["edges"],
        "initiation": initiation,
        **({"faults": faults} if include_faults else {}),
        **(
            {
                "requested_facts": [
                    {"unit_id": unit_id, "facts": retained_requested[unit_id]}
                    for unit_id in sorted(retained_requested)
                    if retained_requested[unit_id]
                ]
            }
            if requested
            else {}
        ),
    }
    normalized_issues = _normalize_issues(issues)
    return {
        "format": proposal_format,
        "status": "incomplete" if normalized_issues else "complete",
        "authorizing": False,
        "uses_bounded_paths": False,
        "inputs": {
            "binary_sha256": binary_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "member_ids": list(members),
            "root_assumptions_sha256": canonical_sha256(assumptions),
            "requested_facts_sha256": canonical_sha256(requested),
            "finite_value_budget": finite_value_budget,
            "candidate_budget": candidate_budget,
        },
        "certificate": certificate,
        "certificate_sha256": canonical_sha256(certificate),
        "issues": normalized_issues,
    }


def _normalize_root_assumptions(
    raw: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    members: frozenset[str],
) -> dict[str, list[dict[str, Any]]]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ExceptionInvariantV2Error("root assumptions must be an object")
    result: dict[str, list[dict[str, Any]]] = {}
    for unit_id in sorted(raw):
        if unit_id not in members:
            raise ExceptionInvariantV2Error(
                f"root assumption target {unit_id!r} is outside the SCC"
            )
        values = raw[unit_id]
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise ExceptionInvariantV2Error("root assumptions must be arrays")
        normalized: list[dict[str, Any]] = []
        for value in values:
            if not isinstance(value, Mapping):
                raise ExceptionInvariantV2Error("root assumption is malformed")
            normalized.append(copy.deepcopy(dict(value)))
        result[unit_id] = normalized
    return result


def _normalize_requested_facts(
    raw: Mapping[str, Sequence[Mapping[str, Any]]] | None,
    members: frozenset[str],
    *,
    finite_value_budget: int,
) -> dict[str, list[dict[str, Any]]]:
    if raw is None:
        return {}
    if not isinstance(raw, Mapping):
        raise ExceptionInvariantV2Error("requested facts must be an object")
    result: dict[str, list[dict[str, Any]]] = {}
    for unit_id in sorted(raw):
        if unit_id not in members:
            raise ExceptionInvariantV2Error(
                f"requested-fact target {unit_id!r} is outside the region"
            )
        values = raw[unit_id]
        if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
            raise ExceptionInvariantV2Error("requested facts must be arrays")
        normalized: list[dict[str, Any]] = []
        for value in values:
            if not isinstance(value, Mapping):
                raise ExceptionInvariantV2Error("requested invariant fact is malformed")
            fact = copy.deepcopy(dict(value))
            _invariant_predicate({"unit_id": unit_id, "facts": [fact]})
            finite_values = fact.get("values") if fact.get("kind") == "finite_values" else None
            if isinstance(finite_values, list) and len(finite_values) > finite_value_budget:
                raise ExceptionInvariantV2Error(
                    "requested finite-value fact exceeds the configured budget"
                )
            _append_unique_fact(normalized, fact)
        result[unit_id] = normalized
    return result


def _edges_by_target(
    edges: Sequence[Mapping[str, Any]],
) -> dict[str, list[Mapping[str, Any]]]:
    result: dict[str, list[Mapping[str, Any]]] = {}
    for edge in sorted(edges, key=_edge_key):
        target = edge.get("target_unit_id")
        if isinstance(target, str):
            result.setdefault(target, []).append(edge)
    return result


def _extend_candidate_facts(
    destination: list[dict[str, Any]],
    predicate: Mapping[str, Any],
    *,
    finite_value_budget: int,
    issues: list[dict[str, str]],
    detail: str,
) -> None:
    facts, supported = _candidate_facts_from_predicate(
        predicate, finite_value_budget=finite_value_budget
    )
    if not supported:
        issues.append(_issue("incomplete", "predicate_shape_unsupported", detail))
    for fact in facts:
        _append_unique_fact(destination, fact)


def _facts_preserved_across_edge(
    predicate: Mapping[str, Any],
    source: Mapping[str, Any],
    finite_value_budget: int,
    issues: list[dict[str, str]],
) -> list[dict[str, Any]]:
    facts, supported = _candidate_facts_from_predicate(
        predicate, finite_value_budget=finite_value_budget
    )
    if not supported:
        issues.append(
            _issue(
                "incomplete",
                "edge_guard_shape_unsupported",
                str(source.get("id", "")),
            )
        )
    written = _written_registers(source)
    return [
        fact
        for fact in facts
        if not (_register_names(fact["expression"]) & written)
    ]


def _candidate_facts_from_predicate(
    predicate: Mapping[str, Any], *, finite_value_budget: int
) -> tuple[list[dict[str, Any]], bool]:
    op = predicate.get("op")
    args = predicate.get("args")
    if op == "true":
        return [], True
    if op == "and_bool" and isinstance(args, list) and args:
        facts: list[dict[str, Any]] = []
        supported = True
        for child in args:
            if not isinstance(child, Mapping):
                return [], False
            child_facts, child_supported = _candidate_facts_from_predicate(
                child, finite_value_budget=finite_value_budget
            )
            supported = supported and child_supported
            for fact in child_facts:
                _append_unique_fact(facts, fact)
        return facts, supported

    congruence = _congruence_fact(predicate)
    if congruence is not None:
        return [congruence], True

    alternatives = _finite_equality_alternatives(predicate)
    if alternatives is not None:
        expression, values = alternatives
        if len(values) > finite_value_budget:
            return [], False
        return [{
            "kind": "finite_values",
            "expression": expression,
            "values": sorted(values),
        }], True

    masked_alternatives = _masked_disequality_alternatives(predicate)
    if masked_alternatives is not None:
        expression, values = masked_alternatives
        if len(values) > finite_value_budget:
            return [], False
        return [{
            "kind": "finite_values",
            "expression": expression,
            "values": sorted(values),
        }], True

    range_fact = _unsigned_range_fact(predicate)
    if range_fact is not None:
        return [range_fact], True
    return [], False


def _masked_disequality_alternatives(
    predicate: Mapping[str, Any],
) -> tuple[dict[str, Any], set[int]] | None:
    args = predicate.get("args")
    if (
        predicate.get("op") != "not"
        or not isinstance(args, list)
        or len(args) != 1
        or not isinstance(args[0], Mapping)
    ):
        return None
    equality = args[0]
    equality_args = equality.get("args")
    if (
        equality.get("op") != "eq"
        or not isinstance(equality_args, list)
        or len(equality_args) != 2
    ):
        return None
    for expression_side, excluded_side in (
        (equality_args[0], equality_args[1]),
        (equality_args[1], equality_args[0]),
    ):
        excluded = _expression_constant(excluded_side)
        if excluded is None or not isinstance(expression_side, Mapping):
            continue
        mask_args = expression_side.get("args")
        if (
            expression_side.get("op") != "and32"
            or not isinstance(mask_args, list)
            or len(mask_args) != 2
        ):
            continue
        masks = [
            _expression_constant(mask_args[0]),
            _expression_constant(mask_args[1]),
        ]
        mask = next((value for value in masks if value is not None), None)
        if (
            mask is None
            or mask >= 0xFFFFFFFF
            or not _is_power_of_two(mask + 1)
            or excluded > mask
        ):
            continue
        return (
            copy.deepcopy(dict(expression_side)),
            set(range(mask + 1)) - {excluded},
        )
    return None


def _finite_equality_alternatives(
    predicate: Mapping[str, Any],
) -> tuple[dict[str, Any], set[int]] | None:
    op = predicate.get("op")
    args = predicate.get("args")
    if op == "or_bool" and isinstance(args, list) and args:
        result: tuple[dict[str, Any], set[int]] | None = None
        for child in args:
            if not isinstance(child, Mapping):
                return None
            current = _finite_equality_alternatives(child)
            if current is None:
                return None
            if result is None:
                result = (current[0], set(current[1]))
            elif canonical_sha256(result[0]) != canonical_sha256(current[0]):
                return None
            else:
                result[1].update(current[1])
        return result
    if op != "eq" or not isinstance(args, list) or len(args) != 2:
        return None
    left, right = args
    right_constant = _expression_constant(right)
    if isinstance(left, Mapping) and right_constant is not None:
        return copy.deepcopy(dict(left)), {right_constant}
    left_constant = _expression_constant(left)
    if isinstance(right, Mapping) and left_constant is not None:
        return copy.deepcopy(dict(right)), {left_constant}
    return None


def _congruence_fact(predicate: Mapping[str, Any]) -> dict[str, Any] | None:
    if predicate.get("op") != "eq":
        return None
    args = predicate.get("args")
    if not isinstance(args, list) or len(args) != 2:
        return None
    for expression_side, value_side in ((args[0], args[1]), (args[1], args[0])):
        remainder = _expression_constant(value_side)
        if remainder is None or not isinstance(expression_side, Mapping):
            continue
        inner_args = expression_side.get("args")
        if expression_side.get("op") == "and32" and isinstance(inner_args, list) and len(inner_args) == 2:
            for value_expr, mask_expr in (
                (inner_args[0], inner_args[1]),
                (inner_args[1], inner_args[0]),
            ):
                mask = _expression_constant(mask_expr)
                if (
                    isinstance(value_expr, Mapping)
                    and mask is not None
                    and mask < 0xFFFFFFFF
                    and _is_power_of_two(mask + 1)
                    and remainder <= mask
                ):
                    return {
                        "kind": "congruence",
                        "expression": copy.deepcopy(dict(value_expr)),
                        "modulus": mask + 1,
                        "remainder": remainder,
                    }
        if expression_side.get("op") == "udiv_rem32" and isinstance(inner_args, list) and len(inner_args) == 3:
            high = _expression_constant(inner_args[0])
            modulus = _expression_constant(inner_args[2])
            value_expr = inner_args[1]
            if (
                high == 0
                and isinstance(value_expr, Mapping)
                and modulus is not None
                and modulus > 0
                and remainder < modulus
            ):
                return {
                    "kind": "congruence",
                    "expression": copy.deepcopy(dict(value_expr)),
                    "modulus": modulus,
                    "remainder": remainder,
                }
    return None


def _unsigned_range_fact(predicate: Mapping[str, Any]) -> dict[str, Any] | None:
    negated = False
    value: Mapping[str, Any] = predicate
    args = predicate.get("args")
    if predicate.get("op") == "not" and isinstance(args, list) and len(args) == 1 and isinstance(args[0], Mapping):
        negated = True
        value = args[0]
    args = value.get("args")
    if value.get("op") != "ult32" or not isinstance(args, list) or len(args) != 2:
        return None
    left, right = args
    left_const = _expression_constant(left)
    right_const = _expression_constant(right)
    if isinstance(left, Mapping) and right_const is not None:
        minimum = right_const if negated else 0
        maximum = 0xFFFFFFFF if negated else right_const - 1
        expression = left
    elif isinstance(right, Mapping) and left_const is not None:
        minimum = 0 if negated else left_const + 1
        maximum = left_const if negated else 0xFFFFFFFF
        expression = right
    else:
        return None
    if not (0 <= minimum <= maximum <= 0xFFFFFFFF):
        return None
    return {
        "kind": "range",
        "expression": copy.deepcopy(dict(expression)),
        "minimum": minimum,
        "maximum": maximum,
    }


def _constant_post_write_facts(unit: Mapping[str, Any]) -> list[dict[str, Any]]:
    semantics = unit.get("semantics")
    writes = semantics.get("register_writes") if isinstance(semantics, Mapping) else None
    result: list[dict[str, Any]] = []
    for write in writes if isinstance(writes, list) else []:
        if not isinstance(write, Mapping) or not isinstance(write.get("register"), str):
            continue
        value = _expression_constant(write.get("value"))
        if value is None:
            continue
        _append_unique_fact(result, {
            "kind": "finite_values",
            "expression": {"op": "reg", "name": str(write["register"]), "width": 32},
            "values": [value],
        })
    return result


def _candidate_is_inductive(
    member: str,
    conclusion: Mapping[str, Any],
    *,
    inventory: Mapping[str, Any],
    incoming_by_target: Mapping[str, Sequence[Mapping[str, Any]]],
    by_id: Mapping[str, Mapping[str, Any]],
    member_set: frozenset[str],
    source_predicates: Mapping[str, Mapping[str, Any]],
    root_assumptions: Mapping[str, Sequence[Mapping[str, Any]]],
    timeout: int,
) -> bool:
    checked = False
    for edge in incoming_by_target.get(member, ()):
        source_id = str(edge["source_unit_id"])
        source = by_id[source_id]
        antecedents: list[Any] = [edge["condition"], *_normal_fault_guards(source)]
        if source_id in member_set:
            source_predicate = source_predicates.get(source_id)
            if source_predicate is None:
                return False
            antecedents.insert(0, source_predicate)
        result = _check_implication(
            antecedents, _substitute_post_state(conclusion, source), timeout
        )
        if result["status"] != "complete":
            return False
        checked = True
    if not inventory["incoming"] and member in root_assumptions:
        result = _check_implication(
            list(root_assumptions[member]), conclusion, timeout
        )
        if result["status"] != "complete":
            return False
        checked = True
    return checked


def _synthesized_initiation(
    inventory: Mapping[str, Any],
    root_assumptions: Mapping[str, Sequence[Mapping[str, Any]]],
    members: Sequence[str],
) -> list[dict[str, Any]]:
    incoming = inventory["incoming"]
    if incoming:
        return [
            {
                "edge": copy.deepcopy(dict(edge)),
                "target_unit_id": str(edge["target_unit_id"]),
                "assumptions": [],
            }
            for edge in incoming
        ]
    return [
        {
            "edge": None,
            "target_unit_id": member,
            "assumptions": copy.deepcopy(list(root_assumptions[member])),
        }
        for member in members
        if member in root_assumptions
    ]


def _predicate_for_facts(facts: Sequence[Mapping[str, Any]]) -> dict[str, Any]:
    return _invariant_predicate({"unit_id": "proposal", "facts": list(facts)})


def _written_registers(unit: Mapping[str, Any]) -> set[str]:
    semantics = unit.get("semantics")
    writes = semantics.get("register_writes") if isinstance(semantics, Mapping) else None
    rows = writes if isinstance(writes, list) else []
    return {
        str(write["register"])
        for write in rows
        if isinstance(write, Mapping) and isinstance(write.get("register"), str)
    }


def _register_names(value: Any) -> set[str]:
    if isinstance(value, list):
        result: set[str] = set()
        for child in value:
            result.update(_register_names(child))
        return result
    if not isinstance(value, Mapping):
        return set()
    result = (
        {str(value["name"])}
        if value.get("op") == "reg" and isinstance(value.get("name"), str)
        else set()
    )
    for child in value.values():
        result.update(_register_names(child))
    return result


def _expression_constant(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("op") != "const":
        return None
    return _u32(value.get("value"))


def _append_unique_fact(
    destination: list[dict[str, Any]], fact: Mapping[str, Any]
) -> None:
    normalized = copy.deepcopy(dict(fact))
    digest = canonical_sha256(normalized)
    if all(canonical_sha256(existing) != digest for existing in destination):
        destination.append(normalized)
        destination.sort(key=canonical_sha256)


def _truncate_candidate_facts(
    candidates: Mapping[str, Sequence[dict[str, Any]]], budget: int
) -> dict[str, list[dict[str, Any]]]:
    result = {member: [] for member in sorted(candidates)}
    rows = sorted(
        (
            (member, canonical_sha256(fact), copy.deepcopy(fact))
            for member, facts in candidates.items()
            for fact in facts
        ),
        key=lambda row: (row[0], row[1]),
    )
    for member, _digest_value, fact in rows[:budget]:
        result[member].append(fact)
    return result


def _is_power_of_two(value: int) -> bool:
    return value > 0 and value & (value - 1) == 0


def _normalize_issues(
    issues: Sequence[Mapping[str, str]],
) -> list[dict[str, str]]:
    unique = sorted(
        {json.dumps(issue, sort_keys=True, separators=(",", ":")) for issue in issues}
    )
    return [json.loads(value) for value in unique]


def _check_invariant_certificate_v2(
    certificate: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    binary_sha256: str,
    machine_ir_sha256: str,
    seh_inventories: Sequence[Mapping[str, Any]] = (),
    solver_timeout_ms: int = 5_000,
) -> dict[str, Any]:
    """Replay one exact SCC exceptional-invariant certificate.

    ``seh_inventories`` is independent platform authority.  A certificate may
    bind its hash but cannot assert handler support by itself.
    """

    if not _digest(binary_sha256) or not _digest(machine_ir_sha256):
        raise ExceptionInvariantV2Error("binary bindings must be SHA-256 digests")
    if (
        not isinstance(solver_timeout_ms, int)
        or isinstance(solver_timeout_ms, bool)
        or solver_timeout_ms <= 0
    ):
        raise ExceptionInvariantV2Error("solver timeout must be a positive integer")

    certificate_format = certificate.get("format") if isinstance(certificate, Mapping) else None
    control_certificate = certificate_format == CONTROL_INVARIANT_CERTIFICATE_V2_FORMAT
    report_format = (
        CONTROL_INVARIANT_CHECK_V2_FORMAT
        if control_certificate
        else EXCEPTION_INVARIANT_CHECK_V2_FORMAT
    )
    issues: list[dict[str, str]] = []
    obligations: list[dict[str, Any]] = []
    fault_results: list[dict[str, Any]] = []
    if not isinstance(certificate, Mapping):
        return _report(
            {},
            issues=[_issue("violated", "certificate_malformed")],
            report_format=report_format,
        )
    if certificate_format not in {
        EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT,
        CONTROL_INVARIANT_CERTIFICATE_V2_FORMAT,
    }:
        issues.append(_issue("violated", "certificate_format_mismatch"))

    try:
        by_id, _by_rva = _unit_indexes(units)
    except ExceptionInvariantV2Error as exc:
        return _report(
            certificate,
            issues=[_issue("violated", "unit_inventory_corrupt", str(exc))],
            report_format=report_format,
        )
    region_key = "region" if control_certificate else "scc"
    region = certificate.get(region_key)
    members_raw = region.get("members") if isinstance(region, Mapping) else None
    if not isinstance(members_raw, list) or not all(
        isinstance(value, str) and value for value in members_raw
    ):
        return _report(
            certificate,
            issues=[*issues, _issue("violated", "scc_members_corrupt")],
            report_format=report_format,
        )
    members = tuple(sorted(members_raw))
    if list(members) != members_raw or len(set(members)) != len(members):
        issues.append(_issue("violated", "scc_members_noncanonical"))
    try:
        inventory = (
            derive_control_region_inventory(
                units,
                members,
                region.get("frontier_members", ()) if isinstance(region, Mapping) else (),
            )
            if control_certificate
            else derive_exception_scc_inventory(units, members)
        )
    except ExceptionInvariantV2Error as exc:
        return _report(
            certificate,
            issues=[*issues, _issue("violated", "scc_members_contradict", str(exc))],
            report_format=report_format,
        )

    bindings = certificate.get("bindings")
    expected_bindings = {
        "binary_sha256": binary_sha256,
        "machine_ir_sha256": machine_ir_sha256,
        "units": [exception_invariant_unit_binding(by_id[member]) for member in members],
    }
    if bindings != expected_bindings:
        issues.append(_issue("violated", "exact_binding_contradiction"))
    if not isinstance(region, Mapping) or region.get("edges") != inventory["edges"]:
        issues.append(_issue("violated", "scc_edge_inventory_contradiction"))
    if not isinstance(region, Mapping) or region.get("exits") != inventory["exits"]:
        issues.append(_issue("violated", "scc_exit_inventory_contradiction"))
    for reason in inventory["incomplete_reasons"]:
        issues.append(_issue("incomplete", "control_effect_unknown", reason))
    if not control_certificate and not _is_cyclic_strong_component(members, inventory["edges"]):
        issues.append(_issue("violated", "members_do_not_form_cyclic_scc"))

    invariants: dict[str, dict[str, Any]] = {}
    invariant_facts: dict[str, list[dict[str, Any]]] = {}
    raw_invariants = certificate.get("invariants")
    if not isinstance(raw_invariants, list):
        raw_invariants = []
        issues.append(_issue("incomplete", "cutpoint_invariants_missing"))
    for index, row in enumerate(raw_invariants):
        if not isinstance(row, Mapping) or row.get("unit_id") not in members:
            issues.append(_issue("violated", "cutpoint_invariant_corrupt", str(index)))
            continue
        unit_id = str(row["unit_id"])
        if unit_id in invariants:
            issues.append(_issue("violated", "cutpoint_invariant_duplicated", unit_id))
            continue
        try:
            predicate = _invariant_predicate(row)
        except ExceptionInvariantV2Error as exc:
            issues.append(_issue("violated", "cutpoint_invariant_corrupt", str(exc)))
            continue
        invariants[unit_id] = predicate
        invariant_facts[unit_id] = copy.deepcopy(list(row.get("facts", ())))
        result = _check_satisfiable(predicate, solver_timeout_ms)
        obligations.append(_obligation("invariant_consistency", unit_id, result))
        _take_solver_status(result, issues, "invariant_contradiction", unit_id)
    for member in members:
        if member not in invariants:
            issues.append(_issue("incomplete", "cutpoint_invariant_missing", member))

    raw_preservation = certificate.get("preservation")
    if raw_preservation != inventory["edges"]:
        issues.append(_issue("incomplete", "preservation_inventory_missing_or_stale"))
    else:
        for edge in inventory["edges"]:
            source = str(edge["source_unit_id"])
            target = str(edge["target_unit_id"])
            if source not in invariants or target not in invariants:
                continue
            antecedents = [invariants[source], edge["condition"]]
            antecedents.extend(_normal_fault_guards(by_id[source]))
            post = _substitute_post_state(invariants[target], by_id[source])
            result = _check_implication(antecedents, post, solver_timeout_ms)
            identity = f"{source}->{target}:{edge['edge_index']}"
            obligations.append(_obligation("inductive_preservation", identity, result))
            _take_solver_status(result, issues, "inductive_preservation_failed", identity)

    _check_initiation(
        certificate.get("initiation"),
        inventory=inventory,
        by_id=by_id,
        invariants=invariants,
        timeout=solver_timeout_ms,
        obligations=obligations,
        issues=issues,
    )

    requested_exports: list[dict[str, Any]] = []
    if control_certificate or "requested_facts" in certificate:
        requested_exports = _check_requested_fact_exports(
            certificate.get("requested_facts"),
            members=members,
            invariant_facts=invariant_facts,
            frontier_members=(
                inventory.get("frontier_members", ())
                if control_certificate
                else ()
            ),
            issues=issues,
        )

    faults = {} if control_certificate else _fault_inventory(by_id, members)
    claims = [] if control_certificate else certificate.get("faults")
    if not isinstance(claims, list):
        claims = []
        issues.append(_issue("incomplete", "fault_implications_missing"))
    claim_index: dict[tuple[str, int], Mapping[str, Any]] = {}
    for claim in claims:
        if not isinstance(claim, Mapping):
            issues.append(_issue("violated", "fault_claim_corrupt"))
            continue
        key = (str(claim.get("source_unit_id")), claim.get("fault_index"))
        if not isinstance(key[1], int) or key in claim_index:
            issues.append(_issue("violated", "fault_claim_corrupt"))
            continue
        claim_index[(key[0], int(key[1]))] = claim
    if set(claim_index) - set(faults):
        issues.append(_issue("violated", "fault_claim_inventory_contradiction"))
    seh_by_site = _seh_index(seh_inventories, issues)
    for key, fault in faults.items():
        claim = claim_index.get(key)
        result = _check_fault(
            key,
            fault,
            claim,
            unit=by_id[key[0]],
            invariant=invariants.get(key[0]),
            units=by_id,
            seh=seh_by_site.get(key),
            timeout=solver_timeout_ms,
        )
        fault_results.append(result)
        if result["status"] != "complete":
            issues.append(
                _issue(result["status"], str(result["reason_code"]), f"{key[0]}:{key[1]}")
            )

    return _report(
        certificate,
        issues=issues,
        obligations=obligations,
        faults=fault_results,
        inventory=inventory,
        report_format=report_format,
        checked_invariants=requested_exports,
    )


def check_exception_invariant_certificate_v2(
    certificate: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    binary_sha256: str,
    machine_ir_sha256: str,
    seh_inventories: Sequence[Mapping[str, Any]] = (),
    solver_timeout_ms: int = 5_000,
) -> dict[str, Any]:
    """Replay one exact SCC exceptional-invariant certificate."""

    if certificate.get("format") != EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT:
        return _report(
            certificate,
            issues=[_issue("violated", "certificate_format_mismatch")],
        )
    return _check_invariant_certificate_v2(
        certificate,
        units=units,
        binary_sha256=binary_sha256,
        machine_ir_sha256=machine_ir_sha256,
        seh_inventories=seh_inventories,
        solver_timeout_ms=solver_timeout_ms,
    )


def check_control_invariant_certificate_v2(
    certificate: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]],
    binary_sha256: str,
    machine_ir_sha256: str,
    solver_timeout_ms: int = 5_000,
) -> dict[str, Any]:
    """Replay one finite control-region invariant certificate."""

    if certificate.get("format") != CONTROL_INVARIANT_CERTIFICATE_V2_FORMAT:
        return _report(
            certificate,
            issues=[_issue("violated", "certificate_format_mismatch")],
            report_format=CONTROL_INVARIANT_CHECK_V2_FORMAT,
        )
    return _check_invariant_certificate_v2(
        certificate,
        units=units,
        binary_sha256=binary_sha256,
        machine_ir_sha256=machine_ir_sha256,
        solver_timeout_ms=solver_timeout_ms,
    )


def _check_requested_fact_exports(
    raw: Any,
    *,
    members: Sequence[str],
    invariant_facts: Mapping[str, Sequence[Mapping[str, Any]]],
    frontier_members: Sequence[str],
    issues: list[dict[str, str]],
) -> list[dict[str, Any]]:
    if not isinstance(raw, list) or not raw:
        issues.append(_issue("incomplete", "requested_control_facts_missing"))
        return []
    exports: list[dict[str, Any]] = []
    seen: set[str] = set()
    canonical_rows: list[dict[str, Any]] = []
    for index, row in enumerate(raw):
        if not isinstance(row, Mapping):
            issues.append(_issue("violated", "requested_control_fact_corrupt", str(index)))
            continue
        unit_id = row.get("unit_id")
        facts = row.get("facts")
        if unit_id not in members or not isinstance(facts, list) or not facts:
            issues.append(_issue("violated", "requested_control_fact_corrupt", str(index)))
            continue
        if str(unit_id) in seen:
            issues.append(_issue("violated", "requested_control_fact_duplicated", str(unit_id)))
            continue
        seen.add(str(unit_id))
        checked_facts = invariant_facts.get(str(unit_id), ())
        checked_digests = {canonical_sha256(fact) for fact in checked_facts}
        normalized: list[dict[str, Any]] = []
        for fact_index, fact in enumerate(facts):
            if not isinstance(fact, Mapping):
                issues.append(
                    _issue(
                        "violated",
                        "requested_control_fact_corrupt",
                        f"{unit_id}:{fact_index}",
                    )
                )
                continue
            normalized_fact = copy.deepcopy(dict(fact))
            digest = canonical_sha256(normalized_fact)
            if digest not in checked_digests:
                issues.append(
                    _issue(
                        "violated",
                        "requested_control_fact_not_in_invariant",
                        f"{unit_id}:{digest}",
                    )
                )
                continue
            normalized.append(normalized_fact)
            exports.append({
                "unit_id": str(unit_id),
                "fact_sha256": digest,
                "fact": normalized_fact,
            })
        canonical_rows.append({"unit_id": str(unit_id), "facts": normalized})
    if raw != sorted(canonical_rows, key=lambda row: row["unit_id"]):
        issues.append(_issue("violated", "requested_control_facts_noncanonical"))
    missing_frontiers = sorted(set(frontier_members) - seen)
    for unit_id in missing_frontiers:
        issues.append(_issue("incomplete", "frontier_control_fact_missing", unit_id))
    return sorted(exports, key=lambda row: (row["unit_id"], row["fact_sha256"]))


def _check_initiation(
    raw: Any,
    *,
    inventory: Mapping[str, Any],
    by_id: Mapping[str, Mapping[str, Any]],
    invariants: Mapping[str, Mapping[str, Any]],
    timeout: int,
    obligations: list[dict[str, Any]],
    issues: list[dict[str, str]],
) -> None:
    if not isinstance(raw, list) or not raw:
        issues.append(_issue("incomplete", "initiation_missing"))
        return
    incoming = inventory["incoming"]
    seen_edges: list[Any] = []
    for index, row in enumerate(raw):
        if not isinstance(row, Mapping) or not isinstance(row.get("assumptions"), list):
            issues.append(_issue("violated", "initiation_corrupt", str(index)))
            continue
        edge = row.get("edge")
        target = row.get("target_unit_id")
        if target not in invariants:
            issues.append(_issue(
                "incomplete"
                if target in inventory.get("members", ())
                else "violated",
                "initiation_target_invariant_missing"
                if target in inventory.get("members", ())
                else "initiation_target_contradiction",
                str(target),
            ))
            continue
        antecedents = list(row["assumptions"])
        conclusion = invariants[str(target)]
        if edge is None:
            if incoming:
                issues.append(_issue("violated", "root_initiation_with_incoming_edges"))
                continue
            identity = f"root->{target}:{index}"
        elif edge in incoming and edge.get("target_unit_id") == target:
            seen_edges.append(edge)
            source = str(edge["source_unit_id"])
            antecedents.extend([edge["condition"], *_normal_fault_guards(by_id[source])])
            conclusion = _substitute_post_state(conclusion, by_id[source])
            identity = f"{source}->{target}:{edge['edge_index']}"
        else:
            issues.append(_issue("violated", "initiation_edge_contradiction", str(index)))
            continue
        result = _check_implication(antecedents, conclusion, timeout)
        obligations.append(_obligation("initiation", identity, result))
        _take_solver_status(result, issues, "initiation_failed", identity)
    if incoming and sorted(seen_edges, key=_edge_key) != incoming:
        issues.append(_issue("incomplete", "incoming_initiation_incomplete"))


def _check_fault(
    key: tuple[str, int],
    fault: Mapping[str, Any],
    claim: Mapping[str, Any] | None,
    *,
    unit: Mapping[str, Any],
    invariant: Mapping[str, Any] | None,
    units: Mapping[str, Mapping[str, Any]],
    seh: Mapping[str, Any] | None,
    timeout: int,
) -> dict[str, Any]:
    base = {
        "source_unit_id": key[0],
        "fault_index": key[1],
        "fault_sha256": canonical_sha256(fault),
    }
    if claim is None or invariant is None:
        return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "fault_claim_missing"}
    if claim.get("fault_sha256") != base["fault_sha256"]:
        return {**base, "status": "violated", "outcome": "incomplete", "reason_code": "fault_hash_contradiction"}
    outcome = claim.get("outcome")
    kind = outcome.get("kind") if isinstance(outcome, Mapping) else None
    condition = fault.get("condition")
    if not isinstance(condition, Mapping):
        return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "fault_predicate_unknown"}
    if kind == "checked_infeasible":
        if fault.get("kind") not in _LOCAL_QF_BV_FAULTS:
            return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "platform_fault_not_qf_bv_local"}
        check = _check_implication([invariant, condition], _false(), timeout)
        status = check["status"]
        return {**base, "status": status, "outcome": "checked_infeasible" if status == "complete" else "incomplete", "reason_code": None if status == "complete" else "fault_infeasibility_not_proved", "obligation": check}
    if kind == "observable_terminal_fault":
        semantics = unit.get("semantics")
        machine_outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
        declared = machine_outcome.get("fault_kind") if isinstance(machine_outcome, Mapping) else None
        if not isinstance(machine_outcome, Mapping) or machine_outcome.get("kind") != "fault" or declared not in {None, fault.get("kind")}:
            return {**base, "status": "violated", "outcome": "incomplete", "reason_code": "terminal_fault_contradiction"}
        if not isinstance(fault.get("kind"), str) or fault.get("kind") == "unknown":
            return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "terminal_fault_kind_unknown"}
        check = _check_implication([invariant], condition, timeout)
        status = check["status"]
        return {**base, "status": status, "outcome": "observable_terminal_fault" if status == "complete" else "incomplete", "reason_code": None if status == "complete" else "terminal_fault_not_unconditional", "obligation": check}
    if kind == "finite_supported_seh_target":
        assert isinstance(outcome, Mapping)
        if seh is None:
            return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "seh_platform_inventory_unknown"}
        if outcome.get("handler_inventory_sha256") != canonical_sha256(seh):
            return {**base, "status": "violated", "outcome": "incomplete", "reason_code": "seh_inventory_hash_contradiction"}
        if seh.get("status") != "complete" or seh.get("platform_effects") != "complete":
            return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "seh_platform_effects_unknown"}
        targets = seh.get("targets")
        if not isinstance(targets, list) or not targets:
            return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "seh_targets_unknown"}
        guards: list[Any] = []
        target_ids: list[str] = []
        for target in targets:
            if not isinstance(target, Mapping) or not isinstance(target.get("condition"), Mapping):
                return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "seh_target_effect_unknown"}
            target_id = target.get("target_unit_id")
            target_unit = units.get(str(target_id))
            if target_unit is None or target_unit.get("status") != "qualified":
                return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "seh_target_unsupported"}
            if target.get("unit_sha256") != canonical_sha256(target_unit):
                return {**base, "status": "violated", "outcome": "incomplete", "reason_code": "seh_target_binding_contradiction"}
            target_ids.append(str(target_id))
            guards.append(target["condition"])
        if outcome.get("target_unit_ids") != sorted(target_ids):
            return {**base, "status": "violated", "outcome": "incomplete", "reason_code": "seh_target_inventory_contradiction"}
        check = _check_implication([invariant, condition], _disjunction(guards), timeout)
        status = check["status"]
        return {**base, "status": status, "outcome": "finite_supported_seh_target" if status == "complete" else "incomplete", "reason_code": None if status == "complete" else "seh_fault_implication_not_proved", "target_unit_ids": sorted(target_ids), "obligation": check}
    if kind == "incomplete":
        return {**base, "status": "incomplete", "outcome": "incomplete", "reason_code": "fault_explicitly_incomplete"}
    return {**base, "status": "violated", "outcome": "incomplete", "reason_code": "fault_outcome_corrupt"}


def _invariant_predicate(row: Mapping[str, Any]) -> dict[str, Any]:
    facts = row.get("facts")
    if not isinstance(facts, list):
        raise ExceptionInvariantV2Error("cutpoint invariant facts must be an array")
    predicates: list[dict[str, Any]] = []
    for fact in facts:
        if not isinstance(fact, Mapping) or not isinstance(fact.get("expression"), Mapping):
            raise ExceptionInvariantV2Error("invariant fact expression is malformed")
        expression = copy.deepcopy(dict(fact["expression"]))
        kind = fact.get("kind")
        if kind == "range":
            minimum = _u32(fact.get("minimum"))
            maximum = _u32(fact.get("maximum"))
            if minimum is None or maximum is None or minimum > maximum:
                raise ExceptionInvariantV2Error("unsigned range is contradictory")
            predicates.append(_conjunction([
                _not({"op": "ult32", "args": [expression, _const(minimum)]}),
                _not({"op": "ult32", "args": [_const(maximum), expression]}),
            ]))
        elif kind == "finite_values":
            values = fact.get("values")
            if not isinstance(values, list) or not values or any(_u32(value) is None for value in values):
                raise ExceptionInvariantV2Error("finite values are malformed")
            if values != sorted(set(values)):
                raise ExceptionInvariantV2Error("finite values must be sorted and unique")
            predicates.append(_disjunction([
                {"op": "eq", "args": [expression, _const(int(value))]}
                for value in values
            ]))
        elif kind == "congruence":
            modulus = _u32(fact.get("modulus"))
            remainder = _u32(fact.get("remainder"))
            if modulus is None or modulus == 0 or remainder is None or remainder >= modulus:
                raise ExceptionInvariantV2Error("congruence is malformed")
            predicates.append({
                "op": "eq",
                "args": [
                    {"op": "udiv_rem32", "args": [_const(0), expression, _const(modulus)]},
                    _const(remainder),
                ],
            })
        elif kind == "predicate":
            if set(fact) != {"kind", "expression"}:
                raise ExceptionInvariantV2Error(
                    "predicate fact has noncanonical fields"
                )
            predicates.append(expression)
        else:
            raise ExceptionInvariantV2Error(f"unsupported invariant fact {kind!r}")
    return _conjunction(predicates)


def _unit_indexes(units: Sequence[Mapping[str, Any]]) -> tuple[dict[str, Mapping[str, Any]], dict[int, Mapping[str, Any]]]:
    by_id: dict[str, Mapping[str, Any]] = {}
    by_rva: dict[int, Mapping[str, Any]] = {}
    for unit in units:
        if not isinstance(unit, Mapping) or not isinstance(unit.get("id"), str):
            raise ExceptionInvariantV2Error("machine-IR unit is malformed")
        unit_id = str(unit["id"])
        source = unit.get("source")
        original = source.get("original") if isinstance(source, Mapping) else None
        rva = original.get("rva_start") if isinstance(original, Mapping) else None
        if unit_id in by_id or not isinstance(rva, int) or isinstance(rva, bool) or rva in by_rva:
            raise ExceptionInvariantV2Error("machine-IR unit identities/RVAs are not unique")
        by_id[unit_id] = unit
        by_rva[rva] = unit
    return by_id, by_rva


def _unit_control(unit: Mapping[str, Any], by_rva: Mapping[int, Mapping[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, Any] | None, str | None]:
    source = str(unit["id"])
    semantics = unit.get("semantics")
    outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
    if not isinstance(outcome, Mapping):
        return [], None, "outcome_missing"
    assert isinstance(semantics, Mapping)
    kind = outcome.get("kind")
    raw_edges = semantics.get("edge_conditions")
    edges: list[dict[str, Any]] = []
    if isinstance(raw_edges, list) and raw_edges:
        for index, edge in enumerate(raw_edges):
            if not isinstance(edge, Mapping) or not isinstance(edge.get("target_rva"), int) or not isinstance(edge.get("condition"), Mapping):
                return [], None, "edge_condition_malformed"
            edges.append(_edge(source, index, int(edge["target_rva"]), edge["condition"], by_rva))
    elif kind in {"jump", "fallthrough"} and isinstance(outcome.get("target_rva"), int):
        edges.append(_edge(source, 0, int(outcome["target_rva"]), _true(), by_rva))
    elif kind == "branch":
        return [], None, "branch_edges_unknown"
    if kind in {"return", "fault", "termination"}:
        return edges, {"source_unit_id": source, "kind": str(kind), "outcome_sha256": canonical_sha256(outcome)}, None
    if kind in {"indirect_jump", "indirect_call", "unknown"}:
        return edges, None, "indirect_or_unknown_control"
    return edges, None, None


def _edge(source: str, index: int, target_rva: int, condition: Mapping[str, Any], by_rva: Mapping[int, Mapping[str, Any]]) -> dict[str, Any]:
    target = by_rva.get(target_rva)
    return {
        "source_unit_id": source,
        "target_unit_id": None if target is None else str(target["id"]),
        "target_rva": target_rva,
        "edge_index": index,
        "condition_sha256": canonical_sha256(condition),
        "condition": copy.deepcopy(dict(condition)),
    }


def _fault_inventory(by_id: Mapping[str, Mapping[str, Any]], members: Sequence[str]) -> dict[tuple[str, int], Mapping[str, Any]]:
    result: dict[tuple[str, int], Mapping[str, Any]] = {}
    for member in members:
        semantics = by_id[member].get("semantics")
        faults = semantics.get("faults") if isinstance(semantics, Mapping) else None
        if isinstance(faults, list):
            for index, fault in enumerate(faults):
                if isinstance(fault, Mapping):
                    result[(member, index)] = fault
    return result


def _normal_fault_guards(unit: Mapping[str, Any]) -> list[dict[str, Any]]:
    semantics = unit.get("semantics")
    faults = semantics.get("faults") if isinstance(semantics, Mapping) else None
    conditions = [fault.get("condition") for fault in faults or [] if isinstance(fault, Mapping) and isinstance(fault.get("condition"), Mapping)]
    return [] if not conditions else [_not(_disjunction(conditions))]


def _substitute_post_state(value: Any, unit: Mapping[str, Any]) -> Any:
    semantics = unit.get("semantics")
    semantics = semantics if isinstance(semantics, Mapping) else {}
    registers = {
        str(write.get("register")): write.get("value")
        for write in semantics.get("register_writes", [])
        if isinstance(write, Mapping)
    }
    flags = {
        str(write.get("flag")): write.get("value")
        for write in semantics.get("flag_writes", [])
        if isinstance(write, Mapping)
    }
    def visit(item: Any) -> Any:
        if isinstance(item, list):
            return [visit(child) for child in item]
        if not isinstance(item, Mapping):
            return copy.deepcopy(item)
        if item.get("op") == "reg" and item.get("name") in registers:
            return copy.deepcopy(registers[str(item["name"])])
        if item.get("op") == "flag" and item.get("name") in flags:
            return copy.deepcopy(flags[str(item["name"])])
        return {str(key): visit(child) for key, child in item.items()}
    return visit(value)


def _check_implication(antecedents: Sequence[Any], conclusion: Any, timeout: int) -> dict[str, Any]:
    if conclusion == _true():
        return {
            "status": "complete",
            "logic": {
                "rule": "implication_to_true",
                "antecedent_sha256": canonical_sha256(list(antecedents)),
            },
        }
    violation = _conjunction([*antecedents, _not(conclusion)])
    result = check_straight_line_semantic_claim(
        {"violation": violation}, {"violation": _false()}, solver_timeout_ms=timeout
    )
    payload = result.to_payload()
    return {"status": "complete" if result.status == "qualified" else result.status, "qf_bv": payload}


def _check_satisfiable(predicate: Any, timeout: int) -> dict[str, Any]:
    result = check_straight_line_semantic_claim(
        {"predicate": predicate}, {"predicate": _false()}, solver_timeout_ms=timeout
    )
    payload = result.to_payload()
    if result.status == "violated":
        return {"status": "complete", "qf_bv": payload}
    if result.status == "qualified":
        return {"status": "violated", "qf_bv": payload}
    return {"status": "incomplete", "qf_bv": payload}


def _seh_index(values: Sequence[Mapping[str, Any]], issues: list[dict[str, str]]) -> dict[tuple[str, int], Mapping[str, Any]]:
    result: dict[tuple[str, int], Mapping[str, Any]] = {}
    for value in values:
        if not isinstance(value, Mapping) or value.get("format") != SUPPORTED_SEH_INVENTORY_V2_FORMAT or not isinstance(value.get("fault_index"), int):
            issues.append(_issue("violated", "seh_inventory_corrupt"))
            continue
        key = (str(value.get("source_unit_id")), int(value["fault_index"]))
        if key in result:
            issues.append(_issue("violated", "seh_inventory_contradiction"))
        else:
            result[key] = value
    return result


def _is_cyclic_strong_component(members: Sequence[str], edges: Sequence[Mapping[str, Any]]) -> bool:
    graph = {member: set() for member in members}
    reverse = {member: set() for member in members}
    for edge in edges:
        source, target = str(edge["source_unit_id"]), str(edge["target_unit_id"])
        graph[source].add(target)
        reverse[target].add(source)
    if len(members) == 1 and members[0] not in graph[members[0]]:
        return False
    def reach(adjacency: Mapping[str, set[str]]) -> set[str]:
        seen: set[str] = set()
        stack = [members[0]]
        while stack:
            node = stack.pop()
            if node not in seen:
                seen.add(node)
                stack.extend(adjacency[node] - seen)
        return seen
    return reach(graph) == set(members) and reach(reverse) == set(members)


def _conjunction(values: Sequence[Any]) -> dict[str, Any]:
    if not values:
        return _true()
    result = copy.deepcopy(values[0])
    for value in values[1:]:
        result = {"op": "and_bool", "args": [result, copy.deepcopy(value)]}
    return result


def _disjunction(values: Sequence[Any]) -> dict[str, Any]:
    if not values:
        return _false()
    result = copy.deepcopy(values[0])
    for value in values[1:]:
        result = {"op": "or_bool", "args": [result, copy.deepcopy(value)]}
    return result


def _not(value: Any) -> dict[str, Any]:
    return {"op": "not", "args": [copy.deepcopy(value)]}


def _const(value: int) -> dict[str, Any]:
    return {"op": "const", "value": value, "width": 32}


def _true() -> dict[str, str]:
    return {"op": "true"}


def _false() -> dict[str, str]:
    return {"op": "false"}


def _u32(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 0xFFFFFFFF else None


def _digest(value: Any) -> bool:
    return isinstance(value, str) and len(value) == _DIGEST_LENGTH and all(character in "0123456789abcdef" for character in value)


def _edge_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (str(row.get("source_unit_id")), int(row.get("edge_index", -1)), int(row.get("target_rva", -1)), str(row.get("target_unit_id")))


def _exit_key(row: Mapping[str, Any]) -> tuple[Any, ...]:
    return (str(row.get("source_unit_id")), str(row.get("kind", "normal")), int(row.get("edge_index", -1)), int(row.get("target_rva", -1)))


def _obligation(kind: str, identity: str, result: Mapping[str, Any]) -> dict[str, Any]:
    return {"kind": kind, "id": identity, **copy.deepcopy(dict(result))}


def _take_solver_status(result: Mapping[str, Any], issues: list[dict[str, str]], code: str, detail: str) -> None:
    if result.get("status") != "complete":
        issues.append(_issue(str(result.get("status")), code, detail))


def _issue(status: str, code: str, detail: str = "") -> dict[str, str]:
    return {"status": status, "code": code, "detail": detail}


def _report(
    certificate: Mapping[str, Any],
    *,
    issues: Sequence[Mapping[str, str]],
    obligations: Sequence[Mapping[str, Any]] = (),
    faults: Sequence[Mapping[str, Any]] = (),
    inventory: Mapping[str, Any] | None = None,
    report_format: str = EXCEPTION_INVARIANT_CHECK_V2_FORMAT,
    checked_invariants: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    unique = sorted(
        {json.dumps(issue, sort_keys=True, separators=(",", ":")) for issue in issues}
    )
    normalized_issues = [json.loads(value) for value in unique]
    status = "violated" if any(issue["status"] == "violated" for issue in normalized_issues) else "incomplete" if normalized_issues else "complete"
    certificate_sha256 = canonical_sha256(certificate)
    return {
        "format": report_format,
        "status": status,
        "certificate_sha256": certificate_sha256,
        "uses_bounded_paths": False,
        "scc_inventory": None if inventory is None else copy.deepcopy(dict(inventory)),
        "obligations": list(obligations),
        "faults": list(faults),
        "checked_invariants": (
            [
                {
                    **copy.deepcopy(dict(row)),
                    "authority_id": "checked-control-fact-v2:"
                    + canonical_sha256({
                        "certificate_sha256": certificate_sha256,
                        "fact": row,
                    }),
                }
                for row in checked_invariants
            ]
            if status == "complete"
            else []
        ),
        "issues": normalized_issues,
    }


__all__ = [
    "CONTROL_INVARIANT_CERTIFICATE_V2_FORMAT",
    "CONTROL_INVARIANT_CHECK_V2_FORMAT",
    "CONTROL_INVARIANT_PROPOSAL_V2_FORMAT",
    "EXCEPTION_INVARIANT_CERTIFICATE_V2_FORMAT",
    "EXCEPTION_INVARIANT_CHECK_V2_FORMAT",
    "EXCEPTION_INVARIANT_PROPOSAL_V2_FORMAT",
    "SUPPORTED_SEH_INVENTORY_V2_FORMAT",
    "ExceptionInvariantV2Error",
    "canonical_sha256",
    "check_control_invariant_certificate_v2",
    "check_exception_invariant_certificate_v2",
    "derive_control_region_inventory",
    "derive_exception_scc_inventory",
    "exception_invariant_unit_binding",
    "synthesize_control_invariant_certificate_v2",
    "synthesize_exception_invariant_certificate_v2",
]
