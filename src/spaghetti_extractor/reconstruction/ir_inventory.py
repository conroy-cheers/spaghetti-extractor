"""Coverage, reachability, and exceptional-control inventories."""

from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from ..authority_bindings_v2 import indirect_exit_id_v2
from ..stage_binary import StageABinary
from ..util import sha256_bytes
from .control_reachability import (
    canonical_indirect_external_targets,
    derive_rooted_reachable_units,
)
from .ir_decoding import _semantic_unit_qualified
from .ir_materialization import _initial_control_roots
from .ir_model import (
    ExportIssue,
    RvaSpan,
    SourceLocation,
    _canonical_json,
    _intersections,
    _merge_ranges,
    _subtract_ranges,
    _u32,
)
from .ir_recovery import (
    _indirect_recovery_unit_binding_complete,
    _local_callback_cutpoint_proposals,
    _rebind_preclassified_static_recoveries,
    _recovery_failure_message,
    _static_jump_table_recovery_fixed_point,
)
from .ir_evidence import _location_from_unit, _root_sort_key
from .validation import check_straight_line_semantic_claim


_QF_BV_LOCALLY_DECIDABLE_FAULT_KINDS = frozenset({"divide_error"})
_FAULT_PREDICATE_ABSTRACT_LEAF_OPS = frozenset(
    {
        "call_flag",
        "call_response",
        "load",
        "undefined_bv",
        "undefined_flag",
    }
)


def _unit_issues(units: Sequence[Mapping[str, Any]]) -> list[ExportIssue]:
    issues: list[ExportIssue] = []
    for unit in units:
        reconciliation = unit.get("control", {}).get("decoded_reconciliation")
        reconciliation_status = (
            reconciliation.get("status")
            if isinstance(reconciliation, Mapping)
            else "incomplete"
        )
        if reconciliation_status != "complete":
            issues.append(
                ExportIssue(
                    status=(
                        "violated"
                        if reconciliation_status == "violated"
                        else "incomplete"
                    ),
                    category="decoded_control_reconciliation",
                    message=(
                        "exact decoded x86 control does not reconcile with the "
                        "aggregate semantic control contract"
                        if reconciliation_status == "violated"
                        else "exact decoded x86 control reconciliation is incomplete"
                    ),
                    next_action=(
                        "regenerate the semantic transfer from the exact PE bytes "
                        "and reconcile its outcome, targets, call events, and return class"
                    ),
                    location=_location_from_unit(
                        unit, "control.decoded_reconciliation"
                    ),
                )
            )
        source_status = unit["source_status"]
        if unit["status"] == "qualified" or _semantic_unit_qualified(
            source_status, unit.get("x87_micro_ops", [])
        ):
            continue
        location = _location_from_unit(unit, "source_status")
        issues.append(
            ExportIssue(
                status="incomplete",
                category=str(source_status.get("blocker_category") or "incomplete_semantic_unit"),
                message=str(source_status.get("blocker") or "source semantic unit is not reimplementable"),
                next_action=str(
                    source_status.get("next_action")
                    or "complete the generic semantic transfer before reconstruction"
                ),
                location=location,
            )
        )
    return issues


def _coverage_inventory(
    binary: StageABinary,
    units: Sequence[Mapping[str, Any]],
    noncode_ranges: Sequence[RvaSpan],
) -> tuple[dict[str, Any], list[ExportIssue]]:
    executable = [
        RvaSpan(section.rva_start, section.rva_end)
        for section in binary.sections
        if section.executable
    ]
    code_ranges = [
        RvaSpan(
            int(unit["source"]["original"]["rva_start"]),
            int(unit["source"]["original"]["rva_end"]),
        )
        for unit in units
    ]
    issues: list[ExportIssue] = []
    for unit, span in zip(units, code_ranges, strict=True):
        if sum(section.start <= span.start and span.end <= section.end for section in executable) != 1:
            issues.append(
                ExportIssue(
                    status="violated",
                    category="semantic_unit_outside_executable_section",
                    message="semantic unit is not contained in one executable PE section",
                    next_action="repair static unit extraction and regenerate the state machine",
                    location=_location_from_unit(unit, "source.original"),
                )
            )
    effective_noncode = [
        remainder
        for span in noncode_ranges
        for remainder in _subtract_ranges(span, _merge_ranges(code_ranges))
    ]
    classified = _merge_ranges([*code_ranges, *effective_noncode])
    gaps = [gap for section in executable for gap in _subtract_ranges(section, classified)]
    for gap in gaps:
        issues.append(
            ExportIssue(
                status="incomplete",
                category="unclassified_executable_span",
                message=(
                    f"executable bytes 0x{gap.start:x}-0x{gap.end:x} are not represented "
                    "by a semantic unit or checked non-code classification"
                ),
                next_action="classify the span as semantic code, checked padding, or embedded data",
                location=SourceLocation(None, None, None, gap, "executable_coverage"),
            )
        )
    executable_bytes = sum(span.size for span in executable)
    covered_code = sum(
        overlap.size
        for section in executable
        for overlap in _intersections(section, _merge_ranges(code_ranges))
    )
    covered_noncode = sum(
        overlap.size
        for section in executable
        for overlap in _intersections(section, _merge_ranges(effective_noncode))
    )
    return (
        {
            "status": "qualified" if not gaps and not any(i.status == "violated" for i in issues) else "incomplete",
            "executable_sections": [span.payload() for span in executable],
            "semantic_code_ranges": [span.payload() for span in _merge_ranges(code_ranges)],
            "checked_noncode_ranges": [span.payload() for span in _merge_ranges(effective_noncode)],
            "unknown_ranges": [span.payload() for span in gaps],
            "counts": {
                "executable_bytes": executable_bytes,
                "semantic_code_bytes": covered_code,
                "checked_noncode_bytes": covered_noncode,
                "unknown_bytes": sum(span.size for span in gaps),
            },
        },
        issues,
    )


def _exact_only_control_inventory(
    *,
    binary: StageABinary,
    units: Sequence[dict[str, Any]],
    roots: Sequence[Mapping[str, Any]],
    direct: Sequence[Mapping[str, Any]],
    indirect: Sequence[dict[str, Any]],
    direct_control_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    static_recoveries: Sequence[Mapping[str, Any]],
    executable_classification: Mapping[str, Any],
    callback_root_proposals: Sequence[Mapping[str, Any]],
    checked_targets: Sequence[Any],
    static_rounds: int,
    static_converged: bool,
    target_profile: Mapping[str, Any] | None,
) -> tuple[dict[str, Any], list[ExportIssue]]:
    """Emit exact units/direct control without running superseded provenance."""

    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in units
    }
    root_unit_ids = [
        str(starts[rva]["id"])
        for root in roots
        for rva in (root.get("rva"),)
        if isinstance(rva, int) and rva in starts
    ]
    issues: list[ExportIssue] = []
    recovered: list[dict[str, Any]] = []
    for exit_record, raw_recovery in zip(
        indirect, static_recoveries, strict=True
    ):
        recovery = copy.deepcopy(dict(raw_recovery))
        complete = (
            recovery.get("status") == "recovered"
            and _indirect_recovery_unit_binding_complete(recovery, starts)
        )
        if complete:
            exit_record["closure"] = "checked_static_target_inventory"
            exit_record["target_rvas"] = list(recovery.get("target_rvas", ()))
            exit_record["target_unit_ids"] = list(
                recovery.get("target_unit_ids", ())
            )
            exit_record["external_targets"] = []
        else:
            exit_record["closure"] = (
                "explicit_trusted_target_profile_without_inventory"
                if target_profile is not None
                else "awaiting_interprocedural_v2"
            )
            failure = recovery.get("failure")
            failure = (
                failure
                if isinstance(failure, Mapping)
                else {"code": "static_target_recovery_incomplete"}
            )
            exit_record["recovery_failure"] = copy.deepcopy(dict(failure))
            source = next(
                unit for unit in units
                if str(unit["id"]) == str(exit_record["source_unit_id"])
            )
            issues.append(ExportIssue(
                status="incomplete",
                category="interprocedural_target_certificate_deferred",
                message=(
                    "indirect target awaits the v2 SCC analysis: "
                    + _recovery_failure_message(failure)
                ),
                next_action=(
                    "run the dependency-aware v2 interprocedural phase; "
                    "machine-IR extraction does not authorize target recovery"
                ),
                location=_location_from_unit(source, "control.indirect_target"),
            ))
        recovered.append(recovery)
    reachability = derive_rooted_reachable_units(
        units=units,
        roots=root_unit_ids,
        direct_edges=direct_control_edges,
        internal_call_edges=internal_call_edges,
        recovered_indirect_targets=recovered,
        indirect_exits=indirect,
    )
    exact_reachable = set(reachability["reachable_units"])
    potentially_reachable = (
        set(str(unit["id"]) for unit in units)
        if reachability["status"] != "complete"
        else exact_reachable
    )
    for unit in units:
        unit_id = str(unit["id"])
        unit["reachable"] = unit_id in exact_reachable
        unit["reachability"] = (
            "reachable"
            if unit_id in exact_reachable
            else "potential" if unit_id in potentially_reachable else "unreachable"
        )
    potential = sorted(potentially_reachable - exact_reachable)
    reachability["potential_units"] = potential
    reachability["confirmed_unreachable_units"] = (
        sorted(set(str(unit["id"]) for unit in units) - exact_reachable)
        if reachability["status"] == "complete"
        else []
    )
    reachability["counts"].update({
        "potential_units": len(potential),
        "confirmed_unreachable_units": len(
            reachability["confirmed_unreachable_units"]
        ),
    })
    call_summaries = {
        "status": "incomplete",
        "summaries": [],
        "reason": "owned_by_interprocedural_v2_phase",
    }
    for unit in units:
        if str(unit["id"]) not in exact_reachable:
            continue
        semantics = unit.get("semantics")
        outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
        faults = semantics.get("faults") if isinstance(semantics, Mapping) else None
        if (
            isinstance(outcome, Mapping)
            and outcome.get("kind") == "fault"
            and isinstance(faults, list)
            and not faults
        ):
            issues.append(
                ExportIssue(
                    status="incomplete",
                    category="terminal_fault_missing_fault_record",
                    message=(
                        "an explicit terminal fault outcome has no exact fault "
                        "predicate or architectural fault class"
                    ),
                    next_action=(
                        "emit the instruction-bound fault record before treating "
                        "the outcome as checked exceptional termination"
                    ),
                    location=_location_from_unit(unit, "semantics.faults"),
                )
            )
    exceptional = _exceptional_control_inventory(
        units,
        root_rvas={
            int(root["rva"])
            for root in roots
            if isinstance(root.get("rva"), int)
        },
        indirect_exits=indirect,
        internal_call_preservation=call_summaries,
    )
    provenance = {
        "format": "stage-a-external-interface-provenance-v1",
        "status": "incomplete",
        "resolutions": [],
        "static_interface_slots": [],
        "rejected_tainted_slots": [],
        "callback_registrations": [],
        "issues": [{
            "code": "owned_by_interprocedural_v2_phase",
        }],
    }
    control = {
        "executable_classification": copy.deepcopy(
            dict(executable_classification)
        ),
        "roots": sorted(roots, key=_root_sort_key),
        "direct_targets": sorted(
            direct,
            key=lambda item: (item["source_rva"], item["target_rva"]),
        ),
        "indirect_exits": sorted(
            indirect,
            key=lambda item: (item["source_rva"], item["source_unit_id"]),
        ),
        "recovered_indirect_targets": sorted(
            recovered,
            key=lambda item: (item["source_rva"], item["source_unit_id"]),
        ),
        "value_provenance": {"status": "incomplete", "resolutions": []},
        "external_interface_provenance": provenance,
        "operation_provenance": {
            "format": "stage-a-operation-provenance-v2",
            "status": "incomplete",
            "resolutions": [],
            "callback_registrations": [],
            "issues": [{"code": "owned_by_interprocedural_v2_phase"}],
        },
        "internal_call_preservation": call_summaries,
        "exceptional_control": exceptional,
        "callback_cutpoint_proposals": list(callback_root_proposals),
        "analysis_fixed_point": {
            "format": "stage-a-interprocedural-analysis-v2",
            "status": "incomplete",
            "rounds": 0,
            "cold_replay_validated": False,
            "global_slot_promotion": False,
            "failure_reasons": ["owned_by_interprocedural_v2_phase"],
            "static_jump_table_rounds": static_rounds,
            "static_jump_table_converged": static_converged,
        },
        "reachability": reachability,
        "checked_jump_table_targets": list(checked_targets),
        "indirect_target_profile": (
            None
            if target_profile is None
            else {
                "id": target_profile["id"],
                "authority": "diagnostic_only",
            }
        ),
        "counts": {
            "roots": len(roots),
            "direct_targets": len(direct),
            "unresolved_direct_targets": sum(
                item["status"] != "resolved" for item in direct
            ),
            "indirect_exits": len(indirect),
            "closed_indirect_exits": sum(
                item["closure"] == "checked_static_target_inventory"
                for item in indirect
            ),
            "exact_reachable_units": len(exact_reachable),
            "potential_reachable_units": len(potential),
            "rooted_frontiers": len(reachability["frontiers"]),
            "exceptional_transitions": len(exceptional["transitions"]),
            "complete_exceptional_transitions": sum(
                transition["status"] == "complete"
                for transition in exceptional["transitions"]
            ),
            "checked_jump_table_targets": len(checked_targets),
            "callback_cutpoint_proposals": len(callback_root_proposals),
        },
    }
    return control, issues


def _control_inventory(
    binary: StageABinary,
    units: Sequence[dict[str, Any]],
    reference: Mapping[str, Any],
    *,
    executable_classification: Mapping[str, Any],
    preclassified_static_recoveries: Sequence[Mapping[str, Any]],
    target_profile: Mapping[str, Any] | None,
    finite_dataflow_factory: Callable[..., Any],
) -> tuple[dict[str, Any], list[ExportIssue]]:
    starts = {int(unit["source"]["original"]["rva_start"]): unit for unit in units}
    block_starts = {
        str(unit["source_location"]["block_id"]): int(
            unit["source"]["original"]["rva_start"]
        )
        for unit in units
        if unit["source_location"].get("block_id")
    }
    initial_roots = _initial_control_roots(binary, reference, block_starts)
    roots_by_rva: dict[int, dict[str, Any]] = {}
    for root in initial_roots:
        raw_rva = root.get("rva", root.get("target_rva"))
        if not isinstance(raw_rva, int):
            continue
        canonical = roots_by_rva.setdefault(raw_rva, copy.deepcopy(dict(root)))
        for key, value in root.items():
            canonical.setdefault(key, copy.deepcopy(value))
    callback_root_proposals = _local_callback_cutpoint_proposals(binary, units)
    roots = list(roots_by_rva.values())

    direct: list[dict[str, Any]] = []
    indirect: list[dict[str, Any]] = []
    issues: list[ExportIssue] = []
    for unit in units:
        location = _location_from_unit(unit, "semantics.outcome")
        control = unit["control"]
        edge_guards = {
            int(edge["target_rva"]): copy.deepcopy(edge.get("condition"))
            for edge in unit.get("semantics", {}).get("edge_conditions", [])
            if isinstance(edge, Mapping)
            and isinstance(edge.get("target_rva"), int)
        }
        for target in control["direct_targets"]:
            resolved = target in starts
            item = {
                "kind": "direct_control",
                "source_unit_id": unit["id"],
                "source_rva": unit["source"]["original"]["rva_start"],
                "target_rva": target,
                "resolved_unit_id": starts[target]["id"] if resolved else None,
                "status": "resolved" if resolved else "incomplete",
                "guard": edge_guards.get(target),
            }
            direct.append(item)
            if not resolved:
                issues.append(
                    ExportIssue(
                        status="incomplete",
                        category="unresolved_direct_control_target",
                        message=f"direct control target 0x{target:x} has no machine IR unit",
                        next_action="export the target unit or prove the edge terminating/infeasible",
                        location=location,
                    )
                )
        if control["has_indirect_target"]:
            item = {
                    "source_unit_id": unit["id"],
                    "source_rva": unit["source"]["original"]["rva_start"],
                    "kind": control["kind"],
                    "target_expression": copy.deepcopy(unit["semantics"]["outcome"].get("target")),
                }
            item["id"] = indirect_exit_id_v2(item)
            indirect.append(item)
        raw_events = unit["semantics"].get("external_events")
        if isinstance(raw_events, list):
            for event_index, event in enumerate(raw_events):
                if not isinstance(event, Mapping):
                    continue
                kind = event.get("kind")
                if kind == "internal_call" and isinstance(event.get("target_rva"), int):
                    target = _u32(
                        event.get("target_rva"),
                        f"{unit['id']} internal call target",
                    )
                    resolved = target in starts
                    direct.append(
                        {
                            "kind": "internal_call",
                            "source_unit_id": unit["id"],
                            "source_rva": unit["source"]["original"]["rva_start"],
                            "source_event_index": event_index,
                            "target_rva": target,
                            "resolved_unit_id": starts[target]["id"] if resolved else None,
                            "status": "resolved" if resolved else "incomplete",
                        }
                    )
                    if not resolved:
                        issues.append(
                            ExportIssue(
                                status="incomplete",
                                category="unresolved_internal_call_target",
                                message=f"internal call target 0x{target:x} has no machine IR unit",
                                next_action="export the callee unit or correct its target recovery",
                                location=_location_from_unit(
                                    unit, f"semantics.external_events[{event_index}]"
                                ),
                            )
                        )
                elif kind in {"indirect_call", "indirect_jump"}:
                    item = {
                            "source_unit_id": unit["id"],
                            "source_rva": unit["source"]["original"]["rva_start"],
                            "source_event_index": event_index,
                            "kind": kind,
                            "target_expression": copy.deepcopy(event.get("target")),
                        }
                    item["id"] = indirect_exit_id_v2(item)
                    indirect.append(item)
    for root in roots:
        rva = root.get("rva", root.get("target_rva")) if isinstance(root, Mapping) else None
        if isinstance(rva, int) and rva not in starts:
            issues.append(
                ExportIssue(
                    status="incomplete",
                    category="unresolved_behavioral_root",
                    message=f"behavioral root 0x{rva:x} has no machine IR unit",
                    next_action="export a unit beginning at the root or correct root recovery",
                    location=SourceLocation(None, None, None, RvaSpan(rva, rva + 1), "control.roots"),
                )
            )
    checked_targets = reference.get("jump_table_targets", [])
    root_unit_ids = [
        starts[int(root["rva"])]["id"]
        for root in roots
        if isinstance(root.get("rva"), int) and int(root["rva"]) in starts
    ]
    direct_control_edges = [
        item for item in direct if item["kind"] == "direct_control"
    ]
    internal_call_edges = [
        item for item in direct if item["kind"] == "internal_call"
    ]
    if preclassified_static_recoveries:
        exact_static_recoveries = _rebind_preclassified_static_recoveries(
            indirect_exits=indirect,
            recoveries=preclassified_static_recoveries,
            starts=starts,
        )
        static_rounds = 0
        static_converged = True
    else:
        (
            exact_static_recoveries,
            static_rounds,
            static_converged,
        ) = _static_jump_table_recovery_fixed_point(
            binary=binary,
            units=units,
            starts=starts,
            indirect_exits=indirect,
            root_unit_ids=root_unit_ids,
            finite_dataflow_factory=finite_dataflow_factory,
        )
    return _exact_only_control_inventory(
        binary=binary,
        units=units,
        roots=roots,
        direct=direct,
        indirect=indirect,
        direct_control_edges=direct_control_edges,
        internal_call_edges=internal_call_edges,
        static_recoveries=exact_static_recoveries,
        executable_classification=executable_classification,
        callback_root_proposals=callback_root_proposals,
        checked_targets=checked_targets,
        static_rounds=static_rounds,
        static_converged=static_converged,
        target_profile=target_profile,
    )


def _exceptional_control_inventory(
    units: Sequence[Mapping[str, Any]],
    *,
    root_rvas: Iterable[int] = (),
    indirect_exits: Sequence[Mapping[str, Any]] = (),
    internal_call_preservation: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Project exact reachable fault sites into fail-closed control records.

    A symbolic fault predicate does not establish whether Windows SEH handles the
    fault.  A site can close locally only when the semantic outcome explicitly
    terminates in that fault or the explicit arithmetic predicate is proved false
    for every machine-IR input.  Every other site remains an unresolved frontier.
    """

    # v1 retains this projection for diagnostics only. Non-local fault
    # infeasibility is authoritative only through the v2 SCC invariant checker;
    # bounded predecessor enumeration cannot establish loop-wide behavior.
    del root_rvas, indirect_exits, internal_call_preservation
    transitions: list[dict[str, Any]] = []
    for unit in units:
        if unit.get("reachable") is not True:
            continue
        unit_id = str(unit["id"])
        source_rva = int(unit["source"]["original"]["rva_start"])
        source_contract_sha256 = str(unit["source"]["contract_sha256"])
        semantics = unit.get("semantics")
        if not isinstance(semantics, Mapping):
            continue
        faults = semantics.get("faults")
        if not isinstance(faults, list):
            continue
        outcome = semantics.get("outcome")
        for fault_index, raw_fault in enumerate(faults):
            if not isinstance(raw_fault, Mapping):
                continue
            fault = copy.deepcopy(dict(raw_fault))
            fault_sha256 = sha256_bytes(_canonical_json(fault))
            terminal_fault = _is_explicit_terminal_fault(unit, fault)
            outcome_sha256 = (
                sha256_bytes(_canonical_json(outcome)) if terminal_fault else None
            )
            infeasibility = (
                None
                if terminal_fault
                else _checked_fault_infeasibility(
                    unit=unit,
                    fault=fault,
                    fault_index=fault_index,
                    fault_sha256=fault_sha256,
                )
            )
            if (
                isinstance(infeasibility, Mapping)
                and infeasibility.get("status") != "complete"
            ):
                infeasibility = {
                    **dict(infeasibility),
                    "scc_invariant_requirement": {
                        "format": "stage-a-scc-exception-invariant-requirement-v2",
                        "status": "incomplete",
                        "source_unit_id": unit_id,
                        "source_fault_index": fault_index,
                        "fault_sha256": fault_sha256,
                        "reason": "checked_scc_invariant_certificate_required",
                    },
                }
            transition: dict[str, Any] = {
                "source_unit_id": unit_id,
                "source_fault_index": fault_index,
                "source_rva": source_rva,
                "instruction_rva": fault.get("instruction_rva"),
                "fault_kind": fault.get("kind"),
                "fault_sha256": fault_sha256,
            }
            if terminal_fault:
                certificate = {
                    "format": "stage-a-explicit-terminal-fault-certificate-v1",
                    "source_unit_id": unit_id,
                    "source_fault_index": fault_index,
                    "source_contract_sha256": source_contract_sha256,
                    "fault_sha256": fault_sha256,
                    "outcome_sha256": outcome_sha256,
                }
                transition.update(
                    {
                        "status": "complete",
                        "disposition": {
                            "kind": "termination",
                            "observable": True,
                            "evidence": {
                                "status": "checked",
                                "checker": (
                                    "stage-a-machine-ir-explicit-terminal-fault-v1"
                                ),
                                "certificate_sha256": sha256_bytes(
                                    _canonical_json(certificate)
                                ),
                                "certificate": certificate,
                            },
                        },
                    }
                )
            elif infeasibility is not None and infeasibility["status"] == "complete":
                transition.update(
                    {
                        "status": "complete",
                        "disposition": {
                            "kind": "infeasible",
                            "observable": False,
                            "evidence": infeasibility["evidence"],
                        },
                    }
                )
            else:
                feasibility = (
                    infeasibility.get("feasibility")
                    if isinstance(infeasibility, Mapping)
                    else None
                )
                analysis = (
                    infeasibility.get("analysis")
                    if isinstance(infeasibility, Mapping)
                    else None
                )
                scc_invariant_requirement = (
                    infeasibility.get("scc_invariant_requirement")
                    if isinstance(infeasibility, Mapping)
                    else None
                )
                abstract_possible = (
                    isinstance(analysis, Mapping)
                    and bool(analysis.get("stateful_leaf_abstractions"))
                    and isinstance(feasibility, Mapping)
                    and feasibility.get("status") == "violated"
                )
                reason = (
                    (
                        "fault predicate is satisfiable in the conservative "
                        "stateful-leaf over-approximation and has no checked "
                        "infeasibility or SEH target"
                    )
                    if abstract_possible
                    else "fault predicate is satisfiable and has no checked SEH target"
                    if isinstance(feasibility, Mapping)
                    and feasibility.get("status") == "violated"
                    else (
                        "fault predicate is outside the checked local "
                        "infeasibility fragment and has no terminal outcome or "
                        "SEH target"
                    )
                )
                transition.update(
                    {
                        "status": "incomplete",
                        "disposition": {
                            "kind": "unresolved",
                            "reason": reason,
                            "evidence": {
                                "status": (
                                    "checked_abstract_possible"
                                    if abstract_possible
                                    else "checked_possible"
                                    if isinstance(feasibility, Mapping)
                                    and feasibility.get("status") == "violated"
                                    else "unchecked"
                                ),
                                "checker": (
                                    "stage-a-machine-ir-exceptional-control-v1"
                                ),
                                **(
                                    {"feasibility": feasibility}
                                    if isinstance(feasibility, Mapping)
                                    else {}
                                ),
                                **(
                                    {"analysis": analysis}
                                    if isinstance(analysis, Mapping)
                                    else {}
                                ),
                                **(
                                    {
                                        "scc_invariant_requirement": (
                                            scc_invariant_requirement
                                        )
                                    }
                                    if isinstance(
                                        scc_invariant_requirement, Mapping
                                    )
                                    else {}
                                ),
                            },
                        },
                    }
                )
            transitions.append(transition)
    transitions.sort(
        key=lambda row: (
            int(row["source_rva"]),
            str(row["source_unit_id"]),
            int(row["source_fault_index"]),
        )
    )
    return {
        "format": "stage-a-exceptional-control-v1",
        "status": (
            "complete"
            if all(row["status"] == "complete" for row in transitions)
            else "incomplete"
        ),
        "transitions": transitions,
        "counts": {
            "transitions": len(transitions),
            "complete": sum(row["status"] == "complete" for row in transitions),
            "incomplete": sum(
                row["status"] == "incomplete" for row in transitions
            ),
        },
    }


def _checked_fault_infeasibility(
    *,
    unit: Mapping[str, Any],
    fault: Mapping[str, Any],
    fault_index: int,
    fault_sha256: str,
) -> dict[str, Any] | None:
    """Prove an explicit, local arithmetic fault predicate is always false.

    The checker intentionally excludes segment-, page-, x87-, and
    platform-mediated fault classes.  Their absence cannot be established from
    a straight-line bitvector predicate alone.  Stateful bitvector leaves are
    over-approximated as independent inputs, so only an unsatisfiable predicate
    can close the transition.
    """

    fault_kind = fault.get("kind")
    condition = fault.get("condition")
    if (
        fault_kind not in _QF_BV_LOCALLY_DECIDABLE_FAULT_KINDS
        or not isinstance(condition, Mapping)
    ):
        return None

    abstract_condition, abstractions, input_widths = (
        _abstract_fault_predicate_stateful_leaves(condition)
    )
    result = check_straight_line_semantic_claim(
        {"fault_condition": abstract_condition},
        {
            "fault_condition": {
                "op": "const",
                "value": 0,
                "width": 32,
            }
        },
        input_widths=input_widths,
        solver_timeout_ms=2_000,
    )
    result_payload = result.to_payload()
    analysis = {
        "format": "stage-a-qf-bv-fault-predicate-analysis-v1",
        "fault_sha256": fault_sha256,
        "predicate_sha256": sha256_bytes(_canonical_json(condition)),
        "abstract_predicate_sha256": sha256_bytes(
            _canonical_json(abstract_condition)
        ),
        "stateful_leaf_abstractions": abstractions,
    }
    if result.status != "qualified":
        return {
            "status": "incomplete",
            "feasibility": result_payload,
            "analysis": analysis,
        }

    unit_id = str(unit["id"])
    source_contract_sha256 = str(unit["source"]["contract_sha256"])
    predicate_sha256 = sha256_bytes(_canonical_json(condition))
    certificate = {
        "format": "stage-a-qf-bv-fault-infeasibility-certificate-v1",
        "source_unit_id": unit_id,
        "source_fault_index": fault_index,
        "source_contract_sha256": source_contract_sha256,
        "fault_kind": fault_kind,
        "fault_sha256": fault_sha256,
        "predicate_sha256": predicate_sha256,
        "abstract_predicate_sha256": analysis["abstract_predicate_sha256"],
        "stateful_leaf_abstractions": abstractions,
        "claim": "fault_condition_is_zero_for_all_machine_ir_inputs",
        "checked_claims": list(result.checked_claims),
    }
    return {
        "status": "complete",
        "evidence": {
            "status": "checked",
            "checker": "stage-a-machine-ir-qf-bv-fault-infeasibility-v1",
            "trust_boundary": result.trust_boundary,
            "certificate_sha256": sha256_bytes(_canonical_json(certificate)),
            "certificate": certificate,
        },
    }


def _abstract_fault_predicate_stateful_leaves(
    condition: Mapping[str, Any],
    *,
    share_identical: bool = False,
) -> tuple[dict[str, Any], list[dict[str, Any]], dict[str, int]]:
    """Over-approximate stateful bitvector leaves with independent inputs.

    Independence deliberately forgets load aliasing and external-state
    constraints.  Proving the fault predicate false in this larger state space
    is sound; a satisfying assignment is diagnostic only and never closes the
    transition.
    """

    abstractions: list[dict[str, Any]] = []
    input_widths: dict[str, int] = {}
    shared_names: dict[tuple[str, str, int], str] = {}

    def visit(value: Any) -> Any:
        if isinstance(value, list):
            return [visit(item) for item in value]
        if not isinstance(value, Mapping):
            return copy.deepcopy(value)
        op = value.get("op")
        if op in _FAULT_PREDICATE_ABSTRACT_LEAF_OPS:
            if op == "load":
                raw_width = value.get("width")
                width = (
                    int(raw_width) * 8
                    if isinstance(raw_width, int)
                    and not isinstance(raw_width, bool)
                    and raw_width in {1, 2, 4}
                    else 32
                )
            elif op in {"call_flag", "undefined_flag"}:
                width = 1
            else:
                raw_width = value.get("width", 32)
                width = (
                    int(raw_width)
                    if isinstance(raw_width, int)
                    and not isinstance(raw_width, bool)
                    and 1 <= int(raw_width) <= 32
                    else 32
                )
            source_sha256 = sha256_bytes(_canonical_json(value))
            shared_key = (str(op), source_sha256, width)
            name = shared_names.get(shared_key) if share_identical else None
            if name is None:
                name = f"fault_leaf_{len(abstractions):04d}"
                abstractions.append(
                    {
                        "name": name,
                        "source_op": op,
                        "source_sha256": source_sha256,
                        "width": width,
                        "relation": (
                            "identical_expression_shared_arbitrary_value_"
                            "overapproximation"
                            if share_identical
                            else "independent_arbitrary_value_overapproximation"
                        ),
                    }
                )
                if share_identical:
                    shared_names[shared_key] = name
            input_widths[name] = width
            return {"op": "reg", "name": name, "width": width}
        return {str(key): visit(item) for key, item in value.items()}

    return visit(condition), abstractions, input_widths


def _is_explicit_terminal_fault(
    unit: Mapping[str, Any], fault: Mapping[str, Any]
) -> bool:
    semantics = unit.get("semantics")
    outcome = semantics.get("outcome") if isinstance(semantics, Mapping) else None
    if not isinstance(outcome, Mapping) or outcome.get("kind") != "fault":
        return False
    fault_kind = fault.get("kind")
    if not isinstance(fault_kind, str) or not fault_kind or fault_kind == "unknown":
        return False
    declared_kind = outcome.get("fault_kind")
    if declared_kind is not None and declared_kind != fault_kind:
        return False
    instruction_rva = fault.get("instruction_rva")
    source = unit.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    if (
        not isinstance(instruction_rva, int)
        or isinstance(instruction_rva, bool)
        or not isinstance(original, Mapping)
        or not isinstance(original.get("rva_start"), int)
        or not isinstance(original.get("rva_end"), int)
        or not int(original["rva_start"]) <= instruction_rva < int(original["rva_end"])
    ):
        return False
    condition = fault.get("condition")
    if not isinstance(condition, Mapping):
        return False
    if condition.get("op") == "true":
        return True
    return (
        condition.get("op") == "const"
        and isinstance(condition.get("value"), int)
        and not isinstance(condition.get("value"), bool)
        and condition.get("value") != 0
    )
