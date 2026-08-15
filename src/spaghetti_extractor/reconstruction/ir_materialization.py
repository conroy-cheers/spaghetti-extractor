"""Executable-data classification and recovered target materialization."""

from __future__ import annotations

import copy
from typing import Any, Callable, Mapping, Sequence

from ..authority_inputs.bindings import indirect_exit_id_v2
from ..static_program.semantics.transfer import semantic_transfer
from ..extraction.cutpoints import semantic_cutpoint_spans_for_side
from ..pe32.recovered_executable_data import recover_executable_data_ranges
from .state_machine import normalize_spx_semantic_transfer
from ..pe32.model import BlockSide, ParsedPEImage
from ..static_program.model import StaticUnitContext
from ..pe32.target_cutpoint_materialization import plan_recovered_target_cutpoints_v2
from ..util import sha256_bytes
from .control_reachability import (
    classify_overlapping_instruction_starts,
    derive_rooted_reachable_units,
)
from .ir_model import (
    ExportIssue,
    RvaSpan,
    SourceLocation,
    _assert_byte_free,
    _canonical_json,
)
from .ir_preparation import _prepare_unit
from .ir_recovery import (
    _rebind_preclassified_static_recoveries,
    _static_jump_table_recovery_fixed_point,
)
from .ir_evidence import _resolved_root


def _immutable_static_data_reader(
    binary: ParsedPEImage,
):
    def read(address: int, size: int) -> bytes | None:
        if size <= 0:
            return None
        rva = address - binary.image_base
        for section in binary.sections:
            initialized_end = min(
                section.rva_end,
                section.rva_start + section.raw_size,
            )
            if (
                section.readable
                and not section.writable
                and section.rva_start <= rva
                and rva + size <= initialized_end
            ):
                data = bytes(binary.pe.get_data(rva, size))
                return data if len(data) == size else None
        return None

    return read


def _materialize_recovered_target_cutpoints(
    *,
    binary: ParsedPEImage,
    units: Sequence[Mapping[str, Any]],
    static_program: Mapping[str, Any],
    static_program_sha256: str | None,
    finite_dataflow_factory: Callable[..., Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    list[ExportIssue],
    list[dict[str, Any]] | None,
    Sequence[Any] | None,
]:
    """Regenerate the rooted finite-control closure from exact PE bytes."""

    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in units
    }
    block_starts = {
        str(unit["source_location"]["block_id"]): int(
            unit["source"]["original"]["rva_start"]
        )
        for unit in units
        if unit["source_location"].get("block_id")
    }
    roots = _initial_control_roots(binary, static_program, block_starts)
    root_unit_ids = [
        str(starts[rva]["id"])
        for root in roots
        for rva in (root.get("rva"),)
        if isinstance(rva, int) and rva in starts
    ]
    recoveries, rounds, converged = _static_jump_table_recovery_fixed_point(
        binary=binary,
        units=units,
        starts=starts,
        indirect_exits=_precontrol_indirect_exits(units),
        root_unit_ids=root_unit_ids,
        finite_dataflow_factory=finite_dataflow_factory,
    )
    data_ranges = recover_executable_data_ranges(
        binary=binary,
        recoveries=recoveries,
        known_code_unit_rvas=set(starts),
    )
    data_spans = [RvaSpan(item.rva_start, item.rva_end) for item in data_ranges]
    augmented = [copy.deepcopy(dict(unit)) for unit in units]
    input_unit_ids = {str(unit["id"]) for unit in units}
    materialized_rows: list[dict[str, Any]] = []
    superseded_rows: list[dict[str, Any]] = []
    iteration_rows: list[dict[str, Any]] = []
    final_plan: dict[str, Any] | None = None
    converged_cutpoints = False
    max_cutpoint_rounds = 16
    recovery_ids = {str(row.get("id")) for row in recoveries}
    for iteration in range(1, max_cutpoint_rounds + 1):
        active_units = [
            unit
            for unit in augmented
            if not any(
                _unit_original_span(unit).start < data.end
                and data.start < _unit_original_span(unit).end
                for data in data_spans
            )
        ]
        active_starts = {
            int(unit["source"]["original"]["rva_start"]): unit
            for unit in active_units
        }
        direct_edges, internal_call_edges = _precontrol_direct_edges(active_units)
        indirect_exits = _precontrol_indirect_exits(active_units)
        known_exits = [
            row for row in indirect_exits if str(row.get("id")) in recovery_ids
        ]
        rebound_recoveries = _rebind_preclassified_static_recoveries(
            indirect_exits=known_exits,
            recoveries=recoveries,
            starts=active_starts,
        )
        active_root_ids = [
            str(active_starts[rva]["id"])
            for root in roots
            for rva in (root.get("rva"),)
            if isinstance(rva, int) and rva in active_starts
        ]
        reachability = derive_rooted_reachable_units(
            units=active_units,
            roots=active_root_ids,
            direct_edges=direct_edges,
            internal_call_edges=internal_call_edges,
            recovered_indirect_targets=rebound_recoveries,
            indirect_exits=indirect_exits,
        )
        reached_ids = set(reachability["reachable_units"])
        required_targets: dict[int, set[str]] = {}
        independently_targeted_rvas: set[int] = set()
        for root in roots:
            rva = root.get("rva")
            if not isinstance(rva, int):
                continue
            independently_targeted_rvas.add(rva)
            if rva not in active_starts:
                required_targets.setdefault(rva, set()).add(
                    f"root:{root.get('kind', 'behavioral')}"
                )
        for edge in (*direct_edges, *internal_call_edges):
            target_rva = edge.get("target_rva")
            if (
                edge.get("source_unit_id") not in reached_ids
                or not isinstance(target_rva, int)
            ):
                continue
            independently_targeted_rvas.add(target_rva)
            if target_rva not in active_starts:
                required_targets.setdefault(target_rva, set()).add(
                    f"{edge.get('kind')}:{edge.get('source_unit_id')}"
                )
        planner_recoveries: list[dict[str, Any]] = []
        for recovery in rebound_recoveries:
            if recovery.get("source_unit_id") not in reached_ids:
                continue
            missing_targets = [
                int(target)
                for target in recovery.get("target_rvas", [])
                if isinstance(target, int) and target not in active_starts
            ]
            independently_targeted_rvas.update(
                int(target)
                for target in recovery.get("target_rvas", [])
                if isinstance(target, int)
            )
            if missing_targets:
                planner_recoveries.append({
                    **copy.deepcopy(dict(recovery)),
                    "target_rvas": missing_targets,
                })
        authoritative_ids = reached_ids | {
            str(active_starts[rva]["id"])
            for rva in independently_targeted_rvas
            if rva in active_starts
        }
        plan = plan_recovered_target_cutpoints_v2(
            binary=binary,
            units=active_units,
            recoveries=planner_recoveries,
            required_targets={
                target: sorted(sources)
                for target, sources in required_targets.items()
            },
            authoritative_unit_ids=sorted(authoritative_ids),
            immutable_data_ranges=data_ranges,
        )
        final_plan = plan
        added = _materialize_target_cutpoint_plan(
            binary=binary,
            augmented=augmented,
            plan=plan,
            static_program_sha256=static_program_sha256,
            iteration=iteration,
            materialized_rows=materialized_rows,
            superseded_rows=superseded_rows,
            input_unit_ids=input_unit_ids,
        )
        iteration_rows.append({
            "iteration": iteration,
            "plan_id": plan["id"],
            "status": plan["status"],
            "reachable_units": len(reached_ids),
            "rooted_frontiers": len(reachability["frontiers"]),
            "targets": plan["counts"]["targets"],
            "materialized_units": added,
        })
        if added == 0:
            converged_cutpoints = True
            break

    augmented.sort(
        key=lambda item: (
            int(item["source"]["original"]["rva_start"]),
            str(item["id"]),
        )
    )
    initial_exit_ids = {
        str(exit_record["id"])
        for exit_record in _precontrol_indirect_exits(units)
    }
    augmented_exits = _precontrol_indirect_exits(augmented)
    augmented_exit_ids = {str(exit_record["id"]) for exit_record in augmented_exits}
    replay_recoveries: list[dict[str, Any]] | None = None
    replay_data_ranges: Sequence[Any] | None = None
    if initial_exit_ids == augmented_exit_ids:
        augmented_starts = {
            int(unit["source"]["original"]["rva_start"]): unit
            for unit in augmented
        }
        replay_recoveries = _rebind_preclassified_static_recoveries(
            indirect_exits=augmented_exits,
            recoveries=recoveries,
            starts=augmented_starts,
        )
        replay_data_ranges = recover_executable_data_ranges(
            binary=binary,
            recoveries=replay_recoveries,
            known_code_unit_rvas=set(augmented_starts),
        )
    if final_plan is None:
        raise AssertionError("target cutpoint closure performed no iterations")
    issues = [
        ExportIssue(
            status=str(issue["status"]),
            category=str(issue["code"]),
            message=(
                f"finite control target 0x{int(issue['target_rva']):x} "
                f"could not become an exact machine-IR cutpoint"
            ),
            next_action=(
                "repair exact target decoding or classify the conflicting "
                "executable bytes before rebuilding machine IR"
            ),
            location=SourceLocation(
                None,
                None,
                None,
                RvaSpan(int(issue["target_rva"]), int(issue["target_rva"]) + 1),
                "control.target_cutpoint_materialization",
            ),
        )
        for issue in final_plan["issues"]
    ]
    report = {
        **copy.deepcopy(final_plan),
        "static_recovery_rounds": rounds,
        "static_recovery_converged": converged,
        "cutpoint_closure_iterations": iteration_rows,
        "cutpoint_closure_converged": converged_cutpoints,
        "static_recovery_reused_after_materialization": (
            replay_recoveries is not None
        ),
        "materialized_units": materialized_rows,
        "superseded_units": superseded_rows,
        "counts": {
            **copy.deepcopy(final_plan["counts"]),
            "materialized_units": len(materialized_rows),
            "qualified_materialized_units": sum(
                row["status"] == "qualified" for row in materialized_rows
            ),
            "superseded_units": len(superseded_rows),
            "superseded_input_units": sum(
                row["origin"] == "prepared_input" for row in superseded_rows
            ),
        },
    }
    if not converged_cutpoints:
        report["status"] = "incomplete"
        issues.append(
            ExportIssue(
                status="incomplete",
                category="target_cutpoint_closure_budget_exceeded",
                message="rooted direct target materialization did not converge",
                next_action=(
                    "inspect the newly exposed direct-control chain or raise "
                    "the generic closure budget"
                ),
                location=SourceLocation(
                    None,
                    None,
                    None,
                    RvaSpan(binary.entrypoint_rva, binary.entrypoint_rva + 1),
                    "control.target_cutpoint_materialization",
                ),
            )
        )
    if not converged:
        report["status"] = "incomplete"
        issues.append(
            ExportIssue(
                status="incomplete",
                category="target_cutpoint_static_recovery_budget_exceeded",
                message=(
                    "finite target discovery did not converge before cutpoint "
                    "planning"
                ),
                next_action=(
                    "reduce the finite target domain or increase the generic "
                    "recovery budget"
                ),
                location=SourceLocation(
                    None,
                    None,
                    None,
                    RvaSpan(binary.entrypoint_rva, binary.entrypoint_rva + 1),
                    "control.target_cutpoint_materialization",
                ),
            )
        )
    return augmented, report, issues, replay_recoveries, replay_data_ranges


def _materialize_target_cutpoint_plan(
    *,
    binary: ParsedPEImage,
    augmented: list[dict[str, Any]],
    plan: Mapping[str, Any],
    static_program_sha256: str | None,
    iteration: int,
    materialized_rows: list[dict[str, Any]],
    superseded_rows: list[dict[str, Any]],
    input_unit_ids: set[str],
) -> int:
    superseded_ids = {
        str(unit_id)
        for target in plan["targets"]
        if target.get("status") == "complete"
        and target.get("disposition") == "materialize"
        for unit_id in target.get("superseded_unit_ids", [])
    }
    if superseded_ids:
        prior_superseded_ids = {str(row["unit_id"]) for row in superseded_rows}
        for unit in augmented:
            unit_id = str(unit["id"])
            if unit_id not in superseded_ids or unit_id in prior_superseded_ids:
                continue
            span = unit["source"]["original"]
            superseded_rows.append({
                "unit_id": unit_id,
                "rva_start": int(span["rva_start"]),
                "rva_end": int(span["rva_end"]),
                "origin": (
                    "prepared_input"
                    if unit_id in input_unit_ids
                    else "materialized_cutpoint"
                ),
                "iteration": iteration,
                "reason": "split_at_authoritative_instruction_boundary",
            })
        augmented[:] = [
            unit for unit in augmented if str(unit["id"]) not in superseded_ids
        ]
        materialized_rows[:] = [
            row
            for row in materialized_rows
            if str(row["unit_id"]) not in superseded_ids
        ]
    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in augmented
    }
    added = 0
    for target in plan["targets"]:
        if (
            target.get("status") != "complete"
            or target.get("disposition") != "materialize"
        ):
            continue
        for region in target["regions"]:
            parent_span = {
                "rva_start": int(region["rva_start"]),
                "rva_end": int(region["rva_end"]),
                "size": int(region["size"]),
                "cutpoint_role": str(region.get("cutpoint_role", "target")),
            }
            spans = semantic_cutpoint_spans_for_side(
                binary,
                parent_span,
                f"recovered-target-{int(target['target_rva']):08x}",
            )
            for span_payload in spans:
                start = int(span_payload["rva_start"])
                end = int(span_payload["rva_end"])
                if start in starts:
                    continue
                identity = f"recovered-target-cutpoint-{start:08x}-{end:08x}"
                side = BlockSide(start, end)
                mapping = StaticUnitContext(
                    id=identity,
                    span=side,
                    kind="code",
                    invariant_checked=False,
                    source={"source": {"function": identity}},
                )
                raw = semantic_transfer(
                    binary,
                    mapping,
                    identity,
                )
                semantic_sha256 = sha256_bytes(_canonical_json(raw))
                normalized = normalize_spx_semantic_transfer(
                    raw,
                    static_program_contract_sha256=static_program_sha256,
                    semantic_transfer_sha256=(
                        semantic_sha256
                        if static_program_sha256 is not None
                        else None
                    ),
                )
                unit = _prepare_unit(
                    normalized,
                    binary=binary,
                    static_program_sha256=static_program_sha256,
                )
                unit["preparation"]["target_cutpoint_materialization"] = {
                    "format": "spaghetti-extractor-target-cutpoint-unit-binding-v2",
                    "target_rva": int(target["target_rva"]),
                    "target_sources": list(target["target_sources"]),
                    "recovery_ids": list(target["recovery_ids"]),
                    "plan_id": plan["id"],
                    "iteration": iteration,
                    "region": copy.deepcopy(parent_span),
                    "superseded_unit_ids": list(
                        target.get("superseded_unit_ids", [])
                    ),
                }
                _assert_byte_free(unit)
                augmented.append(unit)
                starts[start] = unit
                materialized_rows.append({
                    "unit_id": unit["id"],
                    "target_rva": int(target["target_rva"]),
                    "rva_start": start,
                    "rva_end": end,
                    "status": unit["status"],
                    "iteration": iteration,
                    "cutpoint_role": parent_span["cutpoint_role"],
                    "superseded_unit_ids": list(
                        target.get("superseded_unit_ids", [])
                    ),
                })
                added += 1
    return added


def _classify_executable_data_before_control(
    *,
    binary: ParsedPEImage,
    units: Sequence[Mapping[str, Any]],
    static_program: Mapping[str, Any],
    precomputed_static_recoveries: Sequence[Mapping[str, Any]] | None = None,
    precomputed_data_ranges: Sequence[Any] | None = None,
    precomputed_static_rounds: int = 0,
    finite_dataflow_factory: Callable[..., Any],
) -> tuple[
    list[dict[str, Any]],
    dict[str, Any],
    list[ExportIssue],
    list[dict[str, Any]],
]:
    """Remove checked executable data and false overlapping decodes first.

    Static extraction intentionally over-approximates possible unit starts.  A
    rooted control graph must not be built over rows that are already proven to
    be immutable jump-table data, nor over a speculative start in the interior
    of an instruction reached from a real root.  This prepass has no authority
    to discard a competing root or incoming edge: those conflicts fail closed.
    """

    starts = {
        int(unit["source"]["original"]["rva_start"]): unit for unit in units
    }
    block_starts = {
        str(unit["source_location"]["block_id"]): int(
            unit["source"]["original"]["rva_start"]
        )
        for unit in units
        if unit["source_location"].get("block_id")
    }
    root_rows = _initial_control_roots(binary, static_program, block_starts)
    root_unit_ids = [
        str(starts[rva]["id"])
        for root in root_rows
        if isinstance((rva := root.get("rva")), int) and rva in starts
    ]
    direct_edges, internal_call_edges = _precontrol_direct_edges(units)
    indirect_exits = _precontrol_indirect_exits(units)
    if precomputed_static_recoveries is None:
        static_recoveries, rounds, converged = (
            _static_jump_table_recovery_fixed_point(
                binary=binary,
                units=units,
                starts=starts,
                indirect_exits=indirect_exits,
                root_unit_ids=root_unit_ids,
                finite_dataflow_factory=finite_dataflow_factory,
            )
        )
        data_ranges = recover_executable_data_ranges(
            binary=binary,
            recoveries=static_recoveries,
            known_code_unit_rvas=set(starts),
        )
    else:
        if precomputed_data_ranges is None:
            raise ValueError(
                "precomputed static recoveries require executable-data ranges"
            )
        static_recoveries = [
            copy.deepcopy(dict(recovery))
            for recovery in precomputed_static_recoveries
        ]
        rounds = precomputed_static_rounds
        converged = True
        data_ranges = tuple(precomputed_data_ranges)
    data_spans = [RvaSpan(item.rva_start, item.rva_end) for item in data_ranges]
    issues: list[ExportIssue] = []
    conflicts: list[dict[str, Any]] = []

    if not converged:
        issues.append(
            ExportIssue(
                status="incomplete",
                category="precontrol_static_data_fixed_point_budget_exceeded",
                message="static executable-data recovery did not converge",
                next_action=(
                    "increase the generic fixed-point budget or reduce the "
                    "finite control domain"
                ),
                location=SourceLocation(
                    None,
                    None,
                    None,
                    RvaSpan(binary.entrypoint_rva, binary.entrypoint_rva + 1),
                    "executable_classification",
                ),
            )
        )

    excluded: dict[str, dict[str, Any]] = {}
    for unit in units:
        unit_span = _unit_original_span(unit)
        overlaps = [
            item
            for item in data_ranges
            if unit_span.start < item.rva_end and item.rva_start < unit_span.end
        ]
        if not overlaps:
            continue
        excluded[str(unit["id"])] = {
            "unit_id": str(unit["id"]),
            "rva_start": unit_span.start,
            "rva_end": unit_span.end,
            "reason": "intersects_checked_immutable_executable_data",
            "evidence_ids": [item.identity for item in overlaps],
        }

    excluded_ids = set(excluded)
    for root in root_rows:
        rva = root.get("rva")
        if isinstance(rva, int):
            match = _range_containing(data_ranges, rva)
            if match is not None:
                conflicts.append({
                    "code": "behavioral_root_inside_immutable_executable_data",
                    "rva": rva,
                    "evidence_id": match.identity,
                })
                issues.append(
                    _classification_conflict_issue(
                        category="behavioral_root_inside_immutable_executable_data",
                        message=(
                            f"behavioral root 0x{rva:x} lies inside checked "
                            "immutable executable data"
                        ),
                        rva=rva,
                        field="control.roots",
                    )
                )

    for edge in (*direct_edges, *internal_call_edges):
        source_id = str(edge.get("source_unit_id"))
        target = edge.get("target_rva")
        if source_id in excluded_ids or not isinstance(target, int):
            continue
        match = _range_containing(data_ranges, target)
        if match is None:
            continue
        conflicts.append({
            "code": "control_target_inside_immutable_executable_data",
            "source_unit_id": source_id,
            "target_rva": target,
            "evidence_id": match.identity,
        })
        issues.append(
            _classification_conflict_issue(
                category="control_target_inside_immutable_executable_data",
                message=(
                    f"control target 0x{target:x} lies inside checked immutable "
                    "executable data"
                ),
                rva=target,
                field="control.direct_target",
                unit_id=source_id,
            )
        )

    for recovery in static_recoveries:
        if str(recovery.get("source_unit_id")) in excluded_ids:
            continue
        for target in recovery.get("target_rvas", []):
            if not isinstance(target, int):
                continue
            match = _range_containing(data_ranges, target)
            if match is None:
                continue
            conflicts.append({
                "code": "recovered_target_inside_immutable_executable_data",
                "source_unit_id": recovery.get("source_unit_id"),
                "target_rva": target,
                "evidence_id": match.identity,
            })
            issues.append(
                _classification_conflict_issue(
                    category="recovered_target_inside_immutable_executable_data",
                    message=(
                        f"finite indirect target 0x{target:x} lies inside checked "
                        "immutable executable data"
                    ),
                    rva=target,
                    field="control.indirect_target",
                    unit_id=str(recovery.get("source_unit_id")),
                )
            )

    active = [unit for unit in units if str(unit["id"]) not in excluded_ids]
    active_ids = {str(unit["id"]) for unit in active}
    reachability = derive_rooted_reachable_units(
        units=active,
        roots=(unit_id for unit_id in root_unit_ids if unit_id in active_ids),
        direct_edges=[
            edge for edge in direct_edges if edge["source_unit_id"] in active_ids
        ],
        internal_call_edges=[
            edge
            for edge in internal_call_edges
            if edge["source_unit_id"] in active_ids
        ],
        recovered_indirect_targets=[
            recovery
            for recovery in static_recoveries
            if recovery.get("source_unit_id") in active_ids
        ],
        indirect_exits=[
            exit_record
            for exit_record in indirect_exits
            if exit_record.get("source_unit_id") in active_ids
        ],
    )
    reached_ids = set(reachability["reachable_units"])
    target_sources = _precontrol_target_sources(
        root_rows=root_rows,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        recoveries=static_recoveries,
        eligible_source_ids=reached_ids,
    )
    overlap_classification = classify_overlapping_instruction_starts(
        units=active,
        reachable_unit_ids=reached_ids,
        target_sources=target_sources,
    )
    active_by_id = {str(unit["id"]): unit for unit in active}
    for row in overlap_classification["excluded_units"]:
        unit_id = str(row["unit_id"])
        unit = active_by_id[unit_id]
        excluded[unit_id] = {
            "unit_id": unit_id,
            "rva_start": int(unit["source"]["original"]["rva_start"]),
            "rva_end": int(unit["source"]["original"]["rva_end"]),
            "reason": row["reason"],
            "instruction_evidence": copy.deepcopy(row["instruction_evidence"]),
        }
    for row in overlap_classification["conflicts"]:
        conflicts.append(copy.deepcopy(row))
        start = int(row["rva"])
        issues.append(
            _classification_conflict_issue(
                category="independent_target_inside_reachable_instruction",
                message=(
                    f"unit start 0x{start:x} lies inside an instruction on "
                    "another rooted path"
                ),
                rva=start,
                field="executable_classification.instruction_interiors",
                unit_id=str(row["unit_id"]),
            )
        )

    # Classification changes only top-level reachability fields in the next
    # phase.  Preserve the checked nested semantic records by reference rather
    # than cloning the full expression inventory again.
    retained = [
        dict(unit) for unit in units if str(unit["id"]) not in excluded
    ]
    range_rows = [_classification_range_payload(item) for item in data_ranges]
    excluded_rows = sorted(
        excluded.values(), key=lambda row: (int(row["rva_start"]), str(row["unit_id"]))
    )
    conflicts = sorted(
        {
            _canonical_json(row): copy.deepcopy(row) for row in conflicts
        }.values(),
        key=lambda row: (
            int(row.get("rva", row.get("target_rva", -1))),
            str(row.get("code")),
            str(row.get("source_unit_id", row.get("unit_id", ""))),
        ),
    )
    status = (
        "violated"
        if conflicts
        else "incomplete"
        if not converged
        else "complete"
    )
    return retained, {
        "format": "spaghetti-extractor-precontrol-executable-classification-v1",
        "status": status,
        "proof_authority": False,
        "ordering": "before_rooted_control_closure",
        "immutable_data_ranges": range_rows,
        "excluded_units": excluded_rows,
        "conflicts": conflicts,
        "analysis": {
            "static_jump_table_rounds": rounds,
            "static_jump_table_converged": converged,
            "preclassification_reachable_units": sorted(reached_ids),
        },
        "counts": {
            "input_units": len(units),
            "retained_units": len(retained),
            "excluded_units": len(excluded_rows),
            "immutable_data_ranges": len(range_rows),
            "immutable_data_bytes": sum(item.size for item in data_ranges),
            "conflicts": len(conflicts),
        },
    }, issues, static_recoveries


def _initial_control_roots(
    binary: ParsedPEImage,
    static_program: Mapping[str, Any],
    block_starts: Mapping[str, int],
) -> list[dict[str, Any]]:
    submitted = [
        _resolved_root(root, block_starts)
        for root in static_program.get("roots", [])
        if isinstance(root, Mapping)
    ]
    binary_roots: list[dict[str, Any]] = [
        {"kind": "pe_entrypoint", "rva": binary.entrypoint_rva}
    ]
    binary_roots.extend(
        {"kind": "pe_export", "rva": exported.rva, "name": exported.name}
        for exported in binary.exports or ()
        if exported.kind == "code"
    )
    binary_roots.extend(
        {"kind": "pe_tls_callback", "rva": rva}
        for rva in binary.tls_callback_rvas or ()
    )
    roots_by_rva: dict[int, dict[str, Any]] = {}
    for root in (*binary_roots, *submitted):
        raw_rva = root.get("rva", root.get("target_rva"))
        if not isinstance(raw_rva, int):
            continue
        canonical = roots_by_rva.setdefault(raw_rva, copy.deepcopy(dict(root)))
        for key, value in root.items():
            canonical.setdefault(key, copy.deepcopy(value))
    return list(roots_by_rva.values())


def _precontrol_direct_edges(
    units: Sequence[Mapping[str, Any]],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    direct: list[dict[str, Any]] = []
    internal: list[dict[str, Any]] = []
    for unit in units:
        source_id = str(unit["id"])
        source_rva = int(unit["source"]["original"]["rva_start"])
        for target in unit["control"]["direct_targets"]:
            direct.append({
                "kind": "direct_control",
                "source_unit_id": source_id,
                "source_rva": source_rva,
                "target_rva": int(target),
            })
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if (
                isinstance(event, Mapping)
                and event.get("kind") == "internal_call"
                and isinstance(event.get("target_rva"), int)
            ):
                internal.append({
                    "kind": "internal_call",
                    "source_unit_id": source_id,
                    "source_rva": source_rva,
                    "source_event_index": event_index,
                    "target_rva": int(event["target_rva"]),
                })
    return direct, internal


def _precontrol_indirect_exits(
    units: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    exits: list[dict[str, Any]] = []
    for unit in units:
        source_id = str(unit["id"])
        source_rva = int(unit["source"]["original"]["rva_start"])
        if unit["control"]["has_indirect_target"]:
            row = {
                "source_unit_id": source_id,
                "source_rva": source_rva,
                "kind": unit["control"]["kind"],
                "target_expression": copy.deepcopy(
                    unit["semantics"]["outcome"].get("target")
                ),
            }
            row["id"] = indirect_exit_id_v2(row)
            exits.append(row)
        events = unit.get("semantics", {}).get("external_events", [])
        if not isinstance(events, list):
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping) or event.get("kind") not in {
                "indirect_call",
                "indirect_jump",
            }:
                continue
            row = {
                "source_unit_id": source_id,
                "source_rva": source_rva,
                "source_event_index": event_index,
                "kind": event["kind"],
                "target_expression": copy.deepcopy(event.get("target")),
            }
            row["id"] = indirect_exit_id_v2(row)
            exits.append(row)
    return exits


def _precontrol_target_sources(
    *,
    root_rows: Sequence[Mapping[str, Any]],
    direct_edges: Sequence[Mapping[str, Any]],
    internal_call_edges: Sequence[Mapping[str, Any]],
    recoveries: Sequence[Mapping[str, Any]],
    eligible_source_ids: set[str],
) -> dict[int, list[str]]:
    result: dict[int, set[str]] = {}
    for root in root_rows:
        if isinstance(root.get("rva"), int):
            result.setdefault(int(root["rva"]), set()).add("behavioral_root")
    for edge in (*direct_edges, *internal_call_edges):
        if (
            edge.get("source_unit_id") in eligible_source_ids
            and isinstance(edge.get("target_rva"), int)
        ):
            result.setdefault(int(edge["target_rva"]), set()).add(
                str(edge.get("kind"))
            )
    for recovery in recoveries:
        if recovery.get("source_unit_id") not in eligible_source_ids:
            continue
        for target in recovery.get("target_rvas", []):
            if isinstance(target, int):
                result.setdefault(target, set()).add("finite_indirect_target")
    return {rva: sorted(sources) for rva, sources in result.items()}


def _unit_original_span(unit: Mapping[str, Any]) -> RvaSpan:
    source = unit["source"]["original"]
    return RvaSpan(int(source["rva_start"]), int(source["rva_end"]))


def _range_containing(ranges: Sequence[Any], rva: int) -> Any | None:
    return next(
        (item for item in ranges if item.rva_start <= rva < item.rva_end),
        None,
    )


def _classification_range_payload(item: Any) -> dict[str, Any]:
    return {
        "id": item.identity,
        "rva_start": item.rva_start,
        "rva_end": item.rva_end,
        "size": item.size,
        "section_index": item.section_index,
        "section_name": item.section_name,
        "bytes_sha256": item.bytes_sha256,
        "kinds": list(item.kinds),
        "recovery_ids": list(item.recovery_ids),
    }


def _classification_conflict_issue(
    *,
    category: str,
    message: str,
    rva: int,
    field: str,
    unit_id: str | None = None,
) -> ExportIssue:
    return ExportIssue(
        status="violated",
        category=category,
        message=message,
        next_action=(
            "repair static code/data classification or provide checked evidence "
            "for an intentional overlapping-code entry"
        ),
        location=SourceLocation(
            unit_id,
            None,
            None,
            RvaSpan(rva, rva + 1),
            field,
        ),
    )
