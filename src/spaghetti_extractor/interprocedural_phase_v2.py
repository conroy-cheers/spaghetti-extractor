"""Narrow authority boundary for the v2 interprocedural analysis phase."""

from __future__ import annotations

import json
from collections.abc import Callable, Mapping, Sequence
from typing import Any

from .control_analysis_v2 import exact_control_inventory_v2
from .external_capabilities import CallableExternalProfile
from .external_interface_profiles import ExternalInterfaceProfile
from .external_operation_profiles import ExternalOperationProfile
from .authority_bindings_v2 import (
    AuthorityDataError,
    canonical_json_bytes,
)
from .global_slot_contract_v2 import GlobalSlotInvariant
from .global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    validate_global_slot_invariant_binding_v2,
)
from .import_abi import SelectedImportABI
from .interprocedural_analysis import (
    INTERPROCEDURAL_ANALYSIS_FORMAT,
    InterproceduralAnalysisResult,
    analyze_interprocedural_control,
)
from .machine_import_profiles import MachineImportIdentity
from .stage_binary import StageABinary
from .stack_range_analysis_v2 import validate_checked_stack_range_facts_v2
from .static_indirect_replay_v2 import replay_exact_static_recoveries_v2


class InterproceduralPhaseV2Error(ValueError):
    """Exact interprocedural phase inputs are malformed or inconsistent."""


def derive_interprocedural_result_v2(
    manifest: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]] | None = None,
    graph: Mapping[str, Any] | None = None,
    binary: StageABinary | None = None,
    machine_ir_sha256: str | None = None,
    global_slot_invariants: Sequence[Mapping[str, Any] | GlobalSlotInvariant] = (),
    checked_stack_entry_offsets: Mapping[str, Sequence[int]] | None = None,
    checked_stack_range_facts: Sequence[Mapping[str, Any]] = (),
    checked_control_invariants: Sequence[Mapping[str, Any]] = (),
    stack_launch_assumptions_sha256: str | None = None,
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI] | None = None,
    interface_profiles: Sequence[ExternalInterfaceProfile] | None = None,
    operation_profiles: Sequence[ExternalOperationProfile] | None = None,
    callable_profiles: Sequence[CallableExternalProfile] | None = None,
    internal_function_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    static_recoveries: Sequence[Mapping[str, Any]] | None = None,
    inductive_hypothesis_recoveries: Sequence[Mapping[str, Any]] = (),
    inductive_hypothesis_call_frames: Sequence[Mapping[str, Any]] = (),
    finite_value_budget: int = 32,
    proposal_only: bool = False,
    authority_only: bool = False,
) -> dict[str, Any]:
    """Replay the unified analyzer instead of inheriting manifest authority."""

    control = _object(manifest.get("control"), "machine-IR control")
    proposal_recoveries = _mapping_rows(
        control.get("recovered_indirect_targets"),
        "manifest recovered indirect targets",
    )
    exact_control = None if units is None else exact_control_inventory_v2(units)
    indirect_exits = (
        _mapping_rows(control.get("indirect_exits"), "manifest indirect exits")
        if exact_control is None
        else tuple(exact_control["indirect_exits"])
    )
    missing: list[str] = []
    if units is None:
        missing.append("machine_ir_units_missing")
    if graph is None:
        missing.append("rooted_control_graph_missing")
    if binary is None:
        missing.append("original_binary_binding_missing")
    if machine_ir_sha256 is None:
        missing.append("machine_ir_binding_missing")
    if binary is not None and binary.imports and import_abis is None:
        missing.append("machine_import_profile_inventory_missing")

    proposal_closures = {str(row.get("closure", "")) for row in proposal_recoveries}
    if any("interface" in closure for closure in proposal_closures):
        if interface_profiles is None:
            missing.append("external_interface_profile_inventory_missing")
    if any("operation" in closure for closure in proposal_closures):
        if operation_profiles is None:
            missing.append("external_operation_profile_inventory_missing")
    if any("callable" in closure for closure in proposal_closures):
        if callable_profiles is None:
            missing.append("callable_external_profile_inventory_missing")
    if (
        indirect_exits
        and static_recoveries is None
        and interface_profiles is None
        and operation_profiles is None
        and callable_profiles is None
    ):
        missing.append("indirect_recovery_replay_inputs_missing")
    if missing:
        return _incomplete_interprocedural_result(
            control=control,
            failure_reasons=missing,
            proposal_only=proposal_only,
        )

    assert units is not None
    assert graph is not None
    assert binary is not None
    assert machine_ir_sha256 is not None
    assert exact_control is not None
    exact_static_replay = static_recoveries is None
    exact_static_recoveries = (
        replay_exact_static_recoveries_v2(
            binary=binary,
            units=units,
            indirect_exits=indirect_exits,
            checked_control_invariants=checked_control_invariants,
            machine_ir_sha256=machine_ir_sha256,
        )
        if static_recoveries is None
        else _validate_static_recoveries(static_recoveries, indirect_exits)
    )
    typed_slots = _strict_global_slot_invariants(
        global_slot_invariants,
        binary=binary,
        machine_ir_sha256=machine_ir_sha256,
        units=units,
    )
    stack_graph_ids = {
        str(binding.get("rooted_graph_id"))
        for fact in checked_stack_range_facts
        if isinstance(fact, Mapping)
        for binding in (fact.get("authority_binding"),)
        if isinstance(binding, Mapping)
        and isinstance(binding.get("rooted_graph_id"), str)
    }
    if checked_stack_range_facts and len(stack_graph_ids) != 1:
        raise InterproceduralPhaseV2Error(
            "checked stack-range facts do not share one rooted graph binding"
        )
    if checked_stack_range_facts and stack_launch_assumptions_sha256 is None:
        raise InterproceduralPhaseV2Error(
            "checked stack-range facts require the launch-assumption identity"
        )
    checked_stack_units: frozenset[str] = frozenset()
    if checked_stack_range_facts:
        try:
            checked_stack_units = validate_checked_stack_range_facts_v2(
                checked_stack_range_facts,
                units=units,
                pe_sha256=binary.sha256,
                machine_ir_sha256=machine_ir_sha256,
                rooted_graph_id=next(iter(stack_graph_ids)),
                launch_assumptions_sha256=(
                    stack_launch_assumptions_sha256 or "unused"
                ),
                image_base=binary.image_base,
                size_of_image=binary.size_of_image,
            )
        except ValueError as exc:
            raise InterproceduralPhaseV2Error(
                f"checked stack-range fact does not replay: {exc}"
            ) from exc
    result = analyze_interprocedural_control(
        units=units,
        roots=_graph_root_ids(graph),
        direct_edges=tuple(exact_control["direct_edges"]),
        internal_call_edges=tuple(exact_control["internal_call_edges"]),
        indirect_exits=indirect_exits,
        static_recoveries=exact_static_recoveries,
        static_recovery_authority=(
            "exact_pe_replay_v2" if exact_static_replay else "untrusted_input"
        ),
        import_abis={} if import_abis is None else import_abis,
        imports=_binary_import_rows(binary),
        image_base=binary.image_base,
        pe_sha256=binary.sha256,
        machine_ir_sha256=machine_ir_sha256,
        image_size=binary.size_of_image,
        writable_image_ranges=tuple(
            (
                binary.image_base + section.rva_start,
                binary.image_base + section.rva_end,
            )
            for section in binary.sections
            if section.writable
        ),
        static_data_reader=_immutable_static_data_reader(binary),
        proposal_static_data_reader=_initialized_image_data_reader(binary),
        interface_profiles=() if interface_profiles is None else interface_profiles,
        operation_profiles=() if operation_profiles is None else operation_profiles,
        callable_profiles=() if callable_profiles is None else callable_profiles,
        internal_function_contracts=(
            {} if internal_function_contracts is None else internal_function_contracts
        ),
        proposal_recoveries=proposal_recoveries,
        inductive_hypothesis_recoveries=inductive_hypothesis_recoveries,
        inductive_hypothesis_call_frames=inductive_hypothesis_call_frames,
        global_slot_invariants=typed_slots,
        checked_stack_entry_offsets=checked_stack_entry_offsets,
        checked_nonimage_stack_units=tuple(sorted(checked_stack_units)),
        finite_value_budget=finite_value_budget,
        proposal_only=proposal_only,
        authority_only=authority_only,
    )
    payload = _interprocedural_result_payload(result, control=control)
    return _validate_interprocedural_mutable_handoff(
        payload,
        global_slot_invariants=typed_slots,
    )


def _incomplete_interprocedural_result(
    *,
    control: Mapping[str, Any],
    failure_reasons: Sequence[str],
    proposal_only: bool = False,
) -> dict[str, Any]:
    fixed_point = {
        "format": INTERPROCEDURAL_ANALYSIS_FORMAT,
        "status": "incomplete",
        "rounds": 0,
        "discovery_rounds": 0,
        "cold_replay_rounds": 0,
        "scc_evaluations": 0,
        "cold_replay_validated": False,
        "authority_replay_validated": False,
        "cold_initial_recoveries_empty": False,
        "inductive_replay": {
            "status": "not_applicable",
            "executed": False,
            "converged": False,
            "proof_authority": False,
            "hypothesis_count": 0,
            "reproduced_ids": [],
            "missing_ids": [],
            "mismatched_ids": [],
            "signature": None,
        },
        "proposal_only": proposal_only,
        "static_recovery_authority_seeded": False,
        "static_recovery_authority": "unavailable",
        "discovery_signature": None,
        "cold_replay_signature": None,
        "authority_artifact_sha256": None,
        "proposal_seed_count": 0,
        "global_slot_promotion": False,
        "mutable_slot_handoff": "missing_exact_replay",
        "finite_value_budget": None,
        "round_bound": 0,
        "round_bound_kind": "transfer_evaluation_resource_limit",
        "typed_fact_count": 0,
        "dependency_edge_count": 0,
        "scc_count": 0,
        "recursive_sccs": [],
        "recursive_summary_roots": [],
        "dependencies": [],
        "failure_reasons": sorted(set(failure_reasons)),
    }
    return {
        "format": INTERPROCEDURAL_ANALYSIS_FORMAT,
        "status": "incomplete",
        "value_provenance": {},
        "operation_provenance": {},
        "call_summaries": {"status": "incomplete", "summaries": []},
        "recovered_targets": [],
        "proposal_artifacts": {
            "proof_authority": False,
            "recoveries": [],
            "call_frame_hypotheses": [],
            "signature": None,
        },
        "fixed_point": fixed_point,
        "manifest_diagnostics": {
            "call_summaries": control.get("internal_call_preservation"),
            "recovered_targets": control.get("recovered_indirect_targets"),
            "fixed_point": control.get("analysis_fixed_point"),
        },
    }


def _interprocedural_result_payload(
    result: InterproceduralAnalysisResult,
    *,
    control: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        "format": INTERPROCEDURAL_ANALYSIS_FORMAT,
        "status": str(result.fixed_point.get("status", "incomplete")),
        "value_provenance": dict(result.value_provenance),
        "operation_provenance": dict(result.operation_provenance),
        "call_summaries": dict(result.call_summaries),
        "recovered_targets": [dict(row) for row in result.recovered_targets],
        "proposal_artifacts": dict(result.proposal_artifacts),
        "fixed_point": dict(result.fixed_point),
        "manifest_diagnostics": {
            "fixed_point": control.get("analysis_fixed_point"),
        },
    }


def _validate_interprocedural_mutable_handoff(
    payload: Mapping[str, Any],
    *,
    global_slot_invariants: Sequence[GlobalSlotInvariant],
) -> dict[str, Any]:
    result = json.loads(canonical_json_bytes(payload))
    fixed: dict[str, Any] = dict(
        _object(result.get("fixed_point"), "interprocedural fixed point")
    )
    recoveries = _mapping_rows(
        result.get("recovered_targets"), "interprocedural recoveries"
    )
    invariant_ids = {record.content_id for record in global_slot_invariants}
    dependency_rows = fixed.get("dependencies")
    dependency_inventory = (
        {
            str(row.get("id")): {
                str(value)
                for value in row.get("dependencies", [])
                if isinstance(value, str)
            }
            for row in dependency_rows
            if isinstance(row, Mapping)
        }
        if isinstance(dependency_rows, list)
        else {}
    )
    failures: set[str] = set()
    if fixed.get("mutable_slot_handoff") != "point_sensitive_dependency_v2":
        failures.add("mutable_slot_handoff_marker_missing")
    if fixed.get("global_slot_promotion") is not False:
        failures.add("mutable_slot_root_promotion_enabled")

    for recovery in recoveries:
        exit_id = str(recovery.get("id", ""))
        slot_dependencies = recovery.get("mutable_slot_dependencies", [])
        authority_dependencies = recovery.get("authority_dependencies", [])
        # Incomplete rows retain slot RVAs and read sites only to explain a
        # frontier. They make no authority claim. Recovered rows, in contrast,
        # must bind every mutable dependency to an exact invariant below.
        if recovery.get("status") != "recovered":
            continue
        authority_ids = {
            str(row.get("content_id"))
            for row in authority_dependencies
            if isinstance(authority_dependencies, list)
            and isinstance(row, Mapping)
            and row.get("role") == "mutable_slot_invariant"
        }
        for dependency in slot_dependencies:
            if not isinstance(dependency, Mapping):
                failures.add("mutable_slot_dependency_corrupt")
                continue
            content_id = dependency.get("content_id")
            if not isinstance(content_id, str) or not content_id:
                failures.add("mutable_slot_dependency_content_id_missing")
                continue
            if content_id not in invariant_ids:
                failures.add("mutable_slot_dependency_record_missing")
            if content_id not in authority_ids:
                failures.add("mutable_slot_authority_dependency_missing")
            if content_id not in dependency_inventory.get(exit_id, set()):
                failures.add("mutable_slot_fixed_point_dependency_missing")

    fixed["handoff_validation"] = {
        "status": "complete" if not failures else "incomplete",
        "global_slot_content_ids": sorted(invariant_ids),
        "failure_reasons": sorted(failures),
    }
    if failures:
        fixed["status"] = "incomplete"
        fixed["authority_replay_validated"] = False
        prior = fixed.get("failure_reasons")
        fixed["failure_reasons"] = sorted(
            set(prior if isinstance(prior, list) else ()) | failures
        )
    result["fixed_point"] = fixed
    result["format"] = INTERPROCEDURAL_ANALYSIS_FORMAT
    result["status"] = str(fixed.get("status", "incomplete"))
    return result


def _graph_root_ids(graph: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    for row in graph.get("roots", []):
        if isinstance(row, str):
            result.append(row)
        elif isinstance(row, Mapping) and isinstance(row.get("unit_id"), str):
            result.append(str(row["unit_id"]))
    return sorted(set(result))


def _incomplete_static_recoveries(
    indirect_exits: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            **json.loads(canonical_json_bytes(row)),
            "status": "incomplete",
            "closure": "unresolved",
            "target_rvas": [],
            "target_unit_ids": [],
            "external_targets": [],
            "failure": {
                "code": "static_recovery_replay_not_supplied",
                "message": "no exact static target recovery was supplied",
            },
        }
        for row in indirect_exits
    ]


def _validate_static_recoveries(
    recoveries: Sequence[Mapping[str, Any]],
    indirect_exits: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    rows = [dict(row) for row in recoveries]
    exit_ids = [str(row.get("id")) for row in indirect_exits]
    recovery_ids = [str(row.get("id")) for row in rows]
    if len(set(recovery_ids)) != len(recovery_ids) or sorted(recovery_ids) != sorted(
        exit_ids
    ):
        raise InterproceduralPhaseV2Error(
            "static recovery inventory must contain exactly one row per indirect exit"
        )
    return rows


def _strict_global_slot_invariants(
    values: Sequence[Mapping[str, Any] | GlobalSlotInvariant],
    *,
    binary: StageABinary,
    machine_ir_sha256: str,
    units: Sequence[Mapping[str, Any]],
) -> tuple[GlobalSlotInvariant, ...]:
    result: list[GlobalSlotInvariant] = []
    for value in values:
        try:
            record = (
                value
                if isinstance(value, GlobalSlotInvariant)
                else GlobalSlotInvariant.parse(value)
            )
        except (AuthorityDataError, TypeError, ValueError) as exc:
            raise InterproceduralPhaseV2Error(
                f"global-slot invariant v2 does not replay: {exc}"
            ) from exc
        if record.status.value != "complete":
            raise InterproceduralPhaseV2Error(
                "only complete GlobalSlotInvariant v2 records may enter "
                "interprocedural authority"
            )
        try:
            validate_global_slot_invariant_binding_v2(
                record,
                binary=binary,
                machine_ir_sha256=machine_ir_sha256,
                units=units,
            )
        except GlobalSlotImageV2Error as exc:
            raise InterproceduralPhaseV2Error(
                f"global-slot invariant binding does not replay: {exc}"
            ) from exc
        result.append(record)
    if len({record.content_id for record in result}) != len(result):
        raise InterproceduralPhaseV2Error(
            "global-slot invariant content IDs must be unique"
        )
    return tuple(sorted(result, key=lambda record: record.content_id))


def _binary_import_rows(binary: StageABinary) -> list[dict[str, Any]]:
    return [
        {
            "dll": imported.dll,
            "symbol": imported.symbol,
            "ordinal": imported.ordinal,
            "thunk_rva": imported.thunk_rva,
        }
        for imported in binary.imports
    ]


def _immutable_static_data_reader(
    binary: StageABinary,
) -> Callable[[int, int], bytes | None]:
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


def _initialized_image_data_reader(
    binary: StageABinary,
) -> Callable[[int, int], bytes | None]:
    """Read file-backed image bytes for untrusted proposal discovery only."""

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
                and section.rva_start <= rva
                and rva + size <= initialized_end
            ):
                data = bytes(binary.pe.get_data(rva, size))
                return data if len(data) == size else None
        return None

    return read


def _mapping_rows(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(
        isinstance(row, Mapping) for row in value
    ):
        raise InterproceduralPhaseV2Error(f"{context} must be an array of objects")
    return [dict(row) for row in value]


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InterproceduralPhaseV2Error(f"{context} must be an object")
    return value


__all__ = [
    "InterproceduralPhaseV2Error",
    "derive_interprocedural_result_v2",
]
