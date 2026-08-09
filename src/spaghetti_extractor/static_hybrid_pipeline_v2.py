"""Path-based orchestration for the strict static-first hybrid v2 pipeline.

This module contains no target policy. It derives phase inputs from exact
machine-IR artifacts, keeps legacy completeness output diagnostic-only, and
emits the authority bundle and final audit consumed by candidate generation.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from .entry_state_analysis_v2 import (
    construct_entry_state_analysis_v2,
    derive_callback_entry_state_contracts_v2,
)
from .entry_fact_derivation_v2 import (
    derive_iat_facts,
    derive_mutable_slot_candidates,
    promote_complete_global_slot_evidence_v2,
)
from .control_analysis_v2 import (
    ROOTED_CONTROL_CLOSURE_V2_FORMAT,
    derive_rooted_control_closure_v2,
    derive_rooted_control_graph_v2,
    exact_control_inventory_v2 as _exact_control_inventory,
    exact_indirect_exit_id_v2 as _exact_indirect_exit_id,
)
from .exception_phase_v2 import (
    EXCEPTION_PROPOSAL_PHASE_V2_FORMAT,
    EXCEPTION_REPLAY_PHASE_V2_FORMAT,
    derive_checked_exception_reports_v2,
    derive_faulting_rooted_sccs_v2,
)
from .external_site_proposals_v2 import (
    derive_external_site_proposals_v2,
    parse_external_site_proposals_v2,
)
from .external_capabilities import (
    CallableExternalProfile,
    load_callable_external_profile,
)
from .external_interface_profiles import (
    ExternalInterfaceProfile,
    load_external_interface_profile,
)
from .external_operation_profiles import (
    ExternalOperationProfile,
    load_external_operation_profile,
)
from .external_profile_authority_v2 import (
    ExternalProfileAuthorityV2,
    build_external_profile_authority_v2,
    parse_external_profile_authority_v2,
)
from .analysis_schema_v2 import ROOTED_CONTROL_GRAPH_V2_FORMAT
from .artifact_identity_v2 import canonical_sha256
from .authority_bindings_v2 import AuthorityDataError
from .global_slot_analysis_v2 import (
    analyze_global_slots_v2,
)
from .global_slot_contract_v2 import GlobalSlotInvariant
from .global_slot_image_v2 import (
    GlobalSlotImageV2Error,
    validate_global_slot_invariant_binding_v2,
)
from .hybrid_authority_v2 import canonical_json_bytes
from .import_abi import load_selected_import_abis
from .interprocedural_phase_v2 import (
    derive_interprocedural_result_v2 as _derive_interprocedural_result_v2,
)
from .internal_function_contracts import load_internal_function_contracts
from .isa_kernel_selection import parse_isa_kernel_selection_authority
from .launch_profile_v2 import (
    LaunchProfileStatus,
    launch_invariants_for_entry_state,
    validate_launch_profile_v2,
)
from .stage_binary import StageABinary, _parse_stage_a_pe
from .static_hybrid_authority_v2 import build_static_hybrid_authority_v2
from .static_hybrid_final_audit_v2 import build_static_hybrid_final_audit_v2
from .util import sha256_file, write_json


STATIC_HYBRID_PIPELINE_V2_FORMAT = "spaghetti-extractor-static-hybrid-pipeline-v2"
STATIC_RECOVERY_INVENTORY_V2_FORMAT = (
    "spaghetti-extractor-interprocedural-static-recovery-inventory-v2"
)


class StaticHybridPipelineV2Error(ValueError):
    """Exact pipeline inputs are malformed or mutually inconsistent."""


def run_static_hybrid_pipeline_v2(
    *,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    original_pe: Path | str,
    behavioral_roots: Path | str | Mapping[str, Any],
    legacy_completeness: Path | str | Mapping[str, Any] | None,
    checked_external_sites: Path | str | Mapping[str, Any] | None = None,
    external_profile_authority: Path | str | Mapping[str, Any] | None = None,
    isa_requirements: Path | str | Mapping[str, Any],
    isa_selection_authority: Path | str | Mapping[str, Any] | None,
    launch_invariants: Path | str | Mapping[str, Any] | None = None,
    checked_exception_reports: Sequence[Path | str | Mapping[str, Any]] = (),
    entry_range_facts: Sequence[Mapping[str, Any]] = (),
    world_range_facts: Sequence[Mapping[str, Any]] = (),
    machine_import_profiles: Sequence[Path | str] | None = None,
    external_interface_profiles: Sequence[Path | str] | None = None,
    external_operation_profiles: Sequence[Path | str] | None = None,
    callable_external_profiles: Sequence[Path | str] | None = None,
    internal_function_contract_profiles: Sequence[Path | str] | None = None,
    static_recovery_inventory: Path | str | Mapping[str, Any] | None = None,
    out_dir: Path | str,
) -> dict[str, Any]:
    """Run static v2 analysis only; this function never generates or runs a PE."""

    machine_path = Path(machine_ir)
    manifest_path = Path(machine_ir_manifest)
    original_path = Path(original_pe)
    output = Path(out_dir)
    rows = _read_jsonl(machine_path)
    manifest = _read_object(manifest_path, "machine-IR manifest")
    roots = _read_input(behavioral_roots, "behavioral roots")
    legacy = (
        {}
        if legacy_completeness is None
        else _read_input(legacy_completeness, "legacy completeness diagnostics")
    )
    binary = _parse_stage_a_pe(original_path)
    if binary.sha256 != roots.get("pe", {}).get("sha256"):
        raise StaticHybridPipelineV2Error(
            "behavioral roots bind a different PE than the submitted original"
        )
    if manifest.get("artifacts", {}).get("machine_ir", {}).get("sha256") != sha256_file(
        machine_path
    ):
        raise StaticHybridPipelineV2Error(
            "machine-IR manifest does not bind the submitted JSONL artifact"
        )

    graph = derive_rooted_control_graph_v2(
        rows=rows, manifest=manifest, behavioral_roots=roots
    )
    provenance = _control_object(manifest, "external_interface_provenance")
    slot_addresses = derive_mutable_slot_candidates(
        binary,
        provenance,
        units=rows,
        graph=graph,
    )
    global_slots = analyze_global_slots_v2(
        units=rows,
        graph=graph,
        candidate_slot_addresses=slot_addresses,
        image_base=binary.image_base,
        size_of_image=binary.size_of_image,
        entry_range_facts=entry_range_facts,
        world_range_facts=world_range_facts,
    )
    launch = (
        None
        if launch_invariants is None
        else _launch_invariants(
            _read_input(launch_invariants, "launch invariants"),
            binary=binary,
            behavioral_roots=roots,
        )
    )
    promotion_provenance = promote_complete_global_slot_evidence_v2(
        provenance,
        global_slots["global_slot_evidence"],
    )
    entry_state_seed = construct_entry_state_analysis_v2(
        behavioral_roots=roots,
        interface_provenance=promotion_provenance,
        units=rows,
        machine_ir_sha256=sha256_file(machine_path),
        global_slot_evidence=global_slots["global_slot_evidence"],
        launch_invariants=launch,
        iat_facts=derive_iat_facts(binary),
    )
    interprocedural = derive_interprocedural_result_v2(
        manifest,
        units=rows,
        graph=graph,
        binary=binary,
        machine_ir_sha256=sha256_file(machine_path),
        global_slot_invariants=entry_state_seed.get("global_slot_invariants", ()),
        import_abis=(
            None
            if machine_import_profiles is None
            else load_selected_import_abis(machine_import_profiles)
        ),
        interface_profiles=(
            None
            if external_interface_profiles is None
            else tuple(
                load_external_interface_profile(path)
                for path in external_interface_profiles
            )
        ),
        operation_profiles=(
            None
            if external_operation_profiles is None
            else tuple(
                load_external_operation_profile(path)
                for path in external_operation_profiles
            )
        ),
        callable_profiles=(
            None
            if callable_external_profiles is None
            else tuple(
                load_callable_external_profile(path)
                for path in callable_external_profiles
            )
        ),
        internal_function_contracts=(
            None
            if internal_function_contract_profiles is None
            else load_internal_function_contracts(
                tuple(Path(path) for path in internal_function_contract_profiles),
                binary_sha256=binary.sha256,
                units=rows,
            )
        ),
        static_recoveries=_load_static_recovery_inventory_v2(
            static_recovery_inventory,
            binary_sha256=binary.sha256,
            machine_ir_sha256=sha256_file(machine_path),
        ),
    )
    authoritative_provenance = promote_complete_global_slot_evidence_v2(
        _object(
            interprocedural.get("operation_provenance"),
            "interprocedural operation provenance",
        ),
        global_slots["global_slot_evidence"],
    )
    callback_entries = derive_callback_entry_state_contracts_v2(
        pe_sha256=binary.sha256,
        image_base=binary.image_base,
        size_of_image=binary.size_of_image,
        interface_provenance=authoritative_provenance,
        units=rows,
        machine_ir_sha256=sha256_file(machine_path),
        global_slot_invariants=entry_state_seed.get(
            "global_slot_invariants", ()
        ),
    )
    entry_state = construct_entry_state_analysis_v2(
        behavioral_roots=roots,
        interface_provenance=authoritative_provenance,
        units=rows,
        machine_ir_sha256=sha256_file(machine_path),
        global_slot_evidence=global_slots["global_slot_evidence"],
        launch_invariants=launch,
        iat_facts=derive_iat_facts(binary),
        callback_entry_state=callback_entries,
    )
    selected_profile_paths = tuple(dict.fromkeys(
        Path(path)
        for inventory in (
            machine_import_profiles,
            external_interface_profiles,
            external_operation_profiles,
            callable_external_profiles,
        )
        if inventory is not None
        for path in inventory
    ))
    profile_authority: ExternalProfileAuthorityV2 | None
    if external_profile_authority is not None:
        profile_authority = parse_external_profile_authority_v2(
            _read_input(external_profile_authority, "external-profile authority")
        )
    elif selected_profile_paths:
        profile_authority = build_external_profile_authority_v2(
            selected_profile_paths
        )
    else:
        profile_authority = None
    root_closure = derive_rooted_control_closure_v2(
        rows=rows,
        base_graph=graph,
        interprocedural=interprocedural,
    )
    if checked_external_sites is not None:
        external_site_artifact: Mapping[str, Any] | None = _read_input(
            checked_external_sites, "external-site proposals"
        )
    elif profile_authority is not None:
        external_site_artifact = derive_external_site_proposals_v2(
            machine_ir_rows=rows,
            interprocedural=interprocedural,
            profile_authority=profile_authority,
            pe_sha256=binary.sha256,
            machine_ir_sha256=sha256_file(machine_path),
            reachable_unit_ids=root_closure["reachable_units"],
        )
    else:
        external_site_artifact = None
    external_sites = (
        ()
        if external_site_artifact is None
        else parse_external_site_proposals_v2(
            external_site_artifact,
            pe_sha256=binary.sha256,
            machine_ir_sha256=sha256_file(machine_path),
        )
    )
    submitted_exceptions = tuple(
        _read_input(item, "checked exception report")
        for item in checked_exception_reports
    )
    exception_proposals, exception_replays, exceptions = (
        derive_checked_exception_reports_v2(
            units=rows,
            graph=root_closure,
            binary_sha256=binary.sha256,
            machine_ir_sha256=sha256_file(machine_path),
            submitted_evidence=submitted_exceptions,
        )
    )
    isa = (
        None
        if isa_selection_authority is None
        else parse_isa_kernel_selection_authority(
            _read_input(isa_selection_authority, "ISA selection authority")
        )
    )
    exact_isa_requirements = _read_input(
        isa_requirements, "exact ISA requirements"
    )
    static_report = build_static_hybrid_authority_v2(
        machine_ir_rows=rows,
        machine_ir_manifest=manifest,
        pe_sha256=binary.sha256,
        behavioral_roots=roots,
        entry_state_analysis=entry_state,
        interprocedural_result=interprocedural,
        checked_external_sites=external_sites,
        external_profile_authority=profile_authority,
        checked_exception_reports=exceptions,
        isa_selection_authority=isa,
        isa_requirements=exact_isa_requirements,
        v1_diagnostics=legacy,
    )

    output.mkdir(parents=True, exist_ok=True)
    graph_path = output / "rooted-control-graph-v2.json"
    closure_path = output / "rooted-control-closure-v2.json"
    slots_path = output / "global-slot-analysis-v2.json"
    entry_path = output / "entry-state-analysis-v2.json"
    callback_path = output / "callback-entry-state-v2.json"
    interprocedural_path = output / "interprocedural-analysis-v2.json"
    profile_authority_path = output / "external-profile-authority-v2.json"
    external_sites_path = output / "external-site-proposals-v2.json"
    exception_proposals_path = output / "exception-invariant-proposals-v2.json"
    exception_replays_path = output / "exception-invariant-replay-reports-v2.json"
    static_path = output / "static-hybrid-authority-v2.json"
    bundle_path = output / "authority-bundle-v2.json"
    write_json(graph_path, graph)
    write_json(closure_path, root_closure)
    write_json(slots_path, global_slots)
    write_json(entry_path, entry_state)
    write_json(callback_path, callback_entries)
    write_json(interprocedural_path, interprocedural)
    if profile_authority is not None:
        write_json(profile_authority_path, profile_authority.payload())
    if external_site_artifact is not None:
        write_json(external_sites_path, external_site_artifact)
    write_json(exception_proposals_path, exception_proposals)
    write_json(exception_replays_path, exception_replays)
    write_json(static_path, static_report)
    bundle = static_report.get("authority_bundle")
    if not isinstance(bundle, Mapping):
        # A missing exact input can prevent bundle construction entirely. Keep
        # the final audit unavailable rather than inventing an empty bundle.
        summary = _pipeline_summary(
            static_report=static_report,
            graph=graph,
            slots=global_slots,
            entry_state=entry_state,
            interprocedural=interprocedural,
            exception_replays=exception_replays,
            final_audit=None,
        )
        write_json(output / "pipeline-summary-v2.json", summary)
        return summary
    write_json(bundle_path, bundle)
    final_audit = build_static_hybrid_final_audit_v2(
        static_authority=static_path,
        authority_bundle=bundle_path,
        machine_ir=machine_path,
        machine_ir_manifest=manifest_path,
    )
    write_json(output / "static-hybrid-final-audit-v2.json", final_audit)
    summary = _pipeline_summary(
        static_report=static_report,
        graph=root_closure,
        slots=global_slots,
        entry_state=entry_state,
        interprocedural=interprocedural,
        exception_replays=exception_replays,
        final_audit=final_audit,
    )
    write_json(output / "pipeline-summary-v2.json", summary)
    return summary


def _legacy_derive_interprocedural_result_v2(
    manifest: Mapping[str, Any],
    *,
    units: Sequence[Mapping[str, Any]] | None = None,
    graph: Mapping[str, Any] | None = None,
    binary: StageABinary | None = None,
    machine_ir_sha256: str | None = None,
    global_slot_invariants: Sequence[Mapping[str, Any] | GlobalSlotInvariant] = (),
    import_abis: Mapping[MachineImportIdentity, SelectedImportABI] | None = None,
    interface_profiles: Sequence[ExternalInterfaceProfile] | None = None,
    operation_profiles: Sequence[ExternalOperationProfile] | None = None,
    callable_profiles: Sequence[CallableExternalProfile] | None = None,
    internal_function_contracts: Mapping[str, Mapping[str, Any]] | None = None,
    static_recoveries: Sequence[Mapping[str, Any]] | None = None,
    finite_value_budget: int = 32,
) -> dict[str, Any]:
    """Replay the unified analyzer instead of inheriting manifest authority.

    Manifest summaries and target recoveries are proposal seeds only.  Missing
    exact replay inputs produce an explicit incomplete result; in particular a
    prior manifest fixed point can never authorize this phase.
    """

    control = _object(manifest.get("control"), "machine-IR control")
    proposal_recoveries = _mapping_rows(
        control.get("recovered_indirect_targets"),
        "manifest recovered indirect targets",
    )
    exact_control = (
        None if units is None else _exact_control_inventory(units)
    )
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

    proposal_closures = {
        str(row.get("closure", "")) for row in proposal_recoveries
    }
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
        )

    assert units is not None
    assert graph is not None
    assert binary is not None
    assert machine_ir_sha256 is not None
    roots = _graph_root_ids(graph)
    assert exact_control is not None
    direct_edges = tuple(exact_control["direct_edges"])
    internal_call_edges = tuple(exact_control["internal_call_edges"])
    exact_static_recoveries = (
        _incomplete_static_recoveries(indirect_exits)
        if static_recoveries is None
        else _validate_static_recoveries(static_recoveries, indirect_exits)
    )
    typed_slots = _strict_global_slot_invariants(
        global_slot_invariants,
        binary=binary,
        machine_ir_sha256=machine_ir_sha256,
        units=units,
    )
    result = analyze_interprocedural_control(
        units=units,
        roots=roots,
        direct_edges=direct_edges,
        internal_call_edges=internal_call_edges,
        indirect_exits=indirect_exits,
        static_recoveries=exact_static_recoveries,
        import_abis={} if import_abis is None else import_abis,
        imports=_binary_import_rows(binary),
        image_base=binary.image_base,
        static_data_reader=_immutable_static_data_reader(binary),
        interface_profiles=() if interface_profiles is None else interface_profiles,
        operation_profiles=() if operation_profiles is None else operation_profiles,
        callable_profiles=() if callable_profiles is None else callable_profiles,
        internal_function_contracts=(
            {} if internal_function_contracts is None else internal_function_contracts
        ),
        proposal_recoveries=proposal_recoveries,
        global_slot_invariants=typed_slots,
        finite_value_budget=finite_value_budget,
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
) -> dict[str, Any]:
    manifest_fixed = control.get("analysis_fixed_point")
    fixed_point = {
        "format": INTERPROCEDURAL_ANALYSIS_FORMAT,
        "status": "incomplete",
        "rounds": 0,
        "discovery_rounds": 0,
        "cold_replay_rounds": 0,
        "scc_evaluations": 0,
        "cold_replay_validated": False,
        "discovery_signature": None,
        "cold_replay_signature": None,
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
        "fixed_point": fixed_point,
        "manifest_diagnostics": {
            "call_summaries": control.get("internal_call_preservation"),
            "recovered_targets": control.get("recovered_indirect_targets"),
            "fixed_point": manifest_fixed,
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
    dependency_inventory = {
        str(row.get("id")): {
            str(value) for value in row.get("dependencies", []) if isinstance(value, str)
        }
        for row in dependency_rows
        if isinstance(dependency_rows, list) and isinstance(row, Mapping)
    } if isinstance(dependency_rows, list) else {}
    failures: set[str] = set()
    if fixed.get("mutable_slot_handoff") != "point_sensitive_dependency_v2":
        failures.add("mutable_slot_handoff_marker_missing")
    if fixed.get("global_slot_promotion") is not False:
        failures.add("mutable_slot_root_promotion_enabled")

    for recovery in recoveries:
        exit_id = str(recovery.get("id", ""))
        slot_dependencies = recovery.get("mutable_slot_dependencies", [])
        authority_dependencies = recovery.get("authority_dependencies", [])
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
        fixed["cold_replay_validated"] = False
        prior = fixed.get("failure_reasons")
        fixed["failure_reasons"] = sorted(
            set(prior if isinstance(prior, list) else ()) | failures
        )
    result["fixed_point"] = fixed
    result["format"] = INTERPROCEDURAL_ANALYSIS_FORMAT
    result["status"] = str(fixed.get("status", "incomplete"))
    return result


def _mapping_rows(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list) or not all(
        isinstance(row, Mapping) for row in value
    ):
        raise StaticHybridPipelineV2Error(f"{context} must be an array of objects")
    return [dict(row) for row in value]


def _graph_root_ids(graph: Mapping[str, Any]) -> list[str]:
    result: list[str] = []
    for row in graph.get("roots", []):
        if isinstance(row, str):
            result.append(row)
        elif isinstance(row, Mapping) and isinstance(row.get("unit_id"), str):
            result.append(str(row["unit_id"]))
    return sorted(set(result))


def _interprocedural_edges(
    control: Mapping[str, Any],
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    direct: list[dict[str, Any]] = []
    internal: list[dict[str, Any]] = []
    for row in _mapping_rows(control.get("direct_targets"), "direct targets"):
        source = row.get("source_unit_id")
        target = row.get("resolved_unit_id", row.get("target_unit_id"))
        if not isinstance(source, str) or not isinstance(target, str):
            continue
        edge: dict[str, Any] = {
            "source_unit_id": source,
            "target_unit_id": target,
        }
        if row.get("kind") == "internal_call":
            event_index = row.get("source_event_index")
            if isinstance(event_index, int) and not isinstance(event_index, bool):
                edge["source_event_index"] = event_index
            internal.append(edge)
        elif row.get("kind") == "direct_control":
            direct.append(edge)
    return direct, internal


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
        raise StaticHybridPipelineV2Error(
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
            raise StaticHybridPipelineV2Error(
                f"global-slot invariant v2 does not replay: {exc}"
            ) from exc
        if record.status.value != "complete":
            raise StaticHybridPipelineV2Error(
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
            raise StaticHybridPipelineV2Error(
                f"global-slot invariant binding does not replay: {exc}"
            ) from exc
        result.append(record)
    if len({record.content_id for record in result}) != len(result):
        raise StaticHybridPipelineV2Error(
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


def _load_static_recovery_inventory_v2(
    value: Path | str | Mapping[str, Any] | None,
    *,
    binary_sha256: str,
    machine_ir_sha256: str,
) -> list[Mapping[str, Any]] | None:
    if value is None:
        return None
    payload = _read_input(value, "static recovery inventory")
    if set(payload) != {
        "format",
        "binary_sha256",
        "machine_ir_sha256",
        "recoveries",
    }:
        raise StaticHybridPipelineV2Error(
            "static recovery inventory fields do not match v2"
        )
    if payload.get("format") != STATIC_RECOVERY_INVENTORY_V2_FORMAT:
        raise StaticHybridPipelineV2Error(
            "static recovery inventory format is unsupported"
        )
    if payload.get("binary_sha256") != binary_sha256:
        raise StaticHybridPipelineV2Error(
            "static recovery inventory binds a different original PE"
        )
    if payload.get("machine_ir_sha256") != machine_ir_sha256:
        raise StaticHybridPipelineV2Error(
            "static recovery inventory binds different machine IR"
        )
    return _mapping_rows(payload.get("recoveries"), "static recoveries")


def _launch_invariants(
    value: Mapping[str, Any],
    *,
    binary: StageABinary,
    behavioral_roots: Mapping[str, Any],
) -> Mapping[str, Any] | None:
    if value.get("format") == "spaghetti-extractor-pe32-launch-profile-v2":
        check = validate_launch_profile_v2(
            value,
            pe_sha256=binary.sha256,
            image_base=binary.image_base,
            size_of_image=binary.size_of_image,
            behavioral_roots=behavioral_roots,
        )
        if check.status is not LaunchProfileStatus.COMPLETE or check.profile is None:
            return None
        return launch_invariants_for_entry_state(check.profile)
    return value


def _pipeline_summary(
    *,
    static_report: Mapping[str, Any],
    graph: Mapping[str, Any],
    slots: Mapping[str, Any],
    entry_state: Mapping[str, Any],
    interprocedural: Mapping[str, Any],
    exception_replays: Mapping[str, Any],
    final_audit: Mapping[str, Any] | None,
) -> dict[str, Any]:
    status = "incomplete" if final_audit is None else str(final_audit["status"])
    return {
        "format": STATIC_HYBRID_PIPELINE_V2_FORMAT,
        "status": status,
        "authorizes_candidate_generation": (
            final_audit is not None and final_audit.get("status") == "pass"
        ),
        "phases": {
            "rooted_control_graph": graph.get("status"),
            "global_slots": slots.get("status"),
            "entry_state": entry_state.get("status"),
            "interprocedural": _object(
                interprocedural.get("fixed_point"),
                "interprocedural fixed point",
            ).get("status"),
            "exception_invariants": _exception_phase_status(exception_replays),
            "static_authority": static_report.get("status"),
            "final_audit": None if final_audit is None else final_audit.get("status"),
        },
        "primary_blocker_ids": list(static_report.get("primary_blocker_ids", [])),
        "policy": {
            "original_binary_executed": False,
            "candidate_generated": False,
            "v1_authorizes": False,
        },
    }


def _exception_phase_status(value: Mapping[str, Any]) -> str:
    reports = value.get("reports")
    if not isinstance(reports, list):
        return "violated"
    statuses = [
        row.get("report", {}).get("status")
        for row in reports
        if isinstance(row, Mapping) and isinstance(row.get("report"), Mapping)
    ]
    if any(status == "violated" for status in statuses):
        return "violated"
    if any(status != "complete" for status in statuses):
        return "incomplete"
    return "complete"


def _control_object(manifest: Mapping[str, Any], key: str) -> Mapping[str, Any]:
    return _object(_object(manifest.get("control"), "machine-IR control").get(key), key)


def _read_jsonl(path: Path) -> list[Mapping[str, Any]]:
    try:
        rows = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StaticHybridPipelineV2Error(f"cannot read machine IR: {exc}") from exc
    if not rows or not all(isinstance(row, Mapping) for row in rows):
        raise StaticHybridPipelineV2Error("machine IR is empty or malformed")
    return rows


def _read_object(path: Path, context: str) -> Mapping[str, Any]:
    return _read_input(path, context)


def _read_input(
    value: Path | str | Mapping[str, Any], context: str
) -> Mapping[str, Any]:
    if isinstance(value, Mapping):
        return json.loads(canonical_json_bytes(value).decode("ascii"))
    try:
        parsed = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise StaticHybridPipelineV2Error(f"cannot read {context}: {exc}") from exc
    return _object(parsed, context)


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StaticHybridPipelineV2Error(f"{context} must be an object")
    return value


# Preserve the public import path while the orchestration module is split into
# independently cacheable authority phases.
derive_interprocedural_result_v2 = _derive_interprocedural_result_v2


__all__ = [
    "EXCEPTION_PROPOSAL_PHASE_V2_FORMAT",
    "EXCEPTION_REPLAY_PHASE_V2_FORMAT",
    "ROOTED_CONTROL_CLOSURE_V2_FORMAT",
    "STATIC_RECOVERY_INVENTORY_V2_FORMAT",
    "STATIC_HYBRID_PIPELINE_V2_FORMAT",
    "StaticHybridPipelineV2Error",
    "derive_iat_facts",
    "derive_checked_exception_reports_v2",
    "derive_faulting_rooted_sccs_v2",
    "derive_interprocedural_result_v2",
    "derive_mutable_slot_candidates",
    "derive_rooted_control_graph_v2",
    "derive_rooted_control_closure_v2",
    "promote_complete_global_slot_evidence_v2",
    "run_static_hybrid_pipeline_v2",
]
