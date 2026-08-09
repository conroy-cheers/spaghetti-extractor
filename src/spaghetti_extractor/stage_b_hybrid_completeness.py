"""Legacy v1 static-completeness diagnostics for hybrid candidates.

The report is proposal and diagnostic evidence only. It may normalize useful
sites and blockers, but it cannot authorize candidate generation. The strict
v2 authority graph independently replays any proposal it consumes.
"""

from __future__ import annotations

import copy
import json
from collections import Counter
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .behavioral_roots import BehavioralRootsError, load_behavioral_roots
from .checked_external_site_contract import (
    CheckedExternalSiteContract,
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
    require_profile_match,
)
from .external_interface_profiles import (
    ExternalInterfaceProfile,
    ExternalInterfaceProfileError,
    InterfaceMethod,
    load_external_interface_profile,
)
from .hybrid_diagnostics_v2 import (
    build_hybrid_diagnostics_v2,
    make_blocker_record,
)
from .machine_import_profiles import (
    MachineImportIdentity,
    MachineImportProfileError,
    SelectedMachineImportContract,
    load_machine_import_profile_set,
)
from .machine_abi import resolve_machine_call_abi
from .roundtrip_fuzz.image_contract import load_stage_a_load_image_contract
from .stage_binary import StageAInputError
from .util import sha256_bytes, sha256_file, write_json


STATIC_HYBRID_COMPLETENESS_FORMAT = "stage-b-static-hybrid-completeness-v1"
_MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
_INSTRUCTION_EFFECT_SCHEDULE_FORMAT = (
    "stage-a-instruction-ordered-effect-schedule-v1"
)
_EXTERNAL_INTERFACE_PROVENANCE_FORMAT = (
    "stage-a-external-interface-provenance-v1"
)
_CALLBACK_REGISTRATION_FORMAT = "stage-a-callback-registration-provenance-v1"
_CHECKED_INSTRUCTION_DECODER = "StageA.Formal.decodeInstructionExact"
_CHECKED_INSTRUCTION_EXECUTOR = "StageA.Formal.executeInstruction"
_SUPPORTED_EXTERNAL_EVENT_KINDS = frozenset({
    "external_call",
    "indirect_call",
    "indirect_jump",
    "internal_call",
})
_INTERNAL_MACHINE_EVENT_KINDS = frozenset({
    "rep_movs",
    "rep_scas",
    "rep_stos",
})
_FAMILIES = (
    "rooted_control",
    "direct_control",
    "indirect_control",
    "callbacks_and_returns",
    "exceptional_control",
    "executable_semantics",
    "machine_abi",
    "external_effects",
    "implementation_coverage",
    "deferred_transfers",
)


class StaticHybridCompletenessError(StageAInputError):
    """The submitted static artifacts are malformed or mutually inconsistent."""


@dataclass(frozen=True)
class _Blocker:
    family: str
    code: str
    message: str
    next_action: str
    location: Mapping[str, Any] | None = None
    details: Mapping[str, Any] | None = None

    def payload(self) -> dict[str, Any]:
        body: dict[str, Any] = {
            "family": self.family,
            "code": self.code,
            "message": self.message,
            "next_action": self.next_action,
            "location": None if self.location is None else dict(self.location),
            "details": None if self.details is None else dict(self.details),
        }
        body["id"] = "static-hybrid-blocker:" + sha256_bytes(
            json.dumps(body, sort_keys=True, separators=(",", ":")).encode("utf-8")
        )[:20]
        return body


@dataclass(frozen=True)
class _SelectedInterfaceMethod:
    profile: ExternalInterfaceProfile
    method: InterfaceMethod


def _selected_import_machine_contract(
    selected: SelectedMachineImportContract,
) -> dict[str, Any]:
    contract = copy.deepcopy(dict(selected.contract))
    contract["id"] = str(contract["id"])
    if selected.arity_kind is not None:
        contract["arity"] = {
            "kind": selected.arity_kind,
            **(
                {"words": selected.argument_words}
                if selected.argument_words is not None
                else {}
            ),
        }
    contract.setdefault("disposition", "returns")
    contract["profile_binding"] = {
        "profile_id": selected.profile_id,
        "profile_sha256": selected.profile_sha256,
        "entry_key": selected.entry_key,
        "entry_index": selected.entry_index,
    }
    return contract


def _interface_method_machine_contract(
    selected: _SelectedInterfaceMethod,
) -> dict[str, Any]:
    method = selected.method
    effects = method.effects
    if effects is None:
        raise StaticHybridCompletenessError(
            "selected interface method has no complete effect contract"
        )
    contract = {
        "id": f"{method.interface_id}::{method.name}",
        "abi_template": method.abi.template,
        "arity": {"kind": "fixed", "words": method.argument_words},
        "disposition": "returns",
        "result_register_relations": [],
        "out_interface_relations": [
            output.as_json() for output in method.outputs
        ],
        "profile_binding": {
            "profile_id": selected.profile.profile_id,
            "profile_sha256": selected.profile.sha256,
        },
        **effects.as_json(),
    }
    return contract


def _protocol_machine_contract(
    protocol: Mapping[str, Any], contract: Mapping[str, Any]
) -> dict[str, Any]:
    result = copy.deepcopy(dict(contract))
    result["profile_binding"] = {
        "profile_id": protocol.get("profile_id"),
        "profile_sha256": protocol.get("profile_sha256"),
    }
    return result


def write_static_hybrid_completeness_report(
    *,
    machine_ir: Path | str,
    machine_ir_manifest: Path | str,
    original_pe: Path | str | None = None,
    load_image_contract: Path | str,
    behavioral_roots: Path | str | None = None,
    machine_import_profiles: Sequence[Path | str],
    external_interface_profiles: Sequence[Path | str] = (),
    out: Path | str,
) -> dict[str, Any]:
    """Write a deterministic static gate report without executing either binary."""

    machine_ir_path = Path(machine_ir)
    manifest_path = Path(machine_ir_manifest)
    original_path = (
        Path(original_pe)
        if original_pe is not None
        else manifest_path.parent / "original.exe"
    )
    load_image_path = Path(load_image_contract)
    behavioral_roots_path = (
        Path(behavioral_roots)
        if behavioral_roots is not None
        else manifest_path.parent / "behavioral-roots.json"
    )
    output = Path(out)
    manifest = _read_object(manifest_path, "machine-IR manifest")
    if manifest.get("format") != _MACHINE_IR_FORMAT:
        raise StaticHybridCompletenessError("unsupported machine-IR manifest format")
    artifact = _object(_object(manifest.get("artifacts"), "artifacts").get("machine_ir"), "machine IR artifact")
    actual_ir_sha256 = sha256_file(machine_ir_path)
    if artifact.get("sha256") != actual_ir_sha256:
        raise StaticHybridCompletenessError(
            "machine-IR manifest does not bind the submitted machine IR"
        )
    rows = _read_jsonl(machine_ir_path)
    counts = _object(manifest.get("counts"), "machine-IR counts")
    if counts.get("units") != len(rows):
        raise StaticHybridCompletenessError("machine-IR unit count differs from manifest")
    rows_by_id: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(rows):
        unit_id = row.get("id")
        if not isinstance(unit_id, str) or not unit_id or unit_id in rows_by_id:
            raise StaticHybridCompletenessError(
                f"machine-IR unit {index} has a missing or duplicate id"
            )
        rows_by_id[unit_id] = row

    try:
        load_image = load_stage_a_load_image_contract(load_image_path)
    except StageAInputError as exc:
        raise StaticHybridCompletenessError(str(exc)) from exc
    if not load_image.completeness.complete:
        raise StaticHybridCompletenessError(
            "load-image contract completeness inventory is not complete"
        )
    try:
        root_contract = load_behavioral_roots(
            behavioral_roots_path, original_pe=original_path
        )
    except BehavioralRootsError as exc:
        raise StaticHybridCompletenessError(str(exc)) from exc
    manifest_inputs = _object(manifest.get("inputs"), "machine-IR inputs")
    original_input = _object(
        manifest_inputs.get("original_pe"), "machine-IR original PE input"
    )
    binary = _object(manifest.get("binary"), "machine-IR binary inventory")
    expected_identity = {
        "sha256": load_image.identity.pe_sha256,
        "machine": load_image.identity.machine,
        "bitness": load_image.identity.bitness,
        "image_base": load_image.identity.preferred_base,
        "entrypoint_rva": load_image.identity.entry_rva,
        "size_of_image": load_image.identity.image_size,
    }
    observed_identity = {
        "sha256": original_input.get("sha256"),
        "machine": binary.get("machine"),
        "bitness": binary.get("bitness"),
        "image_base": binary.get("image_base"),
        "entrypoint_rva": binary.get("entrypoint_rva"),
        "size_of_image": binary.get("size_of_image"),
    }
    if observed_identity != expected_identity or binary.get("sha256") != expected_identity["sha256"]:
        raise StaticHybridCompletenessError(
            "load-image contract identity does not match the machine-IR original PE"
        )
    root_identity = _object(root_contract.get("pe"), "behavioral-root PE binding")
    if any(
        root_identity.get(field) != expected_identity[field]
        for field in (
            "sha256",
            "machine",
            "bitness",
            "image_base",
            "entrypoint_rva",
            "size_of_image",
        )
    ):
        raise StaticHybridCompletenessError(
            "behavioral-root artifact targets a different exact PE"
        )

    try:
        profile_set = load_machine_import_profile_set(machine_import_profiles)
    except MachineImportProfileError as exc:
        raise StaticHybridCompletenessError(str(exc)) from exc
    import_contracts = profile_set.by_identity()
    interface_methods = _load_interface_effect_contracts(
        external_interface_profiles
    )

    blockers: list[_Blocker] = []
    violated_inventory_claims = 0
    derived_manifest_instruction_count = sum(
        len(row.get("instructions"))
        for row in rows
        if isinstance(row.get("instructions"), list)
    )
    if counts.get("instructions") != derived_manifest_instruction_count:
        blockers.append(_Blocker(
            family="executable_semantics",
            code="machine_ir_instruction_inventory_mismatch",
            message="the manifest instruction count contradicts the machine-IR rows",
            next_action="regenerate the manifest from the exact machine-IR instruction inventories",
            details={
                "reported_instructions": counts.get("instructions"),
                "derived_instructions": derived_manifest_instruction_count,
            },
        ))
        violated_inventory_claims += 1
    control = _object(manifest.get("control"), "control inventory")
    reachability = _object(control.get("reachability"), "reachability inventory")
    reachable_ids = _string_set(
        reachability.get("reachable_units"), "reachable unit inventory"
    )
    potential_ids = _string_set(
        reachability.get("potential_units"), "potential unit inventory"
    )
    confirmed_unreachable_ids = _string_set(
        reachability.get("confirmed_unreachable_units"),
        "confirmed-unreachable unit inventory",
    )
    if not reachable_ids or not reachable_ids <= rows_by_id.keys():
        raise StaticHybridCompletenessError(
            "reachability inventory has no roots or references unknown units"
        )
    if (potential_ids | confirmed_unreachable_ids) - rows_by_id.keys():
        raise StaticHybridCompletenessError(
            "reachability inventory references unknown non-reachable units"
        )
    if reachable_ids & potential_ids or reachable_ids & confirmed_unreachable_ids:
        raise StaticHybridCompletenessError("reachability classes overlap")

    roots = _string_set(reachability.get("roots"), "root inventory")
    if not roots or not roots <= reachable_ids:
        blockers.append(_Blocker(
            family="rooted_control",
            code="roots_not_closed",
            message="not every declared behavioral root is in the checked reachable set",
            next_action="bind each PE entry, export, TLS, and callback root to an exact machine-IR unit",
            details={"roots": len(roots), "reachable_roots": len(roots & reachable_ids)},
        ))

    units_by_rva = _units_by_rva(rows_by_id)
    canonical_roots: set[str] = set()
    root_normalization_complete = True
    mandatory_root_rvas = [
        (str(root["kind"]), int(root["rva"]))
        for root in _list(root_contract.get("roots"), "behavioral-root inventory")
    ]
    for root_kind, root_rva in mandatory_root_rvas:
        matches = units_by_rva.get(root_rva, [])
        if len(matches) != 1:
            root_normalization_complete = False
            blockers.append(_Blocker(
                family="rooted_control",
                code=(
                    "mandatory_root_missing"
                    if not matches
                    else "mandatory_root_ambiguous"
                ),
                message="a mandatory PE launch root does not identify one exact machine-IR unit",
                next_action="decode one exact unit at every PE entry and TLS callback RVA",
                details={
                    "root_kind": root_kind,
                    "rva": root_rva,
                    "matching_unit_ids": matches,
                },
            ))
        else:
            canonical_roots.add(matches[0])

    callback_proposals = _list(
        control.get("callback_cutpoint_proposals"), "callback cutpoint proposals"
    )
    callback_root_ids = _normalize_callback_proposals(
        callback_proposals,
        rows_by_id=rows_by_id,
        units_by_rva=units_by_rva,
    )
    canonical_roots.update(callback_root_ids)
    if root_normalization_complete and roots != canonical_roots:
        blockers.append(_Blocker(
            family="rooted_control",
            code="canonical_root_inventory_mismatch",
            message="submitted behavioral roots differ from PE launch and recovered callback roots",
            next_action="regenerate reachability from the exact load-image and callback root inventory",
            details={
                "missing_root_unit_ids": sorted(canonical_roots - roots),
                "spurious_root_unit_ids": sorted(roots - canonical_roots),
            },
        ))
        violated_inventory_claims += 1

    frontiers = _list(reachability.get("frontiers"), "reachability frontiers")
    if reachability.get("status") != "complete" or frontiers or potential_ids:
        blockers.append(_Blocker(
            family="rooted_control",
            code="rooted_reachability_incomplete",
            message="rooted static reachability has unresolved behavior",
            next_action="resolve every rooted exit, then recompute closure until no unit remains potential",
            details={
                "frontiers": len(frontiers),
                "potential_units": len(potential_ids),
                "reported_status": reachability.get("status"),
            },
        ))

    raw_analysis_fixed_point = control.get("analysis_fixed_point")
    analysis_fixed_point = (
        raw_analysis_fixed_point
        if isinstance(raw_analysis_fixed_point, Mapping)
        else {}
    )
    if (
        analysis_fixed_point.get("status") != "complete"
        or analysis_fixed_point.get("cold_replay_validated") is not True
    ):
        blockers.append(_Blocker(
            family="rooted_control",
            code="control_fixed_point_not_cold_validated",
            message=(
                "the recovered control graph was not reproduced by an "
                "unseeded fixed-point analysis"
            ),
            next_action=(
                "rerun control and provenance analysis to convergence, then "
                "require an identical no-seed replay before authorization"
            ),
            details={
                "reported_status": analysis_fixed_point.get("status"),
                "cold_replay_validated": analysis_fixed_point.get(
                    "cold_replay_validated"
                ),
                "rounds": analysis_fixed_point.get("rounds"),
                "record_is_object": isinstance(
                    raw_analysis_fixed_point, Mapping
                ),
            },
        ))

    canonical_direct = _canonical_direct_sites(rows_by_id, reachable_ids)
    direct_blockers, direct_violations = _reconcile_direct_inventory(
        canonical_direct,
        _list(control.get("direct_targets"), "direct-control inventory"),
        rows_by_id=rows_by_id,
        units_by_rva=units_by_rva,
        reachable_ids=reachable_ids,
    )
    blockers.extend(direct_blockers)
    violated_inventory_claims += direct_violations

    canonical_indirect = _canonical_indirect_sites(rows_by_id, reachable_ids)
    submitted_indirect = _list(
        control.get("indirect_exits"), "indirect-exit inventory"
    )
    indirect_inventory_blockers, indirect_inventory_violations = (
        _reconcile_indirect_inventory(
            canonical_indirect,
            submitted_indirect,
            rows_by_id=rows_by_id,
            reachable_ids=reachable_ids,
        )
    )
    blockers.extend(indirect_inventory_blockers)
    violated_inventory_claims += indirect_inventory_violations

    canonical_external_events = _canonical_external_events(
        rows_by_id, reachable_ids
    )
    for (unit_id, event_index), event_row in sorted(
        canonical_external_events.items()
    ):
        kind = event_row.get("kind")
        if kind in _SUPPORTED_EXTERNAL_EVENT_KINDS | _INTERNAL_MACHINE_EVENT_KINDS:
            continue
        blockers.append(_Blocker(
            family="machine_abi",
            code="external_event_kind_unsupported",
            message="a reachable external event uses a kind outside the closed supported algebra",
            next_action="classify the event as one supported call/jump kind and emit its complete closure evidence",
            location={
                "unit_id": unit_id,
                "rva_start": event_row.get("unit_rva"),
                "event_index": event_index,
            },
            details={
                "event_kind": kind,
                "supported_kinds": sorted(_SUPPORTED_EXTERNAL_EVENT_KINDS),
                "internal_machine_kinds": sorted(_INTERNAL_MACHINE_EVENT_KINDS),
            },
        ))
    external_inventory = _list(
        _object(manifest.get("external"), "external inventory").get("events"),
        "external event inventory",
    )
    external_inventory_blockers, external_inventory_violations = (
        _reconcile_external_inventory(
            canonical_external_events,
            external_inventory,
            rows_by_id=rows_by_id,
            reachable_ids=reachable_ids,
        )
    )
    blockers.extend(external_inventory_blockers)
    violated_inventory_claims += external_inventory_violations

    manifest_issues = _list(manifest.get("issues"), "machine-IR issues")
    violated_source_issues = 0
    for issue in manifest_issues:
        if not isinstance(issue, Mapping) or issue.get("status") not in {
            "incomplete", "violated"
        }:
            continue
        if issue.get("status") == "violated":
            violated_source_issues += 1
        category = str(issue.get("category") or "unknown")
        if category == "unresolved_indirect_control":
            continue
        family = {
            "unresolved_direct_control_target": "direct_control",
            "unresolved_internal_call_target": "direct_control",
            "unsupported_semantics": "executable_semantics",
            "unclassified_executable_span": "executable_semantics",
        }.get(category, "implementation_coverage")
        location = issue.get("location")
        unit_id = location.get("unit_id") if isinstance(location, Mapping) else None
        if (
            issue.get("status") != "violated"
            and isinstance(unit_id, str)
            and unit_id not in reachable_ids | potential_ids
        ):
            continue
        blockers.append(_Blocker(
            family=family,
            code=category,
            message=str(issue.get("message") or category.replace("_", " ")),
            next_action=str(issue.get("next_action") or "close the checked static obligation"),
            location=location if isinstance(location, Mapping) else None,
            details={
                "source_issue_id": issue.get("id"),
                "source_status": issue.get("status"),
            },
        ))

    interface_provenance = _object(
        control.get("external_interface_provenance"),
        "external-interface provenance",
    )
    provenance_mismatches = _external_interface_provenance_mismatches(
        interface_provenance
    )
    if provenance_mismatches:
        blockers.append(_Blocker(
            family="external_effects",
            code="external_interface_provenance_incomplete",
            message="the external-interface provenance artifact is malformed or did not converge",
            next_action="regenerate the structurally valid provenance proposal to a converged fixed point",
            details={"mismatches": provenance_mismatches},
        ))
    # The post-conflict indirect inventory is the control-flow authority.  The
    # interface analysis is a proposal source and may legitimately be unable
    # to explain a transfer already closed by a checked static table.  Preserve
    # proposal-only origin diagnostics only when its target inventory agrees
    # exactly with the canonical closure.
    provenance_resolutions = _list(
        interface_provenance.get("resolutions"), "provenance resolutions"
    )
    provenance_by_source = {
        _indirect_site_key(
            _object(raw, "provenance resolution"), "provenance resolution"
        ): _object(raw, "provenance resolution")
        for raw in provenance_resolutions
    }
    resolutions: list[dict[str, Any]] = []
    for raw in submitted_indirect:
        canonical_resolution = _object(raw, "canonical indirect resolution")
        key = _indirect_site_key(
            canonical_resolution, "canonical indirect resolution"
        )
        proposal = provenance_by_source.get(key)
        normalized = dict(canonical_resolution)
        normalized["status"] = (
            "recovered"
            if normalized.get("closure") == "checked_finite_target_inventory"
            else "incomplete"
        )
        if proposal is not None and proposal.get("status") == "recovered":
            canonical_targets = _indirect_target_inventory_signature(normalized)
            proposed_targets = _indirect_target_inventory_signature(proposal)
            if canonical_targets != proposed_targets:
                blockers.append(_Blocker(
                    family="indirect_control",
                    code="indirect_provenance_disagrees_with_canonical_closure",
                    message="an indirect provenance proposal contradicts the canonical post-conflict target inventory",
                    next_action="regenerate the control fixed point and preserve disagreement as a failed obligation",
                    location={
                        "unit_id": key[0],
                        "rva_start": normalized.get("source_rva"),
                        "event_index": key[1],
                    },
                    details={
                        "canonical_targets": canonical_targets,
                        "proposed_targets": proposed_targets,
                    },
                ))
                violated_inventory_claims += 1
            else:
                for field in ("origin_count", "origin_kinds"):
                    if field in proposal:
                        normalized[field] = copy.deepcopy(proposal[field])
        resolutions.append(normalized)
    resolution_by_source: dict[tuple[str, int | None], Mapping[str, Any]] = {}
    for raw in resolutions:
        resolution = _object(raw, "indirect resolution")
        unit_id = resolution.get("source_unit_id")
        event_index = resolution.get("source_event_index")
        if not isinstance(unit_id, str) or unit_id not in rows_by_id:
            raise StaticHybridCompletenessError("indirect resolution has no source unit")
        if event_index is not None and (
            not isinstance(event_index, int) or isinstance(event_index, bool)
        ):
            raise StaticHybridCompletenessError(
                "indirect resolution has an invalid source event index"
            )
        key = (unit_id, event_index)
        if unit_id in reachable_ids:
            if key in resolution_by_source:
                raise StaticHybridCompletenessError(
                    "duplicate indirect resolution source key"
                )
            resolution_by_source[key] = resolution
        if unit_id not in reachable_ids:
            continue
        resolution_closed = (
            resolution.get("closure") == "checked_finite_target_inventory"
        )
        if not resolution_closed:
            failure = resolution.get("recovery_failure")
            failure = failure if isinstance(failure, Mapping) else {}
            blockers.append(_Blocker(
                family="indirect_control",
                code=str(failure.get("code") or "unresolved_indirect_control"),
                message="reachable indirect control has no checked complete target inventory",
                next_action=str(
                    failure.get("next_action")
                    or "recover bounded target provenance and add every feasible target to rooted closure"
                ),
                location={
                    "unit_id": unit_id,
                    "rva_start": resolution.get("source_rva"),
                    "event_index": event_index,
                },
                details={"resolution_id": resolution.get("id")},
            ))

    for key in sorted(canonical_indirect.keys() - resolution_by_source.keys(), key=str):
        expected = canonical_indirect[key]
        blockers.append(_Blocker(
            family="indirect_control",
            code="indirect_resolution_missing",
            message="a reachable indirect exit has no provenance resolution record",
            next_action="emit one finite-target resolution for every machine-IR indirect site",
            location={
                "unit_id": key[0],
                "rva_start": expected.get("source_rva"),
                "event_index": key[1],
            },
        ))
    for key in sorted(resolution_by_source.keys() - canonical_indirect.keys(), key=str):
        observed = resolution_by_source[key]
        blockers.append(_Blocker(
            family="indirect_control",
            code="indirect_resolution_contains_spurious_site",
            message="an indirect resolution refers to no reachable machine-IR indirect exit",
            next_action="regenerate provenance resolutions from canonical indirect sites",
            location={
                "unit_id": key[0],
                "rva_start": observed.get("source_rva"),
                "event_index": key[1],
            },
        ))
        violated_inventory_claims += 1
    for key in sorted(canonical_indirect.keys() & resolution_by_source.keys(), key=str):
        expected = canonical_indirect[key]
        observed = resolution_by_source[key]
        if any(
            observed.get(field) != expected.get(field)
            for field in ("source_rva", "kind", "target_expression")
        ):
            blockers.append(_Blocker(
                family="indirect_control",
                code="indirect_resolution_site_binding_mismatch",
                message="an indirect resolution contradicts its machine-IR target expression",
                next_action="regenerate provenance for the exact indirect site",
                location={
                    "unit_id": key[0],
                    "rva_start": expected.get("source_rva"),
                    "event_index": key[1],
                },
            ))
            violated_inventory_claims += 1
        if observed.get("closure") != "checked_finite_target_inventory":
            continue
        target_unit_ids = _list(
            observed.get("target_unit_ids"), "indirect internal targets"
        )
        external_targets = _list(
            observed.get("external_targets"), "indirect external targets"
        )
        if any(not isinstance(target, str) for target in target_unit_ids):
            raise StaticHybridCompletenessError(
                "indirect resolution has a non-string internal target"
            )
        if len(set(target_unit_ids)) != len(target_unit_ids) or any(
            target not in rows_by_id for target in target_unit_ids
        ):
            raise StaticHybridCompletenessError(
                "indirect resolution has duplicate or unknown internal targets"
            )
        missing_reachable_targets = sorted(
            str(target) for target in target_unit_ids if target not in reachable_ids
        )
        if missing_reachable_targets:
            blockers.append(_Blocker(
                family="indirect_control",
                code="indirect_targets_not_reachable",
                message="a recovered finite indirect target set escapes rooted closure",
                next_action="add every feasible finite target to rooted reachability",
                location={
                    "unit_id": key[0],
                    "rva_start": expected.get("source_rva"),
                    "event_index": key[1],
                },
                details={"missing_target_unit_ids": missing_reachable_targets},
            ))
        if not target_unit_ids and not external_targets:
            blockers.append(_Blocker(
                family="indirect_control",
                code="indirect_target_set_empty",
                message="a recovered indirect exit has no internal or external target",
                next_action="supply a nonempty finite target set or a checked infeasibility certificate",
                location={
                    "unit_id": key[0],
                    "rva_start": expected.get("source_rva"),
                    "event_index": key[1],
                },
            ))

    for raw in _list(interface_provenance.get("issues"), "interface issues"):
        issue = _object(raw, "interface issue")
        unit_id = issue.get("unit_id")
        if isinstance(unit_id, str) and unit_id not in reachable_ids:
            continue
        blockers.append(_Blocker(
            family="external_effects",
            code=str(issue.get("code") or "external_interface_contract_incomplete"),
            message="reachable interface call lacks complete argument/effect provenance",
            next_action="recover the call-frame arguments and bind all external reads, writes, resources, and outputs",
            location={"unit_id": unit_id},
            details={key: value for key, value in issue.items() if key != "unit_id"},
        ))

    callback_registrations = _list(
        interface_provenance.get("callback_registrations"),
        "callback registration inventory",
    )
    callback_registration_by_site: dict[tuple[str, int], Mapping[str, Any]] = {}
    callback_registration_source_keys: set[tuple[str, int]] = set()
    ambiguous_callback_registration_sources: set[tuple[str, int]] = set()
    for registration_index, registration in enumerate(callback_registrations):
        row = _object(registration, "callback registration")
        unit_id = row.get("unit_id")
        event_index = row.get("event_index")
        source_key = (
            (unit_id, event_index)
            if isinstance(unit_id, str)
            and isinstance(event_index, int)
            and not isinstance(event_index, bool)
            else None
        )
        if source_key is not None and unit_id in reachable_ids:
            if source_key in callback_registration_source_keys:
                blockers.append(_Blocker(
                    family="callbacks_and_returns",
                    code="callback_registration_source_ambiguous",
                    message="multiple callback-registration records claim the same reachable source event",
                    next_action="emit exactly one callback-registration record per source unit and event",
                    location={"unit_id": unit_id, "event_index": event_index},
                ))
                violated_inventory_claims += 1
                ambiguous_callback_registration_sources.add(source_key)
                callback_registration_by_site.pop(source_key, None)
            else:
                callback_registration_source_keys.add(source_key)
            registration_mismatches = _callback_registration_record_mismatches(
                row,
                source_event=canonical_external_events.get(source_key),
                rows_by_id=rows_by_id,
                reachable_ids=reachable_ids,
            )
            if registration_mismatches:
                blockers.append(_Blocker(
                    family="callbacks_and_returns",
                    code="callback_registration_not_canonical",
                    message="a reachable callback registration is not canonically bound to its source event and targets",
                    next_action="regenerate one complete registration with the exact source instruction and paired callback RVA/unit targets",
                    location={
                        "unit_id": unit_id,
                        "instruction_rva": row.get("instruction_rva"),
                        "event_index": event_index,
                    },
                    details={
                        "registration_index": registration_index,
                        "mismatches": registration_mismatches,
                    },
                ))
            elif source_key not in ambiguous_callback_registration_sources:
                callback_registration_by_site[source_key] = row
        elif unit_id in reachable_ids or (
            isinstance(unit_id, str) and unit_id not in rows_by_id
        ):
            blockers.append(_Blocker(
                family="callbacks_and_returns",
                code="callback_registration_source_invalid",
                message="a callback registration has no exact known source event key",
                next_action="bind the registration to one source unit and integer event index",
                location={
                    "unit_id": unit_id,
                    "instruction_rva": row.get("instruction_rva"),
                },
                details={"registration_index": registration_index},
            ))
        if row.get("unit_id") in reachable_ids and row.get("status") != "complete":
            blockers.append(_Blocker(
                family="callbacks_and_returns",
                code="callback_registration_incomplete",
                message="reachable callback registration lacks a checked target, ABI, or lifetime",
                next_action="recover the callback source, finite targets, calling convention, and lifetime",
                location={"unit_id": row.get("unit_id"), "instruction_rva": row.get("instruction_rva")},
            ))

    required_callback_registration_sites = _required_callback_registration_sites(
        canonical_external_events,
        resolution_by_source,
        import_contracts=import_contracts,
        interface_methods=interface_methods,
    )
    for unit_id, event_index in sorted(
        required_callback_registration_sites - callback_registration_by_site.keys()
    ):
        event_row = canonical_external_events[(unit_id, event_index)]
        blockers.append(_Blocker(
            family="callbacks_and_returns",
            code="callback_registration_missing",
            message="a reachable callback-bearing source event has no canonical registration record",
            next_action="emit exactly one complete callback registration for this source event",
            location={
                "unit_id": unit_id,
                "rva_start": event_row.get("unit_rva"),
                "event_index": event_index,
            },
        ))
    for unit_id, event_index in sorted(
        callback_registration_by_site.keys() - required_callback_registration_sites
    ):
        blockers.append(_Blocker(
            family="callbacks_and_returns",
            code="callback_registration_spurious",
            message="a reachable callback registration has no callback-bearing source contract",
            next_action="remove invented registration metadata or bind the exact source event to a reviewed callback contract",
            location={"unit_id": unit_id, "event_index": event_index},
        ))

    internal_calls = _object(
        control.get("internal_call_preservation"),
        "internal-call preservation inventory",
    )
    if (
        internal_calls.get("status") != "complete"
        or internal_calls.get("fixed_point_complete") is not True
    ):
        blockers.append(_Blocker(
            family="callbacks_and_returns",
            code="call_summary_fixed_point_incomplete",
            message="call/behavioral-root summaries did not reach a complete fixed point",
            next_action="close all call targets and recompute summaries to a stable fixed point",
            details={
                "status": internal_calls.get("status"),
                "fixed_point_complete": internal_calls.get("fixed_point_complete"),
            },
        ))
    internal_summaries = _list(
        internal_calls.get("summaries"), "internal-call summaries"
    )
    summary_by_target: dict[str, Mapping[str, Any]] = {}
    covered_return_units: set[str] = set()
    for raw in internal_summaries:
        summary = _object(raw, "internal-call summary")
        target_unit_id = summary.get("target_unit_id")
        if not isinstance(target_unit_id, str) or target_unit_id not in rows_by_id:
            raise StaticHybridCompletenessError(
                "internal-call summary references an unknown target unit"
            )
        if target_unit_id in summary_by_target:
            raise StaticHybridCompletenessError(
                "internal-call summary target inventory contains duplicates"
            )
        summary_by_target[target_unit_id] = summary
        if target_unit_id not in reachable_ids:
            continue
        return_behavior = summary.get("return_behavior")
        return_behavior = (
            return_behavior if isinstance(return_behavior, Mapping) else {}
        )
        may_return = return_behavior.get("may_return")
        may_not_return = return_behavior.get("may_not_return")
        return_unit_ids = summary.get("return_unit_ids")
        return_units_valid = (
            isinstance(return_unit_ids, list)
            and len(set(return_unit_ids)) == len(return_unit_ids)
            and all(
                isinstance(item, str) and item in reachable_ids
                for item in return_unit_ids
            )
        )
        stack_cleanup = summary.get("stack_cleanup")
        stack_cleanup_complete = _stack_cleanup_claim_complete(stack_cleanup)
        graph_problems = _internal_summary_graph_problems(
            summary,
            target_unit_id=target_unit_id,
            rows_by_id=rows_by_id,
            units_by_rva=units_by_rva,
            binary_sha256=expected_identity["sha256"],
        )
        complete = (
            summary.get("status") == "complete"
            and return_behavior.get("status") == "complete"
            and isinstance(may_return, bool)
            and isinstance(may_not_return, bool)
            and (may_return or may_not_return)
            and return_units_valid
            and bool(return_unit_ids) == may_return
            and (not may_return or stack_cleanup_complete)
            and not graph_problems
        )
        if complete:
            covered_return_units.update(str(item) for item in return_unit_ids)
            continue
        blockers.append(_Blocker(
            family="callbacks_and_returns",
            code="internal_call_return_summary_incomplete",
            message="a reachable call or behavioral root has an incomplete return/frame summary",
            next_action=(
                "close every path and recover return units, return behavior, stack "
                "deltas, preserved registers, and caller continuations"
            ),
            location={
                "unit_id": target_unit_id,
                "rva_start": summary.get("target_rva"),
            },
            details={
                "blocker_codes": summary.get("blocker_codes"),
                "return_nodes": summary.get("return_nodes"),
                "return_unit_ids": return_unit_ids,
                "return_behavior": dict(return_behavior),
                "reached_units": summary.get("reached_units"),
                "stack_cleanup": stack_cleanup,
                "graph_problems": graph_problems,
            },
        ))

    executable_instruction_count = 0
    executable_semantics_complete_units = 0
    for unit_id in sorted(reachable_ids | potential_ids):
        row = rows_by_id[unit_id]
        problems, instruction_count = _executable_semantics_problems(row)
        executable_instruction_count += instruction_count
        row_qualified = row.get("status") == "qualified"
        if not problems and row_qualified:
            executable_semantics_complete_units += 1
            continue
        is_reachable = unit_id in reachable_ids
        status_spoofed = row_qualified and bool(problems)
        blockers.append(_Blocker(
            family="executable_semantics",
            code=(
                "qualified_instruction_schedule_inconsistent"
                if status_spoofed
                else "reachable_instruction_schedule_incomplete"
                if is_reachable
                else "potential_instruction_schedule_incomplete"
            ),
            message=(
                "a qualified transfer contradicts its exact instruction-effect schedule"
                if status_spoofed
                else "a rooted reachable transfer lacks a complete exact instruction-effect schedule"
                if is_reachable
                else "a potentially reachable transfer lacks a complete exact instruction-effect schedule"
            ),
            next_action=(
                "regenerate the machine IR from exact decoded instructions and checked semantic effects"
            ),
            location=_row_location(row),
            details={
                "reachability": "reachable" if is_reachable else "potential",
                "reported_status": row.get("status"),
                "derived_instruction_count": instruction_count,
                "problems": problems,
            },
        ))
        if status_spoofed:
            violated_inventory_claims += 1

    reachable_return_count = 0
    reachable_return_units: set[str] = set()
    for unit_id in sorted(reachable_ids):
        row = rows_by_id[unit_id]
        control_row = row.get("control")
        if isinstance(control_row, Mapping) and control_row.get("kind") == "return":
            reachable_return_count += 1
            reachable_return_units.add(unit_id)
            if row.get("status") != "qualified":
                blockers.append(_Blocker(
                    family="callbacks_and_returns",
                    code="return_semantics_incomplete",
                    message="a reachable return lacks checked stack/control semantics",
                    next_action="qualify the return instruction and relational call-frame transition",
                    location=_row_location(row),
                ))
    for unit_id in sorted(reachable_return_units - covered_return_units):
        blockers.append(_Blocker(
            family="callbacks_and_returns",
            code="reachable_return_not_summarized",
            message="a rooted reachable return is absent from every complete call/launch summary",
            next_action="include the return in a complete relational call-frame or behavioral-root summary",
            location=_row_location(rows_by_id[unit_id]),
        ))

    canonical_faults = _canonical_fault_sites(rows_by_id, reachable_ids)
    exceptional_blockers, exceptional_violations = _reconcile_exceptional_control(
        canonical_faults,
        control.get("exceptional_control"),
        rows_by_id=rows_by_id,
        units_by_rva=units_by_rva,
        reachable_ids=reachable_ids,
    )
    blockers.extend(exceptional_blockers)
    violated_inventory_claims += exceptional_violations

    for unit_id in sorted(potential_ids):
        row = rows_by_id[unit_id]
        if row.get("status") != "qualified":
            blockers.append(_Blocker(
                family="deferred_transfers",
                code="potential_transfer_semantics_incomplete",
                message="a potentially reachable transfer would have to be deferred",
                next_action="resolve reachability and either qualify the transfer or prove it unreachable",
                location=_row_location(row),
            ))
        else:
            blockers.append(_Blocker(
                family="deferred_transfers",
                code="potential_transfer_reachability_unresolved",
                message="a qualified transfer is still only potentially reachable",
                next_action="resolve the transfer as rooted reachable or prove it unreachable before candidate generation",
                location=_row_location(row),
            ))

    external_events = [
        canonical_external_events[key] for key in sorted(canonical_external_events)
    ]
    reachable_call_count = 0
    reachable_internal_call_count = 0
    profiled_import_calls = 0
    recovered_interface_calls = 0
    effect_complete_calls = 0
    checked_external_sites: list[dict[str, Any]] = []
    (
        indirect_effect_blockers,
        indirect_profiled_imports,
        indirect_interface_calls,
        indirect_effect_complete,
    ) = _validate_indirect_external_protocols(
        canonical_indirect,
        resolution_by_source,
        import_contracts=import_contracts,
        interface_methods=interface_methods,
        callback_registrations=callback_registration_by_site,
        rows_by_id=rows_by_id,
        reachable_ids=reachable_ids,
        checked_sites=checked_external_sites,
    )
    blockers.extend(indirect_effect_blockers)
    profiled_import_calls += indirect_profiled_imports
    recovered_interface_calls += indirect_interface_calls
    effect_complete_calls += indirect_effect_complete
    for raw in external_events:
        event_row = _object(raw, "external event")
        unit_id = event_row.get("unit_id")
        if unit_id not in reachable_ids:
            continue
        event = _object(event_row.get("event"), "external event payload")
        kind = event.get("kind")
        if kind == "internal_call":
            reachable_internal_call_count += 1
            target_rva = event.get("target_rva")
            target_summaries = [
                summary
                for summary in summary_by_target.values()
                if summary.get("target_rva") == target_rva
            ]
            if len(target_summaries) != 1 or target_summaries[0].get("status") != "complete":
                blockers.append(_Blocker(
                    family="callbacks_and_returns",
                    code="internal_call_summary_missing",
                    message="a reachable internal call has no unique complete callee summary",
                    next_action="bind the exact call target to one complete call-frame summary",
                    location={"unit_id": unit_id, "rva_start": event_row.get("unit_rva")},
                    details={"target_rva": target_rva},
                ))
                continue
            if _summary_may_return(target_summaries[0]) and not _continuation_closed(
                event.get("return_rva"), rows_by_id=rows_by_id, reachable_ids=reachable_ids
            ):
                blockers.append(_Blocker(
                    family="callbacks_and_returns",
                    code="internal_call_continuation_missing",
                    message="a returning internal call has no rooted reachable continuation",
                    next_action="decode and root the exact return continuation",
                    location={"unit_id": unit_id, "rva_start": event_row.get("unit_rva")},
                    details={"return_rva": event.get("return_rva")},
                ))
        elif kind == "external_call":
            reachable_call_count += 1
            identity = MachineImportIdentity.from_mapping(
                event, context=f"{unit_id} external call"
            )
            contract = import_contracts.get(identity)
            if contract is None:
                blockers.append(_Blocker(
                    family="machine_abi",
                    code="machine_import_contract_missing",
                    message=f"reachable import {identity.dll}!{identity.value} has no selected machine contract",
                    next_action="add a pinned machine-level ABI, memory-footprint, and world-effect contract for this import",
                    location={"unit_id": unit_id, "rva_start": event_row.get("unit_rva")},
                    details={"dll": identity.dll, identity.kind: identity.value},
                ))
                continue
            profiled_import_calls += 1
            missing = _external_contract_missing_fields(contract)
            if missing:
                blockers.append(_Blocker(
                    family="external_effects",
                    code="machine_import_effects_incomplete",
                    message=f"reachable import {identity.dll}!{identity.value} has an incomplete external-effect contract",
                    next_action="declare explicit memory footprints, world/resource effects, and result relations",
                    location={"unit_id": unit_id, "rva_start": event_row.get("unit_rva")},
                    details={"missing_fields": missing, "profile_id": contract.profile_id},
                ))
                continue
            try:
                source_row = rows_by_id[str(unit_id)]
                outcome = _semantics(source_row, str(unit_id)).get("outcome")
                tail_jump = (
                    isinstance(outcome, Mapping)
                    and outcome.get("kind") == "external_jump"
                )
                site_contract = checked_external_site_contract_from_event(
                    event=event,
                    identity=ExternalSiteIdentity.imported(
                        event, context=f"{unit_id} external call"
                    ),
                    transfer_kind="jump" if tail_jump else "call",
                    disposition="tail_jump" if tail_jump else "returns_here",
                    callback_evidence=callback_registration_by_site.get(
                        (str(unit_id), int(event_row.get("event_index")))
                    ),
                    context=f"{unit_id} external call",
                )
                require_profile_match(
                    site_contract,
                    profile_contract=contract.contract,
                    profile_id=contract.profile_id,
                    profile_sha256=contract.profile_sha256,
                    entry_key=contract.entry_key,
                    entry_index=contract.entry_index,
                    context=f"{unit_id} external call",
                )
            except (CheckedExternalSiteContractError, TypeError, ValueError) as exc:
                blockers.append(_Blocker(
                    family="external_effects",
                    code="external_site_contract_incomplete",
                    message="a reachable import site does not match one exact executable machine contract",
                    next_action="emit exact fixed arguments, stack projection, disposition, effects, callback metadata, and selected-profile binding",
                    location={
                        "unit_id": unit_id,
                        "rva_start": event_row.get("unit_rva"),
                        "event_index": event_row.get("event_index"),
                    },
                    details={"reason": str(exc), "profile_id": contract.profile_id},
                ))
            else:
                effect_complete_calls += 1
                checked_external_sites.append({
                    "unit_id": str(unit_id),
                    "event_index": int(event_row.get("event_index")),
                    "contract": site_contract.payload(),
                })
        elif kind == "indirect_call":
            reachable_call_count += 1
            event_index = event_row.get("event_index")
            resolution = resolution_by_source.get((str(unit_id), event_index))
            if resolution is None or resolution.get("status") != "recovered":
                continue
            for target_unit_id in _list(
                resolution.get("target_unit_ids"), "indirect internal targets"
            ):
                summary = summary_by_target.get(str(target_unit_id))
                if summary is None or summary.get("status") != "complete":
                    blockers.append(_Blocker(
                        family="callbacks_and_returns",
                        code="indirect_internal_call_summary_missing",
                        message="a recovered indirect internal call target has no complete callee summary",
                        next_action="derive a complete call-frame summary for every finite internal target",
                        location={"unit_id": unit_id, "rva_start": event_row.get("unit_rva")},
                        details={"target_unit_id": target_unit_id},
                    ))
                elif _summary_may_return(summary) and not _continuation_closed(
                    event.get("return_rva"), rows_by_id=rows_by_id, reachable_ids=reachable_ids
                ):
                    blockers.append(_Blocker(
                        family="callbacks_and_returns",
                        code="indirect_internal_call_continuation_missing",
                        message="a returning indirect internal call has no rooted reachable continuation",
                        next_action="decode and root the exact return continuation",
                        location={"unit_id": unit_id, "rva_start": event_row.get("unit_rva")},
                    ))
    coverage = _object(manifest.get("coverage"), "executable coverage")
    coverage_counts = _object(coverage.get("counts"), "executable coverage counts")
    if coverage_counts.get("unknown_bytes") != 0:
        blockers.append(_Blocker(
            family="implementation_coverage",
            code="executable_byte_coverage_incomplete",
            message="executable image bytes remain unclassified",
            next_action="classify every executable byte as semantic code or checked non-code data/padding",
            details={"unknown_bytes": coverage_counts.get("unknown_bytes")},
        ))
    classified_ids = reachable_ids | potential_ids | confirmed_unreachable_ids
    if classified_ids != rows_by_id.keys():
        blockers.append(_Blocker(
            family="implementation_coverage",
            code="transfer_inventory_not_partitioned",
            message="machine-IR transfers are not completely partitioned by checked reachability",
            next_action="repair rooted closure so every transfer is reachable, potential, or proved unreachable",
            details={"unclassified_units": len(rows_by_id.keys() - classified_ids)},
        ))

    blocker_payloads = sorted(
        (item.payload() for item in blockers),
        key=lambda item: (item["family"], item["code"], item["id"]),
    )
    diagnostics_v2 = _build_dependency_diagnostics_v2(blocker_payloads)
    family_counts = Counter(item["family"] for item in blocker_payloads)
    families = {
        family: {
            "status": "satisfied" if family_counts[family] == 0 else "incomplete",
            "blockers": family_counts[family],
        }
        for family in _FAMILIES
    }
    report: dict[str, Any] = {
        "format": STATIC_HYBRID_COMPLETENESS_FORMAT,
        "status": (
            "violated"
            if violated_source_issues or violated_inventory_claims
            else "complete"
            if not blocker_payloads
            else "incomplete"
        ),
        "authority": "legacy diagnostic and proposal inventory only; no candidate-generation or behavioral authority",
        "inputs": {
            "machine_ir": {
                "path": machine_ir_path.name,
                "sha256": actual_ir_sha256,
            },
            "machine_ir_manifest": {
                "path": manifest_path.name,
                "sha256": sha256_file(manifest_path),
            },
            "load_image_contract": {
                "path": load_image_path.name,
                "sha256": sha256_file(load_image_path),
                "contract_sha256": load_image.hashes.contract_sha256,
                "original_pe_sha256": load_image.identity.pe_sha256,
            },
            "behavioral_roots": {
                "path": behavioral_roots_path.name,
                "sha256": sha256_file(behavioral_roots_path),
                "contract_sha256": root_contract["contract_sha256"],
                "original_pe_sha256": root_contract["pe"]["sha256"],
            },
            "machine_import_profiles": [
                {"id": profile.profile_id, "sha256": profile.sha256}
                for profile in profile_set.profiles
            ],
            "external_interface_profiles": [
                {"path": Path(path).name, "sha256": sha256_file(path)}
                for path in external_interface_profiles
            ],
        },
        "policy": {
            "rooted_reachability_must_be_closed": True,
            "potential_transfers_may_be_deferred": False,
            "reachable_semantics_must_be_executable": True,
            "indirect_targets_must_be_finite_and_complete": True,
            "callbacks_are_behavioral_roots": True,
            "returns_use_checked_machine_call_frames": True,
            "reported_faults_require_checked_exceptional_control": True,
            "external_calls_require_machine_abi_and_effect_contracts": True,
            "fallback_covers_every_reachable_nonportable_region": True,
            "original_binary_executed": False,
        },
        "counts": {
            "units": len(rows),
            "reachable_units": len(reachable_ids),
            "potential_units": len(potential_ids),
            "confirmed_unreachable_units": len(confirmed_unreachable_ids),
            "reachable_returns": reachable_return_count,
            "reachable_external_calls": reachable_call_count,
            "reachable_internal_calls": reachable_internal_call_count,
            "profiled_import_calls": profiled_import_calls,
            "recovered_interface_calls": recovered_interface_calls,
            "effect_complete_calls": effect_complete_calls,
            "callback_roots": len(callback_root_ids),
            "mandatory_roots": len(mandatory_root_rvas),
            "reachable_direct_exits": len(canonical_direct),
            "reachable_indirect_exits": len(canonical_indirect),
            "reachable_faults": len(canonical_faults),
            "executable_semantics_complete_units": (
                executable_semantics_complete_units
            ),
            "executable_instruction_count": executable_instruction_count,
            "violated_source_issues": violated_source_issues,
            "violated_inventory_claims": violated_inventory_claims,
            "blockers": len(blocker_payloads),
        },
        "families": families,
        "diagnostics_v2": diagnostics_v2,
        "checked_external_sites": sorted(
            checked_external_sites,
            key=lambda item: (item["unit_id"], item["event_index"]),
        ),
        "blockers": blocker_payloads,
    }
    digest_body = dict(report)
    report["contract_sha256"] = sha256_bytes(
        json.dumps(digest_body, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )
    write_json(output, report)
    return report


_CALL_SUMMARY_DOWNSTREAM_CODES = frozenset({
    "internal_call_summary_missing",
    "indirect_internal_call_summary_missing",
    "reachable_return_not_summarized",
    "internal_call_continuation_missing",
    "indirect_internal_call_continuation_missing",
})
_AGGREGATE_BLOCKER_CODES = frozenset({
    "call_summary_fixed_point_incomplete",
    "rooted_reachability_incomplete",
    "control_fixed_point_not_cold_validated",
})
_DEPENDENCY_SUMMARY_CODES = frozenset({
    "indirect_call_target_unresolved",
    "nested_call_return_behavior_incomplete",
})


def _build_dependency_diagnostics_v2(
    blockers: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """Turn flat v1 diagnostics into a deterministic repair dependency DAG."""

    rows = [dict(row) for row in blockers]
    records: list[dict[str, Any]] = []
    by_legacy_id: dict[str, dict[str, Any]] = {}

    def add(row: Mapping[str, Any], dependencies: Sequence[str] = ()) -> dict[str, Any]:
        record = make_blocker_record(
            status=_diagnostic_blocker_status(row),
            category=_diagnostic_category(str(row.get("code") or "unknown")),
            message=str(row.get("message") or "static evidence is missing"),
            next_action=str(row.get("next_action") or "complete the missing evidence"),
            blocked_by=tuple(sorted(set(dependencies))),
            frontiers=_diagnostic_frontiers(row),
            details={
                "legacy_id": row.get("id"),
                "family": row.get("family"),
                "location": copy.deepcopy(row.get("location")),
                "evidence": copy.deepcopy(row.get("details")),
            },
        )
        records.append(record)
        legacy_id = row.get("id")
        if isinstance(legacy_id, str):
            by_legacy_id[legacy_id] = record
        return record

    deferred: list[dict[str, Any]] = []
    upstream_summaries: list[dict[str, Any]] = []
    aggregate: dict[str, dict[str, Any]] = {}
    for row in rows:
        code = str(row.get("code") or "")
        if code in _AGGREGATE_BLOCKER_CODES:
            aggregate[code] = row
        elif code in _CALL_SUMMARY_DOWNSTREAM_CODES or code.startswith(
            "potential_transfer_"
        ):
            deferred.append(row)
        elif code == "internal_call_return_summary_incomplete" and any(
            blocker in _DEPENDENCY_SUMMARY_CODES
            for blocker in (
                row.get("details", {}).get("blocker_codes", [])
                if isinstance(row.get("details"), Mapping)
                else []
            )
        ):
            upstream_summaries.append(row)
        else:
            add(row)

    indirect_ids = sorted(
        record["id"]
        for row in rows
        if row.get("family") == "indirect_control"
        and isinstance(row.get("id"), str)
        and (record := by_legacy_id.get(str(row["id"]))) is not None
    )
    for row in upstream_summaries:
        add(row, indirect_ids)

    summary_ids = sorted(
        record["id"]
        for row in rows
        if row.get("code") == "internal_call_return_summary_incomplete"
        and isinstance(row.get("id"), str)
        and (record := by_legacy_id.get(str(row["id"]))) is not None
    )
    call_aggregate: dict[str, Any] | None = None
    if "call_summary_fixed_point_incomplete" in aggregate:
        call_aggregate = add(
            aggregate["call_summary_fixed_point_incomplete"],
            summary_ids or indirect_ids,
        )
    root_aggregate: dict[str, Any] | None = None
    if "rooted_reachability_incomplete" in aggregate:
        root_aggregate = add(
            aggregate["rooted_reachability_incomplete"],
            indirect_ids,
        )
    if "control_fixed_point_not_cold_validated" in aggregate:
        dependencies = [*indirect_ids]
        if call_aggregate is not None:
            dependencies.append(call_aggregate["id"])
        if root_aggregate is not None:
            dependencies.append(root_aggregate["id"])
        add(aggregate["control_fixed_point_not_cold_validated"], dependencies)

    for row in deferred:
        if str(row.get("code")).startswith("potential_transfer_"):
            dependencies = (
                [root_aggregate["id"]]
                if root_aggregate is not None
                else indirect_ids
            )
        else:
            dependencies = (
                [call_aggregate["id"]]
                if call_aggregate is not None
                else summary_ids or indirect_ids
            )
        add(row, dependencies)
    return build_hybrid_diagnostics_v2(records)


def _diagnostic_category(code: str) -> str:
    if (
        code
        and len(code) <= 64
        and code[0].isalpha()
        and all(character.islower() or character.isdigit() or character == "_" for character in code)
    ):
        return code
    return "blocker_" + sha256_bytes(code.encode("utf-8"))[:16]


def _diagnostic_blocker_status(row: Mapping[str, Any]) -> str:
    code = str(row.get("code") or "")
    violated_markers = (
        "contradict",
        "corrupt",
        "mismatch",
        "spurious",
        "conflict",
        "invented",
    )
    return "violated" if any(marker in code for marker in violated_markers) else "incomplete"


def _diagnostic_frontiers(row: Mapping[str, Any]) -> dict[str, list[dict[str, Any]]]:
    location = row.get("location")
    location = location if isinstance(location, Mapping) else {}
    unit_id = location.get("unit_id")
    event_index = location.get("event_index")
    result: dict[str, list[dict[str, Any]]] = {
        "scc": [],
        "environment": [],
        "isa": [],
    }
    family = row.get("family")
    if family == "callbacks_and_returns" and isinstance(unit_id, str):
        result["scc"].append({"id": f"scc:{unit_id}"})
    if family in {"machine_abi", "external_effects"} and isinstance(unit_id, str):
        result["environment"].append({
            "id": f"environment:{unit_id}:{event_index if event_index is not None else 'unit'}"
        })
    if family == "isa" and isinstance(unit_id, str):
        result["isa"].append({"id": f"isa:{unit_id}"})
    return result


def _units_by_rva(
    rows_by_id: Mapping[str, Mapping[str, Any]],
) -> dict[int, list[str]]:
    result: dict[int, list[str]] = {}
    for unit_id, row in rows_by_id.items():
        rva = _unit_rva(row)
        if rva is not None:
            result.setdefault(rva, []).append(unit_id)
    return {rva: sorted(unit_ids) for rva, unit_ids in result.items()}


def _normalize_callback_proposals(
    proposals: Sequence[Any],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    units_by_rva: Mapping[int, list[str]],
) -> set[str]:
    result: set[str] = set()
    for index, raw in enumerate(proposals):
        proposal = _object(raw, f"callback proposal {index}")
        submitted_unit = proposal.get("target_unit_id")
        submitted_rva = proposal.get("rva")
        if submitted_unit is not None and (
            not isinstance(submitted_unit, str) or not submitted_unit
        ):
            raise StaticHybridCompletenessError(
                f"callback proposal {index} has an invalid target unit id"
            )
        if submitted_rva is not None and (
            not isinstance(submitted_rva, int) or isinstance(submitted_rva, bool)
        ):
            raise StaticHybridCompletenessError(
                f"callback proposal {index} has an invalid target RVA"
            )
        if submitted_unit is None and submitted_rva is None:
            raise StaticHybridCompletenessError(
                f"callback proposal {index} has no target"
            )
        unit_from_id: str | None = None
        if isinstance(submitted_unit, str):
            if submitted_unit not in rows_by_id:
                raise StaticHybridCompletenessError(
                    f"callback proposal {index} references an unknown unit"
                )
            unit_from_id = submitted_unit
        unit_from_rva: str | None = None
        if isinstance(submitted_rva, int):
            matches = units_by_rva.get(submitted_rva, [])
            if len(matches) != 1:
                qualifier = "no" if not matches else "multiple"
                raise StaticHybridCompletenessError(
                    f"callback proposal {index} RVA identifies {qualifier} machine-IR units"
                )
            unit_from_rva = matches[0]
        if (
            unit_from_id is not None
            and unit_from_rva is not None
            and unit_from_id != unit_from_rva
        ):
            raise StaticHybridCompletenessError(
                f"callback proposal {index} has conflicting unit and RVA targets"
            )
        unit_id = unit_from_id or unit_from_rva
        assert unit_id is not None
        result.add(unit_id)
    return result


def _semantics(row: Mapping[str, Any], unit_id: str) -> Mapping[str, Any]:
    return _object(row.get("semantics"), f"{unit_id} semantics")


def _executable_semantics_problems(
    row: Mapping[str, Any],
) -> tuple[list[str], int]:
    """Reconcile one executable unit without trusting its reported status.

    Machine-IR export deliberately strips raw executable bytes.  The retained
    authority is therefore the exact transfer digest plus the independently
    exported instruction and schedule ledgers.  This check binds every retained
    field across those ledgers and validates effect inventories structurally;
    it does not pretend to re-decode bytes that are intentionally absent.
    """

    problems: list[str] = []

    def problem(message: str) -> None:
        if message not in problems:
            problems.append(message)

    source = row.get("source")
    source = source if isinstance(source, Mapping) else {}
    original = source.get("original")
    original = original if isinstance(original, Mapping) else {}
    rva_start = _plain_integer(original.get("rva_start"))
    rva_end = _plain_integer(original.get("rva_end"))
    if rva_start is None or rva_end is None or rva_end <= rva_start:
        problem("source.original is not a nonempty exact RVA span")
    source_size = _plain_integer(original.get("size"))
    if source_size is not None and (
        rva_start is None or rva_end is None or source_size != rva_end - rva_start
    ):
        problem("source.original.size differs from its RVA span")
    transfer_digest = source.get("instruction_bytes_sha256")
    if not _is_sha256(transfer_digest):
        problem("source instruction_bytes_sha256 is missing or malformed")

    instructions_raw = row.get("instructions")
    instructions = instructions_raw if isinstance(instructions_raw, list) else []
    if not isinstance(instructions_raw, list) or not instructions:
        problem("instruction inventory is missing or empty")
    expected_rva = rva_start
    checked_instructions: list[tuple[int, int, str]] = []
    for index, raw in enumerate(instructions):
        if not isinstance(raw, Mapping):
            problem(f"instruction {index} is not an object")
            continue
        start = _plain_integer(raw.get("rva_start"))
        end = _plain_integer(raw.get("rva_end"))
        size = _plain_integer(raw.get("size"))
        digest = raw.get("instruction_sha256")
        if (
            start is None
            or end is None
            or size is None
            or size <= 0
            or end != start + size
        ):
            problem(f"instruction {index} has an invalid exact span")
            continue
        if expected_rva is None or start != expected_rva:
            problem(f"instruction {index} is not contiguous with its predecessor")
        if not _is_sha256(digest):
            problem(f"instruction {index} has no valid byte digest")
            digest = ""
        checked_instructions.append((start, end, str(digest)))
        expected_rva = end
    if rva_end is not None and expected_rva != rva_end:
        problem("instruction inventory does not cover the complete unit span")

    semantics_raw = row.get("semantics")
    semantics = semantics_raw if isinstance(semantics_raw, Mapping) else {}
    if not isinstance(semantics_raw, Mapping):
        problem("semantic aggregate is missing")
    aggregate_fields = (
        "edge_conditions",
        "external_events",
        "faults",
        "flag_writes",
        "memory_events",
        "ordered_events",
        "register_writes",
    )
    aggregate_lists = _check_counted_lists(
        semantics,
        aggregate_fields,
        "semantic aggregate",
        problem,
    )

    schedule_raw = semantics.get("instruction_effect_schedule")
    schedule = schedule_raw if isinstance(schedule_raw, Mapping) else {}
    if not isinstance(schedule_raw, Mapping):
        problem("instruction-effect schedule is missing")
    if schedule.get("format") != _INSTRUCTION_EFFECT_SCHEDULE_FORMAT:
        problem("instruction-effect schedule format is unsupported")
    if schedule.get("status") != "complete":
        problem("instruction-effect schedule status is not complete")
    if schedule.get("proof_authority") is not False:
        problem("instruction-effect schedule proof-authority marker is invalid")
    if schedule.get("ordering") != "strict_contiguous_rva_order":
        problem("instruction-effect schedule ordering is not strict contiguous RVA order")
    if schedule.get("rva_start") != rva_start or schedule.get("rva_end") != rva_end:
        problem("instruction-effect schedule span differs from its unit")
    if schedule.get("transfer_bytes_sha256") != transfer_digest:
        problem("instruction-effect schedule transfer digest differs from its unit")
    if not _is_sha256(schedule.get("source_schedule_sha256")):
        problem("instruction-effect schedule source digest is missing or malformed")
    schedule_digest = schedule.get("schedule_sha256")
    if not _is_sha256(schedule_digest):
        problem("instruction-effect schedule emitted digest is missing or malformed")
    else:
        schedule_body = dict(schedule)
        del schedule_body["schedule_sha256"]
        if _json_sha256(schedule_body) != schedule_digest:
            problem("instruction-effect schedule emitted digest does not match its contents")
    blockers = schedule.get("blockers")
    if blockers != []:
        problem("instruction-effect schedule contains blockers or a malformed blocker inventory")

    records_raw = schedule.get("records")
    records = records_raw if isinstance(records_raw, list) else []
    if not isinstance(records_raw, list):
        problem("instruction-effect schedule record inventory is malformed")
    if len(records) != len(instructions):
        problem("instruction-effect schedule does not contain one record per instruction")
    schedule_counts = schedule.get("counts")
    schedule_counts = schedule_counts if isinstance(schedule_counts, Mapping) else {}
    if not isinstance(schedule.get("counts"), Mapping):
        problem("instruction-effect schedule counts are missing")
    if schedule_counts.get("instructions") != len(records):
        problem("instruction-effect schedule instruction count is inconsistent")
    expected_blocker_count = len(blockers) if isinstance(blockers, list) else None
    if schedule_counts.get("blockers") != expected_blocker_count:
        problem("instruction-effect schedule blocker count is inconsistent")

    effect_fields = (
        "call_effects",
        "defined_flag_writes",
        "faults",
        "memory_events",
        "ordered_events",
        "register_writes",
        "undefined_flag_writes",
        "undefined_flags",
    )
    scheduled_ordered_events: list[Any] = []
    scheduled_faults: list[Any] = []
    ordinary_count = 0
    x87_count = 0
    for index, raw in enumerate(records):
        if not isinstance(raw, Mapping):
            problem(f"schedule record {index} is not an object")
            continue
        instruction = (
            checked_instructions[index] if index < len(checked_instructions) else None
        )
        if raw.get("index") != index:
            problem(f"schedule record {index} has an inconsistent index")
        if instruction is not None and (
            raw.get("rva_start") != instruction[0]
            or raw.get("rva_end") != instruction[1]
            or raw.get("bytes_sha256") != instruction[2]
        ):
            problem(f"schedule record {index} differs from its exact instruction")
        if raw.get("transfer_bytes_sha256") != transfer_digest:
            problem(f"schedule record {index} has an inconsistent transfer digest")
        for field in (
            "source_record_sha256",
            "record_sha256",
            "symbolic_pre_state_sha256",
            "symbolic_post_state_sha256",
        ):
            if not _is_sha256(raw.get(field)):
                problem(f"schedule record {index} has no valid {field}")
        record_digest = raw.get("record_sha256")
        if _is_sha256(record_digest):
            record_body = dict(raw)
            del record_body["record_sha256"]
            if _json_sha256(record_body) != record_digest:
                problem(f"schedule record {index} digest does not match its contents")
        instruction_class = raw.get("instruction_class")
        if instruction_class == "ordinary_symbolic_instruction":
            ordinary_count += 1
        elif instruction_class == "x87_singleton_checked_replay":
            x87_count += 1
        else:
            problem(f"schedule record {index} has an unsupported instruction class")
        classification = raw.get("classification")
        classification = classification if isinstance(classification, Mapping) else {}
        if (
            classification.get("status")
            != "proposal_requires_lean_exact_byte_replay"
            or classification.get("proof_authority") is not False
            or classification.get("checked_decoder")
            != _CHECKED_INSTRUCTION_DECODER
            or classification.get("checked_executor")
            != _CHECKED_INSTRUCTION_EXECUTOR
        ):
            problem(f"schedule record {index} lacks a checked semantic classification")
        effects_raw = raw.get("effects")
        effects = effects_raw if isinstance(effects_raw, Mapping) else {}
        if not isinstance(effects_raw, Mapping):
            problem(f"schedule record {index} has no effect summary")
        effect_lists = _check_counted_lists(
            effects,
            effect_fields,
            f"schedule record {index} effects",
            problem,
        )
        if not isinstance(effects.get("control"), Mapping):
            problem(f"schedule record {index} has no control effect")
        scheduled_ordered_events.extend(effect_lists.get("ordered_events", []))
        scheduled_faults.extend(effect_lists.get("faults", []))

    if schedule_counts.get("ordinary_instructions") != ordinary_count:
        problem("instruction-effect schedule ordinary-instruction count is inconsistent")
    if schedule_counts.get("x87_singletons") != x87_count:
        problem("instruction-effect schedule x87-instruction count is inconsistent")
    aggregate_ordered = aggregate_lists.get("ordered_events", [])
    if [_event_identity(item) for item in scheduled_ordered_events] != [
        _event_identity(item) for item in aggregate_ordered
    ]:
        problem("instruction effects and aggregate ordered-event inventory differ")
    aggregate_faults = aggregate_lists.get("faults", [])
    if [_fault_identity(item) for item in scheduled_faults] != [
        _fault_identity(item) for item in aggregate_faults
    ]:
        problem("instruction effects and aggregate fault inventory differ")
    if len(aggregate_lists.get("external_events", [])) != sum(
        _event_family(item) == "external" for item in aggregate_ordered
    ):
        problem("semantic external-event and ordered-event inventories differ")
    if len(aggregate_lists.get("memory_events", [])) != sum(
        _event_family(item) == "memory" for item in aggregate_ordered
    ):
        problem("semantic memory-event and ordered-event inventories differ")

    return problems, len(instructions)


def _check_counted_lists(
    owner: Mapping[str, Any],
    fields: Sequence[str],
    context: str,
    problem: Callable[[str], None],
) -> dict[str, list[Any]]:
    counts_raw = owner.get("counts")
    counts = counts_raw if isinstance(counts_raw, Mapping) else {}
    if not isinstance(counts_raw, Mapping):
        problem(f"{context} counts are missing")
    result: dict[str, list[Any]] = {}
    for field in fields:
        raw = owner.get(field)
        values = raw if isinstance(raw, list) else []
        result[field] = values
        if not isinstance(raw, list):
            problem(f"{context}.{field} is missing or malformed")
        if counts.get(field) != len(values):
            problem(f"{context}.{field} count is inconsistent")
    return result


def _event_identity(value: Any) -> tuple[Any, ...]:
    event = value if isinstance(value, Mapping) else {}
    return (
        event.get("instruction_rva"),
        event.get("family"),
        event.get("kind"),
        event.get("width"),
        event.get("target_rva"),
        event.get("return_rva"),
        str(event.get("dll") or "").lower(),
        event.get("symbol"),
        event.get("ordinal"),
    )


def _fault_identity(value: Any) -> tuple[Any, ...]:
    fault = value if isinstance(value, Mapping) else {}
    return (
        fault.get("instruction_rva"),
        fault.get("kind"),
        fault.get("category"),
        fault.get("mnemonic"),
    )


def _event_family(value: Any) -> Any:
    return value.get("family") if isinstance(value, Mapping) else None


def _plain_integer(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _semantic_list(
    row: Mapping[str, Any], unit_id: str, field: str
) -> list[Any]:
    return _list(_semantics(row, unit_id).get(field), f"{unit_id} semantics.{field}")


def _canonical_direct_sites(
    rows_by_id: Mapping[str, Mapping[str, Any]], reachable_ids: set[str]
) -> dict[tuple[str, str, int | None, int], dict[str, Any]]:
    result: dict[tuple[str, str, int | None, int], dict[str, Any]] = {}
    for unit_id in sorted(reachable_ids):
        row = rows_by_id[unit_id]
        source_rva = _unit_rva(row)
        control = _object(row.get("control"), f"{unit_id} control")
        targets = _list(control.get("direct_targets"), f"{unit_id} direct targets")
        conditions: dict[int, Any] = {}
        for index, raw in enumerate(_semantic_list(row, unit_id, "edge_conditions")):
            condition = _object(raw, f"{unit_id} edge condition {index}")
            target_rva = condition.get("target_rva")
            if isinstance(target_rva, int) and not isinstance(target_rva, bool):
                if target_rva in conditions:
                    raise StaticHybridCompletenessError(
                        f"{unit_id} has duplicate direct-edge conditions"
                    )
                conditions[target_rva] = condition.get("condition")
        for target_rva in targets:
            if not isinstance(target_rva, int) or isinstance(target_rva, bool):
                raise StaticHybridCompletenessError(
                    f"{unit_id} direct target is not an RVA"
                )
            key = ("direct_control", unit_id, None, target_rva)
            if key in result:
                raise StaticHybridCompletenessError(
                    f"{unit_id} contains duplicate direct targets"
                )
            result[key] = {
                "kind": "direct_control",
                "source_unit_id": unit_id,
                "source_rva": source_rva,
                "target_rva": target_rva,
                "guard": conditions.get(target_rva),
            }
        for event_index, raw in enumerate(
            _semantic_list(row, unit_id, "external_events")
        ):
            event = _object(raw, f"{unit_id} external event {event_index}")
            if event.get("kind") != "internal_call":
                continue
            target_rva = event.get("target_rva")
            if not isinstance(target_rva, int) or isinstance(target_rva, bool):
                raise StaticHybridCompletenessError(
                    f"{unit_id} internal call {event_index} has no exact target RVA"
                )
            key = ("internal_call", unit_id, event_index, target_rva)
            if key in result:
                raise StaticHybridCompletenessError(
                    f"{unit_id} contains a duplicate internal-call site"
                )
            result[key] = {
                "kind": "internal_call",
                "source_unit_id": unit_id,
                "source_rva": source_rva,
                "source_event_index": event_index,
                "target_rva": target_rva,
            }
    return result


def _direct_site_key(
    row: Mapping[str, Any], context: str
) -> tuple[str, str, int | None, int]:
    kind = row.get("kind")
    unit_id = row.get("source_unit_id")
    event_index = row.get("source_event_index")
    target_rva = row.get("target_rva")
    if kind not in {"direct_control", "internal_call"}:
        raise StaticHybridCompletenessError(f"{context} has an invalid kind")
    if not isinstance(unit_id, str) or not unit_id:
        raise StaticHybridCompletenessError(f"{context} has no source unit")
    if event_index is not None and (
        not isinstance(event_index, int) or isinstance(event_index, bool)
    ):
        raise StaticHybridCompletenessError(f"{context} has an invalid event index")
    if not isinstance(target_rva, int) or isinstance(target_rva, bool):
        raise StaticHybridCompletenessError(f"{context} has no target RVA")
    return str(kind), unit_id, event_index, target_rva


def _reconcile_direct_inventory(
    canonical: Mapping[tuple[str, str, int | None, int], Mapping[str, Any]],
    submitted: Sequence[Any],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    units_by_rva: Mapping[int, list[str]],
    reachable_ids: set[str],
) -> tuple[list[_Blocker], int]:
    indexed: dict[tuple[str, str, int | None, int], Mapping[str, Any]] = {}
    for index, raw in enumerate(submitted):
        row = _object(raw, f"direct-control inventory row {index}")
        key = _direct_site_key(row, f"direct-control inventory row {index}")
        if key[1] not in rows_by_id:
            raise StaticHybridCompletenessError(
                "direct-control inventory references an unknown source unit"
            )
        if key in indexed:
            raise StaticHybridCompletenessError(
                "direct-control inventory contains duplicate sites"
            )
        if key[1] in reachable_ids:
            indexed[key] = row
    blockers: list[_Blocker] = []
    violations = 0
    for key in sorted(canonical.keys() - indexed.keys()):
        expected = canonical[key]
        blockers.append(_Blocker(
            family="direct_control",
            code="direct_inventory_omits_machine_ir_exit",
            message="the submitted direct-edge inventory omits a reachable machine-IR exit",
            next_action="regenerate direct edges from the hash-bound reachable machine IR",
            location={"unit_id": key[1], "rva_start": expected.get("source_rva")},
            details={"kind": key[0], "event_index": key[2], "target_rva": key[3]},
        ))
        violations += 1
    for key in sorted(indexed.keys() - canonical.keys()):
        blockers.append(_Blocker(
            family="direct_control",
            code="direct_inventory_contains_spurious_exit",
            message="the submitted direct-edge inventory invents a reachable exit absent from machine IR",
            next_action="regenerate direct edges from the hash-bound reachable machine IR",
            location={"unit_id": key[1], "rva_start": indexed[key].get("source_rva")},
            details={"kind": key[0], "event_index": key[2], "target_rva": key[3]},
        ))
        violations += 1
    for key in sorted(canonical.keys() & indexed.keys()):
        expected = canonical[key]
        observed = indexed[key]
        matches = units_by_rva.get(key[3], [])
        expected_target = matches[0] if len(matches) == 1 else None
        expected_status = "resolved" if expected_target is not None else "incomplete"
        if (
            observed.get("source_rva") != expected.get("source_rva")
            or observed.get("guard") != expected.get("guard")
            or observed.get("status") != expected_status
            or observed.get("resolved_unit_id") != expected_target
        ):
            blockers.append(_Blocker(
                family="direct_control",
                code="direct_inventory_edge_binding_mismatch",
                message="a submitted direct edge contradicts its machine-IR source or target binding",
                next_action="regenerate the direct edge and unique target-unit binding",
                location={"unit_id": key[1], "rva_start": expected.get("source_rva")},
                details={"target_rva": key[3], "expected_target_unit_id": expected_target},
            ))
            violations += 1
        if expected_target is None:
            blockers.append(_Blocker(
                family="direct_control",
                code=(
                    "direct_target_missing"
                    if not matches
                    else "direct_target_ambiguous"
                ),
                message="a reachable direct exit does not identify one exact target unit",
                next_action="materialize one exact machine-IR unit at the direct target RVA",
                location={"unit_id": key[1], "rva_start": expected.get("source_rva")},
                details={"target_rva": key[3], "matching_unit_ids": matches},
            ))
        elif expected_target not in reachable_ids:
            blockers.append(_Blocker(
                family="direct_control",
                code="direct_target_not_reachable",
                message="a reachable direct edge targets a unit omitted from rooted closure",
                next_action="include the checked direct-edge target in rooted reachability",
                location={"unit_id": key[1], "rva_start": expected.get("source_rva")},
                details={"target_unit_id": expected_target, "target_rva": key[3]},
            ))
    return blockers, violations


def _canonical_indirect_sites(
    rows_by_id: Mapping[str, Mapping[str, Any]], reachable_ids: set[str]
) -> dict[tuple[str, int | None], dict[str, Any]]:
    result: dict[tuple[str, int | None], dict[str, Any]] = {}
    for unit_id in sorted(reachable_ids):
        row = rows_by_id[unit_id]
        source_rva = _unit_rva(row)
        control = _object(row.get("control"), f"{unit_id} control")
        semantics = _semantics(row, unit_id)
        if control.get("has_indirect_target") is True:
            outcome = _object(semantics.get("outcome"), f"{unit_id} outcome")
            key = (unit_id, None)
            result[key] = {
                "source_unit_id": unit_id,
                "source_rva": source_rva,
                "kind": control.get("kind"),
                "target_expression": outcome.get("target"),
            }
        for event_index, raw in enumerate(
            _semantic_list(row, unit_id, "external_events")
        ):
            event = _object(raw, f"{unit_id} external event {event_index}")
            if event.get("kind") not in {"indirect_call", "indirect_jump"}:
                continue
            key = (unit_id, event_index)
            if key in result:
                raise StaticHybridCompletenessError(
                    f"{unit_id} contains duplicate indirect sites"
                )
            result[key] = {
                "source_unit_id": unit_id,
                "source_rva": source_rva,
                "source_event_index": event_index,
                "kind": event.get("kind"),
                "target_expression": event.get("target"),
            }
    return result


def _indirect_site_key(
    row: Mapping[str, Any], context: str
) -> tuple[str, int | None]:
    unit_id = row.get("source_unit_id")
    event_index = row.get("source_event_index")
    if not isinstance(unit_id, str) or not unit_id:
        raise StaticHybridCompletenessError(f"{context} has no source unit")
    if event_index is not None and (
        not isinstance(event_index, int) or isinstance(event_index, bool)
    ):
        raise StaticHybridCompletenessError(f"{context} has an invalid event index")
    return unit_id, event_index


def _indirect_target_inventory_signature(row: Mapping[str, Any]) -> str:
    return _json_sha256({
        "target_rvas": row.get("target_rvas", []),
        "target_unit_ids": row.get("target_unit_ids", []),
        "external_targets": row.get("external_targets", []),
    })


def _reconcile_indirect_inventory(
    canonical: Mapping[tuple[str, int | None], Mapping[str, Any]],
    submitted: Sequence[Any],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> tuple[list[_Blocker], int]:
    indexed: dict[tuple[str, int | None], Mapping[str, Any]] = {}
    for index, raw in enumerate(submitted):
        row = _object(raw, f"indirect-exit inventory row {index}")
        key = _indirect_site_key(row, f"indirect-exit inventory row {index}")
        if key[0] not in rows_by_id:
            raise StaticHybridCompletenessError(
                "indirect-exit inventory references an unknown source unit"
            )
        if key in indexed:
            raise StaticHybridCompletenessError(
                "indirect-exit inventory contains duplicate sites"
            )
        if key[0] in reachable_ids:
            indexed[key] = row
    blockers: list[_Blocker] = []
    violations = 0
    for key in sorted(canonical.keys() - indexed.keys(), key=str):
        expected = canonical[key]
        blockers.append(_Blocker(
            family="indirect_control",
            code="indirect_inventory_omits_machine_ir_exit",
            message="the submitted indirect inventory omits a reachable machine-IR exit",
            next_action="regenerate indirect sites from the hash-bound reachable machine IR",
            location={"unit_id": key[0], "rva_start": expected.get("source_rva"), "event_index": key[1]},
        ))
        violations += 1
    for key in sorted(indexed.keys() - canonical.keys(), key=str):
        blockers.append(_Blocker(
            family="indirect_control",
            code="indirect_inventory_contains_spurious_exit",
            message="the submitted indirect inventory invents a reachable exit absent from machine IR",
            next_action="regenerate indirect sites from the hash-bound reachable machine IR",
            location={"unit_id": key[0], "rva_start": indexed[key].get("source_rva"), "event_index": key[1]},
        ))
        violations += 1
    for key in sorted(canonical.keys() & indexed.keys(), key=str):
        expected = canonical[key]
        observed = indexed[key]
        if any(
            observed.get(field) != expected.get(field)
            for field in ("source_rva", "kind", "target_expression")
        ):
            blockers.append(_Blocker(
                family="indirect_control",
                code="indirect_inventory_site_binding_mismatch",
                message="a submitted indirect exit contradicts the machine-IR site",
                next_action="regenerate the indirect exit from its exact target expression",
                location={"unit_id": key[0], "rva_start": expected.get("source_rva"), "event_index": key[1]},
            ))
            violations += 1
    return blockers, violations


def _canonical_external_events(
    rows_by_id: Mapping[str, Mapping[str, Any]], reachable_ids: set[str]
) -> dict[tuple[str, int], dict[str, Any]]:
    result: dict[tuple[str, int], dict[str, Any]] = {}
    for unit_id in sorted(reachable_ids):
        row = rows_by_id[unit_id]
        unit_rva = _unit_rva(row)
        for event_index, raw in enumerate(
            _semantic_list(row, unit_id, "external_events")
        ):
            event = _object(raw, f"{unit_id} external event {event_index}")
            result[(unit_id, event_index)] = {
                "unit_id": unit_id,
                "unit_rva": unit_rva,
                "event_index": event_index,
                "kind": event.get("kind"),
                "instruction_rva": event.get("instruction_rva"),
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "ordinal": event.get("ordinal"),
                "event": dict(event),
            }
    return result


def _external_site_key(row: Mapping[str, Any], context: str) -> tuple[str, int]:
    unit_id = row.get("unit_id")
    event_index = row.get("event_index")
    if not isinstance(unit_id, str) or not unit_id:
        raise StaticHybridCompletenessError(f"{context} has no source unit")
    if not isinstance(event_index, int) or isinstance(event_index, bool):
        raise StaticHybridCompletenessError(f"{context} has an invalid event index")
    return unit_id, event_index


def _reconcile_external_inventory(
    canonical: Mapping[tuple[str, int], Mapping[str, Any]],
    submitted: Sequence[Any],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> tuple[list[_Blocker], int]:
    indexed: dict[tuple[str, int], Mapping[str, Any]] = {}
    for index, raw in enumerate(submitted):
        row = _object(raw, f"external event inventory row {index}")
        key = _external_site_key(row, f"external event inventory row {index}")
        if key[0] not in rows_by_id:
            raise StaticHybridCompletenessError(
                "external event inventory references an unknown source unit"
            )
        if key in indexed:
            raise StaticHybridCompletenessError(
                "external event inventory contains duplicate sites"
            )
        if key[0] in reachable_ids:
            indexed[key] = row
    blockers: list[_Blocker] = []
    violations = 0
    for key in sorted(canonical.keys() - indexed.keys()):
        blockers.append(_Blocker(
            family="machine_abi",
            code="external_inventory_omits_machine_ir_event",
            message="the submitted external inventory omits a reachable machine-IR event",
            next_action="regenerate external events from the hash-bound reachable machine IR",
            location={"unit_id": key[0], "rva_start": canonical[key].get("unit_rva"), "event_index": key[1]},
        ))
        violations += 1
    for key in sorted(indexed.keys() - canonical.keys()):
        blockers.append(_Blocker(
            family="machine_abi",
            code="external_inventory_contains_spurious_event",
            message="the submitted external inventory invents a reachable event absent from machine IR",
            next_action="regenerate external events from the hash-bound reachable machine IR",
            location={"unit_id": key[0], "rva_start": indexed[key].get("unit_rva"), "event_index": key[1]},
        ))
        violations += 1
    for key in sorted(canonical.keys() & indexed.keys()):
        if dict(indexed[key]) != dict(canonical[key]):
            blockers.append(_Blocker(
                family="machine_abi",
                code="external_inventory_event_binding_mismatch",
                message="a submitted external event contradicts its machine-IR payload",
                next_action="regenerate the exact event payload and site binding",
                location={"unit_id": key[0], "rva_start": canonical[key].get("unit_rva"), "event_index": key[1]},
            ))
            violations += 1
    return blockers, violations


def _external_interface_provenance_mismatches(
    provenance: Mapping[str, Any],
) -> list[str]:
    mismatches: list[str] = []
    if provenance.get("format") != _EXTERNAL_INTERFACE_PROVENANCE_FORMAT:
        mismatches.append("format")
    if provenance.get("proof_authority") is not False:
        mismatches.append("proof_authority")
    fixed_point = provenance.get("fixed_point")
    if (
        not isinstance(fixed_point, Mapping)
        or fixed_point.get("converged") is not True
        or _plain_integer(fixed_point.get("rounds")) is None
        or int(fixed_point["rounds"]) <= 0
    ):
        mismatches.append("fixed_point")
    issues = provenance.get("issues")
    if not isinstance(issues, list):
        mismatches.append("issues")
    for field in ("resolutions", "callback_registrations"):
        if not isinstance(provenance.get(field), list):
            mismatches.append(field)
    resolutions = provenance.get("resolutions")
    if isinstance(resolutions, list) and any(
        not isinstance(item, Mapping) for item in resolutions
    ):
        mismatches.append("resolution_structure")
    registrations = provenance.get("callback_registrations")
    if isinstance(registrations, list) and any(
        not isinstance(item, Mapping)
        or item.get("status") != "complete"
        or item.get("failure") is not None
        for item in registrations
    ):
        mismatches.append("callback_registration_completeness")
    return mismatches


def _canonical_fault_sites(
    rows_by_id: Mapping[str, Mapping[str, Any]], reachable_ids: set[str]
) -> dict[tuple[str, int], dict[str, Any]]:
    result: dict[tuple[str, int], dict[str, Any]] = {}
    for unit_id in sorted(reachable_ids):
        row = rows_by_id[unit_id]
        for fault_index, raw in enumerate(_semantic_list(row, unit_id, "faults")):
            fault = _object(raw, f"{unit_id} fault {fault_index}")
            result[(unit_id, fault_index)] = {
                "source_unit_id": unit_id,
                "source_fault_index": fault_index,
                "source_rva": _unit_rva(row),
                "instruction_rva": fault.get("instruction_rva"),
                "fault_kind": fault.get("kind"),
                "fault_sha256": _json_sha256(fault),
                "source_contract_sha256": row.get("source", {}).get(
                    "contract_sha256"
                ),
                "outcome_sha256": _json_sha256(
                    _semantics(row, unit_id).get("outcome")
                ),
            }
    return result


def _checked_exception_evidence(
    value: Any,
    *,
    expected: Mapping[str, Any],
    disposition_kind: Any,
) -> bool:
    if not isinstance(value, Mapping):
        return False
    checker = value.get("checker")
    digest = value.get("certificate_sha256")
    certificate = value.get("certificate")
    checker_formats = {
        "stage-a-machine-ir-explicit-terminal-fault-v1": (
            "stage-a-explicit-terminal-fault-certificate-v1",
            "termination",
        ),
        "stage-a-machine-ir-qf-bv-fault-infeasibility-v1": (
            "stage-a-qf-bv-fault-infeasibility-certificate-v1",
            "infeasible",
        ),
        "stage-a-machine-ir-qf-bv-path-fault-infeasibility-v1": (
            "stage-a-qf-bv-path-fault-infeasibility-certificate-v1",
            "infeasible",
        ),
        "stage-a-machine-ir-qf-bv-finite-join-fault-infeasibility-v1": (
            "stage-a-qf-bv-finite-join-fault-infeasibility-certificate-v1",
            "infeasible",
        ),
    }
    expected_checker = checker_formats.get(checker)
    if expected_checker is None:
        return False
    certificate_format, expected_disposition = expected_checker
    common_valid = (
        value.get("status") == "checked"
        and disposition_kind == expected_disposition
        and _is_sha256(digest)
        and isinstance(certificate, Mapping)
        and _json_sha256(certificate) == digest
        and certificate.get("format") == certificate_format
        and certificate.get("source_unit_id") == expected.get("source_unit_id")
        and certificate.get("source_fault_index")
        == expected.get("source_fault_index")
        and certificate.get("source_contract_sha256")
        == expected.get("source_contract_sha256")
        and certificate.get("fault_sha256") == expected.get("fault_sha256")
    )
    if not common_valid:
        return False
    if expected_disposition == "termination":
        return certificate.get("outcome_sha256") == expected.get("outcome_sha256")
    claim = certificate.get("claim")
    if not isinstance(claim, str) or "fault_condition" not in claim:
        return False
    if certificate_format.endswith("finite-join-fault-infeasibility-certificate-v1"):
        alternatives = certificate.get("alternative_certificate_sha256s")
        return (
            isinstance(alternatives, list)
            and bool(alternatives)
            and all(_is_sha256(item) for item in alternatives)
            and certificate.get("alternative_count") == len(alternatives)
        )
    return isinstance(certificate.get("checked_claims"), list) and bool(
        certificate["checked_claims"]
    )


def _exception_site_key(row: Mapping[str, Any], context: str) -> tuple[str, int]:
    unit_id = row.get("source_unit_id")
    fault_index = row.get("source_fault_index")
    if not isinstance(unit_id, str) or not unit_id:
        raise StaticHybridCompletenessError(f"{context} has no source unit")
    if not isinstance(fault_index, int) or isinstance(fault_index, bool) or fault_index < 0:
        raise StaticHybridCompletenessError(f"{context} has an invalid fault index")
    return unit_id, fault_index


def _reconcile_exceptional_control(
    canonical: Mapping[tuple[str, int], Mapping[str, Any]],
    submitted: Any,
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    units_by_rva: Mapping[int, list[str]],
    reachable_ids: set[str],
) -> tuple[list[_Blocker], int]:
    if submitted is None:
        transitions: list[Any] = []
    else:
        inventory = _object(submitted, "exceptional-control inventory")
        if inventory.get("format") != "stage-a-exceptional-control-v1":
            raise StaticHybridCompletenessError(
                "exceptional-control inventory has an unsupported format"
            )
        transitions = _list(
            inventory.get("transitions"), "exceptional-control transitions"
        )
    indexed: dict[tuple[str, int], Mapping[str, Any]] = {}
    for index, raw in enumerate(transitions):
        transition = _object(raw, f"exceptional-control transition {index}")
        key = _exception_site_key(
            transition, f"exceptional-control transition {index}"
        )
        if key[0] not in rows_by_id:
            raise StaticHybridCompletenessError(
                "exceptional-control transition references an unknown source unit"
            )
        if key in indexed:
            raise StaticHybridCompletenessError(
                "exceptional-control inventory contains duplicate fault sites"
            )
        if key[0] in reachable_ids:
            indexed[key] = transition

    blockers: list[_Blocker] = []
    violations = 0
    for key in sorted(canonical.keys() - indexed.keys()):
        expected = canonical[key]
        blockers.append(_Blocker(
            family="exceptional_control",
            code="reachable_fault_transition_missing",
            message="a reachable machine-IR fault has no checked exceptional transition",
            next_action="prove the exact fault infeasible or bind it to checked termination or SEH control",
            location={
                "unit_id": key[0],
                "rva_start": expected.get("source_rva"),
                "instruction_rva": expected.get("instruction_rva"),
                "fault_index": key[1],
            },
            details={"fault_kind": expected.get("fault_kind")},
        ))
    for key in sorted(indexed.keys() - canonical.keys()):
        blockers.append(_Blocker(
            family="exceptional_control",
            code="exception_inventory_contains_spurious_fault",
            message="the exceptional-control inventory invents a fault absent from machine IR",
            next_action="regenerate exceptional control from the exact machine-IR fault list",
            location={"unit_id": key[0], "fault_index": key[1]},
        ))
        violations += 1
    for key in sorted(canonical.keys() & indexed.keys()):
        expected = canonical[key]
        observed = indexed[key]
        if (
            observed.get("fault_sha256") != expected.get("fault_sha256")
            or observed.get("fault_kind") != expected.get("fault_kind")
            or observed.get("instruction_rva") != expected.get("instruction_rva")
        ):
            blockers.append(_Blocker(
                family="exceptional_control",
                code="exception_transition_fault_binding_mismatch",
                message="a submitted exceptional transition contradicts its machine-IR fault",
                next_action="bind the transition to the exact canonical fault digest",
                location={
                    "unit_id": key[0],
                    "rva_start": expected.get("source_rva"),
                    "instruction_rva": expected.get("instruction_rva"),
                    "fault_index": key[1],
                },
            ))
            violations += 1
            continue
        disposition = observed.get("disposition")
        disposition = disposition if isinstance(disposition, Mapping) else {}
        kind = disposition.get("kind")
        evidence_valid = _checked_exception_evidence(
            disposition.get("evidence"),
            expected=expected,
            disposition_kind=kind,
        )
        valid = observed.get("status") == "complete" and evidence_valid
        if kind == "infeasible":
            pass
        elif kind == "termination":
            valid = valid and disposition.get("observable") is True
        elif kind == "seh_transition":
            # SEH requires checked registration-chain, handler-selection, frame,
            # and continuation evidence.  No supported certificate emits those
            # facts yet, so a target address alone can never close the site.
            valid = False
        else:
            valid = False
        if not valid:
            blockers.append(_Blocker(
                family="exceptional_control",
                code="exception_transition_incomplete",
                message="a reachable fault lacks a complete checked disposition",
                next_action="supply checked infeasibility, observable termination, or a unique reachable SEH target",
                location={
                    "unit_id": key[0],
                    "rva_start": expected.get("source_rva"),
                    "instruction_rva": expected.get("instruction_rva"),
                    "fault_index": key[1],
                },
                details={"disposition_kind": kind},
            ))
    return blockers, violations


def _json_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    )


def _is_sha256(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _validate_indirect_external_protocols(
    canonical: Mapping[tuple[str, int | None], Mapping[str, Any]],
    resolutions: Mapping[tuple[str, int | None], Mapping[str, Any]],
    *,
    import_contracts: Mapping[MachineImportIdentity, SelectedMachineImportContract],
    interface_methods: Mapping[tuple[str, str, int], _SelectedInterfaceMethod],
    callback_registrations: Mapping[tuple[str, int], Mapping[str, Any]],
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
    checked_sites: list[dict[str, Any]],
) -> tuple[list[_Blocker], int, int, int]:
    blockers: list[_Blocker] = []
    profiled_imports = 0
    interface_calls = 0
    effect_complete = 0
    for site_key in sorted(canonical, key=str):
        site = canonical[site_key]
        resolution = resolutions.get(site_key)
        if resolution is None or resolution.get("status") != "recovered":
            continue
        transfer_kind = (
            "call" if site.get("kind") == "indirect_call" else "jump"
        )
        location = {
            "unit_id": site_key[0],
            "rva_start": site.get("source_rva"),
            "event_index": site_key[1],
        }
        source_event = _indirect_source_event(site_key, rows_by_id=rows_by_id)
        for raw_target in _list(
            resolution.get("external_targets"), "indirect external targets"
        ):
            target = _object(raw_target, "indirect external target")
            if "external_protocol" in target:
                protocol = _object(
                    target.get("external_protocol"), "external protocol"
                )
                protocol_kind = protocol.get("kind")
                if protocol_kind == "pe32-resolved-export":
                    contract = protocol.get("machine_contract")
                    imported = protocol.get("target")
                    arity = contract.get("arity") if isinstance(contract, Mapping) else None
                    effect = (
                        contract.get("effect_model")
                        if isinstance(contract, Mapping)
                        else None
                    )
                    valid = (
                        protocol.get("transfer_kind") == transfer_kind
                        and isinstance(imported, Mapping)
                        and isinstance(contract, Mapping)
                        and contract.get("import") == imported
                        and isinstance(arity, Mapping)
                        and arity.get("kind") == "fixed"
                        and arity.get("words") == target.get("argument_words")
                        and isinstance(effect, Mapping)
                        and effect.get("kind") == "exact_native_dll_callthrough_v1"
                        and effect.get("prerequisites")
                        == {
                            "same_pinned_dll_implementation": True,
                            "exact_machine_arguments": True,
                            "candidate_address_space_used_directly": True,
                        }
                        and contract.get("memory_effect") == "nativeCallthrough"
                        and contract.get("world_effect") == "nativeCallthrough"
                        and contract.get("callback_effect") == "none"
                    )
                    if not valid:
                        blockers.append(_Blocker(
                            family="external_effects",
                            code="resolved_export_effects_incomplete",
                            message="a reachable resolver-returned export has malformed ABI, effects, or transfer kind",
                            next_action="bind the exact export and matching call/jump kind to one pinned-DLL contract",
                            location=location,
                            details={
                                "expected_transfer_kind": transfer_kind,
                                "protocol": dict(protocol),
                            },
                        ))
                        continue
                    assert isinstance(imported, Mapping)
                    assert isinstance(contract, Mapping)
                    try:
                        identity = ExternalSiteIdentity.interface(
                            protocol,
                            context=f"{site_key[0]} resolved export",
                        )
                    except CheckedExternalSiteContractError as exc:
                        site_problems = [str(exc)]
                    else:
                        site_contract, site_problems = _checked_indirect_external_site(
                            source_event=source_event,
                            target=target,
                            identity=identity,
                            transfer_kind=transfer_kind,
                            callback_evidence=callback_registrations.get(
                                (site_key[0], int(site_key[1]))
                                if site_key[1] is not None
                                else (site_key[0], -1)
                            ),
                            expected_machine_contract=_protocol_machine_contract(
                                protocol, contract
                            ),
                            expected_protocol=protocol,
                            rows_by_id=rows_by_id,
                            reachable_ids=reachable_ids,
                            context=f"{site_key[0]} resolved export",
                        )
                    if site_problems:
                        blockers.append(_Blocker(
                            family="external_effects",
                            code="indirect_external_site_contract_incomplete",
                            message="a reachable resolver-returned export lacks exact source-site ABI or continuation evidence",
                            next_action="bind exact call arguments and effects to the source event and root its returning continuation",
                            location=location,
                            details={"problems": site_problems},
                        ))
                    else:
                        effect_complete += 1
                        assert site_contract is not None
                        checked_sites.append(_checked_site_row(site_key, site_contract))
                    continue
                if protocol_kind == "pe32-previous-callback":
                    callback_abi = protocol.get("callback_abi")
                    callback_template = resolve_machine_call_abi("pe32-stdcall-v1")
                    valid = (
                        transfer_kind == "call"
                        and _generic_callback_abi_complete(callback_abi)
                        and isinstance(protocol.get("contract_id"), str)
                        and bool(protocol.get("contract_id"))
                        and isinstance(protocol.get("profile_binding"), Mapping)
                        and isinstance(protocol.get("callback_lifetime"), (str, Mapping))
                        and bool(protocol.get("callback_lifetime"))
                        and protocol.get("effect_model")
                        == "same-process-callback-callthrough-v1"
                        and callback_template is not None
                        and target.get("abi") == callback_template.as_json()
                        and isinstance(callback_abi, Mapping)
                        and target.get("argument_words")
                        == callback_abi.get("argument_words")
                    )
                    binding_mismatches = _previous_callback_binding_mismatches(
                        protocol,
                        resolution=resolution,
                        site_key=site_key,
                        callback_registrations=callback_registrations,
                        rows_by_id=rows_by_id,
                        reachable_ids=reachable_ids,
                    )
                    if not valid or binding_mismatches:
                        blockers.append(_Blocker(
                            family="external_effects",
                            code="previous_callback_effects_incomplete",
                            message="a reachable API-returned callback is not bound to one prior registration contract",
                            next_action="bind the callback token to its unique prior registration, profile, contract, ABI, and lifetime",
                            location=location,
                            details={"mismatches": binding_mismatches},
                        ))
                        continue
                    try:
                        identity = ExternalSiteIdentity.interface(
                            protocol,
                            context=f"{site_key[0]} previous callback",
                        )
                    except CheckedExternalSiteContractError as exc:
                        site_problems = [str(exc)]
                    else:
                        site_contract, site_problems = _checked_indirect_external_site(
                            source_event=source_event,
                            target=target,
                            identity=identity,
                            transfer_kind=transfer_kind,
                            callback_evidence=None,
                            expected_protocol=protocol,
                            rows_by_id=rows_by_id,
                            reachable_ids=reachable_ids,
                            context=f"{site_key[0]} previous callback",
                        )
                    if site_problems:
                        blockers.append(_Blocker(
                            family="external_effects",
                            code="indirect_external_site_contract_incomplete",
                            message="a reachable previous-callback invocation lacks exact source-site ABI or continuation evidence",
                            next_action="emit exact callback invocation arguments and root its return continuation",
                            location=location,
                            details={"problems": site_problems},
                        ))
                    else:
                        effect_complete += 1
                        assert site_contract is not None
                        checked_sites.append(_checked_site_row(site_key, site_contract))
                    continue
                if protocol_kind == "pe32-interface-method":
                    interface_calls += 1
                    transfer_valid = protocol.get("transfer_kind") == transfer_kind
                    method_key = (
                        str(protocol.get("profile_id")),
                        str(protocol.get("interface_id")),
                        protocol.get("slot"),
                    )
                    selected = interface_methods.get(method_key)
                    missing = _interface_target_mismatches(
                        target,
                        protocol,
                        selected,
                    )
                    if not transfer_valid:
                        missing.append("transfer_kind")
                    if (
                        selected is not None
                        and selected.method.effects is not None
                        and selected.method.effects.callback_effect == "explicit"
                    ):
                        registration = callback_registrations.get(
                            (site_key[0], int(site_key[1]))
                            if site_key[1] is not None
                            else (site_key[0], -1)
                        )
                        missing.extend(_callback_registration_mismatches(
                            registration,
                            site_key=site_key,
                            selected=selected,
                            rows_by_id=rows_by_id,
                            reachable_ids=reachable_ids,
                        ))
                    if missing:
                        blockers.append(_Blocker(
                            family="external_effects",
                            code=(
                                "interface_callback_registration_incomplete"
                                if any(
                                    field.startswith("callback_registration")
                                    for field in missing
                                )
                                else "interface_method_contract_mismatch"
                            ),
                            message="a reachable interface transfer differs from its typed profile or callback registration",
                            next_action="regenerate the exact typed interface target and complete callback evidence for this source event",
                            location=location,
                            details={
                                "protocol": dict(protocol),
                                "mismatches": sorted(set(missing)),
                            },
                        ))
                    else:
                        try:
                            identity = ExternalSiteIdentity.interface(
                                protocol,
                                context=f"{site_key[0]} interface method",
                            )
                        except CheckedExternalSiteContractError as exc:
                            site_problems = [str(exc)]
                        else:
                            site_contract, site_problems = _checked_indirect_external_site(
                                source_event=source_event,
                                target=target,
                                identity=identity,
                                transfer_kind=transfer_kind,
                                callback_evidence=callback_registrations.get(
                                    (site_key[0], int(site_key[1]))
                                    if site_key[1] is not None
                                    else (site_key[0], -1)
                                ),
                                expected_protocol=protocol,
                                expected_machine_contract=(
                                    _interface_method_machine_contract(selected)
                                ),
                                rows_by_id=rows_by_id,
                                reachable_ids=reachable_ids,
                                context=f"{site_key[0]} interface method",
                            )
                        if site_problems:
                            blockers.append(_Blocker(
                                family="external_effects",
                                code="indirect_external_site_contract_incomplete",
                                message="a reachable interface alternative lacks exact source-site ABI or continuation evidence",
                                next_action="emit exact interface-call arguments and root its return continuation",
                                location=location,
                                details={"problems": site_problems},
                            ))
                        else:
                            effect_complete += 1
                            assert site_contract is not None
                            checked_sites.append(_checked_site_row(site_key, site_contract))
                    continue
                blockers.append(_Blocker(
                    family="external_effects",
                    code="indirect_external_protocol_unsupported",
                    message="a reachable indirect external target uses an unsupported protocol",
                    next_action="add a checked machine-level ABI/effect protocol for this exact target kind",
                    location=location,
                    details={"protocol_kind": protocol_kind},
                ))
                continue
            if "import" in target:
                imported = _object(target.get("import"), "indirect import")
                identity = MachineImportIdentity.from_mapping(
                    imported, context=f"{site_key[0]} indirect import"
                )
                contract = import_contracts.get(identity)
                if contract is None:
                    blockers.append(_Blocker(
                        family="machine_abi",
                        code="indirect_import_contract_missing",
                        message=f"reachable indirect import {identity.dll}!{identity.value} has no selected machine contract",
                        next_action="bind the recovered import target to a pinned machine-level contract",
                        location=location,
                    ))
                else:
                    profiled_imports += 1
                    missing = _external_contract_missing_fields(contract)
                    if missing:
                        blockers.append(_Blocker(
                            family="external_effects",
                            code="indirect_import_effects_incomplete",
                            message=f"reachable indirect import {identity.dll}!{identity.value} has incomplete effects",
                            next_action="complete the selected import memory and world-effect contract",
                            location=location,
                            details={"missing_fields": missing},
                        ))
                    else:
                        site_problems: list[str] = []
                        try:
                            site_identity = ExternalSiteIdentity.imported(
                                imported,
                                context=f"{site_key[0]} indirect import",
                            )
                            site_contract, site_problems = (
                                _checked_indirect_external_site(
                                    source_event=source_event,
                                    target=target,
                                    identity=site_identity,
                                    transfer_kind=transfer_kind,
                                    callback_evidence=callback_registrations.get(
                                        (site_key[0], int(site_key[1]))
                                        if site_key[1] is not None
                                        else (site_key[0], -1)
                                    ),
                                    expected_protocol=None,
                                    expected_machine_contract=(
                                        _selected_import_machine_contract(contract)
                                    ),
                                    rows_by_id=rows_by_id,
                                    reachable_ids=reachable_ids,
                                    context=f"{site_key[0]} indirect import",
                                )
                            )
                            if site_contract is not None:
                                require_profile_match(
                                    site_contract,
                                    profile_contract=contract.contract,
                                    profile_id=contract.profile_id,
                                    profile_sha256=contract.profile_sha256,
                                    entry_key=contract.entry_key,
                                    entry_index=contract.entry_index,
                                    context=f"{site_key[0]} indirect import",
                                )
                        except (CheckedExternalSiteContractError, TypeError, ValueError) as exc:
                            site_problems = [*site_problems, str(exc)]
                        if site_problems:
                            blockers.append(_Blocker(
                                family="external_effects",
                                code="indirect_external_site_contract_incomplete",
                                message="a reachable indirect import lacks exact source-site ABI or continuation evidence",
                                next_action="bind exact call arguments and effects to the selected import contract and root its continuation",
                                location=location,
                                details={"problems": site_problems},
                            ))
                        else:
                            effect_complete += 1
                            assert site_contract is not None
                            checked_sites.append(_checked_site_row(site_key, site_contract))
                continue
            blockers.append(_Blocker(
                family="external_effects",
                code="indirect_external_target_malformed",
                message="a reachable indirect external target has neither an import nor a checked protocol",
                next_action="emit one exact external target identity and ABI/effect contract",
                location=location,
            ))
    return blockers, profiled_imports, interface_calls, effect_complete


def _checked_site_row(
    site_key: tuple[str, int | None],
    contract: CheckedExternalSiteContract,
) -> dict[str, Any]:
    event_index = site_key[1]
    if event_index is None:
        raise StaticHybridCompletenessError(
            "checked external site has no exact source event index"
        )
    return {
        "unit_id": site_key[0],
        "event_index": int(event_index),
        "contract": contract.payload(),
    }


def _indirect_source_event(
    site_key: tuple[str, int | None],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
) -> Mapping[str, Any] | None:
    event_index = site_key[1]
    row = rows_by_id.get(site_key[0])
    if row is None or event_index is None:
        return None
    events = _semantics(row, site_key[0]).get("external_events")
    if (
        not isinstance(events, list)
        or not 0 <= event_index < len(events)
        or not isinstance(events[event_index], Mapping)
    ):
        return None
    return events[event_index]


def _checked_indirect_external_site(
    *,
    source_event: Mapping[str, Any] | None,
    target: Mapping[str, Any],
    identity: ExternalSiteIdentity,
    transfer_kind: str,
    callback_evidence: Mapping[str, Any] | None,
    expected_protocol: Mapping[str, Any] | None,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
    context: str,
    expected_machine_contract: Mapping[str, Any] | None = None,
) -> tuple[CheckedExternalSiteContract | None, list[str]]:
    if source_event is None:
        return None, ["source event has no exact external-event site"]
    if source_event.get("kind") not in {"indirect_call", "indirect_jump"}:
        return None, ["source event kind differs from its indirect resolution"]
    expected_kind = "indirect_call" if transfer_kind == "call" else "indirect_jump"
    if source_event.get("kind") != expected_kind:
        return None, ["source event transfer kind differs from its resolution"]
    try:
        site_contract = checked_external_site_contract_from_event(
            event=source_event,
            identity=identity,
            transfer_kind=transfer_kind,
            disposition="returns_here" if transfer_kind == "call" else "tail_jump",
            protocol_target=target,
            callback_evidence=callback_evidence,
            resolved_machine_contract=expected_machine_contract,
            context=context,
        )
    except (CheckedExternalSiteContractError, TypeError, ValueError) as exc:
        return None, [str(exc)]

    problems: list[str] = []
    target_abi = target.get("abi")
    canonical_abi = resolve_machine_call_abi(site_contract.abi_template)
    if canonical_abi is None or target_abi != canonical_abi.as_json():
        problems.append("external target ABI is not the canonical machine ABI")
    if expected_protocol is not None:
        protocol_binding = expected_protocol.get("profile_binding")
        protocol_binding = (
            protocol_binding if isinstance(protocol_binding, Mapping) else {}
        )
        protocol_profile_id = expected_protocol.get(
            "profile_id", protocol_binding.get("profile_id", protocol_binding.get("id"))
        )
        protocol_profile_sha256 = expected_protocol.get(
            "profile_sha256",
            protocol_binding.get("profile_sha256", protocol_binding.get("sha256")),
        )
        binding = site_contract.profile_binding
        binding_profile_id = binding.get("profile_id", binding.get("id"))
        binding_profile_sha256 = binding.get(
            "profile_sha256", binding.get("sha256")
        )
        if (
            not isinstance(protocol_profile_id, str)
            or not isinstance(protocol_profile_sha256, str)
            or binding_profile_id != protocol_profile_id
            or binding_profile_sha256 != protocol_profile_sha256
        ):
            problems.append("source-site profile binding differs from its protocol")
    if expected_machine_contract is not None:
        problems.extend(_machine_contract_site_mismatches(
            site_contract, expected_machine_contract
        ))
    if (
        transfer_kind == "call"
        and site_contract.profile_disposition == "returns"
        and not _continuation_closed(
            source_event.get("return_rva"),
            rows_by_id=rows_by_id,
            reachable_ids=reachable_ids,
        )
    ):
        problems.append("return_rva has no rooted reachable continuation")
    return site_contract, problems


def _machine_contract_site_mismatches(
    observed: CheckedExternalSiteContract,
    expected: Mapping[str, Any],
) -> list[str]:
    arity = expected.get("arity")
    expected_words = arity.get("words") if isinstance(arity, Mapping) else None
    comparisons = {
        "contract_id": (observed.contract_id, expected.get("id")),
        "abi_template": (observed.abi_template, expected.get("abi_template")),
        "argument_words": (observed.argument_words, expected_words),
        "disposition": (
            observed.profile_disposition,
            expected.get("disposition", "returns"),
        ),
        "result_register_relations": (
            list(observed.result_register_relations),
            expected.get("result_register_relations"),
        ),
        "memory_effect": (observed.memory_effect, expected.get("memory_effect")),
        "memory_footprints": (
            list(observed.memory_footprints),
            expected.get("memory_footprints"),
        ),
        "world_effect": (observed.world_effect, expected.get("world_effect")),
        "callback_effect": (
            observed.callback_effect,
            expected.get("callback_effect"),
        ),
    }
    return [
        f"source-site {field} differs from embedded machine contract"
        for field, (actual, wanted) in comparisons.items()
        if actual != wanted
    ]


def _previous_callback_binding_mismatches(
    protocol: Mapping[str, Any],
    *,
    resolution: Mapping[str, Any],
    site_key: tuple[str, int | None],
    callback_registrations: Mapping[tuple[str, int], Mapping[str, Any]],
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> list[str]:
    mismatches: list[str] = []
    origin_kinds = resolution.get("origin_kinds")
    if not isinstance(origin_kinds, list) or "callback_token" not in origin_kinds:
        mismatches.append("resolution.callback_token_origin")

    candidates: list[tuple[str, int]] = []
    for registration_key, registration in callback_registrations.items():
        if not _registration_precedes_site(
            registration_key,
            site_key,
            rows_by_id=rows_by_id,
            reachable_ids=reachable_ids,
        ):
            continue
        if (
            registration.get("status") != "complete"
            or registration.get("failure") is not None
            or registration.get("contract_id") != protocol.get("contract_id")
            or registration.get("profile_binding")
            != protocol.get("profile_binding")
            or registration.get("callback_lifetime")
            != protocol.get("callback_lifetime")
        ):
            continue
        source_event = _indirect_source_event(
            registration_key, rows_by_id=rows_by_id
        )
        if source_event is None:
            source_row = rows_by_id.get(registration_key[0])
            events = (
                _semantics(source_row, registration_key[0]).get("external_events")
                if isinstance(source_row, Mapping)
                else None
            )
            source_event = (
                events[registration_key[1]]
                if isinstance(events, list)
                and 0 <= registration_key[1] < len(events)
                and isinstance(events[registration_key[1]], Mapping)
                else None
            )
        if source_event is None or source_event.get("kind") != "external_call":
            continue
        source_contract = source_event.get("abi_contract")
        source_contract = (
            source_contract if isinstance(source_contract, Mapping) else {}
        )
        callback_result = source_contract.get("callback_result")
        source_abi = source_contract.get("callback_abi")
        protocol_abi = protocol.get("callback_abi")
        if (
            source_contract.get("contract_id") != protocol.get("contract_id")
            or source_contract.get("profile_binding")
            != protocol.get("profile_binding")
            or registration.get("callback_abi") != source_abi
            or not isinstance(source_abi, Mapping)
            or not isinstance(protocol_abi, Mapping)
            or any(
                source_abi.get(field) != protocol_abi.get(field)
                for field in (
                    "kind",
                    "argument_words",
                    "stack_cleanup_bytes",
                )
            )
            or source_contract.get("callback_lifetime")
            != protocol.get("callback_lifetime")
            or not isinstance(callback_result, Mapping)
            or callback_result.get("origin") != "previous_registered_callback"
            or callback_result.get("nullable")
            != protocol_abi.get("nullable")
        ):
            continue
        candidates.append(registration_key)
    if not candidates:
        mismatches.append("prior_registration.missing")
    elif len(candidates) != 1:
        mismatches.append("prior_registration.ambiguous")
    return mismatches


def _registration_precedes_site(
    registration_key: tuple[str, int],
    site_key: tuple[str, int | None],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> bool:
    if registration_key[0] == site_key[0]:
        return site_key[1] is not None and registration_key[1] < site_key[1]
    if registration_key[0] not in reachable_ids or site_key[0] not in reachable_ids:
        return False
    units_by_rva = _units_by_rva({
        unit_id: rows_by_id[unit_id] for unit_id in reachable_ids
    })
    work = [registration_key[0]]
    visited: set[str] = set()
    while work:
        unit_id = work.pop()
        if unit_id in visited:
            continue
        visited.add(unit_id)
        row = rows_by_id[unit_id]
        control = row.get("control")
        direct_targets = (
            control.get("direct_targets")
            if isinstance(control, Mapping)
            else None
        )
        if not isinstance(direct_targets, list):
            continue
        for target_rva in direct_targets:
            if _plain_integer(target_rva) is None:
                continue
            matches = units_by_rva.get(int(target_rva), [])
            if len(matches) != 1:
                continue
            target_id = matches[0]
            if target_id == site_key[0]:
                return True
            if target_id not in visited:
                work.append(target_id)
    return False


def _external_contract_missing_fields(
    contract: SelectedMachineImportContract,
) -> list[str]:
    row = contract.contract
    missing: list[str] = []
    if not isinstance(row.get("abi_template"), str):
        missing.append("abi_template")
    if contract.arity_kind is None:
        missing.append("arity")
    if not isinstance(row.get("memory_effect"), str):
        missing.append("memory_effect")
    if not isinstance(row.get("memory_footprints"), list):
        missing.append("memory_footprints")
    if not isinstance(row.get("world_effect"), str):
        missing.append("world_effect")
    if not isinstance(row.get("result_register_relations"), list):
        missing.append("result_register_relations")
    if row.get("callback_effect") not in {"none", "explicit"}:
        missing.append("callback_effect")
    world_effect = row.get("world_effect")
    if world_effect == "callbackRegistration":
        if not isinstance(row.get("callback_abi"), Mapping):
            missing.append("callback_abi")
        if not isinstance(row.get("callback_lifetime"), str):
            missing.append("callback_lifetime")
        if not isinstance(row.get("callback_source"), Mapping) and not isinstance(
            row.get("world_effect_argument"), int
        ):
            missing.append("callback_source")
    if world_effect == "dynamicRangeRelease" and not isinstance(
        row.get("world_effect_argument"), int
    ):
        missing.append("world_effect_argument")
    return missing


def _required_callback_registration_sites(
    external_events: Mapping[tuple[str, int], Mapping[str, Any]],
    resolutions: Mapping[tuple[str, int | None], Mapping[str, Any]],
    *,
    import_contracts: Mapping[MachineImportIdentity, SelectedMachineImportContract],
    interface_methods: Mapping[tuple[str, str, int], _SelectedInterfaceMethod],
) -> set[tuple[str, int]]:
    required: set[tuple[str, int]] = set()
    for site_key, event_row in external_events.items():
        event = event_row.get("event")
        if not isinstance(event, Mapping):
            continue
        kind = event.get("kind")
        if kind == "external_call":
            try:
                identity = MachineImportIdentity.from_mapping(
                    event, context=f"{site_key[0]} external call"
                )
            except MachineImportProfileError:
                identity = None
            selected = import_contracts.get(identity) if identity is not None else None
            event_contract = event.get("abi_contract")
            if (
                selected is not None
                and _contract_registers_callback(selected.contract)
            ) or (
                isinstance(event_contract, Mapping)
                and _contract_registers_callback(event_contract)
            ):
                required.add(site_key)
            continue
        if kind != "indirect_call":
            continue
        resolution = resolutions.get(site_key)
        if resolution is None or resolution.get("status") != "recovered":
            continue
        raw_targets = resolution.get("external_targets")
        if not isinstance(raw_targets, list):
            continue
        for raw_target in raw_targets:
            if not isinstance(raw_target, Mapping):
                continue
            protocol = raw_target.get("external_protocol")
            if isinstance(protocol, Mapping) and protocol.get("kind") == "pe32-interface-method":
                selected_method = interface_methods.get((
                    str(protocol.get("profile_id")),
                    str(protocol.get("interface_id")),
                    protocol.get("slot"),
                ))
                effects = (
                    selected_method.method.effects
                    if selected_method is not None
                    else None
                )
                if effects is not None and effects.callback_effect == "explicit":
                    required.add(site_key)
            imported = raw_target.get("import")
            if not isinstance(imported, Mapping):
                continue
            try:
                identity = MachineImportIdentity.from_mapping(
                    imported, context=f"{site_key[0]} indirect import"
                )
            except MachineImportProfileError:
                continue
            selected_import = import_contracts.get(identity)
            if (
                selected_import is not None
                and _contract_registers_callback(selected_import.contract)
            ):
                required.add(site_key)
    return required


def _contract_registers_callback(contract: Mapping[str, Any]) -> bool:
    return (
        contract.get("callback_effect") == "explicit"
        or contract.get("world_effect") == "callbackRegistration"
    )


def _interface_target_mismatches(
    target: Mapping[str, Any],
    protocol: Mapping[str, Any],
    selected: _SelectedInterfaceMethod | None,
) -> list[str]:
    if selected is None:
        return ["profile.method"]
    method = selected.method
    expected = method.target_json(
        profile_id=selected.profile.profile_id,
        profile_sha256=selected.profile.sha256,
    )
    expected_protocol = _object(
        expected.get("external_protocol"), "typed interface protocol"
    )
    mismatches = [
        f"external_protocol.{field}"
        for field in (
            "profile_id",
            "profile_sha256",
            "interface_id",
            "method",
            "slot",
            "offset",
        )
        if protocol.get(field) != expected_protocol.get(field)
    ]
    if method.effects is None:
        mismatches.append("profile.effect_contract")
        return mismatches
    for field in (
        "abi",
        "argument_words",
        "out_interfaces",
        "effect_model",
        "memory_effect",
        "memory_footprints",
        "world_effect",
        "callback_effect",
    ):
        if target.get(field) != expected.get(field):
            mismatches.append(field)
    callback_fields = (
        "callback_source",
        "callback_abi",
        "callback_lifetime",
        "callback_contract_status",
        "callback_contract_blockers",
    )
    if method.effects.callback_effect == "explicit":
        for field in callback_fields:
            if target.get(field) != expected.get(field):
                mismatches.append(field)
        if method.effects.callback_status != "complete":
            mismatches.append("profile.callback_contract_status")
    elif any(field in target for field in callback_fields):
        mismatches.append("unexpected_callback_metadata")
    return mismatches


def _callback_registration_record_mismatches(
    registration: Mapping[str, Any],
    *,
    source_event: Mapping[str, Any] | None,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> list[str]:
    mismatches: list[str] = []
    if registration.get("format") != _CALLBACK_REGISTRATION_FORMAT:
        mismatches.append("format")
    if registration.get("record_kind") != "callback_registration":
        mismatches.append("record_kind")
    if registration.get("proof_authority") is not False:
        mismatches.append("proof_authority")
    if registration.get("status") != "complete":
        mismatches.append("status")
    if registration.get("failure") is not None:
        mismatches.append("failure")
    if source_event is None:
        mismatches.append("source_event")
    else:
        event = source_event.get("event")
        event = event if isinstance(event, Mapping) else {}
        if registration.get("instruction_rva") != event.get("instruction_rva"):
            mismatches.append("instruction_rva")
        event_kind = event.get("kind")
        if event_kind not in {"external_call", "indirect_call"}:
            mismatches.append("source_event_kind")
        expected_import = (
            {
                "dll": event.get("dll"),
                "symbol": event.get("symbol"),
                "ordinal": event.get("ordinal"),
            }
            if event_kind == "external_call"
            else None
        )
        if registration.get("import") != expected_import:
            mismatches.append("import")
        if event_kind == "external_call":
            contract = event.get("abi_contract")
            contract = contract if isinstance(contract, Mapping) else {}
            for field in (
                "contract_id",
                "profile_binding",
                "callback_source",
                "callback_abi",
                "callback_lifetime",
            ):
                if contract.get(field) != registration.get(field):
                    mismatches.append(field)

    contract_id = registration.get("contract_id")
    if not isinstance(contract_id, str) or not contract_id:
        mismatches.append("contract_id")
    if not isinstance(registration.get("profile_binding"), Mapping):
        mismatches.append("profile_binding")
    if not isinstance(registration.get("callback_source"), Mapping):
        mismatches.append("callback_source")
    callback_abi = registration.get("callback_abi")
    if not _generic_callback_abi_complete(callback_abi):
        mismatches.append("callback_abi")
    lifetime = registration.get("callback_lifetime")
    if not isinstance(lifetime, (str, Mapping)) or not lifetime:
        mismatches.append("callback_lifetime")
    mismatches.extend(_callback_target_pairing_mismatches(
        registration,
        rows_by_id=rows_by_id,
        reachable_ids=reachable_ids,
    ))
    return sorted(set(mismatches))


def _generic_callback_abi_complete(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    argument_words = _plain_integer(value.get("argument_words"))
    return (
        value.get("kind") == "generic_callback"
        and argument_words is not None
        and 0 <= argument_words <= 256
        and value.get("stack_cleanup_bytes") == argument_words * 4
        and isinstance(value.get("nullable"), bool)
    )


def _callback_target_pairing_mismatches(
    registration: Mapping[str, Any],
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> list[str]:
    target_rvas = registration.get("target_rvas")
    target_unit_ids = registration.get("target_unit_ids")
    finite_rvas = (
        isinstance(target_rvas, list)
        and all(_plain_integer(item) is not None for item in target_rvas)
        and len(set(target_rvas)) == len(target_rvas)
    )
    finite_units = (
        isinstance(target_unit_ids, list)
        and all(isinstance(item, str) and item for item in target_unit_ids)
        and len(set(target_unit_ids)) == len(target_unit_ids)
    )
    if not finite_rvas or not finite_units:
        return ["finite_targets"]
    assert isinstance(target_rvas, list)
    assert isinstance(target_unit_ids, list)
    mismatches: list[str] = []
    if target_rvas != sorted(target_rvas) or target_unit_ids != sorted(target_unit_ids):
        mismatches.append("target_order")
    if len(target_rvas) != len(target_unit_ids):
        mismatches.append("target_pairing")
    else:
        for target_rva, target_unit_id in zip(
            target_rvas, target_unit_ids, strict=True
        ):
            target_row = rows_by_id.get(target_unit_id)
            if (
                target_unit_id not in reachable_ids
                or target_row is None
                or _unit_rva(target_row) != target_rva
            ):
                mismatches.append("target_pairing")
                break
    callback_abi = registration.get("callback_abi")
    nullable = (
        callback_abi.get("nullable")
        if isinstance(callback_abi, Mapping)
        else None
    )
    if not target_rvas and nullable is not True:
        mismatches.append("empty_nonnullable_targets")
    return mismatches


def _callback_registration_mismatches(
    registration: Mapping[str, Any] | None,
    *,
    site_key: tuple[str, int | None],
    selected: _SelectedInterfaceMethod,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> list[str]:
    prefix = "callback_registration"
    if registration is None:
        return [f"{prefix}.missing"]
    method = selected.method
    effect = method.effects
    if effect is None or effect.callback_effect != "explicit":
        return [f"{prefix}.profile_effect"]
    mismatches: list[str] = []
    event_index = site_key[1]
    if (
        registration.get("format")
        != _CALLBACK_REGISTRATION_FORMAT
    ):
        mismatches.append(f"{prefix}.format")
    if registration.get("record_kind") != "callback_registration":
        mismatches.append(f"{prefix}.record_kind")
    if registration.get("proof_authority") is not False:
        mismatches.append(f"{prefix}.proof_authority")
    if registration.get("status") != "complete":
        mismatches.append(f"{prefix}.status")
    if registration.get("failure") is not None:
        mismatches.append(f"{prefix}.failure")
    if (
        registration.get("unit_id") != site_key[0]
        or registration.get("event_index") != event_index
    ):
        mismatches.append(f"{prefix}.source_event")
    source_row = rows_by_id.get(site_key[0])
    source_events = (
        _semantics(source_row, site_key[0]).get("external_events")
        if isinstance(source_row, Mapping)
        else None
    )
    source_event = (
        source_events[event_index]
        if isinstance(source_events, list)
        and isinstance(event_index, int)
        and not isinstance(event_index, bool)
        and 0 <= event_index < len(source_events)
        and isinstance(source_events[event_index], Mapping)
        else None
    )
    if (
        source_event is None
        or registration.get("instruction_rva")
        != source_event.get("instruction_rva")
    ):
        mismatches.append(f"{prefix}.instruction_rva")
    expected_binding = {
        "interface_protocols": [{
            "profile_sha256": selected.profile.sha256,
            "interface_id": method.interface_id,
            "method": method.name,
            "slot": method.slot,
            "callback_arguments": [
                dict(argument) for argument in effect.callback_arguments
            ],
        }]
    }
    if registration.get("profile_binding") != expected_binding:
        mismatches.append(f"{prefix}.profile_binding")
    if registration.get("callback_source") != effect.callback_source:
        mismatches.append(f"{prefix}.callback_source")
    if registration.get("callback_abi") != effect.callback_abi:
        mismatches.append(f"{prefix}.callback_abi")
    if registration.get("callback_lifetime") != effect.callback_lifetime:
        mismatches.append(f"{prefix}.callback_lifetime")

    mismatches.extend(
        f"{prefix}.{field}"
        for field in _callback_target_pairing_mismatches(
            registration,
            rows_by_id=rows_by_id,
            reachable_ids=reachable_ids,
        )
    )
    return mismatches


def _load_interface_effect_contracts(
    paths: Sequence[Path | str],
) -> dict[tuple[str, str, int], _SelectedInterfaceMethod]:
    result: dict[tuple[str, str, int], _SelectedInterfaceMethod] = {}
    profile_ids: set[str] = set()
    for path in paths:
        try:
            profile = load_external_interface_profile(path)
        except ExternalInterfaceProfileError as exc:
            raise StaticHybridCompletenessError(str(exc)) from exc
        if profile.profile_id in profile_ids:
            raise StaticHybridCompletenessError(
                "duplicate external-interface profile ID"
            )
        profile_ids.add(profile.profile_id)
        for interface in profile.interfaces:
            for method in interface.methods:
                key = (profile.profile_id, interface.interface_id, method.slot)
                if key in result:
                    raise StaticHybridCompletenessError("duplicate interface method contract")
                result[key] = _SelectedInterfaceMethod(profile, method)
    return result


def _stack_cleanup_claim_complete(value: Any) -> bool:
    if not isinstance(value, Mapping) or value.get("status") != "complete":
        return False
    transform = value.get("transform")
    if transform is None:
        return _plain_integer(value.get("stack_delta")) is not None
    if (
        not isinstance(transform, Mapping)
        or transform.get("format") != "stage-a-affine-stack-transform-v1"
        or _plain_integer(transform.get("constant")) is None
    ):
        return False
    terms = transform.get("register_terms")
    if not isinstance(terms, list):
        return False
    registers: set[str] = set()
    for raw in terms:
        if not isinstance(raw, Mapping):
            return False
        register = raw.get("register")
        coefficient = _plain_integer(raw.get("coefficient"))
        if (
            register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp"}
            or register in registers
            or coefficient is None
            or coefficient == 0
            or abs(coefficient) > 16
        ):
            return False
        registers.add(str(register))
    expected_delta = transform["constant"] if not terms else None
    return value.get("stack_delta") == expected_delta


def _internal_summary_graph_problems(
    summary: Mapping[str, Any],
    *,
    target_unit_id: str,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    units_by_rva: Mapping[int, list[str]],
    binary_sha256: str,
) -> list[str]:
    closure: set[str] = {target_unit_id}
    pending = [target_unit_id]
    while pending:
        unit_id = pending.pop()
        control = rows_by_id[unit_id].get("control")
        if not isinstance(control, Mapping):
            return [f"{unit_id}.control"]
        targets = control.get("direct_targets")
        if not isinstance(targets, list):
            return [f"{unit_id}.direct_targets"]
        for target_rva in targets:
            if _plain_integer(target_rva) is None:
                return [f"{unit_id}.direct_target"]
            matches = units_by_rva.get(int(target_rva), [])
            if len(matches) != 1:
                return [f"{unit_id}.direct_target_binding"]
            target = matches[0]
            if target not in closure:
                closure.add(target)
                pending.append(target)

    problems: list[str] = []
    return_ids = summary.get("return_unit_ids")
    if not isinstance(return_ids, list):
        return ["return_unit_ids"]
    reported_returns = {
        str(unit_id) for unit_id in return_ids if isinstance(unit_id, str)
    }
    if reported_returns - closure:
        problems.append("return_units_outside_normal_closure")
    decoded_returns = {
        unit_id
        for unit_id in closure
        if isinstance(rows_by_id[unit_id].get("control"), Mapping)
        and rows_by_id[unit_id]["control"].get("kind") == "return"
    }
    if decoded_returns - reported_returns:
        problems.append("decoded_returns_omitted")

    declared = summary.get("declared_internal_contract")
    if isinstance(declared, Mapping):
        body = declared.get("body_units")
        if not isinstance(body, list):
            problems.append("declared_body_units")
        else:
            bound: dict[str, str] = {}
            for raw in body:
                if not isinstance(raw, Mapping):
                    problems.append("declared_body_unit_shape")
                    continue
                unit_id = raw.get("unit_id")
                digest = raw.get("contract_sha256")
                if not isinstance(unit_id, str) or unit_id in bound:
                    problems.append("declared_body_unit_identity")
                    continue
                bound[unit_id] = str(digest)
            if set(bound) != closure:
                problems.append("declared_body_closure")
            for unit_id in set(bound) & rows_by_id.keys():
                source = rows_by_id[unit_id].get("source")
                expected = (
                    source.get("contract_sha256")
                    if isinstance(source, Mapping)
                    else None
                )
                if bound[unit_id] != expected:
                    problems.append(f"declared_body_hash:{unit_id}")
        source = rows_by_id[target_unit_id].get("source")
        original = source.get("original") if isinstance(source, Mapping) else None
        expected_binding = {
            "binary_sha256": binary_sha256,
            "entry_unit_id": target_unit_id,
            "entry_rva": (
                original.get("rva_start") if isinstance(original, Mapping) else None
            ),
            "entry_contract_sha256": (
                source.get("contract_sha256") if isinstance(source, Mapping) else None
            ),
            "entry_instruction_bytes_sha256": (
                source.get("instruction_bytes_sha256")
                if isinstance(source, Mapping)
                else None
            ),
            "body_unit_count": len(closure),
            "replacement_authority": False,
        }
        for field, expected in expected_binding.items():
            if declared.get(field) != expected:
                problems.append(f"declared_{field}")
    elif summary.get("reached_units") != len(closure):
        problems.append("reached_unit_count")
    return sorted(set(problems))


def _summary_may_return(summary: Mapping[str, Any]) -> bool:
    behavior = summary.get("return_behavior")
    return isinstance(behavior, Mapping) and behavior.get("may_return") is True


def _continuation_closed(
    return_rva: Any,
    *,
    rows_by_id: Mapping[str, Mapping[str, Any]],
    reachable_ids: set[str],
) -> bool:
    if not isinstance(return_rva, int) or isinstance(return_rva, bool):
        return False
    return sum(
        _unit_rva(rows_by_id[unit_id]) == return_rva
        for unit_id in reachable_ids
    ) == 1


def _unit_rva(row: Mapping[str, Any]) -> int | None:
    source = row.get("source")
    original = source.get("original") if isinstance(source, Mapping) else None
    value = original.get("rva_start") if isinstance(original, Mapping) else None
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _row_location(row: Mapping[str, Any]) -> dict[str, Any]:
    return {"unit_id": row.get("id"), "rva_start": _unit_rva(row)}


def _read_object(path: Path, context: str) -> Mapping[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticHybridCompletenessError(f"cannot read {context}: {exc}") from exc
    return _object(value, context)


def _read_jsonl(path: Path) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    try:
        with path.open(encoding="utf-8") as source:
            for line_number, line in enumerate(source, 1):
                if not line.strip():
                    continue
                result.append(_object(json.loads(line), f"machine IR line {line_number}"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StaticHybridCompletenessError(f"cannot read machine IR: {exc}") from exc
    return result


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StaticHybridCompletenessError(f"{context} must be an object")
    return value


def _list(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StaticHybridCompletenessError(f"{context} must be a list")
    return value


def _string_set(value: Any, context: str) -> set[str]:
    rows = _list(value, context)
    if any(not isinstance(item, str) or not item for item in rows):
        raise StaticHybridCompletenessError(f"{context} must contain nonempty strings")
    if len(set(rows)) != len(rows):
        raise StaticHybridCompletenessError(f"{context} contains duplicates")
    return set(rows)


__all__ = [
    "STATIC_HYBRID_COMPLETENESS_FORMAT",
    "StaticHybridCompletenessError",
    "write_static_hybrid_completeness_report",
]
