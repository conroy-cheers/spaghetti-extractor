"""Narrow command adapters for the strict static-first v2 authority pipeline."""

from __future__ import annotations

import json
import tempfile
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from .external_site_proposals_v2 import build_external_site_proposals_v2
from .entry_state_analysis_v2 import derive_callback_entry_state_contracts_v2
from .hybrid_authority_v2 import canonical_json_bytes
from .launch_profile_v2 import (
    LaunchProfileStatus,
    build_launch_profile_v2,
    finalize_launch_profile_v2,
    parse_launch_profile_v2,
    validate_launch_profile_v2,
)
from .stage_b_candidate_authority_v2 import (
    CandidateAuthorityV2Receipt,
    build_stage_b_candidate_authority_v2,
    validate_stage_b_candidate_authority_v2,
)
from .static_hybrid_authority_v2 import validate_static_hybrid_authority_v2
from .static_hybrid_final_audit_v2 import validate_static_hybrid_final_audit_v2
from .static_hybrid_pipeline_v2 import run_static_hybrid_pipeline_v2
from .stage_binary import _parse_stage_a_pe
from .util import sha256_file


_STATIC_ARTIFACTS = (
    "rooted-control-graph-v2.json",
    "global-slot-analysis-v2.json",
    "callback-entry-state-v2.json",
    "entry-state-analysis-v2.json",
    "interprocedural-analysis-v2.json",
    "external-profile-authority-v2.json",
    "exception-invariant-proposals-v2.json",
    "exception-invariant-replay-reports-v2.json",
    "static-hybrid-authority-v2.json",
    "authority-bundle-v2.json",
    "static-hybrid-final-audit-v2.json",
    "pipeline-summary-v2.json",
)


class AuthorityV2CommandError(ValueError):
    """A command input cannot participate in the strict v2 authority graph."""


def build_base_launch_profile_v2_from_paths(
    *,
    original: Path,
    behavioral_roots: Path,
    assumptions: Path,
    feature_inventory: Path,
    out: Path,
) -> dict[str, Any]:
    """Build the exact static launch half before callback roots are known."""

    binary = _parse_stage_a_pe(original)
    profile = build_launch_profile_v2(
        pe_sha256=binary.sha256,
        image_base=binary.image_base,
        size_of_image=binary.size_of_image,
        behavioral_roots=_read_object(behavioral_roots, "behavioral roots"),
        assumptions=_read_object(assumptions, "launch assumptions"),
        callback_roots=(),
        feature_inventory=_read_object(
            feature_inventory, "launch feature inventory"
        ),
    )
    payload = profile.to_payload()
    _write_canonical_json(out, payload)
    return payload


def derive_callback_entry_contracts_v2_from_paths(
    *,
    original: Path,
    machine_ir: Path,
    interface_provenance: Path,
    global_slot_invariants: Path,
    out: Path,
) -> dict[str, Any]:
    """Derive callback entry contracts from exact static machine evidence."""

    binary = _parse_stage_a_pe(original)
    result = derive_callback_entry_state_contracts_v2(
        pe_sha256=binary.sha256,
        image_base=binary.image_base,
        size_of_image=binary.size_of_image,
        interface_provenance=_read_object(
            interface_provenance, "interface provenance"
        ),
        units=_read_jsonl_objects(machine_ir, "machine IR"),
        machine_ir_sha256=sha256_file(machine_ir),
        global_slot_invariants=_global_slot_invariant_rows(
            global_slot_invariants
        ),
    )
    _write_canonical_json(out, result)
    return result


def finalize_launch_profile_v2_from_paths(
    *,
    base_launch_profile: Path,
    behavioral_roots: Path,
    callback_entry_contracts: Path,
    out: Path,
) -> dict[str, Any]:
    """Finalize one base profile with checked event-derived callback roots."""

    base = parse_launch_profile_v2(
        _read_object(base_launch_profile, "base launch profile")
    )
    roots = _read_object(behavioral_roots, "behavioral roots")
    base_check = validate_launch_profile_v2(
        base.to_payload(),
        pe_sha256=base.binary.pe_sha256,
        image_base=base.binary.image_base,
        size_of_image=base.binary.size_of_image,
        behavioral_roots=roots,
    )
    if base_check.status is LaunchProfileStatus.VIOLATED:
        raise AuthorityV2CommandError(
            "base launch profile contains contradictory evidence"
        )
    blocking_base_issues = [
        issue
        for issue in base_check.issues
        if issue.code != "callback_entry_state_unchecked"
    ]
    if blocking_base_issues:
        codes = ", ".join(sorted({issue.code for issue in blocking_base_issues}))
        raise AuthorityV2CommandError(
            f"base launch profile is incomplete before callback finalization: {codes}"
        )
    assumptions = {
        assumption.kind: assumption.value.to_value()
        for assumption in base.assumptions
    }
    features = {
        kind: [site.to_value() for site in sites]
        for kind, sites in base.feature_inventory
    }
    finalized = finalize_launch_profile_v2(
        pe_sha256=base.binary.pe_sha256,
        image_base=base.binary.image_base,
        size_of_image=base.binary.size_of_image,
        behavioral_roots=roots,
        assumptions=assumptions,
        callback_entry_state=_read_object(
            callback_entry_contracts, "callback entry contracts"
        ),
        feature_inventory=features,
    )
    payload = finalized.to_payload()
    _write_canonical_json(out, payload)
    return payload


def build_external_site_proposals_v2_from_paths(
    *,
    legacy_v1_diagnostic: Path,
    machine_ir: Path,
    original: Path,
    out: Path,
) -> dict[str, Any]:
    """Isolate legacy normalized rows as untrusted, exact-bound proposals."""

    diagnostic = _read_object(legacy_v1_diagnostic, "legacy v1 diagnostic")
    rows = diagnostic.get("checked_external_sites")
    if not isinstance(rows, list):
        raise AuthorityV2CommandError(
            "legacy diagnostic has no normalized checked-external-site inventory"
        )
    result = build_external_site_proposals_v2(
        checked_sites=[
            _object(row, f"checked external site {index}")
            for index, row in enumerate(rows)
        ],
        pe_sha256=_parse_stage_a_pe(original).sha256,
        machine_ir_sha256=sha256_file(machine_ir),
        source_diagnostic_sha256=sha256_file(legacy_v1_diagnostic),
    )
    _write_canonical_json(out, result)
    return result


def build_static_hybrid_authority_v2_from_paths(
    *,
    machine_ir: Path,
    machine_ir_manifest: Path,
    original: Path,
    behavioral_roots: Path,
    legacy_v1_diagnostic: Path | None,
    checked_external_sites: Path | None = None,
    external_profile_authority: Path | None = None,
    isa_requirements: Path,
    isa_selection_authority: Path,
    launch_profile: Path | None = None,
    launch_invariants: Path | None = None,
    checked_exception_reports: Sequence[Path] = (),
    entry_range_facts: Sequence[Path] = (),
    world_range_facts: Sequence[Path] = (),
    machine_import_profiles: Sequence[Path] = (),
    external_interface_profiles: Sequence[Path] = (),
    external_operation_profiles: Sequence[Path] = (),
    callable_external_profiles: Sequence[Path] = (),
    internal_function_contract_profiles: Sequence[Path] = (),
    static_recovery_inventory: Path | None = None,
    out: Path,
) -> dict[str, Any]:
    """Run the generic path-based static pipeline without generating a PE."""

    selected_launch_profile = _selected_launch_profile(
        launch_profile=launch_profile,
        deprecated_launch_invariants=launch_invariants,
    )
    return run_static_hybrid_pipeline_v2(
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        original_pe=original,
        behavioral_roots=behavioral_roots,
        legacy_completeness=legacy_v1_diagnostic,
        checked_external_sites=checked_external_sites,
        external_profile_authority=external_profile_authority,
        isa_requirements=isa_requirements,
        isa_selection_authority=isa_selection_authority,
        launch_invariants=selected_launch_profile,
        checked_exception_reports=checked_exception_reports,
        entry_range_facts=_fact_rows(entry_range_facts, "entry range facts"),
        world_range_facts=_fact_rows(world_range_facts, "world range facts"),
        machine_import_profiles=machine_import_profiles,
        external_interface_profiles=external_interface_profiles,
        external_operation_profiles=external_operation_profiles,
        callable_external_profiles=callable_external_profiles,
        internal_function_contract_profiles=internal_function_contract_profiles,
        static_recovery_inventory=static_recovery_inventory,
        out_dir=out,
    )


def validate_static_hybrid_authority_v2_from_paths(
    *,
    pipeline: Path,
    machine_ir: Path,
    machine_ir_manifest: Path,
    original: Path,
    behavioral_roots: Path,
    legacy_v1_diagnostic: Path | None,
    checked_external_sites: Path | None = None,
    external_profile_authority: Path | None = None,
    isa_requirements: Path,
    isa_selection_authority: Path,
    launch_profile: Path | None = None,
    launch_invariants: Path | None = None,
    checked_exception_reports: Sequence[Path] = (),
    entry_range_facts: Sequence[Path] = (),
    world_range_facts: Sequence[Path] = (),
    machine_import_profiles: Sequence[Path] = (),
    external_interface_profiles: Sequence[Path] = (),
    external_operation_profiles: Sequence[Path] = (),
    callable_external_profiles: Sequence[Path] = (),
    internal_function_contract_profiles: Sequence[Path] = (),
    static_recovery_inventory: Path | None = None,
    out: Path | None = None,
) -> dict[str, Any]:
    """Cold-rerun the static pipeline and reject stale phase artifacts."""

    with tempfile.TemporaryDirectory(prefix="spaghetti-static-v2-") as temporary:
        replay_dir = Path(temporary)
        expected_summary = build_static_hybrid_authority_v2_from_paths(
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
            original=original,
            behavioral_roots=behavioral_roots,
            legacy_v1_diagnostic=legacy_v1_diagnostic,
            checked_external_sites=checked_external_sites,
            external_profile_authority=external_profile_authority,
            isa_requirements=isa_requirements,
            isa_selection_authority=isa_selection_authority,
            launch_profile=launch_profile,
            launch_invariants=launch_invariants,
            checked_exception_reports=checked_exception_reports,
            entry_range_facts=entry_range_facts,
            world_range_facts=world_range_facts,
            machine_import_profiles=machine_import_profiles,
            external_interface_profiles=external_interface_profiles,
            external_operation_profiles=external_operation_profiles,
            callable_external_profiles=callable_external_profiles,
            internal_function_contract_profiles=internal_function_contract_profiles,
            static_recovery_inventory=static_recovery_inventory,
            out=replay_dir,
        )
        for name in _STATIC_ARTIFACTS:
            observed_path = pipeline / name
            expected_path = replay_dir / name
            if observed_path.exists() != expected_path.exists():
                raise AuthorityV2CommandError(
                    f"static v2 artifact inventory is stale at {name}"
                )
            if expected_path.exists() and _read_json(
                observed_path, f"observed {name}"
            ) != _read_json(expected_path, f"replayed {name}"):
                raise AuthorityV2CommandError(
                    f"static v2 artifact is stale or binds different inputs: {name}"
                )

    static_path = pipeline / "static-hybrid-authority-v2.json"
    validate_static_hybrid_authority_v2(
        _read_object(static_path, "static-hybrid authority")
    )
    bundle_path = pipeline / "authority-bundle-v2.json"
    audit_path = pipeline / "static-hybrid-final-audit-v2.json"
    if bundle_path.exists() or audit_path.exists():
        if not bundle_path.exists() or not audit_path.exists():
            raise AuthorityV2CommandError(
                "static v2 bundle and final audit must either both exist or both be absent"
            )
        validate_static_hybrid_final_audit_v2(
            _read_object(audit_path, "static-hybrid final audit"),
            static_authority=static_path,
            authority_bundle=bundle_path,
            machine_ir=machine_ir,
            machine_ir_manifest=machine_ir_manifest,
        )
    if out is not None:
        _write_canonical_json(out, expected_summary)
    return expected_summary


def build_candidate_authority_v2_from_paths(
    *,
    final_static_hybrid_audit: Path,
    authority_bundle: Path,
    machine_ir: Path,
    machine_ir_manifest: Path,
    fallback_coverage_receipt: Path,
    legacy_v1_diagnostics: Sequence[Path] = (),
    out: Path,
) -> dict[str, Any]:
    """Build a strict candidate receipt; v1 inputs remain diagnostic-only."""

    receipt = build_stage_b_candidate_authority_v2(
        final_static_hybrid_audit=final_static_hybrid_audit,
        authority_bundle=authority_bundle,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        fallback_coverage_receipt=fallback_coverage_receipt,
        legacy_diagnostic_artifacts=legacy_v1_diagnostics,
    )
    _write_candidate_receipt(out, receipt)
    return receipt.to_payload()


def validate_candidate_authority_v2_from_paths(
    *,
    receipt: Path,
    final_static_hybrid_audit: Path,
    authority_bundle: Path,
    machine_ir: Path,
    machine_ir_manifest: Path,
    fallback_coverage_receipt: Path,
    legacy_v1_diagnostics: Sequence[Path] = (),
    out: Path | None = None,
) -> dict[str, Any]:
    """Recompute a candidate receipt from exact inputs and return its status."""

    validated = validate_stage_b_candidate_authority_v2(
        receipt=receipt,
        final_static_hybrid_audit=final_static_hybrid_audit,
        authority_bundle=authority_bundle,
        machine_ir=machine_ir,
        machine_ir_manifest=machine_ir_manifest,
        fallback_coverage_receipt=fallback_coverage_receipt,
        legacy_diagnostic_artifacts=legacy_v1_diagnostics,
        require_authorized=False,
    )
    if out is not None:
        _write_candidate_receipt(out, validated)
    return validated.to_payload()


def _fact_rows(paths: Sequence[Path], label: str) -> list[Mapping[str, Any]]:
    result: list[Mapping[str, Any]] = []
    for index, path in enumerate(paths):
        value = _read_json(path, f"{label} input {index}")
        rows: Any = value
        if isinstance(value, Mapping):
            rows = value.get("facts", [value])
        if not isinstance(rows, list):
            raise AuthorityV2CommandError(f"{label} input {index} must contain an array")
        result.extend(
            _object(row, f"{label} input {index} row {row_index}")
            for row_index, row in enumerate(rows)
        )
    return result


def _global_slot_invariant_rows(path: Path) -> list[Mapping[str, Any]]:
    value = _read_json(path, "global-slot invariants")
    rows: Any
    if isinstance(value, list):
        rows = value
    elif isinstance(value, Mapping) and isinstance(
        value.get("global_slot_invariants"), list
    ):
        rows = value["global_slot_invariants"]
    elif isinstance(value, Mapping) and {
        "format", "content_id", "slot_rva"
    } <= set(value):
        rows = [value]
    else:
        raise AuthorityV2CommandError(
            "global-slot invariant input must be a strict record or inventory"
        )
    return [
        _object(row, f"global-slot invariant {index}")
        for index, row in enumerate(rows)
    ]


def _read_jsonl_objects(path: Path, label: str) -> list[Mapping[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeError) as exc:
        raise AuthorityV2CommandError(f"cannot read {label}: {exc}") from exc
    result: list[Mapping[str, Any]] = []
    for index, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            value = json.loads(
                line,
                object_pairs_hook=_unique_object,
                parse_float=_reject_float,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, ValueError) as exc:
            raise AuthorityV2CommandError(
                f"cannot read {label} line {index}: {exc}"
            ) from exc
        result.append(_object(value, f"{label} line {index}"))
    return result


def _selected_launch_profile(
    *,
    launch_profile: Path | None,
    deprecated_launch_invariants: Path | None,
) -> Path | None:
    if launch_profile is not None and deprecated_launch_invariants is not None:
        raise AuthorityV2CommandError(
            "submit --launch-profile only; the deprecated launch-invariants input conflicts"
        )
    return launch_profile or deprecated_launch_invariants


def _read_object(path: Path, label: str) -> Mapping[str, Any]:
    return _object(_read_json(path, label), label)


def _read_json(path: Path, label: str) -> Any:
    try:
        return json.loads(
            path.read_text(encoding="utf-8"),
            object_pairs_hook=_unique_object,
            parse_float=_reject_float,
            parse_constant=_reject_constant,
        )
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        raise AuthorityV2CommandError(f"cannot read {label}: {exc}") from exc


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise AuthorityV2CommandError(f"{label} must be an object")
    return value


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def _reject_float(value: str) -> Any:
    raise ValueError(f"floating-point value {value} is not canonical evidence")


def _reject_constant(value: str) -> Any:
    raise ValueError(f"JSON constant {value} is not canonical evidence")


def _write_candidate_receipt(
    path: Path, receipt: CandidateAuthorityV2Receipt
) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(receipt.to_json(), encoding="ascii")


def _write_canonical_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(canonical_json_bytes(value))


__all__ = [
    "AuthorityV2CommandError",
    "build_base_launch_profile_v2_from_paths",
    "build_candidate_authority_v2_from_paths",
    "derive_callback_entry_contracts_v2_from_paths",
    "finalize_launch_profile_v2_from_paths",
    "build_static_hybrid_authority_v2_from_paths",
    "validate_candidate_authority_v2_from_paths",
    "validate_static_hybrid_authority_v2_from_paths",
]
