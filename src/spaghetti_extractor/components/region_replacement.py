"""Contracts and candidate-only validation for regional C replacements.

This module deliberately consumes no original executable or source.  A
replacement is bound to stable machine-IR and cluster identities, while its
behavior is checked against observations from the generated baseline.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..stage_binary import StageAInputError
from ..util import sha256_file, write_json
from .region_replacement_model import (
    REGION_OBSERVATIONS_FORMAT,
    REGION_OVERRIDE_TABLE_FORMAT,
    REGION_REPLACEMENT_BUNDLE_FORMAT,
    REGION_REPLACEMENT_FORMAT,
    REGION_REPLACEMENT_VALIDATION_FORMAT,
    _REGION_REPLACEMENT_FORMATS,
    RegionOverrideTableArtifacts,
    RegionReplacementManifest,
    _array,
    _canonical_sha256,
    _json_copy,
    _object,
)
from .region_replacement_render import (
    _override_entry,
    _render_override_header,
    _render_override_source,
    _validate_override_inventory,
)
from .region_replacement_schema import (
    _canonical_json_value,
    _normalize_manifest,
    _normalize_observations,
    _parse_manifest,
    _read_json_object,
    _relative_path,
)


def write_region_replacement_manifest(
    path: Path,
    payload: Mapping[str, Any],
    *,
    source_root: Path,
) -> RegionReplacementManifest:
    """Canonicalize, bind, verify, and write a replacement manifest."""

    raw = _json_copy(payload)
    raw.pop("manifest_sha256", None)
    if raw.get("format") not in _REGION_REPLACEMENT_FORMATS:
        raise StageAInputError(
            "region replacement manifest must use a supported version: "
            f"{sorted(_REGION_REPLACEMENT_FORMATS)}"
        )
    normalized = _normalize_manifest(raw, expect_digest=False)
    normalized["manifest_sha256"] = _canonical_sha256(normalized)
    manifest = _parse_manifest(normalized)
    _verify_source_binding(manifest, Path(source_root))
    write_json(Path(path), manifest.to_payload())
    return manifest


def load_region_replacement_manifest(
    path: Path,
    *,
    source_root: Path,
) -> RegionReplacementManifest:
    payload = _read_json_object(Path(path), "region replacement manifest")
    manifest = _parse_manifest(payload)
    _verify_source_binding(manifest, Path(source_root))
    return manifest


def validate_region_replacement(
    *,
    manifest: Path | Mapping[str, Any] | RegionReplacementManifest,
    baseline_observations: Path | Mapping[str, Any],
    replacement_observations: Path | Mapping[str, Any],
    source_root: Path,
    out: Path | None = None,
) -> dict[str, Any]:
    """Compare candidate-only baseline and replacement observations.

    Structural absence or an invalid test setup is ``incomplete``.  A concrete
    difference in outputs, memory, control, faults, or external events is
    ``violated``.  A violated result dominates incomplete diagnostics because
    it is already a concrete counterexample to the regional contract.
    """

    contract = _coerce_manifest(manifest, source_root=Path(source_root))
    deltas: list[dict[str, Any]] = []
    for evidence in contract.evidence:
        status = str(evidence["status"])
        if status != "qualified":
            _append_delta(
                deltas,
                contract,
                status=status,
                family="evidence",
                case_id=None,
                path=f"/evidence/{_pointer(str(evidence['id']))}",
                expected="qualified",
                observed=status,
                message=f"evidence {evidence['id']} is not qualified",
                next_action="close or replace the named evidence before qualifying the region",
            )

    baseline = _load_observations_for_validation(
        baseline_observations, contract, "baseline", deltas
    )
    replacement = _load_observations_for_validation(
        replacement_observations, contract, "replacement", deltas
    )
    compared_cases = 0
    if baseline is not None and replacement is not None:
        baseline_cases = {case["id"]: case for case in baseline["cases"]}
        replacement_cases = {case["id"]: case for case in replacement["cases"]}
        if not baseline_cases:
            _append_delta(
                deltas,
                contract,
                status="incomplete",
                family="case_inventory",
                case_id=None,
                path="/cases",
                expected="at least one baseline case",
                observed=[],
                message="the baseline observation set is empty",
                next_action="capture candidate-only baseline observations for this region",
            )
        for case_id in sorted(set(baseline_cases) - set(replacement_cases)):
            _append_delta(
                deltas,
                contract,
                status="incomplete",
                family="case_inventory",
                case_id=case_id,
                path=f"/cases/{_pointer(case_id)}",
                expected="replacement observation",
                observed=None,
                message=f"replacement observations omit case {case_id}",
                next_action="run the replacement on the missing baseline case",
            )
        for case_id in sorted(set(replacement_cases) - set(baseline_cases)):
            _append_delta(
                deltas,
                contract,
                status="incomplete",
                family="case_inventory",
                case_id=case_id,
                path=f"/cases/{_pointer(case_id)}",
                expected="matching baseline observation",
                observed="replacement-only case",
                message=f"case {case_id} has no baseline observation",
                next_action="capture the same case from the generated baseline",
            )
        for case_id in sorted(set(baseline_cases) & set(replacement_cases)):
            baseline_case = baseline_cases[case_id]
            replacement_case = replacement_cases[case_id]
            _check_case_against_contract(
                contract, baseline_case, side="baseline", deltas=deltas
            )
            _check_case_against_contract(
                contract, replacement_case, side="replacement", deltas=deltas
            )
            _compare_cases(contract, baseline_case, replacement_case, deltas)
            compared_cases += 1

    deltas.sort(
        key=lambda item: (
            0 if item["status"] == "violated" else 1,
            item["family"],
            item["case_id"] or "",
            item["path"],
            item["id"],
        )
    )
    status = (
        "violated"
        if any(item["status"] == "violated" for item in deltas)
        else "incomplete"
        if deltas
        else "qualified"
    )
    report = {
        "format": REGION_REPLACEMENT_VALIDATION_FORMAT,
        "status": status,
        "executes_original_binary": False,
        "bindings": {
            "replacement_manifest_sha256": contract.manifest_sha256,
            "machine_ir_sha256": contract.bindings["machine_ir_sha256"],
            "baseline_program_sha256": contract.bindings[
                "baseline_program_sha256"
            ],
            "baseline_observations_sha256": (
                None if baseline is None else _canonical_sha256(baseline)
            ),
            "replacement_observations_sha256": (
                None if replacement is None else _canonical_sha256(replacement)
            ),
        },
        "counts": {
            "compared_cases": compared_cases,
            "deltas": len(deltas),
            "violated": sum(item["status"] == "violated" for item in deltas),
            "incomplete": sum(item["status"] == "incomplete" for item in deltas),
        },
        "deltas": deltas,
    }
    if out is not None:
        write_json(Path(out), report)
    return report


def generate_region_override_table(
    *,
    manifests: Sequence[Path | Mapping[str, Any] | RegionReplacementManifest],
    source_root: Path,
    out_dir: Path,
    runtime_header: str = "state-machine-runtime.h",
    fallback_on_unimplemented_ids: Sequence[str] = (),
) -> RegionOverrideTableArtifacts:
    """Generate a deterministic interpreter override lookup table."""

    if not manifests:
        raise StageAInputError("region override table requires at least one manifest")
    runtime_header = _relative_path(runtime_header, "override runtime header")
    contracts = [
        _coerce_manifest(item, source_root=Path(source_root)) for item in manifests
    ]
    _validate_override_inventory(contracts)
    contracts.sort(key=lambda item: (int(item.cluster["entry_rva"]), item.id))
    fallback_ids = {str(value) for value in fallback_on_unimplemented_ids}
    contract_ids = {item.id for item in contracts}
    unknown_fallbacks = fallback_ids.difference(contract_ids)
    if unknown_fallbacks:
        raise StageAInputError(
            "override fallback IDs are absent from the manifest inventory: "
            + ", ".join(sorted(unknown_fallbacks))
        )

    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    header_path = out_dir / "region-overrides.h"
    source_path = out_dir / "region-overrides.c"
    manifest_path = out_dir / "region-overrides-manifest.json"
    header_path.write_text(
        _render_override_header(contracts, runtime_header), encoding="ascii"
    )
    source_path.write_text(
        _render_override_source(contracts, fallback_ids), encoding="ascii"
    )

    entries = [
        _override_entry(
            contract,
            fallback_on_unimplemented=contract.id in fallback_ids,
        )
        for contract in contracts
    ]
    table_core = {
        "machine_ir_sha256": contracts[0].bindings["machine_ir_sha256"],
        "baseline_program_sha256": contracts[0].bindings[
            "baseline_program_sha256"
        ],
        "entries": entries,
    }
    payload = {
        "format": REGION_OVERRIDE_TABLE_FORMAT,
        "status": "ready",
        "executes_original_binary": False,
        "table_sha256": _canonical_sha256(table_core),
        **table_core,
        "artifacts": {
            "header": {"path": header_path.name, "sha256": sha256_file(header_path)},
            "source": {"path": source_path.name, "sha256": sha256_file(source_path)},
        },
        "checks": {
            "manifest_hashes": "verified",
            "source_hashes": "verified",
            "unique_ids": "verified",
            "unique_units": "verified",
            "unique_entry_rvas": "verified",
            "non_overlapping_rva_spans": "verified",
            "qualified_evidence": "verified",
            "guarded_fallbacks": "verified",
        },
    }
    write_json(manifest_path, payload)
    return RegionOverrideTableArtifacts(
        header=header_path,
        source=source_path,
        manifest=manifest_path,
        count=len(contracts),
    )


def _verify_source_binding(manifest: RegionReplacementManifest, root: Path) -> Path:
    root = root.resolve()
    source = manifest.source
    unresolved = root / str(source["path"])
    if unresolved.is_symlink():
        raise StageAInputError("replacement source must be a regular non-symlink file")
    path = unresolved.resolve()
    if path == root or root not in path.parents:
        raise StageAInputError("replacement source escapes its declared source root")
    if path.is_symlink() or not path.is_file():
        raise StageAInputError("replacement source must be a regular non-symlink file")
    if sha256_file(path) != source["sha256"]:
        raise StageAInputError("replacement source hash does not match its manifest")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeDecodeError as exc:
        raise StageAInputError("replacement source must be UTF-8 text") from exc
    if int(source["line_end"]) > len(lines):
        raise StageAInputError("replacement source location exceeds the source file")
    selected = "\n".join(
        lines[int(source["line_start"]) - 1 : int(source["line_end"])]
    )
    if re.search(rf"\b{re.escape(str(source['symbol']))}\b", selected) is None:
        raise StageAInputError(
            "replacement source symbol is outside its declared source location"
        )
    for support in manifest.support_sources:
        unresolved_support = root / str(support["path"])
        if unresolved_support.is_symlink():
            raise StageAInputError(
                "replacement support source must be a regular non-symlink file"
            )
        support_path = unresolved_support.resolve()
        if support_path == root or root not in support_path.parents:
            raise StageAInputError("replacement support source escapes its source root")
        if support_path.is_symlink() or not support_path.is_file():
            raise StageAInputError("replacement support source must be a regular file")
        if sha256_file(support_path) != support["sha256"]:
            raise StageAInputError(
                "replacement support source hash does not match its manifest"
            )
    return path


def _load_observations_for_validation(
    value: Path | Mapping[str, Any],
    manifest: RegionReplacementManifest,
    side: str,
    deltas: list[dict[str, Any]],
) -> dict[str, Any] | None:
    try:
        payload = (
            _read_json_object(value, f"{side} region observations")
            if isinstance(value, Path)
            else _object(value, f"{side} region observations")
        )
        return _normalize_observations(payload, manifest)
    except (StageAInputError, OSError, json.JSONDecodeError) as exc:
        _append_delta(
            deltas,
            manifest,
            status="incomplete",
            family="observation_schema",
            case_id=None,
            path="/",
            expected=REGION_OBSERVATIONS_FORMAT,
            observed=str(exc),
            message=f"{side} observation artifact is unusable",
            next_action=f"regenerate structurally valid {side} observations",
        )
        return None


def _check_case_against_contract(
    manifest: RegionReplacementManifest,
    case: Mapping[str, Any],
    *,
    side: str,
    deltas: list[dict[str, Any]],
) -> None:
    case_id = str(case["id"])
    if case["entry_unit_id"] != manifest.cluster["entry_unit_id"]:
        _append_delta(
            deltas, manifest, status="incomplete", family="test_setup",
            case_id=case_id, path="/entry_unit_id",
            expected=manifest.cluster["entry_unit_id"], observed=case["entry_unit_id"],
            message=f"{side} case starts at the wrong unit",
            next_action="invoke both implementations at the declared cluster entry",
        )
    live = _object(manifest.payload["live_state"], "manifest live state")
    for field in ("live_inputs", "live_outputs"):
        declaration_field = "inputs" if field == "live_inputs" else "outputs"
        expected = {item["id"] for item in live[declaration_field]}
        observed = {item["id"] for item in case[field]}
        _inventory_deltas(
            manifest, deltas, side=side, case_id=case_id, family=field,
            expected=expected, observed=observed, path=f"/{field}",
        )
    view_declarations = {
        item["id"]: item for item in manifest.payload["memory_views"]
    }
    observed_views = {item["id"]: item for item in case["memory_views"]}
    _inventory_deltas(
        manifest, deltas, side=side, case_id=case_id, family="memory_view",
        expected=set(view_declarations), observed=set(observed_views), path="/memory_views",
    )
    for view_id in sorted(set(view_declarations) & set(observed_views)):
        declared_length = view_declarations[view_id]["byte_length"]
        if declared_length is None:
            continue
        for phase in ("before", "after"):
            observed_length = len(observed_views[view_id][phase]) // 2
            if observed_length != declared_length:
                _append_delta(
                    deltas, manifest, status="incomplete", family="memory_view",
                    case_id=case_id,
                    path=f"/memory_views/{_pointer(view_id)}/{phase}",
                    expected=declared_length, observed=observed_length,
                    message=f"{side} memory view {view_id} has the wrong byte length",
                    next_action="capture the complete declared memory view",
                )

    control = case["control"]
    control_catalog = {item["id"]: item for item in manifest.payload["expectations"]["control"]}
    expected_control = control_catalog.get(control["id"])
    if expected_control is None:
        _contract_expectation_delta(
            manifest, deltas, side, case_id, "control", "/control/id",
            sorted(control_catalog), control["id"], "control exit is not declared",
        )
    elif control["kind"] != expected_control["kind"] or not _control_target_allowed(
        control, expected_control
    ):
        _contract_expectation_delta(
            manifest, deltas, side, case_id, "control", "/control",
            expected_control, control, "control exit does not satisfy its declaration",
        )

    fault_contract = manifest.payload["expectations"]["fault"]
    fault_catalog = {item["id"]: item for item in fault_contract["variants"]}
    fault = case["fault"]
    if fault is None and not fault_contract["allow_none"]:
        _contract_expectation_delta(
            manifest, deltas, side, case_id, "fault", "/fault",
            "one declared fault", None, "a required fault is absent",
        )
    elif fault is not None:
        expected_fault = fault_catalog.get(fault["id"])
        if expected_fault is None or expected_fault["kind"] != fault["kind"]:
            _contract_expectation_delta(
                manifest, deltas, side, case_id, "fault", "/fault",
                sorted(fault_catalog), fault, "fault is not declared",
            )

    event_catalog = {
        item["id"]: item for item in manifest.payload["expectations"]["external_events"]
    }
    for index, event in enumerate(case["external_events"]):
        expected_event = event_catalog.get(event["id"])
        if (
            expected_event is None
            or expected_event["kind"] != event["kind"]
            or expected_event["identity"] != event["identity"]
        ):
            _contract_expectation_delta(
                manifest, deltas, side, case_id, "external_event",
                f"/external_events/{index}", expected_event, event,
                "external event is not declared",
            )


def _compare_cases(
    manifest: RegionReplacementManifest,
    baseline: Mapping[str, Any],
    replacement: Mapping[str, Any],
    deltas: list[dict[str, Any]],
) -> None:
    case_id = str(baseline["id"])
    _compare_id_values(
        manifest, deltas, case_id, "live_input", baseline["live_inputs"],
        replacement["live_inputs"], status="incomplete",
        next_action="run baseline and replacement from the same live input state",
    )
    _compare_id_values(
        manifest, deltas, case_id, "live_output", baseline["live_outputs"],
        replacement["live_outputs"], status="violated",
        next_action="repair the mapped replacement output expression",
    )
    baseline_views = {item["id"]: item for item in baseline["memory_views"]}
    replacement_views = {item["id"]: item for item in replacement["memory_views"]}
    for view_id in sorted(set(baseline_views) & set(replacement_views)):
        left = baseline_views[view_id]
        right = replacement_views[view_id]
        for field in ("base", "before"):
            if left[field] != right[field]:
                _append_delta(
                    deltas, manifest, status="incomplete", family="memory_input",
                    case_id=case_id,
                    path=f"/memory_views/{_pointer(view_id)}/{field}",
                    expected=left[field], observed=right[field],
                    message=f"memory view {view_id} did not start from the same state",
                    next_action="run baseline and replacement with identical mapped memory",
                )
        left_bytes = [left["after"][index:index + 2] for index in range(0, len(left["after"]), 2)]
        right_bytes = [right["after"][index:index + 2] for index in range(0, len(right["after"]), 2)]
        _recursive_differences(
            left_bytes,
            right_bytes,
            path=f"/memory_views/{_pointer(view_id)}/after",
            callback=lambda path, expected, observed: _append_delta(
                deltas, manifest, status="violated", family="memory_output",
                case_id=case_id, path=path, expected=expected, observed=observed,
                message=f"replacement changed memory view {view_id} differently",
                next_action="repair writes through the named memory view",
            ),
        )
    _recursive_differences(
        baseline["guest_memory_writes"],
        replacement["guest_memory_writes"],
        path="/guest_memory_writes",
        callback=lambda path, expected, observed: _append_delta(
            deltas,
            manifest,
            status="violated",
            family="guest_memory_write",
            case_id=case_id,
            path=path,
            expected=expected,
            observed=observed,
            message="replacement guest-memory writes differ from baseline",
            next_action="repair the adapter guest-memory write footprint or value",
        ),
    )
    for family, field, next_action in (
        ("control", "control", "repair the replacement exit and target selection"),
        ("fault", "fault", "repair fault conditions and fault metadata"),
    ):
        _recursive_differences(
            baseline[field], replacement[field], path=f"/{field}",
            callback=lambda path, expected, observed, family=family, action=next_action: _append_delta(
                deltas, manifest, status="violated", family=family,
                case_id=case_id, path=path, expected=expected, observed=observed,
                message=f"replacement {family.replace('_', ' ')} differs from baseline",
                next_action=action,
            ),
        )
    _recursive_differences(
        _project_external_events(manifest, baseline["external_events"]),
        _project_external_events(manifest, replacement["external_events"]),
        path="/external_events",
        callback=lambda path, expected, observed: _append_delta(
            deltas,
            manifest,
            status="violated",
            family="external_event",
            case_id=case_id,
            path=path,
            expected=expected,
            observed=observed,
            message="replacement external event differs from baseline",
            next_action=(
                "repair the external call identity, ordering, arguments, "
                "effects, or callback protocol"
            ),
        ),
    )


def _project_external_events(
    manifest: RegionReplacementManifest,
    events: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    expectations = {
        item["id"]: item
        for item in manifest.payload["expectations"]["external_events"]
    }
    projected = []
    for event in events:
        result = dict(event)
        expectation = expectations.get(event["id"])
        comparison = None if expectation is None else expectation.get("comparison")
        if (
            comparison is not None
            and comparison["mode"] == "checked_machine_abi_v1"
            and "machine_call" in result
        ):
            machine_call = dict(_object(result["machine_call"], "observed machine call"))
            machine_call.pop("registers", None)
            machine_call.pop("flags", None)
            result["machine_call"] = machine_call
        projected.append(result)
    return projected


def _control_target_allowed(
    observed: Mapping[str, Any], expected: Mapping[str, Any]
) -> bool:
    unit_targets = set(expected["target_unit_ids"])
    rva_targets = set(expected["target_rvas"])
    observed_unit = observed["target_unit_id"]
    observed_rva = observed["target_rva"]
    target_values = set(expected.get("target_values", []))
    if expected["kind"] == "indirect_jump" and target_values:
        return (
            observed_unit is None
            and observed_rva is None
            and isinstance(observed["value"], int)
            and not isinstance(observed["value"], bool)
            and observed["value"] in target_values
        )
    if not unit_targets and not rva_targets:
        return observed_unit is None and observed_rva is None
    if observed_unit is None and observed_rva is None:
        return False
    if observed_unit is not None and observed_unit not in unit_targets:
        return False
    if observed_rva is not None and observed_rva not in rva_targets:
        return False
    return True


def _compare_id_values(
    manifest: RegionReplacementManifest,
    deltas: list[dict[str, Any]],
    case_id: str,
    family: str,
    baseline: Sequence[Mapping[str, Any]],
    replacement: Sequence[Mapping[str, Any]],
    *,
    status: str,
    next_action: str,
) -> None:
    left = {item["id"]: item["value"] for item in baseline}
    right = {item["id"]: item["value"] for item in replacement}
    for identity in sorted(set(left) & set(right)):
        _recursive_differences(
            left[identity], right[identity], path=f"/{family}s/{_pointer(identity)}/value",
            callback=lambda path, expected, observed: _append_delta(
                deltas, manifest, status=status, family=family,
                case_id=case_id, path=path, expected=expected, observed=observed,
                message=f"replacement {family.replace('_', ' ')} {identity} differs from baseline",
                next_action=next_action,
            ),
        )


def _recursive_differences(
    expected: Any,
    observed: Any,
    *,
    path: str,
    callback: Any,
) -> None:
    if type(expected) is not type(observed):
        callback(path, expected, observed)
        return
    if isinstance(expected, Mapping):
        for key in sorted(set(expected) | set(observed)):
            child = f"{path}/{_pointer(str(key))}"
            if key not in expected:
                callback(child, None, observed[key])
            elif key not in observed:
                callback(child, expected[key], None)
            else:
                _recursive_differences(expected[key], observed[key], path=child, callback=callback)
        return
    if isinstance(expected, list):
        for index in range(max(len(expected), len(observed))):
            child = f"{path}/{index}"
            if index >= len(expected):
                callback(child, None, observed[index])
            elif index >= len(observed):
                callback(child, expected[index], None)
            else:
                _recursive_differences(expected[index], observed[index], path=child, callback=callback)
        return
    if expected != observed:
        callback(path, expected, observed)


def _inventory_deltas(
    manifest: RegionReplacementManifest,
    deltas: list[dict[str, Any]],
    *,
    side: str,
    case_id: str,
    family: str,
    expected: set[str],
    observed: set[str],
    path: str,
) -> None:
    for identity in sorted(expected - observed):
        _append_delta(
            deltas, manifest, status="incomplete", family=family,
            case_id=case_id, path=f"{path}/{_pointer(identity)}",
            expected="declared observation", observed=None,
            message=f"{side} observations omit declared {family} {identity}",
            next_action=f"capture the complete {family} inventory",
        )
    for identity in sorted(observed - expected):
        _append_delta(
            deltas, manifest, status="incomplete", family=family,
            case_id=case_id, path=f"{path}/{_pointer(identity)}",
            expected=None, observed="undeclared observation",
            message=f"{side} observations contain undeclared {family} {identity}",
            next_action=f"update the contract or remove the stray {family} observation",
        )


def _contract_expectation_delta(
    manifest: RegionReplacementManifest,
    deltas: list[dict[str, Any]],
    side: str,
    case_id: str,
    family: str,
    path: str,
    expected: Any,
    observed: Any,
    message: str,
) -> None:
    _append_delta(
        deltas, manifest,
        status="incomplete" if side == "baseline" else "violated",
        family=family, case_id=case_id, path=path,
        expected=expected, observed=observed,
        message=f"{side} {message}",
        next_action=(
            "repair the baseline observation contract before using it as an oracle"
            if side == "baseline"
            else "repair the replacement to stay within the declared regional behavior"
        ),
    )


def _append_delta(
    deltas: list[dict[str, Any]],
    manifest: RegionReplacementManifest,
    *,
    status: str,
    family: str,
    case_id: str | None,
    path: str,
    expected: Any,
    observed: Any,
    message: str,
    next_action: str,
) -> None:
    source = manifest.source
    location = {
        "cluster_id": manifest.cluster["id"],
        "unit_ids": list(manifest.cluster["unit_ids"]),
        "rva_spans": _json_copy(manifest.cluster["rva_spans"]),
        "source": {
            "path": source["path"],
            "symbol": source["symbol"],
            "line_start": source["line_start"],
            "line_end": source["line_end"],
        },
    }
    core = {
        "status": status,
        "family": family,
        "case_id": case_id,
        "path": path,
        "expected": _json_copy(expected),
        "observed": _json_copy(observed),
        "location": location,
        "message": message,
        "next_action": next_action,
    }
    core["id"] = "region-delta-" + _canonical_sha256(core)[:20]
    deltas.append(core)


def _coerce_manifest(
    value: Path | Mapping[str, Any] | RegionReplacementManifest,
    *,
    source_root: Path,
) -> RegionReplacementManifest:
    if isinstance(value, RegionReplacementManifest):
        manifest = _parse_manifest(value.to_payload())
        _verify_source_binding(manifest, source_root)
        return manifest
    if isinstance(value, Path):
        return load_region_replacement_manifest(value, source_root=source_root)
    manifest = _parse_manifest(_object(value, "region replacement manifest"))
    _verify_source_binding(manifest, source_root)
    return manifest


def _pointer(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


__all__ = [
    "REGION_OBSERVATIONS_FORMAT",
    "REGION_OVERRIDE_TABLE_FORMAT",
    "REGION_REPLACEMENT_FORMAT",
    "REGION_REPLACEMENT_BUNDLE_FORMAT",
    "REGION_REPLACEMENT_VALIDATION_FORMAT",
    "RegionOverrideTableArtifacts",
    "RegionReplacementManifest",
    "generate_region_override_table",
    "load_region_replacement_manifest",
    "validate_region_replacement",
    "write_region_replacement_manifest",
]
