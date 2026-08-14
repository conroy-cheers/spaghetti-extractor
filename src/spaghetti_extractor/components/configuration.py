"""Compose checked components while retaining total machine-IR fallback coverage."""

from __future__ import annotations

import copy
import json
from hashlib import sha256
from pathlib import Path
from typing import Mapping

from ..artifact_formats import (
    MACHINE_IR_FORMAT,
)
from .formats import (
    COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
    COMPONENT_CONFIGURATION_RESOLUTION_V2_FORMAT,
    COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
    COMPONENT_QUALIFICATION_V3_FORMAT,
    COMPONENT_RESOLUTION_V2_FORMAT,
)
from ..util import sha256_file, write_json
from .intent import ComponentIntentError
from .source import load_component_source_package


def compose_component_configuration(
    *,
    machine_ir: Path | str,
    resolution: Path | str | Mapping[str, object],
    configuration_id: str,
    contracts: Mapping[str, Path | str | Mapping[str, object]],
    implementations: Mapping[str, Path | str] | None,
    qualifications: Mapping[str, Path | str | Mapping[str, object]] | None,
    out: Path | str,
) -> dict[str, object]:
    """Produce the sole v3 implementation-ownership authority.

    Draft and unselected units retain machine-IR fallback. An enabled unit is
    either backed by an exact v3 qualification or is explicitly blocked; it
    can never silently return to fallback.
    """

    resolution_payload = _load(resolution, "component resolution")
    _self_hash(
        resolution_payload,
        format_name=COMPONENT_RESOLUTION_V2_FORMAT,
        field="resolution_sha256",
        description="component resolution",
    )
    configuration = _configuration(resolution_payload, configuration_id)
    machine = _load_machine_ir(Path(machine_ir))
    qualification_inputs = qualifications or {}
    implementation_inputs = implementations or {}
    issues: list[dict[str, object]] = []
    ownership_by_unit: dict[str, dict[str, object]] = {}
    selection_rows: list[dict[str, object]] = []

    for raw_selection in _array(configuration.get("selections"), "configuration selections"):
        selection = _object(raw_selection, "configuration selection")
        lift_unit_id = _string(selection.get("id"), "selection id")
        expected_units = _string_set(selection.get("unit_ids"), "selection unit ids")
        contract_value = contracts.get(lift_unit_id)
        if contract_value is None:
            raise ComponentIntentError(f"missing contract for selected lift unit {lift_unit_id}")
        contract = _load_contract(contract_value)
        contract_unit = _object(contract.get("lift_unit"), "contract lift unit")
        contract_units = _string_set(contract_unit.get("unit_ids"), "contract unit ids")
        if contract_unit.get("id") != lift_unit_id or contract_units != expected_units:
            raise ComponentIntentError(
                f"component contract membership is stale for {lift_unit_id}"
            )
        requested = selection.get("activation")
        if requested not in {"draft", "enabled"}:
            raise ComponentIntentError(
                f"component selection {lift_unit_id} has invalid activation mode"
            )
        ownership_state = "machine_ir_fallback"
        qualification_sha256 = None
        implementation_sha256 = None
        if requested == "enabled":
            ownership_state = "blocked"
            implementation_value = implementation_inputs.get(lift_unit_id)
            if implementation_value is None:
                _issue(
                    issues,
                    "incomplete",
                    "enabled_component_source_package_missing",
                    lift_unit_id=lift_unit_id,
                )
            else:
                implementation = load_component_source_package(implementation_value)
                implementation_sha256 = implementation["implementation_sha256"]
                if implementation.get("lift_unit_id") != lift_unit_id:
                    raise ComponentIntentError(
                        f"component source package targets another lift unit: {lift_unit_id}"
                    )
            qualification_value = qualification_inputs.get(lift_unit_id)
            if qualification_value is None:
                _issue(
                    issues,
                    "incomplete",
                    "enabled_component_qualification_missing",
                    lift_unit_id=lift_unit_id,
                )
            else:
                qualification = _load_qualification(qualification_value)
                qualification_sha256 = qualification["qualification_sha256"]
                bindings = _object(
                    qualification.get("bindings"), "component qualification bindings"
                )
                activated = (
                    implementation_sha256 is not None
                    and contract.get("status") == "checked"
                    and qualification.get("status") == "qualified"
                    and qualification.get("lift_unit_id") == lift_unit_id
                    and qualification.get("evidence_profile")
                    == contract_unit.get("evidence_profile")
                    and bindings.get("contract_sha256") == contract.get("contract_sha256")
                    and bindings.get("implementation_sha256")
                    == implementation_sha256
                    and _object(
                        qualification.get("activation"), "component qualification activation"
                    ).get("authorized")
                    is True
                )
                if bindings.get("contract_sha256") != contract.get("contract_sha256"):
                    _issue(
                        issues,
                        "violated",
                        "enabled_component_contract_binding_stale",
                        lift_unit_id=lift_unit_id,
                    )
                if implementation_sha256 is not None and bindings.get(
                    "implementation_sha256"
                ) != implementation_sha256:
                    _issue(
                        issues,
                        "violated",
                        "enabled_component_source_binding_stale",
                        lift_unit_id=lift_unit_id,
                    )
                if qualification.get("lift_unit_id") != lift_unit_id:
                    _issue(
                        issues,
                        "violated",
                        "enabled_component_qualification_identity_mismatch",
                        lift_unit_id=lift_unit_id,
                    )
                if activated:
                    ownership_state = "portable_replacement"
                else:
                    _issue(
                        issues,
                        (
                            "violated"
                            if qualification.get("status") == "violated"
                            else "incomplete"
                        ),
                        (
                            "enabled_component_qualification_violated"
                            if qualification.get("status") == "violated"
                            else "enabled_component_not_qualified"
                        ),
                        lift_unit_id=lift_unit_id,
                    )
            if contract.get("status") != "checked":
                _issue(
                    issues,
                    "violated" if contract.get("status") == "violated" else "incomplete",
                    "enabled_component_contract_not_checked",
                    lift_unit_id=lift_unit_id,
                    observed=contract.get("status"),
                )
        for unit_id in expected_units:
            if unit_id not in machine["units"]:
                raise ComponentIntentError(
                    f"configuration references unknown machine unit {unit_id}"
                )
            if unit_id in ownership_by_unit:
                raise ComponentIntentError(
                    f"configuration assigns machine unit {unit_id} more than once"
                )
            ownership_by_unit[unit_id] = {
                "lift_unit_id": lift_unit_id,
                "requested_activation": requested,
                "ownership_state": ownership_state,
                "contract_sha256": contract["contract_sha256"],
                "qualification_sha256": qualification_sha256,
                "implementation_sha256": implementation_sha256,
            }
        selection_rows.append(
            {
                "kind": selection["kind"],
                "id": lift_unit_id,
                "requested_activation": requested,
                "ownership_state": ownership_state,
                "unit_ids": sorted(expected_units),
                "source": copy.deepcopy(selection.get("source")),
                "contract_sha256": contract["contract_sha256"],
                "qualification_sha256": qualification_sha256,
                "implementation_sha256": implementation_sha256,
            }
        )

    entries: list[dict[str, object]] = []
    for unit_id, unit in sorted(
        machine["units"].items(), key=lambda item: (item[1]["rva"], item[0])
    ):
        selection = ownership_by_unit.get(unit_id)
        ownership_state = (
            "machine_ir_fallback"
            if selection is None
            else _string(selection.get("ownership_state"), "ownership state")
        )
        entries.append(
            {
                "unit_id": unit_id,
                "rva": unit["rva"],
                "implementation_kind": ownership_state,
                "dispatch_lookup": (
                    "stage_b_region_override_lookup"
                    if ownership_state == "portable_replacement"
                    else "stage_b_program_lookup"
                    if ownership_state == "machine_ir_fallback"
                    else None
                ),
                "selected_owner": copy.deepcopy(selection),
            }
        )
    blocked_count = sum(row["implementation_kind"] == "blocked" for row in entries)
    status = (
        "violated"
        if any(row["status"] == "violated" for row in issues)
        else "incomplete"
        if issues or blocked_count
        else "checked"
    )
    counts = {
        state: sum(row["implementation_kind"] == state for row in entries)
        for state in ("portable_replacement", "machine_ir_fallback", "blocked")
    }
    core = {
        "format": COMPONENT_ACTIVATION_PLAN_V3_FORMAT,
        "status": status,
        "configuration_id": configuration_id,
        "bindings": {
            "component_resolution_sha256": resolution_payload["resolution_sha256"],
            "configuration_sha256": configuration["configuration_sha256"],
            "machine_ir_sha256": machine["ir_sha256"],
            "machine_ir_manifest_sha256": machine["manifest_sha256"],
        },
        "policy": {
            "one_implementation_per_structural_unit": True,
            "enabled_components_must_activate": True,
            "enabled_components_may_silently_fallback": False,
            "draft_and_unselected_units_use_machine_ir_fallback": True,
            "blocked_units_prevent_runtime_construction": True,
            "portable_fallback_on_unimplemented": False,
            "overlapping_selected_ownership": False,
            "runtime_package_is_sole_candidate_authority": True,
        },
        "ownership": {
            "complete": True,
            "exclusive": True,
            "states": [
                "portable_replacement",
                "machine_ir_fallback",
                "blocked",
            ],
            "enabled_units_never_receive_fallback_ownership": True,
        },
        "hybrid": {
            "structurally_executable": blocked_count == 0,
            "release_ready": False,
            "readiness_authority": "checked_component_runtime_package_v3_required",
            "machine_ir_status": machine["status"],
            "executes_original_binary": False,
        },
        "selections": selection_rows,
        "entries": entries,
        "counts": {
            "structural_units": len(entries),
            **counts,
            "issues": len(issues),
        },
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row["status"]),
                str(row["code"]),
                str(row.get("lift_unit_id", "")),
            ),
        ),
    }
    result = {**core, "activation_plan_sha256": _canonical_sha256(core)}
    write_json(Path(out), result)
    return result


def _load_machine_ir(path: Path) -> dict[str, object]:
    manifest_path = path / "machine-ir-manifest.json" if path.is_dir() else path
    manifest = _load(manifest_path, "machine-IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise ComponentIntentError("unsupported machine-IR manifest format")
    artifacts = _object(manifest.get("artifacts"), "machine-IR artifacts")
    artifact = _object(artifacts.get("machine_ir"), "machine-IR artifact")
    ir_path = manifest_path.parent / _string(artifact.get("path"), "machine-IR path")
    ir_sha256 = sha256_file(ir_path)
    if artifact.get("sha256") != ir_sha256:
        raise ComponentIntentError("machine-IR artifact binding is stale")
    units: dict[str, dict[str, object]] = {}
    for number, line in enumerate(ir_path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            raw = json.loads(line)
        except json.JSONDecodeError as exc:
            raise ComponentIntentError(f"invalid machine IR line {number}: {exc}") from exc
        unit = _object(raw, f"machine IR line {number}")
        identity = _string(unit.get("id"), f"machine IR line {number} id")
        source = _object(unit.get("source"), f"machine unit {identity} source")
        original = _object(source.get("original"), f"machine unit {identity} original")
        rva = original.get("rva_start")
        if not isinstance(rva, int) or isinstance(rva, bool):
            raise ComponentIntentError(f"machine unit {identity} has invalid RVA")
        if identity in units:
            raise ComponentIntentError(f"duplicate machine unit {identity}")
        units[identity] = {"rva": rva}
    if not units:
        raise ComponentIntentError("machine IR contains no structural units")
    return {
        "units": units,
        "ir_sha256": ir_sha256,
        "manifest_sha256": sha256_file(manifest_path),
        "status": manifest.get("status"),
    }


def _configuration(
    resolution: Mapping[str, object], identity: str
) -> dict[str, object]:
    matches = [
        dict(row)
        for row in _array(resolution.get("configurations"), "configurations")
        if isinstance(row, Mapping) and row.get("id") == identity
    ]
    if len(matches) != 1:
        raise ComponentIntentError(
            f"configuration {identity!r} resolved to {len(matches)} definitions"
        )
    _self_hash(
        matches[0],
        format_name=COMPONENT_CONFIGURATION_RESOLUTION_V2_FORMAT,
        field="configuration_sha256",
        description="component configuration",
    )
    return matches[0]


def _load_contract(value: Path | str | Mapping[str, object]) -> dict[str, object]:
    payload = _load_local(value, "contract.json", "component contract")
    _self_hash(
        payload,
        format_name=COMPONENT_CONTRACT_PACKAGE_V2_FORMAT,
        field="contract_sha256",
        description="component contract",
    )
    return payload


def _load_qualification(value: Path | str | Mapping[str, object]) -> dict[str, object]:
    payload = _load_local(value, "qualification.json", "component qualification")
    if payload.get("format") != COMPONENT_QUALIFICATION_V3_FORMAT:
        raise ComponentIntentError("unsupported component qualification format")
    _self_hash(
        payload,
        format_name=COMPONENT_QUALIFICATION_V3_FORMAT,
        field="qualification_sha256",
        description="component qualification",
    )
    _exact_keys(
        payload,
        {
            "format",
            "status",
            "lift_unit_id",
            "evidence_profile",
            "bindings",
            "assurance",
            "activation",
            "issues",
            "qualification_sha256",
        },
        "component qualification",
    )
    status = payload.get("status")
    if status not in {"qualified", "incomplete", "violated"}:
        raise ComponentIntentError("component qualification status is invalid")
    activation = _object(payload.get("activation"), "component qualification activation")
    _exact_keys(
        activation,
        {
            "authorized",
            "requires_exact_configuration_ownership",
            "fallback_on_unimplemented",
        },
        "component qualification activation",
    )
    if (
        activation.get("authorized") is not (status == "qualified")
        or activation.get("requires_exact_configuration_ownership") is not True
        or activation.get("fallback_on_unimplemented") is not False
    ):
        raise ComponentIntentError("component qualification activation is inconsistent")
    bindings = _object(payload.get("bindings"), "component qualification bindings")
    _exact_keys(
        bindings,
        {
            "contract_sha256",
            "evidence_sha256",
            "implementation_sha256",
            "machine_ir_sha256",
            "domain_sha256",
            "source_entry",
            "tool_id",
            "tool_version",
        },
        "component qualification bindings",
    )
    for field in (
        "contract_sha256",
        "evidence_sha256",
        "implementation_sha256",
        "machine_ir_sha256",
        "domain_sha256",
    ):
        value = bindings.get(field)
        if not isinstance(value, str) or len(value) != 64:
            raise ComponentIntentError(
                f"component qualification binding {field} is invalid"
            )
    issues = _array(payload.get("issues"), "component qualification issues")
    if (status == "qualified") != (not issues):
        raise ComponentIntentError("component qualification issues are inconsistent")
    return payload


def _load_local(
    value: Path | str | Mapping[str, object], filename: str, description: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    path = Path(value)
    return _load(path / filename if path.is_dir() else path, description)


def _load(
    value: Path | str | Mapping[str, object], description: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    try:
        raw = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {description}: {exc}") from exc
    return dict(_object(raw, description))


def _self_hash(
    payload: Mapping[str, object],
    *,
    format_name: str,
    field: str,
    description: str,
) -> None:
    if payload.get("format") != format_name:
        raise ComponentIntentError(f"unsupported {description} format")
    expected = payload.get(field)
    core = copy.deepcopy(dict(payload))
    core.pop(field, None)
    if expected != _canonical_sha256(core):
        raise ComponentIntentError(f"{description} self-hash is stale")


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{description} must be an object")
    return value


def _array(value: object, description: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{description} must be an array")
    return value


def _exact_keys(
    value: Mapping[str, object], expected: set[str], description: str
) -> None:
    missing = sorted(expected - set(value))
    unknown = sorted(set(value) - expected)
    if missing or unknown:
        raise ComponentIntentError(
            f"{description} fields differ: missing={missing}, unknown={unknown}"
        )


def _string(value: object, description: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{description} must be a nonempty string")
    return value


def _string_set(value: object, description: str) -> set[str]:
    rows = _array(value, description)
    result = {_string(row, description) for row in rows}
    if not result or len(result) != len(rows):
        raise ComponentIntentError(f"{description} must be nonempty and unique")
    return result


def _issue(
    issues: list[dict[str, object]], status: str, code: str, **details: object
) -> None:
    issues.append({"status": status, "code": code, **details})


def _canonical_sha256(value: object) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()
