"""Nonauthorizing contracts for independent component development.

Development contracts intentionally stop at the operator-declared boundary and
a reviewed portable interface. They make source and interface work independent of
proposal discovery and whole-target analysis without allowing that work to
activate source in an executable candidate.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..util import write_json
from .formats import (
    COMPONENT_BOUNDARY_REVIEW_V2_FORMAT,
    COMPONENT_DEVELOPMENT_CONTRACT_V1_FORMAT,
    COMPONENT_DEVELOPMENT_DECLARATION_V1_FORMAT,
)
from .interface_ir import (
    COMPONENT_INTERFACE_IR_V1,
    COMPONENT_INTERFACE_IR_V2,
    ComponentInterfaceIRError,
    ComponentInterfaceIRV1,
    PortableComponentInterfaceV2,
)
from .intent import ComponentIntentError


def build_component_development_contract(
    *,
    declaration: Path | str | Mapping[str, object],
    review: Path | str | Mapping[str, object],
    out_dir: Path | str,
) -> dict[str, object]:
    """Build the minimum checked artifact required for isolated source work."""

    declared = _load_object(declaration, "component development declaration")
    common_fields = {
        "format",
        "program_id",
        "kind",
        "id",
        "label",
        "boundary",
        "evidence_profile",
    }
    if set(declared) == common_fields | {"source_entry"}:
        source = {"entry": declared["source_entry"]}
    elif set(declared) == common_fields | {"source"}:
        source = _object(declared.get("source"), "declared component source")
    else:
        raise ComponentIntentError(
            "component development declaration fields are noncanonical"
        )
    if declared.get("format") != COMPONENT_DEVELOPMENT_DECLARATION_V1_FORMAT:
        raise ComponentIntentError("unsupported component development declaration")
    lift_unit_id = _text(declared.get("id"), "component id")
    kind = declared.get("kind")
    if kind not in {"component", "group"}:
        raise ComponentIntentError("component declaration kind is unsupported")
    boundary = _object(declared.get("boundary"), "declared component boundary")
    expected_boundary_key = "selector" if kind == "component" else "members"
    _exact(boundary, {expected_boundary_key}, "declared component boundary")
    if kind == "component":
        _object(boundary[expected_boundary_key], "declared component selector")
    else:
        members = _array(boundary[expected_boundary_key], "declared group members")
        if not members or any(not isinstance(item, str) or not item for item in members):
            raise ComponentIntentError("declared group members must be nonempty strings")
        if len(members) != len(set(members)):
            raise ComponentIntentError("declared group members must be unique")
    source_entry = source.get("entry")
    source_operations = source.get("operations")
    if (source_entry is None) == (source_operations is None):
        raise ComponentIntentError(
            "component development requires exactly one source entry or operation map"
        )

    reviewed = _load_object(review, "component boundary review")
    if reviewed.get("format") != COMPONENT_BOUNDARY_REVIEW_V2_FORMAT:
        raise ComponentIntentError("unsupported component boundary-review format")
    if reviewed.get("lift_unit_id") != lift_unit_id:
        raise ComponentIntentError("component boundary review names another lift unit")
    overrides = _object(reviewed.get("overrides"), "component boundary overrides")
    portable_payload = overrides.get("portable_interface_ir")
    if portable_payload is None:
        raise ComponentIntentError(
            "component development requires a reviewed portable_interface_ir"
        )
    try:
        portable_format = _object(
            portable_payload, "reviewed portable interface"
        ).get("format")
        if portable_format == COMPONENT_INTERFACE_IR_V2:
            interface = PortableComponentInterfaceV2.parse(portable_payload)
        elif portable_format == COMPONENT_INTERFACE_IR_V1:
            interface = ComponentInterfaceIRV1.parse(portable_payload)
        else:
            raise ComponentInterfaceIRError(
                "unsupported portable component interface format"
            )
    except ComponentInterfaceIRError as exc:
        raise ComponentIntentError(f"portable component interface is invalid: {exc}") from exc
    if isinstance(interface, PortableComponentInterfaceV2):
        operations = _object(source_operations, "declared source operations")
        interface.validate_operation_symbols(operations)
    else:
        entry = _object(source_entry, "declared source entry")
        _exact(entry, {"abi", "symbol"}, "declared source entry")
        if (
            entry.get("abi") != "portable-interface-v1"
            or overrides.get("source_abi") != entry.get("abi")
        ):
            raise ComponentIntentError(
                "legacy component development requires portable-interface-v1"
            )
        _text(entry.get("symbol"), "declared source symbol")

    review_sha256 = canonical_sha256_v3(reviewed)
    declaration_sha256 = canonical_sha256_v3(declared)
    core: dict[str, object] = {
        "format": COMPONENT_DEVELOPMENT_CONTRACT_V1_FORMAT,
        "status": "checked",
        "lift_unit": {
            "program_id": declared.get("program_id"),
            "kind": kind,
            "id": lift_unit_id,
            "label": declared.get("label"),
            "declared_boundary": boundary,
            "evidence_profile": declared.get("evidence_profile"),
            "source": source,
        },
        "executes_original_binary": False,
        "bindings": {
            "development_declaration_sha256": declaration_sha256,
            "boundary_review_sha256": review_sha256,
            "portable_interface_ir_sha256": interface.sha256,
        },
        "authority": {
            "purpose": "isolated_component_development",
            "machine_effects_checked": False,
            "external_sites_checked": False,
            "activation_authorized": False,
            "candidate_runtime_authorized": False,
        },
        "artifacts": {
            "reviewed_interface": "reviewed-interface.json",
            "portable_interface": "portable-interface.json",
            "portable_interface_header": "portable-interface.h",
        },
    }
    result = {**core, "contract_sha256": canonical_sha256_v3(core)}
    output = Path(out_dir)
    output.mkdir(parents=True, exist_ok=True)
    write_json(output / "contract.json", result)
    write_json(output / "reviewed-interface.json", dict(overrides))
    write_json(output / "portable-interface.json", interface.to_payload())
    (output / "portable-interface.h").write_text(
        (
            interface.render_public_header()
            if isinstance(interface, PortableComponentInterfaceV2)
            else interface.render_c_header()
        ),
        encoding="ascii",
    )
    return result


def _load_object(
    value: Path | str | Mapping[str, object], context: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    path = Path(value)
    try:
        loaded = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentIntentError(f"cannot read {context}: {exc}") from exc
    if not isinstance(loaded, Mapping):
        raise ComponentIntentError(f"{context} must be an object")
    return json.loads(json.dumps(loaded))


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise ComponentIntentError(f"{context} must be an array")
    return value


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentIntentError(f"{context} must be an object")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentIntentError(f"{context} must be a nonempty string")
    return value


def _exact(value: Mapping[str, object], fields: set[str], context: str) -> None:
    if set(value) != fields:
        raise ComponentIntentError(
            f"{context} fields differ: missing={sorted(fields - set(value))!r}, "
            f"extra={sorted(set(value) - fields)!r}"
        )


__all__ = ["build_component_development_contract"]
