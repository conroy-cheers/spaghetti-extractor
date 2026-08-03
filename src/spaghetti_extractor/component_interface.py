"""Authoritative machine-to-logical interface refinement for components.

The semantic component catalog intentionally contains operator-authored logical
proposals.  This module binds a structured interface specification to one exact
catalog component and checks every claim against the canonical machine IR.
Free-form prose is never consulted while deciding the result.

The checker is deliberately narrower than a source-equivalence proof.  A
``checked`` artifact establishes that the declared logical boundary is a
complete, non-contradictory projection of the component's machine effects.  It
does not establish that a portable implementation satisfies that boundary.
"""

from __future__ import annotations

import copy
import json
from collections import defaultdict
from functools import lru_cache
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from .artifact_formats import (
    COMPONENT_INTERFACE_REFINEMENT_FORMAT,
    COMPONENT_INTERFACE_SPEC_FORMAT,
    MACHINE_IR_FORMAT,
    SEMANTIC_COMPONENT_CATALOG_FORMAT,
)
from .util import sha256_file, write_json


_MACHINE_IR_FILENAME = "machine-ir.jsonl"
_MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"
_REGISTER_WIDTHS = {
    "eax": 32,
    "ebx": 32,
    "ecx": 32,
    "edx": 32,
    "esi": 32,
    "edi": 32,
    "esp": 32,
    "ebp": 32,
    "eip": 32,
    "ax": 16,
    "bx": 16,
    "cx": 16,
    "dx": 16,
    "si": 16,
    "di": 16,
    "sp": 16,
    "bp": 16,
    "al": 8,
    "ah": 8,
    "bl": 8,
    "bh": 8,
    "cl": 8,
    "ch": 8,
    "dl": 8,
    "dh": 8,
}
_ADAPTER_REASONS = {
    "machine_register_projection",
    "machine_flag_projection",
    "stack_frame_projection",
    "internal_call_frame",
    "internal_control_table_projection",
}
_IDENTITY_FIELDS = (
    "kind",
    "dll",
    "symbol",
    "ordinal",
    "target_rva",
    "return_rva",
    "identity",
    "name",
)


class ComponentInterfaceError(ValueError):
    """An interface input is not structurally usable JSON."""


def check_component_interface(
    *,
    catalog: Path | str | Mapping[str, Any],
    machine_ir: Path | str,
    component_id: str,
    interface_spec: Path | str | Mapping[str, Any],
) -> dict[str, Any]:
    """Check one structured logical interface against exact machine effects."""

    machine = _load_machine_ir(Path(machine_ir))
    catalog_payload = _load_json_input(catalog, "semantic component catalog")
    spec = _load_json_input(interface_spec, "component interface specification")
    component = _find_component(catalog_payload, component_id)
    issues: list[dict[str, Any]] = []

    _check_catalog_binding(catalog_payload, component, machine, issues)
    _check_spec_binding(
        spec,
        component,
        machine,
        component_id,
        issues,
    )

    member_ids = _member_ids(component, machine, issues)
    inventory = _effect_inventory(member_ids, machine, component)
    owners: dict[str, list[dict[str, str]]] = defaultdict(list)

    parameters = _named_entries(spec, "parameters", issues)
    results = _named_entries(spec, "results", issues)
    objects = _named_entries(spec, "objects", issues)
    services = _named_entries(spec, "services", issues)

    for index, parameter in enumerate(parameters):
        _check_machine_source(
            parameter.get("machine_source"),
            machine,
            issues,
            json_location=f"/parameters/{index}/machine_source",
            label=f"parameter {parameter.get('id')!r}",
        )

    for object_index, logical_object in enumerate(objects):
        _check_object(
            logical_object,
            object_index,
            machine,
            inventory,
            owners,
            issues,
        )

    for service_index, service in enumerate(services):
        _check_service(
            service,
            service_index,
            machine,
            inventory,
            owners,
            issues,
        )

    for result_index, result in enumerate(results):
        _check_result(
            result,
            result_index,
            machine,
            inventory,
            owners,
            issues,
        )

    _check_adapter_effects(
        spec.get("adapter_effects", []),
        machine,
        component,
        member_ids,
        inventory,
        owners,
        issues,
    )
    _check_effect_coverage(inventory, owners, issues)

    issues.sort(key=_issue_sort_key)
    status = (
        "violated"
        if any(issue["status"] == "violated" for issue in issues)
        else "incomplete"
        if issues
        else "checked"
    )
    result = {
        "format": COMPONENT_INTERFACE_REFINEMENT_FORMAT,
        "status": status,
        "component_id": component_id,
        "component": {
            "id": component_id,
            "sha256": component.get("component_sha256"),
        },
        "proof_authority": (
            "checked_machine_to_logical_interface_projection"
            if status == "checked"
            else "none"
        ),
        "executes_original_binary": False,
        "bindings": {
            "component_sha256": component.get("component_sha256"),
            "machine_ir_sha256": machine["ir_sha256"],
            "machine_ir_manifest_sha256": machine["manifest_sha256"],
            "original_binary_sha256": machine["manifest"].get("binary", {}).get("sha256"),
            "interface_spec_sha256": spec.get("interface_spec_sha256"),
        },
        "policy": {
            "english_claims_authority": "none",
            "structured_interface_authority": "exact_machine_ir_projection_v1",
            "unrepresented_effects": "incomplete",
            "contradictory_or_stale_evidence": "violated",
            "adapter_ownership": "checked_narrow_machine_boundary_only",
        },
        "coverage": {
            "machine_effects": len(inventory),
            "represented_once": sum(len(owners.get(key, [])) == 1 for key in inventory),
            "unrepresented": sum(not owners.get(key) for key in inventory),
            "multiply_represented": sum(len(owners.get(key, [])) > 1 for key in inventory),
            "complete": all(len(owners.get(key, [])) == 1 for key in inventory),
        },
        "issues": issues,
        "counts": {
            "parameters": len(parameters),
            "results": len(results),
            "objects": len(objects),
            "services": len(services),
            "issues": len(issues),
        },
        "logical_interface": {
            key: copy.deepcopy(spec.get(key, [] if key != "policy" else {}))
            for key in (
                "parameters",
                "results",
                "objects",
                "services",
                "adapter_effects",
                "claims",
                "policy",
            )
        },
    }
    result["refinement_sha256"] = _canonical_sha256(result)
    return result


def write_component_interface_refinement(
    *,
    catalog: Path | str | Mapping[str, Any],
    machine_ir: Path | str,
    component_id: str,
    interface_spec: Path | str | Mapping[str, Any],
    out: Path | str,
) -> dict[str, Any]:
    """Check and write one deterministic refinement artifact."""

    result = check_component_interface(
        catalog=catalog,
        machine_ir=machine_ir,
        component_id=component_id,
        interface_spec=interface_spec,
    )
    write_json(Path(out), result)
    return result


def synthesize_component_interface_spec(
    *,
    catalog: Path | str | Mapping[str, Any],
    machine_ir: Path | str,
    component_id: str,
) -> dict[str, Any]:
    """Create a conservative, machine-shaped interface specification.

    Synthesis is a convenience, not authority.  It names raw register inputs,
    one object field per non-stack memory location, exact external events, and
    exact control exits.  The operator can coarsen and rename this specification
    without changing the checked evidence references.
    """

    machine = _load_machine_ir(Path(machine_ir))
    catalog_payload = _load_json_input(catalog, "semantic component catalog")
    component = _find_component(catalog_payload, component_id)
    structural_issues: list[dict[str, Any]] = []
    _check_catalog_binding(catalog_payload, component, machine, structural_issues)
    if structural_issues:
        first = sorted(structural_issues, key=_issue_sort_key)[0]
        raise ComponentInterfaceError(
            f"cannot synthesize from stale catalog: {first['code']}"
        )
    member_ids = _member_ids(component, machine, structural_issues)
    if structural_issues:
        raise ComponentInterfaceError("cannot synthesize an interface for invalid membership")
    inventory = _effect_inventory(member_ids, machine, component)

    register_occurrences: dict[str, tuple[dict[str, Any], str, str]] = {}
    for unit_id in member_ids:
        unit = machine["units_by_id"][unit_id]
        for expression, pointer in _expression_occurrences(unit):
            if expression.get("op") != "reg":
                continue
            name = str(expression.get("name", "")).lower()
            if name in {"esp", "ebp", "sp", "bp"} or name not in _REGISTER_WIDTHS:
                continue
            register_occurrences.setdefault(name, (copy.deepcopy(expression), unit_id, pointer))

    parameters = []
    for name in sorted(register_occurrences):
        expression, unit_id, pointer = register_occurrences[name]
        parameters.append(
            {
                "id": f"input_{name}",
                "type": f"uint{_REGISTER_WIDTHS[name]}_t",
                "machine_source": {
                    "kind": "register",
                    "name": name,
                    "width": _REGISTER_WIDTHS[name],
                    "evidence": {"unit_id": unit_id, "json_pointer": pointer},
                },
            }
        )

    objects: list[dict[str, Any]] = []
    services: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    adapter_effects: list[dict[str, Any]] = []
    for key, effect in inventory.items():
        reference = copy.deepcopy(effect["reference"])
        family = effect["family"]
        if family in {"register_write", "flag_write"}:
            adapter_effects.append(
                {
                    "effect": reference,
                    "reason": (
                        "machine_register_projection"
                        if family == "register_write"
                        else "machine_flag_projection"
                    ),
                }
            )
        elif family == "memory_event":
            event = effect["payload"]
            address = event.get("address")
            if _is_stack_expression(address):
                adapter_effects.append(
                    {"effect": reference, "reason": "stack_frame_projection"}
                )
                continue
            objects.append(
                {
                    "id": f"machine_object_{len(objects):04d}",
                    "kind": "machine_memory_location",
                    "base": copy.deepcopy(address),
                    "fields": [
                        {
                            "id": "value",
                            "offset": 0,
                            "width": event.get("width"),
                            "permissions": [str(event.get("kind"))],
                            "event_refs": [reference],
                        }
                    ],
                }
            )
        elif family == "external_event":
            event = effect["payload"]
            if event.get("kind") == "internal_call" and _internal_call_is_member(
                event, member_ids, machine
            ):
                adapter_effects.append(
                    {"effect": reference, "reason": "internal_call_frame"}
                )
                continue
            identity = _event_identity(event)
            services.append(
                {
                    "id": f"machine_service_{len(services):04d}",
                    "identity": identity,
                    "events": [
                        {
                            **reference,
                            "arguments": copy.deepcopy(event.get("arguments", [])),
                        }
                    ],
                }
            )
        elif family == "control_exit":
            outcome = effect["payload"]
            results.append(
                {
                    "id": f"control_{effect['unit_id'].replace(':', '_')}",
                    "kind": "control",
                    "control": _control_spec(effect["unit_id"], outcome),
                }
            )
        elif family == "fault":
            results.append(
                {
                    "id": f"fault_{len(results):04d}",
                    "kind": "fault",
                    "effect_refs": [reference],
                }
            )

    spec = {
        "format": COMPONENT_INTERFACE_SPEC_FORMAT,
        "component_id": component_id,
        "bindings": {
            "component_sha256": component.get("component_sha256"),
            "machine_ir_sha256": machine["ir_sha256"],
            "machine_ir_manifest_sha256": machine["manifest_sha256"],
            "original_binary_sha256": machine["manifest"].get("binary", {}).get("sha256"),
        },
        "parameters": parameters,
        "results": results,
        "objects": objects,
        "services": services,
        "adapter_effects": adapter_effects,
        "claims": [],
        "policy": {"english_claims_authority": "none"},
    }
    return finalize_component_interface_spec(spec)


def finalize_component_interface_spec(spec: Mapping[str, Any]) -> dict[str, Any]:
    """Return a JSON copy with a canonical self-binding."""

    result = _json_copy(spec, "component interface specification")
    result.pop("interface_spec_sha256", None)
    result["interface_spec_sha256"] = _canonical_sha256(result)
    return result


def _load_machine_ir(path: Path) -> dict[str, Any]:
    return _load_machine_ir_cached(str(path.resolve()))


@lru_cache(maxsize=8)
def _load_machine_ir_cached(path_text: str) -> dict[str, Any]:
    path = Path(path_text)
    manifest_path = path / _MACHINE_IR_MANIFEST_FILENAME if path.is_dir() else path
    manifest = _json_file(manifest_path, "machine IR manifest")
    if manifest.get("format") != MACHINE_IR_FORMAT:
        raise ComponentInterfaceError("machine IR manifest has an unsupported format")
    artifact = manifest.get("artifacts", {}).get("machine_ir")
    if not isinstance(artifact, Mapping):
        raise ComponentInterfaceError("machine IR manifest has no machine_ir artifact")
    ir_path = manifest_path.parent / str(artifact.get("path", _MACHINE_IR_FILENAME))
    if not ir_path.is_file():
        raise ComponentInterfaceError(f"machine IR JSONL does not exist: {ir_path}")
    ir_sha256 = sha256_file(ir_path)
    if artifact.get("sha256") != ir_sha256:
        raise ComponentInterfaceError("machine IR JSONL hash does not match its manifest")
    units: list[dict[str, Any]] = []
    with ir_path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, 1):
            if not line.strip():
                continue
            try:
                value = json.loads(line)
            except json.JSONDecodeError as error:
                raise ComponentInterfaceError(
                    f"invalid machine IR JSONL at line {line_number}: {error}"
                ) from error
            if not isinstance(value, dict):
                raise ComponentInterfaceError(
                    f"machine IR line {line_number} is not an object"
                )
            units.append(value)
    units_by_id: dict[str, dict[str, Any]] = {}
    units_by_rva: dict[int, dict[str, Any]] = {}
    for unit in units:
        identity = unit.get("id")
        if not isinstance(identity, str) or not identity or identity in units_by_id:
            raise ComponentInterfaceError("machine IR unit IDs must be unique strings")
        rva = _unit_rva(unit)
        if rva in units_by_rva:
            raise ComponentInterfaceError("machine IR unit RVAs must be unique")
        units_by_id[identity] = unit
        units_by_rva[rva] = unit
    return {
        "manifest": manifest,
        "manifest_path": manifest_path,
        "manifest_sha256": sha256_file(manifest_path),
        "ir_path": ir_path,
        "ir_sha256": ir_sha256,
        "units": units,
        "units_by_id": units_by_id,
        "units_by_rva": units_by_rva,
    }


def _check_catalog_binding(
    catalog: Mapping[str, Any],
    component: Mapping[str, Any],
    machine: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> None:
    if catalog.get("format") != SEMANTIC_COMPONENT_CATALOG_FORMAT:
        raise ComponentInterfaceError("semantic component catalog has an unsupported format")
    expected_catalog_hash = _canonical_sha256(
        {key: copy.deepcopy(value) for key, value in catalog.items() if key != "catalog_sha256"}
    )
    if catalog.get("catalog_sha256") != expected_catalog_hash:
        _issue(
            issues,
            "violated",
            "catalog_self_binding_mismatch",
            "/bindings/catalog_sha256",
            expected=expected_catalog_hash,
            observed=catalog.get("catalog_sha256"),
            remediation="regenerate the semantic component catalog",
        )
    expected_component_hash = _canonical_sha256(
        {key: copy.deepcopy(value) for key, value in component.items() if key != "component_sha256"}
    )
    if component.get("component_sha256") != expected_component_hash:
        _issue(
            issues,
            "violated",
            "component_self_binding_mismatch",
            "/bindings/component_sha256",
            expected=expected_component_hash,
            observed=component.get("component_sha256"),
            remediation="regenerate the semantic component catalog",
        )
    expected = {
        "machine_ir_sha256": machine["ir_sha256"],
        "machine_ir_manifest_sha256": machine["manifest_sha256"],
        "original_binary_sha256": machine["manifest"].get("binary", {}).get("sha256"),
    }
    bindings = catalog.get("bindings")
    bindings = bindings if isinstance(bindings, Mapping) else {}
    for field, value in expected.items():
        if bindings.get(field) != value:
            _issue(
                issues,
                "violated",
                "catalog_machine_binding_mismatch",
                f"/bindings/{field}",
                expected=value,
                observed=bindings.get(field),
                remediation="regenerate the component catalog from the current machine IR",
            )
    if component.get("definition_status") != "valid":
        _issue(
            issues,
            "violated",
            "invalid_component_definition",
            "/component_id",
            expected="valid",
            observed=component.get("definition_status"),
            remediation="repair the component definition before refining its interface",
        )


def _check_spec_binding(
    spec: Mapping[str, Any],
    component: Mapping[str, Any],
    machine: Mapping[str, Any],
    component_id: str,
    issues: list[dict[str, Any]],
) -> None:
    if spec.get("format") != COMPONENT_INTERFACE_SPEC_FORMAT:
        raise ComponentInterfaceError("component interface specification has an unsupported format")
    if spec.get("component_id") != component_id:
        _issue(
            issues,
            "violated",
            "interface_component_mismatch",
            "/component_id",
            expected=component_id,
            observed=spec.get("component_id"),
            remediation="select or regenerate the specification for this component",
        )
    expected_self_hash = _canonical_sha256(
        {key: copy.deepcopy(value) for key, value in spec.items() if key != "interface_spec_sha256"}
    )
    if spec.get("interface_spec_sha256") != expected_self_hash:
        _issue(
            issues,
            "violated",
            "interface_spec_self_binding_mismatch",
            "/interface_spec_sha256",
            expected=expected_self_hash,
            observed=spec.get("interface_spec_sha256"),
            remediation="finalize the interface specification after editing it",
        )
    expected = {
        "component_sha256": component.get("component_sha256"),
        "machine_ir_sha256": machine["ir_sha256"],
        "machine_ir_manifest_sha256": machine["manifest_sha256"],
        "original_binary_sha256": machine["manifest"].get("binary", {}).get("sha256"),
    }
    bindings = spec.get("bindings")
    bindings = bindings if isinstance(bindings, Mapping) else {}
    for field, value in expected.items():
        if bindings.get(field) != value:
            _issue(
                issues,
                "violated",
                "interface_binding_mismatch",
                f"/bindings/{field}",
                expected=value,
                observed=bindings.get(field),
                remediation="regenerate or rebind the interface specification",
            )


def _check_machine_source(
    source: Any,
    machine: Mapping[str, Any],
    issues: list[dict[str, Any]],
    *,
    json_location: str,
    label: str,
) -> bool:
    if isinstance(source, str):
        _issue(
            issues,
            "incomplete",
            "unlocated_machine_source",
            json_location,
            expected="structured source with exact unit_id and json_pointer evidence",
            observed=source,
            remediation=f"bind {label} to an exact machine-IR expression",
        )
        return False
    if not isinstance(source, Mapping):
        _issue(
            issues,
            "incomplete",
            "missing_machine_source",
            json_location,
            expected="structured machine source",
            observed=source,
            remediation=f"provide exact machine evidence for {label}",
        )
        return False
    evidence = source.get("evidence")
    if not isinstance(evidence, Mapping):
        _issue(
            issues,
            "incomplete",
            "missing_machine_source_evidence",
            json_location + "/evidence",
            expected={"unit_id": "...", "json_pointer": "/..."},
            observed=evidence,
            remediation=f"locate {label} in the canonical machine IR",
        )
        return False
    unit_id = evidence.get("unit_id")
    pointer = evidence.get("json_pointer")
    unit = machine["units_by_id"].get(unit_id) if isinstance(unit_id, str) else None
    if unit is None or not isinstance(pointer, str):
        _issue(
            issues,
            "violated",
            "invalid_machine_source_evidence",
            json_location + "/evidence",
            unit_id=unit_id if isinstance(unit_id, str) else None,
            expected="an existing unit and valid JSON pointer",
            observed=copy.deepcopy(evidence),
            remediation="regenerate the source evidence from the current machine IR",
        )
        return False
    try:
        observed = _json_pointer(unit, pointer)
    except (KeyError, IndexError, TypeError, ValueError):
        _issue(
            issues,
            "violated",
            "invalid_machine_source_pointer",
            json_location + "/evidence/json_pointer",
            unit_id=unit_id,
            rva=_unit_rva(unit),
            expected="a JSON pointer resolving inside the named machine unit",
            observed=pointer,
            remediation="regenerate the source evidence from the current machine IR",
        )
        return False
    kind = source.get("kind")
    if kind == "register":
        name = str(source.get("name", "")).lower()
        width = source.get("width", _REGISTER_WIDTHS.get(name))
        expected = {"op": "reg", "name": name, "width": width}
    elif kind == "expression":
        expected = source.get("expression")
    elif kind == "constant":
        expected = {
            "op": "const",
            "value": source.get("value"),
            "width": source.get("width"),
        }
    else:
        _issue(
            issues,
            "incomplete",
            "unsupported_machine_source_kind",
            json_location + "/kind",
            unit_id=unit_id,
            rva=_unit_rva(unit),
            expected=["constant", "expression", "register"],
            observed=kind,
            remediation="express the source using a supported normalized form",
        )
        return False
    if observed != expected:
        _issue(
            issues,
            "violated",
            "machine_source_expression_mismatch",
            json_location,
            unit_id=unit_id,
            rva=_unit_rva(unit),
            expected=copy.deepcopy(expected),
            observed=copy.deepcopy(observed),
            remediation=(
                f"change {label} to match the observed expression or select "
                "the correct evidence path"
            ),
        )
        return False
    return True


def _check_object(
    logical_object: Mapping[str, Any],
    object_index: int,
    machine: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]],
    owners: dict[str, list[dict[str, str]]],
    issues: list[dict[str, Any]],
) -> None:
    location = f"/objects/{object_index}"
    base = logical_object.get("base")
    if not isinstance(base, Mapping):
        _issue(
            issues,
            "incomplete",
            "missing_object_base",
            location + "/base",
            expected="normalized address expression",
            observed=base,
            remediation="bind the object to the base expression used by its memory events",
        )
        return
    fields = logical_object.get("fields")
    if not isinstance(fields, list) or not fields:
        _issue(
            issues,
            "incomplete",
            "missing_object_fields",
            location + "/fields",
            expected="one or more checked fields",
            observed=fields,
            remediation="declare field offsets, widths, permissions, and event references",
        )
        return
    for field_index, raw_field in enumerate(fields):
        field_location = f"{location}/fields/{field_index}"
        if not isinstance(raw_field, Mapping):
            _issue(
                issues,
                "violated",
                "malformed_object_field",
                field_location,
                expected="object",
                observed=raw_field,
                remediation="replace the field with a structured field declaration",
            )
            continue
        offset = raw_field.get("offset")
        width = raw_field.get("width")
        permissions = raw_field.get("permissions")
        refs = raw_field.get("event_refs")
        if (
            not isinstance(offset, int)
            or isinstance(offset, bool)
            or not isinstance(width, int)
            or width <= 0
        ):
            _issue(
                issues,
                "violated",
                "invalid_object_field_shape",
                field_location,
                expected="integer offset and positive byte width",
                observed={"offset": offset, "width": width},
                remediation="use exact byte offsets and widths from machine memory events",
            )
            continue
        if (
            not isinstance(permissions, list)
            or not permissions
            or any(value not in {"read", "write"} for value in permissions)
        ):
            _issue(
                issues,
                "violated",
                "invalid_object_permissions",
                field_location + "/permissions",
                expected="non-empty subset of read and write",
                observed=permissions,
                remediation="declare exactly the memory operations represented by this field",
            )
            continue
        if not isinstance(refs, list) or not refs:
            _issue(
                issues,
                "incomplete",
                "unbound_object_field",
                field_location + "/event_refs",
                expected="at least one exact memory-event reference",
                observed=refs,
                remediation="bind this field to every represented machine memory event",
            )
            continue
        observed_permissions: set[str] = set()
        for ref_index, reference in enumerate(refs):
            key, effect = _resolve_effect_reference(
                reference,
                inventory,
                "memory_event",
                issues,
                f"{field_location}/event_refs/{ref_index}",
            )
            if key is None or effect is None:
                continue
            event = effect["payload"]
            observed_permissions.add(str(event.get("kind")))
            expected_address = _address_with_offset(base, offset)
            if not _addresses_equal(expected_address, event.get("address")):
                _issue(
                    issues,
                    "violated",
                    "object_field_address_mismatch",
                    field_location,
                    unit_id=effect["unit_id"],
                    rva=effect["rva"],
                    expected=expected_address,
                    observed=event.get("address"),
                    remediation="correct the object base or field offset",
                )
            if event.get("width") != width:
                _issue(
                    issues,
                    "violated",
                    "object_field_width_mismatch",
                    field_location + "/width",
                    unit_id=effect["unit_id"],
                    rva=effect["rva"],
                    expected=event.get("width"),
                    observed=width,
                    remediation="use the exact byte width of the machine memory event",
                )
            _add_owner(owners, key, "object", str(logical_object.get("id")), field_location)
        if set(permissions) != observed_permissions:
            _issue(
                issues,
                "violated",
                "object_field_permissions_mismatch",
                field_location + "/permissions",
                expected=sorted(observed_permissions),
                observed=sorted(set(str(value) for value in permissions)),
                remediation="declare exactly the read/write kinds referenced by this field",
            )


def _check_service(
    service: Mapping[str, Any],
    service_index: int,
    machine: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]],
    owners: dict[str, list[dict[str, str]]],
    issues: list[dict[str, Any]],
) -> None:
    location = f"/services/{service_index}"
    identity = service.get("identity")
    events = service.get("events")
    if not isinstance(identity, Mapping):
        _issue(
            issues,
            "incomplete",
            "missing_service_identity",
            location + "/identity",
            expected="structured machine event identity",
            observed=identity,
            remediation=(
                "declare the exact import, internal call, callback, or platform "
                "event identity"
            ),
        )
        return
    if not isinstance(events, list) or not events:
        _issue(
            issues,
            "incomplete",
            "unbound_service",
            location + "/events",
            expected="one or more exact external-event references",
            observed=events,
            remediation="bind the service to its machine external events",
        )
        return
    for event_index, reference in enumerate(events):
        ref_location = f"{location}/events/{event_index}"
        key, effect = _resolve_effect_reference(
            reference,
            inventory,
            "external_event",
            issues,
            ref_location,
        )
        if key is None or effect is None:
            continue
        event = effect["payload"]
        observed_identity = _event_identity(event)
        if not _identity_complete(observed_identity):
            _issue(
                issues,
                "incomplete",
                "unsupported_service_identity",
                location + "/identity",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected="an event with a stable machine identity",
                observed=observed_identity,
                remediation="extend the structured event identity profile",
            )
        elif _normalize_identity(identity) != observed_identity:
            _issue(
                issues,
                "violated",
                "service_identity_mismatch",
                location + "/identity",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=observed_identity,
                observed=_normalize_identity(identity),
                remediation="bind the service to the exact observed machine event",
            )
        if not isinstance(reference, Mapping) or "arguments" not in reference:
            _issue(
                issues,
                "incomplete",
                "unrepresented_service_arguments",
                ref_location + "/arguments",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=event.get("arguments", []),
                observed=None,
                remediation="represent the exact logical argument expressions",
            )
        elif reference.get("arguments") != event.get("arguments", []):
            _issue(
                issues,
                "violated",
                "service_arguments_mismatch",
                ref_location + "/arguments",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=event.get("arguments", []),
                observed=reference.get("arguments"),
                remediation="correct the service argument projection",
            )
        _add_owner(owners, key, "service", str(service.get("id")), location)


def _check_result(
    result: Mapping[str, Any],
    result_index: int,
    machine: Mapping[str, Any],
    inventory: Mapping[str, Mapping[str, Any]],
    owners: dict[str, list[dict[str, str]]],
    issues: list[dict[str, Any]],
) -> None:
    location = f"/results/{result_index}"
    kind = result.get("kind")
    if kind == "control":
        control = result.get("control")
        if not isinstance(control, Mapping):
            _issue(
                issues,
                "incomplete",
                "missing_control_result",
                location + "/control",
                expected="structured control result",
                observed=control,
                remediation="bind the result to an exact component control exit",
            )
            return
        unit_id = control.get("unit_id")
        reference = {"family": "control_exit", "unit_id": unit_id}
        key, effect = _resolve_effect_reference(
            reference,
            inventory,
            "control_exit",
            issues,
            location + "/control",
        )
        if key is None or effect is None:
            return
        observed = _control_spec(str(unit_id), effect["payload"])
        if dict(control) != observed:
            _issue(
                issues,
                "violated",
                "control_result_mismatch",
                location + "/control",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=observed,
                observed=copy.deepcopy(dict(control)),
                remediation="use the exact outcome condition and route inventory",
            )
        _add_owner(owners, key, "result", str(result.get("id")), location)
    elif kind in {"value", "return"}:
        _check_machine_source(
            result.get("machine_source"),
            machine,
            issues,
            json_location=location + "/machine_source",
            label=f"result {result.get('id')!r}",
        )
    elif kind not in {"fault", "termination"}:
        _issue(
            issues,
            "incomplete",
            "unsupported_result_kind",
            location + "/kind",
            expected=["control", "fault", "return", "termination", "value"],
            observed=kind,
            remediation="express the result using a supported structured kind",
        )
    refs = result.get("effect_refs", [])
    if not isinstance(refs, list):
        _issue(
            issues,
            "violated",
            "malformed_result_effect_refs",
            location + "/effect_refs",
            expected="array",
            observed=refs,
            remediation="provide an array of exact machine effect references",
        )
        return
    for ref_index, reference in enumerate(refs):
        key, _effect = _resolve_effect_reference(
            reference,
            inventory,
            None,
            issues,
            f"{location}/effect_refs/{ref_index}",
        )
        if key is not None:
            _add_owner(owners, key, "result", str(result.get("id")), location)


def _check_adapter_effects(
    raw_effects: Any,
    machine: Mapping[str, Any],
    component: Mapping[str, Any],
    member_ids: Sequence[str],
    inventory: Mapping[str, Mapping[str, Any]],
    owners: dict[str, list[dict[str, str]]],
    issues: list[dict[str, Any]],
) -> None:
    if not isinstance(raw_effects, list):
        _issue(
            issues,
            "violated",
            "malformed_adapter_effects",
            "/adapter_effects",
            expected="array",
            observed=raw_effects,
            remediation="provide exact adapter-owned effect references",
        )
        return
    member_set = set(member_ids)
    for index, item in enumerate(raw_effects):
        location = f"/adapter_effects/{index}"
        if not isinstance(item, Mapping):
            _issue(
                issues,
                "violated",
                "malformed_adapter_effect",
                location,
                expected="object",
                observed=item,
                remediation="provide an exact effect and reviewed adapter reason",
            )
            continue
        reason = item.get("reason")
        key, effect = _resolve_effect_reference(
            item.get("effect"), inventory, None, issues, location + "/effect"
        )
        if key is None or effect is None:
            continue
        allowed = (
            (effect["family"] == "register_write" and reason == "machine_register_projection")
            or (effect["family"] == "flag_write" and reason == "machine_flag_projection")
            or (
                effect["family"] == "memory_event"
                and reason == "stack_frame_projection"
                and _is_stack_expression(effect["payload"].get("address"))
            )
            or (
                effect["family"] == "external_event"
                and reason == "internal_call_frame"
                and effect["payload"].get("kind") == "internal_call"
                and _internal_call_is_member(effect["payload"], member_set, machine)
            )
            or (
                effect["family"] == "memory_event"
                and reason == "internal_control_table_projection"
                and _is_internal_control_table_read(effect["payload"], component)
            )
        )
        if reason not in _ADAPTER_REASONS or not allowed:
            _issue(
                issues,
                "violated",
                "invalid_adapter_effect_ownership",
                location,
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=(
                    "a register, flag, stack-frame, internal-control-table, "
                    "or member-internal-call "
                    "projection with its matching reason"
                ),
                observed={"family": effect["family"], "reason": reason},
                remediation=(
                    "represent observable effects logically instead of hiding "
                    "them in the adapter"
                ),
            )
        _add_owner(owners, key, "adapter", str(reason), location)


def _is_internal_control_table_read(
    event: Mapping[str, Any], component: Mapping[str, Any]
) -> bool:
    if event.get("kind") != "read" or not isinstance(event.get("width"), int):
        return False
    boundary = component.get("machine_boundary")
    if not isinstance(boundary, Mapping):
        return False
    controls = boundary.get("internal_indirect_controls", [])
    if not isinstance(controls, list):
        return False
    for control in controls:
        if not isinstance(control, Mapping):
            continue
        inventory = control.get("target_inventory")
        target = control.get("target_expression")
        if (
            not isinstance(inventory, Mapping)
            or inventory.get("status") != "recovered"
            or inventory.get("closure") != "checked_finite_target_inventory"
            or inventory.get("failure") is not None
            or control.get("external_target_unit_ids") not in ([], None)
            or not isinstance(target, Mapping)
            or target.get("op") != "load"
            or target.get("width") != event.get("width")
        ):
            continue
        if _addresses_equal(target.get("address"), event.get("address")):
            return True
    return False


def _check_effect_coverage(
    inventory: Mapping[str, Mapping[str, Any]],
    owners: Mapping[str, Sequence[Mapping[str, str]]],
    issues: list[dict[str, Any]],
) -> None:
    for key in sorted(inventory):
        effect = inventory[key]
        bound = owners.get(key, [])
        if not bound:
            reference = effect["reference"]
            _issue(
                issues,
                "incomplete",
                "unrepresented_machine_effect",
                "/effect_coverage",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected=reference,
                observed=None,
                remediation=_effect_remediation(effect["family"]),
            )
        elif len(bound) > 1:
            _issue(
                issues,
                "violated",
                "multiply_owned_machine_effect",
                "/effect_coverage",
                unit_id=effect["unit_id"],
                rva=effect["rva"],
                expected="exactly one logical or adapter owner",
                observed=copy.deepcopy(list(bound)),
                remediation="remove duplicate effect references",
            )


def _effect_inventory(
    member_ids: Sequence[str],
    machine: Mapping[str, Any],
    component: Mapping[str, Any],
) -> dict[str, dict[str, Any]]:
    members = set(member_ids)
    boundary = component.get("machine_boundary")
    boundary_exits = boundary.get("exits") if isinstance(boundary, Mapping) else None
    boundary_exit_units = (
        {
            str(exit_item["source_unit_id"])
            for exit_item in boundary_exits
            if isinstance(exit_item, Mapping)
            and isinstance(exit_item.get("source_unit_id"), str)
        }
        if isinstance(boundary_exits, list)
        else None
    )
    result: dict[str, dict[str, Any]] = {}
    for unit_id in sorted(
        member_ids,
        key=lambda value: (_unit_rva(machine["units_by_id"][value]), value),
    ):
        unit = machine["units_by_id"][unit_id]
        semantics = unit.get("semantics")
        semantics = semantics if isinstance(semantics, Mapping) else {}
        for family, field in (
            ("register_write", "register_writes"),
            ("flag_write", "flag_writes"),
            ("memory_event", "memory_events"),
            ("external_event", "external_events"),
            ("fault", "faults"),
        ):
            values = semantics.get(field, [])
            if not isinstance(values, list):
                continue
            for index, payload in enumerate(values):
                reference = {"family": family, "unit_id": unit_id, "index": index}
                key = _effect_key(reference)
                result[key] = {
                    "family": family,
                    "unit_id": unit_id,
                    "rva": _unit_rva(unit),
                    "index": index,
                    "payload": copy.deepcopy(payload),
                    "reference": reference,
                }
        outcome = semantics.get("outcome")
        is_boundary_exit = (
            unit_id in boundary_exit_units
            if boundary_exit_units is not None
            else isinstance(outcome, Mapping)
            and _outcome_leaves_component(outcome, members, machine)
        )
        if isinstance(outcome, Mapping) and is_boundary_exit:
            reference = {"family": "control_exit", "unit_id": unit_id}
            result[_effect_key(reference)] = {
                "family": "control_exit",
                "unit_id": unit_id,
                "rva": _unit_rva(unit),
                "payload": copy.deepcopy(dict(outcome)),
                "reference": reference,
            }
    return result


def _resolve_effect_reference(
    reference: Any,
    inventory: Mapping[str, Mapping[str, Any]],
    expected_family: str | None,
    issues: list[dict[str, Any]],
    json_location: str,
) -> tuple[str | None, Mapping[str, Any] | None]:
    if not isinstance(reference, Mapping):
        _issue(
            issues,
            "violated",
            "malformed_effect_reference",
            json_location,
            expected="structured effect reference",
            observed=reference,
            remediation="use a reference emitted by interface synthesis",
        )
        return None, None
    normalized = {
        "family": reference.get("family"),
        "unit_id": reference.get("unit_id"),
        **({"index": reference.get("index")} if "index" in reference else {}),
    }
    key = _effect_key(normalized)
    effect = inventory.get(key)
    if effect is None:
        unit_id = reference.get("unit_id")
        _issue(
            issues,
            "violated",
            "unknown_effect_reference",
            json_location,
            unit_id=unit_id if isinstance(unit_id, str) else None,
            expected="an effect in the selected component",
            observed=copy.deepcopy(normalized),
            remediation="regenerate the interface against current component membership",
        )
        return None, None
    if expected_family is not None and effect["family"] != expected_family:
        _issue(
            issues,
            "violated",
            "effect_owner_family_mismatch",
            json_location,
            unit_id=effect["unit_id"],
            rva=effect["rva"],
            expected=expected_family,
            observed=effect["family"],
            remediation="bind this declaration to the corresponding effect family",
        )
        return key, effect
    return key, effect


def _outcome_leaves_component(
    outcome: Mapping[str, Any], members: set[str], machine: Mapping[str, Any]
) -> bool:
    kind = outcome.get("kind")
    if kind in {"return", "fault", "termination", "indirect_call", "indirect_jump"}:
        return True
    targets = _outcome_targets(outcome)
    if not targets:
        return False
    return any(
        target not in machine["units_by_rva"]
        or machine["units_by_rva"][target]["id"] not in members
        for target in targets
    )


def _outcome_targets(outcome: Mapping[str, Any]) -> list[int]:
    result = []
    for field in ("target_rva", "true_target_rva", "false_target_rva"):
        value = outcome.get(field)
        if isinstance(value, int) and not isinstance(value, bool):
            result.append(value)
    return result


def _control_spec(unit_id: str, outcome: Mapping[str, Any]) -> dict[str, Any]:
    kind = str(outcome.get("kind"))
    result: dict[str, Any] = {"unit_id": unit_id, "outcome_kind": kind}
    if "condition" in outcome:
        result["condition"] = copy.deepcopy(outcome["condition"])
    routes = []
    if kind == "branch":
        routes = [
            {"when": True, "target_rva": outcome.get("true_target_rva")},
            {"when": False, "target_rva": outcome.get("false_target_rva")},
        ]
    elif isinstance(outcome.get("target_rva"), int):
        routes = [{"when": "always", "target_rva": outcome["target_rva"]}]
    if routes:
        result["routes"] = routes
    if kind.startswith("indirect") and "target" in outcome:
        result["target_expression"] = copy.deepcopy(outcome["target"])
    if kind == "return" and "value" in outcome:
        result["return_target"] = copy.deepcopy(outcome["value"])
    return result


def _event_identity(event: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        field: copy.deepcopy(event[field])
        for field in _IDENTITY_FIELDS
        if field in event
    }
    return _normalize_identity(result)


def _normalize_identity(identity: Mapping[str, Any]) -> dict[str, Any]:
    result = {
        field: copy.deepcopy(identity[field])
        for field in _IDENTITY_FIELDS
        if field in identity
    }
    if isinstance(result.get("dll"), str):
        result["dll"] = result["dll"].lower()
    return result


def _identity_complete(identity: Mapping[str, Any]) -> bool:
    kind = identity.get("kind")
    if kind == "external_call":
        return isinstance(identity.get("dll"), str) and (
            isinstance(identity.get("symbol"), str) or isinstance(identity.get("ordinal"), int)
        )
    if kind == "internal_call":
        return isinstance(identity.get("target_rva"), int)
    return isinstance(kind, str) and len(identity) > 1


def _internal_call_is_member(
    event: Mapping[str, Any], members: Iterable[str], machine: Mapping[str, Any]
) -> bool:
    target = event.get("target_rva")
    unit = machine["units_by_rva"].get(target) if isinstance(target, int) else None
    return unit is not None and unit.get("id") in set(members)


def _address_with_offset(base: Mapping[str, Any], offset: int) -> dict[str, Any]:
    if offset == 0:
        return copy.deepcopy(dict(base))
    return {
        "op": "add32",
        "args": [
            copy.deepcopy(dict(base)),
            {"op": "const", "value": offset & 0xFFFFFFFF, "width": 32},
        ],
    }


def _addresses_equal(left: Any, right: Any) -> bool:
    return left == right or _decompose_address(left) == _decompose_address(right)


def _decompose_address(value: Any) -> tuple[str, int] | None:
    if not isinstance(value, Mapping):
        return None
    op = value.get("op")
    if op in {"reg", "load"}:
        return (_canonical_json(value), 0)
    if op == "const" and isinstance(value.get("value"), int):
        return ("const-base", int(value["value"]) & 0xFFFFFFFF)
    args = value.get("args")
    if op in {"add32", "sub32"} and isinstance(args, list) and len(args) == 2:
        left, right = args
        if (
            isinstance(right, Mapping)
            and right.get("op") == "const"
            and isinstance(right.get("value"), int)
        ):
            base = _decompose_address(left)
            if base is not None:
                delta = int(right["value"]) * (1 if op == "add32" else -1)
                return (base[0], (base[1] + delta) & 0xFFFFFFFF)
        if (
            op == "add32"
            and isinstance(left, Mapping)
            and left.get("op") == "const"
            and isinstance(left.get("value"), int)
        ):
            base = _decompose_address(right)
            if base is not None:
                return (base[0], (base[1] + int(left["value"])) & 0xFFFFFFFF)
    return (_canonical_json(value), 0)


def _is_stack_expression(value: Any) -> bool:
    if isinstance(value, Mapping):
        if value.get("op") == "reg" and str(value.get("name", "")).lower() in {
            "esp",
            "ebp",
            "sp",
            "bp",
        }:
            return True
        return any(_is_stack_expression(item) for item in value.values())
    if isinstance(value, list):
        return any(_is_stack_expression(item) for item in value)
    return False


def _expression_occurrences(unit: Mapping[str, Any]) -> Iterable[tuple[dict[str, Any], str]]:
    semantics = unit.get("semantics")
    if not isinstance(semantics, Mapping):
        return

    def visit(value: Any, pointer: str) -> Iterable[tuple[dict[str, Any], str]]:
        if isinstance(value, dict):
            if isinstance(value.get("op"), str):
                yield value, pointer
            for key in sorted(value):
                yield from visit(value[key], pointer + "/" + _pointer_escape(str(key)))
        elif isinstance(value, list):
            for index, item in enumerate(value):
                yield from visit(item, pointer + f"/{index}")

    # pre_state declares the whole architectural state; it is not evidence that
    # every register is an input to this component. Instruction replay likewise
    # duplicates the normalized effects below.
    for field in (
        "edge_conditions",
        "external_events",
        "faults",
        "flag_writes",
        "memory_events",
        "ordered_events",
        "outcome",
        "register_writes",
        "x87_micro_ops",
    ):
        if field in semantics:
            yield from visit(semantics[field], f"/semantics/{field}")


def _named_entries(
    spec: Mapping[str, Any], field: str, issues: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    raw = spec.get(field, [])
    if not isinstance(raw, list):
        _issue(
            issues,
            "violated",
            "malformed_interface_family",
            f"/{field}",
            expected="array",
            observed=raw,
            remediation=f"replace {field} with an array of structured declarations",
        )
        return []
    result: list[dict[str, Any]] = []
    seen: set[str] = set()
    for index, item in enumerate(raw):
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not item["id"]:
            _issue(
                issues,
                "violated",
                "malformed_interface_entry",
                f"/{field}/{index}",
                expected="object with a non-empty id",
                observed=item,
                remediation="add a stable logical identifier",
            )
            continue
        if item["id"] in seen:
            _issue(
                issues,
                "violated",
                "duplicate_interface_id",
                f"/{field}/{index}/id",
                expected="unique ID within interface family",
                observed=item["id"],
                remediation="rename or merge the duplicate declaration",
            )
        seen.add(item["id"])
        result.append(item)
    return result


def _member_ids(
    component: Mapping[str, Any],
    machine: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> list[str]:
    membership = component.get("membership")
    raw = membership.get("resolved_unit_ids") if isinstance(membership, Mapping) else None
    if not isinstance(raw, list) or not raw:
        _issue(
            issues,
            "violated",
            "missing_component_membership",
            "/component_id",
            expected="non-empty resolved_unit_ids",
            observed=raw,
            remediation="regenerate the semantic component catalog",
        )
        return []
    result = []
    for unit_id in raw:
        if not isinstance(unit_id, str) or unit_id not in machine["units_by_id"]:
            _issue(
                issues,
                "violated",
                "unknown_component_member",
                "/component_id",
                unit_id=unit_id if isinstance(unit_id, str) else None,
                expected="machine IR unit",
                observed=unit_id,
                remediation="regenerate the semantic component catalog",
            )
        else:
            result.append(unit_id)
    return sorted(set(result), key=lambda value: (_unit_rva(machine["units_by_id"][value]), value))


def _find_component(catalog: Mapping[str, Any], component_id: str) -> dict[str, Any]:
    components = catalog.get("components")
    if not isinstance(components, list):
        raise ComponentInterfaceError("semantic component catalog has no component array")
    matches = [
        item
        for item in components
        if isinstance(item, dict) and item.get("id") == component_id
    ]
    if len(matches) != 1:
        raise ComponentInterfaceError(f"component {component_id!r} is not unique in the catalog")
    return matches[0]


def _add_owner(
    owners: dict[str, list[dict[str, str]]],
    key: str,
    kind: str,
    identity: str,
    location: str,
) -> None:
    owners[key].append({"kind": kind, "id": identity, "json_location": location})


def _effect_key(reference: Mapping[str, Any]) -> str:
    family = str(reference.get("family"))
    unit_id = str(reference.get("unit_id"))
    suffix = f":{reference.get('index')}" if "index" in reference else ""
    return f"{family}:{unit_id}{suffix}"


def _effect_remediation(family: str) -> str:
    return {
        "memory_event": "bind the effect to a checked object field or eligible stack adapter",
        "external_event": "bind the event to a checked service or eligible internal-call frame",
        "control_exit": "add an exact structured control result",
        "fault": "add a structured fault result",
        "register_write": "bind the output result or declare machine-register adapter projection",
        "flag_write": "bind the output result or declare machine-flag adapter projection",
    }.get(family, "represent this effect explicitly")


def _issue(
    issues: list[dict[str, Any]],
    status: str,
    code: str,
    json_location: str,
    *,
    unit_id: str | None = None,
    rva: int | None = None,
    expected: Any = None,
    observed: Any = None,
    remediation: str,
) -> None:
    message = code.replace("_", " ")
    core = {
        "status": status,
        "code": code,
        "message": message,
        "json_location": json_location,
        "unit_id": unit_id,
        "rva": rva,
        "expected": copy.deepcopy(expected),
        "observed": copy.deepcopy(observed),
        "remediation": remediation,
    }
    issues.append(
        {"id": "component-interface-issue:" + _canonical_sha256(core)[:20], **core}
    )


def _issue_sort_key(issue: Mapping[str, Any]) -> tuple[Any, ...]:
    return (
        0 if issue.get("status") == "violated" else 1,
        str(issue.get("json_location", "")),
        str(issue.get("unit_id", "")),
        int(issue.get("rva")) if isinstance(issue.get("rva"), int) else -1,
        str(issue.get("code", "")),
        str(issue.get("id", "")),
    )


def _json_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not pointer.startswith("/"):
        raise ValueError("JSON pointer must start with slash")
    current = value
    for encoded in pointer[1:].split("/"):
        token = encoded.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            current = current[token]
        elif isinstance(current, list):
            current = current[int(token)]
        else:
            raise TypeError("JSON pointer traversed a scalar")
    return copy.deepcopy(current)


def _pointer_escape(value: str) -> str:
    return value.replace("~", "~0").replace("/", "~1")


def _unit_rva(unit: Mapping[str, Any]) -> int:
    try:
        return int(unit["source"]["original"]["rva_start"])
    except (KeyError, TypeError, ValueError) as error:
        raise ComponentInterfaceError("machine IR unit has no original RVA") from error


def _load_json_input(
    value: Path | str | Mapping[str, Any], label: str
) -> dict[str, Any]:
    if isinstance(value, Mapping):
        result = _json_copy(value, label)
        if not isinstance(result, dict):
            raise ComponentInterfaceError(f"{label} must be an object")
        return result
    return _json_file(Path(value), label)


def _input_artifact_sha256(
    source: Path | str | Mapping[str, Any], payload: Mapping[str, Any]
) -> str:
    if isinstance(source, Mapping):
        return _canonical_sha256(payload)
    return sha256_file(Path(source))


def _json_file(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ComponentInterfaceError(f"cannot read {label} {path}: {error}") from error
    if not isinstance(value, dict):
        raise ComponentInterfaceError(f"{label} must be a JSON object")
    return value


def _json_copy(value: Any, label: str) -> Any:
    try:
        return json.loads(json.dumps(value))
    except (TypeError, ValueError) as error:
        raise ComponentInterfaceError(f"{label} must contain JSON values") from error


def _canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _canonical_sha256(value: Any) -> str:
    return sha256(_canonical_json(value).encode("utf-8")).hexdigest()


__all__ = [
    "ComponentInterfaceError",
    "check_component_interface",
    "finalize_component_interface_spec",
    "synthesize_component_interface_spec",
    "write_component_interface_refinement",
]
