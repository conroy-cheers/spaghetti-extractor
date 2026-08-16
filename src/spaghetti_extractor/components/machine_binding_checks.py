"""Cross-input checks shared by component machine-binding phases."""

from __future__ import annotations

import json
import re
from collections.abc import Mapping, Sequence
from typing import Protocol

from .interface_ir import PortableComponentInterfaceV2
from .value_codec import value_codec_expression_references


class ComponentMachineBindingError(ValueError):
    """A component machine binding is malformed or contradicts checked inputs."""


class LogicalMachineValue(Protocol):
    identity: str
    decoding: Mapping[str, object] | None


class BoundValue(Protocol):
    identity: str


class BoundOperation(Protocol):
    operation_id: str
    parameters: Sequence[BoundValue]
    state: Sequence[BoundValue]


def check_result_decoding(
    *,
    value: LogicalMachineValue,
    operation_parameters: Mapping[str, Mapping[str, object]],
    types: Mapping[str, Mapping[str, object]],
    operation_id: str,
    issues: list[dict[str, object]],
) -> None:
    if value.decoding is None:
        return
    references = value_codec_expression_references(value.decoding)
    if references["projected_value"] != {"value"}:
        _issue(
            issues,
            "violated",
            "result_decoding_must_use_projected_value",
            id=operation_id,
            value_id=value.identity,
        )
    if references["state_input"]:
        _issue(
            issues,
            "violated",
            "result_decoding_references_component_state",
            id=operation_id,
            value_id=value.identity,
        )
    referenced_parameters = (
        references["parameter"]
        | references["bytes_address"]
        | references["byte_extent"]
        | references["byte_read"]
    )
    if referenced_parameters - set(operation_parameters):
        _issue(
            issues,
            "violated",
            "result_decoding_references_unknown_parameter",
            id=operation_id,
            value_id=value.identity,
        )
    byte_references = (
        references["bytes_address"]
        | references["byte_extent"]
        | references["byte_read"]
    )
    for parameter_id in sorted(byte_references):
        parameter = operation_parameters.get(parameter_id)
        parameter_type = (
            None
            if parameter is None
            else types.get(str(parameter.get("type_id")))
        )
        if parameter_type is None or parameter_type.get("kind") != "bytes":
            _issue(
                issues,
                "violated",
                "result_decoding_byte_reference_has_non_byte_parameter",
                id=operation_id,
                value_id=value.identity,
                parameter_id=parameter_id,
            )


def check_operation_view_aliases(
    *,
    bound: BoundOperation,
    parameter_index: Mapping[str, Mapping[str, object]],
    states: Mapping[str, Mapping[str, object]],
    types: Mapping[str, Mapping[str, object]],
    issues: list[dict[str, object]],
) -> None:
    views: list[tuple[str, str]] = []
    for value in bound.parameters:
        logical = parameter_index.get(value.identity)
        if logical is not None:
            logical_type = types.get(str(logical.get("type_id")))
            if logical_type is not None and logical_type.get("kind") == "bytes":
                views.append((value.identity, str(logical_type.get("access"))))
    for value in bound.state:
        logical = states.get(value.identity)
        if logical is not None:
            logical_type = types.get(str(logical.get("type_id")))
            if logical_type is not None and logical_type.get("kind") == "bytes":
                views.append((value.identity, str(logical_type.get("access"))))
    if len(views) > 1 and any(access != "read" for _, access in views):
        _issue(
            issues,
            "incomplete",
            "operation_memory_alias_relation_unresolved",
            id=bound.operation_id,
            view_ids=[identity for identity, _ in views],
        )


def logical_scalar_width(logical_type: Mapping[str, object]) -> int:
    c_type = str(logical_type.get("c_type", ""))
    match = re.fullmatch(r"u?int(8|16|32|64)_t", c_type)
    if match is None:
        raise ComponentMachineBindingError(
            f"logical scalar C type {c_type!r} has no fixed width"
        )
    return int(match.group(1))


def projection_issue(
    issues: list[dict[str, object]],
    operation_id: str,
    logical_value: Mapping[str, object],
    code: str,
    **fields: object,
) -> None:
    _issue(
        issues,
        "violated",
        code,
        id=operation_id,
        value_id=logical_value.get("id"),
        **fields,
    )


def machine_manifest_pe_sha256(manifest: Mapping[str, object]) -> str:
    candidates: list[object] = []
    binary = manifest.get("binary")
    if isinstance(binary, Mapping):
        candidates.append(binary.get("sha256"))
    inputs = manifest.get("inputs")
    if isinstance(inputs, Mapping):
        original = inputs.get("original_pe")
        if isinstance(original, Mapping):
            candidates.append(original.get("sha256"))
    values = {
        value
        for value in candidates
        if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
    }
    if len(values) != 1:
        raise ComponentMachineBindingError(
            "machine-IR manifest has no unique PE binding"
        )
    return next(iter(values))


def interface_payload(value: object) -> dict[str, object]:
    if hasattr(value, "to_payload"):
        value = value.to_payload()
    if isinstance(value, (str, bytes)) or not isinstance(value, Mapping):
        raise ComponentMachineBindingError(
            "portable component interface must be a parsed object"
        )
    payload = json.loads(json.dumps(value))
    try:
        return PortableComponentInterfaceV2.parse(payload).to_payload()
    except ValueError as exc:
        raise ComponentMachineBindingError(
            f"portable interface V2 is invalid: {exc}"
        ) from exc


def _issue(
    issues: list[dict[str, object]],
    status: str,
    code: str,
    **detail: object,
) -> None:
    issues.append({"status": status, "code": code, **detail})


__all__ = [
    "ComponentMachineBindingError",
    "check_operation_view_aliases",
    "check_result_decoding",
    "interface_payload",
    "logical_scalar_width",
    "machine_manifest_pe_sha256",
    "projection_issue",
]
