"""Checked state and code-capability transducers for V5 machine overlays."""

from __future__ import annotations

import json
import re
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import BoundaryModelError, object_
from .interface_package_v5 import CompiledComponentInterfaceV5


def callback_type_ids(bundle: CompiledComponentInterfaceV5) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                value.type_id
                for signature in bundle.intent.schema.signatures
                for value in (*signature.parameters, *signature.results)
                if value.interpretation == "callback"
            }
        )
    )


def callback_projection_lines(
    *,
    value: object,
    projection: Mapping[str, object],
    name: str,
    code_capabilities: Mapping[str, Mapping[str, object]],
) -> list[str]:
    authority_id = str(projection.get("authority_id", ""))
    protocol_id = str(projection.get("protocol_id", ""))
    source = object_(projection.get("source"), "component callback source")
    capability = code_capabilities.get(authority_id)
    if (
        getattr(value, "interpretation", None) != "callback"
        or source.get("kind") != "constant"
        or source.get("width") != 32
        or capability is None
        or capability.get("protocol_id") != protocol_id
        or _uint(source.get("value"), "component callback source word")
        != capability.get("target_word")
    ):
        raise BoundaryModelError(
            "component callback projection lacks an exact code-capability bridge"
        )
    type_id = _c_identifier(getattr(value, "type_id"))
    return [
        f"  uint32_t {name}_physical_word =",
        f"      spx_native_code_bridge_address(UINT32_C({capability['target_rva']}));",
        f"  struct spx_callback_{type_id}_v5 {name} = {{",
        f"    {name}_physical_word,",
        f"    UINT32_C({capability['target_rva']})",
        "  };",
    ]


def state_projection_index(
    value: object, context: str
) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        raise BoundaryModelError(f"{context} must be an array")
    result: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(value):
        row = object_(item, f"{context} {index}")
        identity = str(row.get("id", ""))
        if not identity or identity in result:
            raise BoundaryModelError(f"{context} identities are invalid or duplicated")
        result[identity] = row
    return result


def _checked_state_reference_projection(value: object, context: str) -> tuple[int, int]:
    projection = object_(value, context)
    source = object_(projection.get("source"), f"{context} source")
    requested = object_(
        projection.get("requested_extent"), f"{context} requested extent"
    )
    if (
        projection.get("kind") != "reference"
        or source.get("kind") != "static_slot"
        or source.get("width") != 32
        or requested.get("kind") != "constant"
    ):
        raise BoundaryModelError(
            "component state requires an exact 32-bit static reference slot"
        )
    return (
        _uint(source.get("rva"), f"{context} slot"),
        _uint(requested.get("value"), f"{context} requested extent"),
    )


def _checked_state_scalar_projection(value: object, context: str) -> tuple[int, int]:
    projection = object_(value, context)
    width = _uint(projection.get("width"), f"{context} width")
    if (
        projection.get("kind") != "static_slot"
        or projection.get("at") not in {"entry", "exit"}
        or width not in {8, 16, 32}
    ):
        raise BoundaryModelError("component scalar state requires an exact static slot")
    return _uint(projection.get("rva"), f"{context} RVA"), width


def _state_scalar_width(bundle: CompiledComponentInterfaceV5, type_id: str) -> int:
    value = bundle.intent.schema.type_index[type_id]
    while value.kind == "enum":
        underlying = value.body.get("underlying_type_id")
        if (
            not isinstance(underlying, str)
            or underlying not in bundle.intent.schema.type_index
        ):
            raise BoundaryModelError("component state enum has no underlying type")
        value = bundle.intent.schema.type_index[underlying]
    width = value.body.get("width_bits")
    if value.kind != "integer" or width not in {8, 16, 32}:
        raise BoundaryModelError(
            "component scalar state requires an IA-32 integer type"
        )
    return int(width)


def state_import_lines(
    *,
    bundle: CompiledComponentInterfaceV5,
    state_projections: Mapping[str, Mapping[str, object]],
    authority_selectors: Mapping[str, str],
    context_expression: str,
    runtime_expression: str,
) -> list[str]:
    lines: list[str] = []
    for item in bundle.interface.state:
        identity = item.value.identity
        name = _c_identifier(identity)
        row = state_projections[identity]
        if item.value.interpretation == "value":
            slot, width = _checked_state_scalar_projection(
                row.get("entry"), f"component state {identity} entry"
            )
            exit_slot, exit_width = _checked_state_scalar_projection(
                row.get("exit"), f"component state {identity} exit"
            )
            if (
                exit_slot != slot
                or exit_width != width
                or width != _state_scalar_width(bundle, item.value.type_id)
            ):
                raise BoundaryModelError(
                    "component scalar state slot changes across operation"
                )
            lines.extend(
                [
                    f"  {context_expression}.state.{name} = spx_component_read(",
                    f"      {runtime_expression}, UINT32_C({slot}), "
                    f"UINT32_C({width // 8}), &memory_fault);",
                    "  if (memory_fault != 0U)",
                    "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                ]
            )
            continue
        slot, requested = _checked_state_reference_projection(
            row.get("entry"), f"component state {identity} entry"
        )
        exit_slot, _exit_requested = _checked_state_reference_projection(
            row.get("exit"), f"component state {identity} exit"
        )
        if exit_slot != slot:
            raise BoundaryModelError(
                "component state slot identity changes across operation"
            )
        if item.value.interpretation != "reference":
            raise BoundaryModelError(
                "component state requires a checked reference transducer"
            )
        permissions = {"read": 1, "write": 2, "read_write": 3}.get(item.value.access, 0)
        nullable = 1 if item.value.nullable else 0
        selector = authority_selector_expression(
            object_(row.get("entry"), f"component state {identity} entry"),
            authority_selectors,
        )
        lines.extend(
            [
                f"  uint32_t component_state_{name}_word = spx_component_read(",
                f"      {runtime_expression}, UINT32_C({slot}), UINT32_C(4), &memory_fault);",
                f"  spx_machine_reference_v1 component_state_{name}_machine = {{0}};",
                "  if (memory_fault != 0U ||",
                f"      {runtime_expression} == 0 || {runtime_expression}->resolve_reference == 0 ||",
                f"      {runtime_expression}->resolve_reference({runtime_expression}->context,",
                f"          component_state_{name}_word, UINT32_C({requested}),",
                f"          UINT32_C({permissions}), {selector}, UINT32_C({nullable}), UINT32_C(0),",
                f"          &component_state_{name}_machine) != SPX_BOUNDARY_OK ||",
                f"      component_state_{name}_machine.domain > UINT32_MAX ||",
                f"      component_state_{name}_machine.object > UINT32_MAX ||",
                f"      component_state_{name}_machine.generation > UINT32_MAX)",
                "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                f"  {context_expression}.state.{name} = (spx_ref_v5){{",
                f"    (uint32_t)component_state_{name}_machine.domain,",
                f"    (uint32_t)component_state_{name}_machine.object,",
                f"    (uint32_t)component_state_{name}_machine.generation,",
                f"    component_state_{name}_machine.offset,",
                f"    component_state_{name}_machine.extent,",
                f"    component_state_{name}_machine.permissions",
                "  };",
            ]
        )
    return lines


def authority_selector_expression(
    projection: Mapping[str, object], authority_selectors: Mapping[str, str]
) -> str:
    """Return the exact rule-id argument for a projection, or explicit none."""

    authority = projection.get("authority")
    if not isinstance(authority, Mapping):
        return "0"
    authority_id = authority.get("id")
    if not isinstance(authority_id, str) or not authority_id:
        raise BoundaryModelError("component object authority identity is invalid")
    rule_id = authority_selectors.get(authority_id)
    return "0" if rule_id is None else json.dumps(rule_id, ensure_ascii=True)


def checked_opaque_resource_projection(
    *, value: object, projection: Mapping[str, object], context: str
) -> tuple[Mapping[str, object], int]:
    """Bind one logical opaque resource to an exact physical word source."""

    resource_kind = getattr(value, "resource_kind", None)
    provider_domain = getattr(value, "provider_domain", None)
    source = object_(projection.get("source"), f"{context} source")
    if (
        getattr(value, "interpretation", None) != "resource"
        or getattr(value, "access", None) != "none"
        or not isinstance(resource_kind, str)
        or not resource_kind
        or not isinstance(provider_domain, str)
        or not provider_domain
        or projection.get("kind") != "resource"
        or projection.get("resource_kind") != resource_kind
        or source.get("kind") not in {"register", "stack", "static_slot", "constant"}
        or source.get("width") != 32
        or (
            source.get("kind") != "constant"
            and source.get("at") not in {"entry", "call"}
        )
    ):
        raise BoundaryModelError(
            f"{context} requires an exact read-only opaque-resource word"
        )
    tag = (
        int(
            canonical_sha256_v3(
                {
                    "provider_domain": provider_domain,
                    "resource_kind": resource_kind,
                }
            )[:8],
            16,
        )
        | 0x80000000
    )
    return source, tag


def state_export_lines(
    *,
    bundle: CompiledComponentInterfaceV5,
    state_projections: Mapping[str, Mapping[str, object]],
    context_expression: str,
    runtime_expression: str,
) -> list[str]:
    if not bundle.interface.state:
        return []
    interpretations = {item.value.interpretation for item in bundle.interface.state}
    if interpretations == {"value"}:
        return _scalar_state_export_lines(
            bundle=bundle,
            state_projections=state_projections,
            context_expression=context_expression,
            runtime_expression=runtime_expression,
        )
    if interpretations != {"reference"}:
        raise BoundaryModelError(
            "component state cannot mix scalar and reference storage"
        )
    lines = ["  uint32_t component_state_restore_fault = 0U;"]
    slots: list[tuple[str, int]] = []
    for item in bundle.interface.state:
        identity = item.value.identity
        name = _c_identifier(identity)
        slot, _requested = _checked_state_reference_projection(
            state_projections[identity].get("exit"),
            f"component state {identity} exit",
        )
        permissions = {"read": 1, "write": 2, "read_write": 3}.get(item.value.access, 0)
        nullable = 1 if item.value.nullable else 0
        slots.append((name, slot))
        lines.extend(
            [
                f"  spx_machine_reference_v1 component_state_{name}_output = {{",
                f"    {context_expression}.state.{name}.domain,",
                f"    {context_expression}.state.{name}.object,",
                f"    {context_expression}.state.{name}.generation,",
                f"    {context_expression}.state.{name}.offset,",
                f"    {context_expression}.state.{name}.extent,",
                f"    {context_expression}.state.{name}.permissions",
                "  };",
                f"  uint32_t component_state_{name}_new_word = 0U;",
                f"  if ({runtime_expression}->realize_reference == 0 ||",
                f"      {runtime_expression}->realize_reference({runtime_expression}->context,",
                f"          &component_state_{name}_output, UINT32_C({permissions}),",
                f"          UINT32_C({nullable}), UINT32_C(0),",
                f"          &component_state_{name}_new_word) != SPX_BOUNDARY_OK)",
                "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                f"  uint32_t component_state_{name}_old_word = spx_component_read(",
                f"      {runtime_expression}, UINT32_C({slot}), UINT32_C(4), &memory_fault);",
            ]
        )
    lines.append(
        "  if (memory_fault != 0U) return "
        "(spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"
    )
    for name, slot in slots:
        lines.append(
            f"  spx_component_write({runtime_expression}, UINT32_C({slot}), "
            f"UINT32_C(4), component_state_{name}_new_word, &memory_fault);"
        )
    lines.append("  if (memory_fault != 0U) {")
    for name, slot in slots:
        lines.append(
            f"    spx_component_write({runtime_expression}, UINT32_C({slot}), "
            f"UINT32_C(4), component_state_{name}_old_word, "
            "&component_state_restore_fault);"
        )
    lines.extend(
        [
            "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            "  }",
        ]
    )
    return lines


def _scalar_state_export_lines(
    *,
    bundle: CompiledComponentInterfaceV5,
    state_projections: Mapping[str, Mapping[str, object]],
    context_expression: str,
    runtime_expression: str,
) -> list[str]:
    lines = ["  uint32_t component_state_restore_fault = 0U;"]
    slots: list[tuple[str, int, int]] = []
    for item in bundle.interface.state:
        identity = item.value.identity
        name = _c_identifier(identity)
        slot, width = _checked_state_scalar_projection(
            state_projections[identity].get("exit"),
            f"component state {identity} exit",
        )
        entry_slot, entry_width = _checked_state_scalar_projection(
            state_projections[identity].get("entry"),
            f"component state {identity} entry",
        )
        if (
            entry_slot != slot
            or entry_width != width
            or width != _state_scalar_width(bundle, item.value.type_id)
        ):
            raise BoundaryModelError(
                "component scalar state slot changes across operation"
            )
        slots.append((name, slot, width // 8))
        lines.extend(
            [
                f"  uint32_t component_state_{name}_old_word = spx_component_read(",
                f"      {runtime_expression}, UINT32_C({slot}), "
                f"UINT32_C({width // 8}), &memory_fault);",
            ]
        )
    lines.append(
        "  if (memory_fault != 0U) return "
        "(spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"
    )
    for name, slot, width in slots:
        lines.append(
            f"  spx_component_write({runtime_expression}, UINT32_C({slot}), "
            f"UINT32_C({width}), (uint32_t){context_expression}.state.{name}, "
            "&memory_fault);"
        )
    lines.append("  if (memory_fault != 0U) {")
    for name, slot, width in slots:
        lines.append(
            f"    spx_component_write({runtime_expression}, UINT32_C({slot}), "
            f"UINT32_C({width}), component_state_{name}_old_word, "
            "&component_state_restore_fault);"
        )
    lines.extend(
        [
            "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            "  }",
        ]
    )
    return lines


def _uint(value: object, context: str) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        raise BoundaryModelError(f"{context} must be a 32-bit unsigned integer")
    return value


def _c_identifier(value: object) -> str:
    text = str(value).replace("-", "_").replace(".", "_")
    if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", text) is None:
        raise BoundaryModelError(f"value {value!r} is not a C identifier")
    return text


__all__ = [
    "authority_selector_expression",
    "callback_projection_lines",
    "callback_type_ids",
    "state_export_lines",
    "state_import_lines",
    "state_projection_index",
]
