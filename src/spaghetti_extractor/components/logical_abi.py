"""Stable logical-C types shared by component checking and execution."""

from __future__ import annotations

from typing import Mapping, Sequence


LOGICAL_C_V1 = "logical-c-v1"
LOGICAL_OBJECT_C_V1 = "logical-object-c-v1"
SCALAR_C_TYPES = frozenset(
    {
        "uint8_t",
        "uint16_t",
        "uint32_t",
        "uint64_t",
        "int8_t",
        "int16_t",
        "int32_t",
        "int64_t",
    }
)
READ_ONLY_BYTES_V1 = "read-only-bytes-v1"
INDEXED_READ_VIEW_V1 = "indexed-read-view-v1"
NUL_TERMINATED_BYTES_V1 = "nul-terminated-bytes-v1"
NUL_TERMINATED_READ_VIEW_V1 = "nul-terminated-read-view-v1"
OFFSET_INTO_VIEW_V1 = "offset-into-view-v1"
LOGICAL_C_TYPES = SCALAR_C_TYPES | {
    READ_ONLY_BYTES_V1,
    NUL_TERMINATED_BYTES_V1,
}


def logical_type_kind(type_name: object, *, source_abi: object) -> str | None:
    if type_name in SCALAR_C_TYPES:
        return (
            "scalar"
            if source_abi in {LOGICAL_C_V1, LOGICAL_OBJECT_C_V1}
            else None
        )
    if type_name == READ_ONLY_BYTES_V1 and source_abi == LOGICAL_OBJECT_C_V1:
        return "read_only_bytes"
    if (
        type_name == NUL_TERMINATED_BYTES_V1
        and source_abi == LOGICAL_OBJECT_C_V1
    ):
        return "nul_terminated_bytes"
    return None


def logical_c_type(type_name: object, *, source_abi: object) -> str | None:
    kind = logical_type_kind(type_name, source_abi=source_abi)
    if kind == "scalar":
        return str(type_name)
    if kind == "read_only_bytes":
        return "const spx_ro_bytes_v1 *"
    if kind == "nul_terminated_bytes":
        return "const spx_c_string_v1 *"
    return None


def parameter_shape_error(
    parameter: Mapping[str, object],
    parameters: Sequence[Mapping[str, object]],
    *,
    source_abi: object,
) -> str | None:
    """Return why a logical parameter cannot be lowered, if applicable."""

    type_name = parameter.get("type")
    kind = logical_type_kind(type_name, source_abi=source_abi)
    view = parameter.get("memory_view")
    if kind is None:
        return f"unsupported logical C type {type_name!r}"
    if kind == "scalar":
        if view is not None:
            return "scalar logical parameter cannot declare a memory view"
        return None
    if not isinstance(view, Mapping):
        return "read-only bytes parameter requires a memory_view"
    view_kind = view.get("kind")
    common_fields = {
        "kind",
        "element_width",
        "event_refs",
        "access_witness",
    }
    expected_fields = (
        common_fields | {"extent_parameter_id"}
        if kind == "read_only_bytes"
        else common_fields
    )
    if set(view) != expected_fields:
        return "read-only bytes memory_view fields are not canonical"
    expected_kind = (
        INDEXED_READ_VIEW_V1
        if kind == "read_only_bytes"
        else NUL_TERMINATED_READ_VIEW_V1
    )
    if view_kind != expected_kind:
        return "read-only bytes memory_view kind is unsupported"
    if view.get("element_width") != 1 or isinstance(view.get("element_width"), bool):
        return "read-only bytes memory_view element_width must be 1"
    event_refs = view.get("event_refs")
    if not isinstance(event_refs, list) or not event_refs:
        return "read-only bytes memory_view event_refs must be a nonempty list"
    if not isinstance(view.get("access_witness"), Mapping):
        return "read-only bytes memory_view access_witness must be an object"
    if kind == "read_only_bytes":
        extent_id = view.get("extent_parameter_id")
        if not isinstance(extent_id, str) or not extent_id:
            return "read-only bytes extent_parameter_id is malformed"
        extent = next((row for row in parameters if row.get("id") == extent_id), None)
        if extent is None:
            return "read-only bytes extent parameter does not exist"
        if extent.get("type") != "uint32_t":
            return "read-only bytes extent parameter must have type uint32_t"
    return None


def result_shape_error(
    result: Mapping[str, object],
    parameters: Sequence[Mapping[str, object]],
    *,
    source_abi: object,
) -> str | None:
    """Return why a logical value result cannot be represented, if applicable."""

    if logical_type_kind(result.get("type"), source_abi=source_abi) != "scalar":
        return "logical result type must be scalar"
    relation = result.get("value_relation")
    if relation is None:
        return None
    if not isinstance(relation, Mapping):
        return "logical result value_relation must be an object"
    if set(relation) != {"kind", "parameter_id"}:
        return "logical result value_relation fields are not canonical"
    if relation.get("kind") != OFFSET_INTO_VIEW_V1:
        return "logical result value_relation kind is unsupported"
    parameter_id = relation.get("parameter_id")
    parameter = next(
        (row for row in parameters if row.get("id") == parameter_id), None
    )
    if parameter is None:
        return "logical result offset view parameter does not exist"
    if logical_type_kind(
        parameter.get("type"), source_abi=source_abi
    ) not in {"read_only_bytes", "nul_terminated_bytes"}:
        return "logical result offset must reference a byte-view parameter"
    return None


def source_abi_error(
    abi: object,
    parameters: Sequence[Mapping[str, object]],
) -> str | None:
    """Return why a checked logical signature is incompatible with a source ABI."""

    if abi not in {LOGICAL_C_V1, LOGICAL_OBJECT_C_V1}:
        return f"source entry ABI is unsupported: {abi!r}"
    for parameter in parameters:
        if logical_type_kind(parameter.get("type"), source_abi=abi) is None:
            if abi == LOGICAL_C_V1 and parameter.get("type") == READ_ONLY_BYTES_V1:
                return "logical-c-v1 accepts scalar parameters only"
            return f"unsupported logical type {parameter.get('type')!r} for {abi}"
    return None


def logical_abi_header() -> str:
    """Render the stable source-level object view ABI."""

    return """#ifndef SPX_OBJECT_ABI_H
#define SPX_OBJECT_ABI_H

#include <stdint.h>

struct spx_ro_bytes_v1 {
  void *context;
  uint32_t extent;
  uint32_t (*read_u8)(void *, uint32_t, uint8_t *);
};
typedef struct spx_ro_bytes_v1 spx_ro_bytes_v1;

struct spx_c_string_v1 {
  void *context;
  uint32_t (*read_u8)(void *, uint32_t, uint8_t *);
};
typedef struct spx_c_string_v1 spx_c_string_v1;

#endif
"""


__all__ = [
    "LOGICAL_C_TYPES",
    "LOGICAL_C_V1",
    "LOGICAL_OBJECT_C_V1",
    "INDEXED_READ_VIEW_V1",
    "NUL_TERMINATED_BYTES_V1",
    "NUL_TERMINATED_READ_VIEW_V1",
    "OFFSET_INTO_VIEW_V1",
    "READ_ONLY_BYTES_V1",
    "SCALAR_C_TYPES",
    "logical_abi_header",
    "logical_c_type",
    "logical_type_kind",
    "parameter_shape_error",
    "result_shape_error",
    "source_abi_error",
]
