"""Deterministic C declarations for canonical boundary schemas."""

from __future__ import annotations

import re
from typing import Mapping

from ._canonical import BoundaryModelError
from .model import BoundarySchemaV1, BoundaryTypeV1


def render_boundary_header(
    schema: BoundarySchemaV1,
    *,
    type_names: Mapping[str, str] | None = None,
    signature_names: Mapping[str, str] | None = None,
) -> str:
    type_name_map = {
        item.identity: _c_identifier(
            (type_names or {}).get(item.identity, f"spx_{item.identity}")
        )
        for item in schema.types
    }
    signature_name_map = {
        item.identity: _c_identifier(
            (signature_names or {}).get(item.identity, f"spx_{item.identity}")
        )
        for item in schema.signatures
    }
    guard = f"SPX_BOUNDARY_{_c_identifier(schema.schema_id).upper()}_H"
    lines = [
        f"#ifndef {guard}", f"#define {guard}", "", "#include <stdbool.h>",
        "#include <stdint.h>", "",
        "#if defined(_WIN32) && defined(__GNUC__)",
        "# define SPX_CDECL __attribute__((cdecl))",
        "# define SPX_STDCALL __attribute__((stdcall))",
        "# define SPX_FASTCALL __attribute__((fastcall))",
        "#else", "# define SPX_CDECL", "# define SPX_STDCALL",
        "# define SPX_FASTCALL", "#endif", "",
    ]
    for node in schema.types:
        if node.kind in {"record", "union", "opaque"}:
            keyword = "union" if node.kind == "union" else "struct"
            lines.append(
                f"typedef {keyword} {type_name_map[node.identity]} {type_name_map[node.identity]};"
            )
    if any(item.kind in {"record", "union", "opaque"} for item in schema.types):
        lines.append("")
    for node in schema.types:
        if node.kind in {"bool", "integer", "float", "enum"}:
            lines.extend(_render_value_type(node, schema, type_name_map))
    emitted: set[str] = {
        item.identity
        for item in schema.types
        if item.kind in {"bool", "integer", "float", "enum", "opaque"}
    }
    for node in schema.types:
        if (
            node.kind == "pointer"
            and schema.type_index[str(node.body["pointee_type_id"])].kind != "function"
        ):
            pointee = schema.type_index[str(node.body["pointee_type_id"])]
            lines.append(
                f"typedef {_c_type(pointee, type_name_map)} *{type_name_map[node.identity]};"
            )
            emitted.add(node.identity)
    if any(
        item.kind == "pointer"
        and schema.type_index[str(item.body["pointee_type_id"])].kind != "function"
        for item in schema.types
    ):
        lines.append("")
    pending = [
        item
        for item in schema.types
        if item.kind in {"record", "union", "function"}
        or (
            item.kind == "pointer"
            and schema.type_index[str(item.body["pointee_type_id"])].kind
            == "function"
        )
    ]
    while pending:
        progress = False
        for node in tuple(pending):
            if node.kind in {"record", "union"}:
                dependencies = {
                    str(field["type_id"]) for field in node.body["fields"]
                }
            elif node.kind == "function":
                dependencies = {
                    item
                    for item in {
                        str(node.body["result_type_id"]),
                        *(str(item) for item in node.body["parameter_type_ids"]),
                    }
                    if schema.type_index[item].kind != "void"
                }
            else:
                dependencies = {str(node.body["pointee_type_id"])}
            if not dependencies <= emitted:
                continue
            if node.kind in {"record", "union"}:
                lines.extend(_render_value_type(node, schema, type_name_map))
            elif node.kind == "function":
                lines.extend(_render_function_type(node, schema, type_name_map))
            else:
                pointee = schema.type_index[str(node.body["pointee_type_id"])]
                lines.extend([
                    f"typedef {_c_type(pointee, type_name_map)} *{type_name_map[node.identity]};",
                    "",
                ])
            emitted.add(node.identity)
            pending.remove(node)
            progress = True
        if not progress:
            raise BoundaryModelError("boundary C type dependencies cannot be ordered")
    for signature in schema.signatures:
        function = schema.type_index[signature.function_type_id]
        result_node = schema.type_index[str(function.body["result_type_id"])]
        convention = {
            "cdecl": "SPX_CDECL", "stdcall": "SPX_STDCALL",
            "fastcall": "SPX_FASTCALL",
        }.get(str(function.body["calling_convention"]), "")
        parameters = ", ".join(
            f"{_c_type(schema.type_index[item.type_id], type_name_map)} {_c_identifier(item.identity)}"
            for item in signature.parameters
        ) or "void"
        if bool(function.body["variadic"]):
            parameters = "..." if parameters == "void" else f"{parameters}, ..."
        lines.append(
            f"{_c_type(result_node, type_name_map)} {convention} "
            f"{signature_name_map[signature.identity]}({parameters});"
        )
    lines.extend(["", f"#endif /* {guard} */", ""])
    return "\n".join(lines)


def _render_value_type(
    node: BoundaryTypeV1,
    schema: BoundarySchemaV1,
    names: Mapping[str, str],
) -> list[str]:
    name = names[node.identity]
    if node.kind in {"record", "union"}:
        keyword = "struct" if node.kind == "record" else "union"
        lines = [f"{keyword} {name} {{"]
        for field in node.body["fields"]:
            field_node = schema.type_index[str(field["type_id"])]
            suffix = "" if field["bit_width"] is None else f" : {int(field['bit_width'])}"
            lines.append(
                f"  {_c_type(field_node, names)} {_c_identifier(str(field['id']))}{suffix};"
            )
        return [*lines, "};", ""]
    return [f"typedef {_primitive_c_type(node)} {name};", ""]


def _c_type(node: BoundaryTypeV1, names: Mapping[str, str]) -> str:
    return "void" if node.kind == "void" else names[node.identity]


def _render_function_type(
    node: BoundaryTypeV1,
    schema: BoundarySchemaV1,
    names: Mapping[str, str],
) -> list[str]:
    result = _c_type(schema.type_index[str(node.body["result_type_id"])], names)
    parameters = ", ".join(
        _c_type(schema.type_index[str(item)], names)
        for item in node.body["parameter_type_ids"]
    ) or "void"
    if bool(node.body["variadic"]):
        parameters = "..." if parameters == "void" else f"{parameters}, ..."
    convention = {
        "cdecl": "SPX_CDECL", "stdcall": "SPX_STDCALL",
        "fastcall": "SPX_FASTCALL",
    }.get(str(node.body["calling_convention"]), "")
    return [f"typedef {result} {convention} {names[node.identity]}({parameters});", ""]


def _primitive_c_type(node: BoundaryTypeV1) -> str:
    if node.kind == "bool":
        return "bool"
    if node.kind == "integer":
        prefix = "int" if bool(node.body["signed"]) else "uint"
        return f"{prefix}{int(node.body['width_bits'])}_t"
    if node.kind == "float":
        return {
            "binary32": "float", "binary64": "double",
            "x87-extended80": "long double",
        }[str(node.body["format"])]
    if node.kind == "enum":
        return "int32_t"
    raise BoundaryModelError(
        f"boundary C renderer does not support standalone {node.kind!r}"
    )


def _c_identifier(value: str) -> str:
    result = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not result or result[0].isdigit():
        result = f"spx_{result}"
    return result


__all__ = ["render_boundary_header"]
