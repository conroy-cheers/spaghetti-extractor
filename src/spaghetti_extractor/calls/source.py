"""Deterministic idiomatic C rendering for portable call types."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Mapping

from ..artifacts.formats import SOURCE_NAMING_V1_FORMAT
from ._canonical import CallProtocolError, array, content_id, exact, identifier, object_, text
from .protocol import IdiomaticCallViewV1
from .types import PortableTypeGraphV1, PortableTypeNodeV1


_C_ID = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")


def _c_identifier(value: object, context: str) -> str:
    result = text(value, context)
    if _C_ID.fullmatch(result) is None:
        raise CallProtocolError(f"{context} is not a C identifier")
    return result


@dataclass(frozen=True)
class SourceNamingV1:
    naming_id: str
    type_names: tuple[tuple[str, str], ...]
    field_names: tuple[tuple[str, str, str], ...]
    value_names: tuple[tuple[str, str], ...]

    @classmethod
    def create(
        cls,
        *,
        type_names: Mapping[str, str] | None = None,
        field_names: Mapping[tuple[str, str], str] | None = None,
        value_names: Mapping[str, str] | None = None,
    ) -> "SourceNamingV1":
        type_names = {} if type_names is None else type_names
        field_names = {} if field_names is None else field_names
        value_names = {} if value_names is None else value_names
        types = tuple(sorted((identifier(key, "named type id"), _c_identifier(value, "C type name")) for key, value in type_names.items()))
        fields = tuple(sorted((identifier(type_id, "named field type id"), identifier(field_id, "named field id"), _c_identifier(value, "C field name")) for (type_id, field_id), value in field_names.items()))
        values = tuple(sorted((identifier(key, "named value id"), _c_identifier(value, "C value name")) for key, value in value_names.items()))
        all_names = [item[1] for item in types]
        if len(all_names) != len(set(all_names)):
            raise CallProtocolError("source type names are duplicated")
        core = {
            "format": SOURCE_NAMING_V1_FORMAT,
            "type_names": [{"type_id": key, "name": value} for key, value in types],
            "field_names": [{"type_id": type_id, "field_id": field_id, "name": value} for type_id, field_id, value in fields],
            "value_names": [{"value_id": key, "name": value} for key, value in values],
        }
        return cls(content_id("source-naming-v1", core), types, fields, values)

    @classmethod
    def parse(cls, value: object) -> "SourceNamingV1":
        row = object_(value, "source naming")
        exact(row, {"format", "id", "type_names", "field_names", "value_names"}, "source naming")
        if row["format"] != SOURCE_NAMING_V1_FORMAT:
            raise CallProtocolError("unsupported source naming format")
        type_names = {}
        for index, item in enumerate(array(row["type_names"], "source type names")):
            entry = object_(item, f"source type name {index}")
            exact(entry, {"type_id", "name"}, f"source type name {index}")
            type_names[str(entry["type_id"])] = str(entry["name"])
        field_names = {}
        for index, item in enumerate(array(row["field_names"], "source field names")):
            entry = object_(item, f"source field name {index}")
            exact(entry, {"type_id", "field_id", "name"}, f"source field name {index}")
            field_names[(str(entry["type_id"]), str(entry["field_id"]))] = str(entry["name"])
        value_names = {}
        for index, item in enumerate(array(row["value_names"], "source value names")):
            entry = object_(item, f"source value name {index}")
            exact(entry, {"value_id", "name"}, f"source value name {index}")
            value_names[str(entry["value_id"])] = str(entry["name"])
        result = cls.create(type_names=type_names, field_names=field_names, value_names=value_names)
        if row["id"] != result.naming_id:
            raise CallProtocolError("source naming id does not bind its contents")
        return result

    def to_payload(self) -> dict[str, object]:
        return {
            "format": SOURCE_NAMING_V1_FORMAT,
            "id": self.naming_id,
            "type_names": [{"type_id": key, "name": value} for key, value in self.type_names],
            "field_names": [{"type_id": type_id, "field_id": field_id, "name": value} for type_id, field_id, value in self.field_names],
            "value_names": [{"value_id": key, "name": value} for key, value in self.value_names],
        }

    def type_name(self, type_id: str) -> str:
        return dict(self.type_names).get(type_id, _synthetic(type_id))

    def field_name(self, type_id: str, field_id: str) -> str:
        return {(owner, field): name for owner, field, name in self.field_names}.get((type_id, field_id), _synthetic(field_id))

    def value_name(self, value_id: str) -> str:
        return dict(self.value_names).get(value_id, _synthetic(value_id))


def render_call_header(
    *,
    type_graph: PortableTypeGraphV1,
    naming: SourceNamingV1,
    function_type_id: str,
    function_name: str,
    idiomatic_view: IdiomaticCallViewV1 | None = None,
) -> str:
    selected = idiomatic_view.idiomatic_function_type_id if idiomatic_view is not None else function_type_id
    function = type_graph.index.get(selected)
    if function is None or function.kind != "function":
        raise CallProtocolError("rendered call type is not a function")
    _c_identifier(function_name, "rendered function name")
    _validate_names(type_graph, naming)
    lines = ["#pragma once", "", "#include <stdbool.h>", "#include <complex.h>", "#include <stdint.h>", ""]
    for node in type_graph.nodes:
        if node.kind in {"record", "union", "opaque"}:
            tag = naming.type_name(node.identity)
            keyword = "union" if node.kind == "union" else "struct"
            lines.append(f"typedef {keyword} {tag} {tag};")
    if any(node.kind in {"record", "union", "opaque"} for node in type_graph.nodes):
        lines.append("")
    for node in _declaration_order(type_graph):
        rendered = _render_type(node, type_graph, naming)
        if rendered:
            lines.extend(rendered)
            lines.append("")
    result = _type_spelling(str(function.body["result_type_id"]), type_graph, naming)
    parameters = [
        f"{_type_spelling(str(type_id), type_graph, naming)} {naming.value_name(f'arg{index}')}"
        for index, type_id in enumerate(function.body["parameter_type_ids"])
    ]
    if bool(function.body["variadic"]):
        parameters.append("...")
    if not parameters:
        parameters.append("void")
    call_spelling, call_declarations = _calling_convention_spelling(
        str(function.body["calling_convention"])
    )
    if call_declarations:
        lines.extend(call_declarations)
        lines.append("")
    separator = f" {call_spelling} " if call_spelling else " "
    lines.append(f"{result}{separator}{function_name}({', '.join(parameters)});")
    lines.append("")
    return "\n".join(lines)


def _validate_names(graph: PortableTypeGraphV1, naming: SourceNamingV1) -> None:
    unknown = set(dict(naming.type_names)) - set(graph.index)
    if unknown:
        raise CallProtocolError(f"source naming references unknown types {sorted(unknown)!r}")


def _declaration_order(graph: PortableTypeGraphV1) -> tuple[PortableTypeNodeV1, ...]:
    index = graph.index
    ordered: list[PortableTypeNodeV1] = []
    done: set[str] = set()

    def visit(node: PortableTypeNodeV1) -> None:
        if node.identity in done:
            return
        for reference in node.references(follow_pointer=False):
            visit(index[reference])
        done.add(node.identity)
        ordered.append(node)

    for node in graph.nodes:
        visit(node)
    return tuple(ordered)


def _render_type(node: PortableTypeNodeV1, graph: PortableTypeGraphV1, naming: SourceNamingV1) -> list[str]:
    name = naming.type_name(node.identity)
    if node.kind in {"void", "function", "opaque"}:
        return []
    if node.kind == "bool":
        return [f"typedef bool {name};"]
    if node.kind == "integer":
        width = int(node.body["width_bits"])
        prefix = "int" if node.body["signed"] else "uint"
        return [f"typedef {prefix}{width}_t {name};"]
    if node.kind == "float":
        spelling = {"binary16": "_Float16", "binary32": "float", "binary64": "double", "x87-extended80": "long double"}[str(node.body["format"])]
        return [f"typedef {spelling} {name};"]
    if node.kind == "complex":
        return [f"typedef {_type_spelling(str(node.body['element_type_id']), graph, naming)} _Complex {name};"]
    if node.kind == "pointer":
        qualifiers = " ".join(str(item) for item in node.body["qualifiers"])
        qualifier_prefix = f"{qualifiers} " if qualifiers else ""
        return [f"typedef {qualifier_prefix}{_type_spelling(str(node.body['pointee_type_id']), graph, naming)} *{name};"]
    if node.kind == "enum":
        values = [f"  {item['id']} = {item['value']}" for item in node.body["enumerators"]]
        return [f"typedef enum {name} {{", ",\n".join(values), f"}} {name};"]
    if node.kind in {"record", "union"}:
        keyword = "struct" if node.kind == "record" else "union"
        lines = [f"{keyword} {name} {{"]
        for field in node.body["fields"]:
            field_name = naming.field_name(node.identity, str(field["id"]))
            declaration = f"  {_type_spelling(str(field['type_id']), graph, naming)} {field_name}"
            if field["bit_width"] is not None:
                declaration += f" : {field['bit_width']}"
            lines.append(declaration + ";")
        lines.append("};")
        return lines
    if node.kind == "array":
        return [f"typedef {_type_spelling(str(node.body['element_type_id']), graph, naming)} {name}[{node.body['element_count']}];"]
    if node.kind == "vector":
        return [f"typedef struct {{ {_type_spelling(str(node.body['element_type_id']), graph, naming)} lane[{node.body['element_count']}]; }} {name};"]
    raise CallProtocolError(f"cannot render portable type kind {node.kind!r}")


def _type_spelling(type_id: str, graph: PortableTypeGraphV1, naming: SourceNamingV1) -> str:
    node = graph.index[type_id]
    return "void" if node.kind == "void" else naming.type_name(type_id)


def _calling_convention_spelling(convention: str) -> tuple[str, list[str]]:
    if convention == "cdecl":
        return "", []
    keywords = {
        "stdcall": "__stdcall",
        "fastcall": "__fastcall",
        "thiscall": "__thiscall",
        "vectorcall": "__vectorcall",
    }
    keyword = keywords.get(convention)
    if keyword is None:
        raise CallProtocolError(
            f"calling convention {convention!r} needs an authored C spelling"
        )
    macro = f"SPX_{convention.upper()}"
    attribute = f"__attribute__(({convention}))"
    declarations = [
        "#if defined(_MSC_VER)",
        f"#define {macro} {keyword}",
        "#elif defined(__GNUC__) && defined(__i386__)",
        f"#define {macro} {attribute}",
        "#else",
        f"#define {macro}",
        "#endif",
    ]
    return macro, declarations


def _synthetic(identity: str) -> str:
    return "spx_" + re.sub(r"[^A-Za-z0-9_]", "_", identity)


__all__ = ["SourceNamingV1", "render_call_header"]
