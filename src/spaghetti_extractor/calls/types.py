"""Portable C type graphs and target-specific storage layouts."""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import PORTABLE_TYPE_GRAPH_V1_FORMAT, TARGET_LAYOUT_SET_V1_FORMAT
from ._canonical import (
    CallProtocolError,
    array,
    boolean,
    canonical,
    content_id,
    exact,
    identifier,
    object_,
    text,
    uint,
    verify_content_id,
)


TYPE_KINDS = frozenset(
    {
        "void",
        "bool",
        "integer",
        "float",
        "complex",
        "enum",
        "pointer",
        "function",
        "array",
        "record",
        "union",
        "vector",
        "opaque",
    }
)
CALLING_CONVENTIONS = frozenset(
    {"cdecl", "stdcall", "fastcall", "thiscall", "vectorcall", "custom"}
)
FLOAT_FORMATS = frozenset({"binary16", "binary32", "binary64", "x87-extended80"})
QUALIFIERS = frozenset({"const", "restrict", "volatile", "atomic"})


@dataclass(frozen=True)
class PortableTypeNodeV1:
    identity: str
    kind: str
    body: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str = "portable type") -> "PortableTypeNodeV1":
        row = object_(value, context)
        identity = identifier(row.get("id"), f"{context} id")
        kind = text(row.get("kind"), f"{context} kind")
        if kind not in TYPE_KINDS:
            raise CallProtocolError(f"{context} kind {kind!r} is unsupported")
        fields = _type_fields(kind)
        exact(row, {"id", "kind", *fields}, context)
        body = {key: canonical(row[key]) for key in sorted(fields)}
        _validate_type_body(kind, body, context)
        return cls(identity, kind, body)

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "kind": self.kind, **copy.deepcopy(dict(self.body))}

    def references(self, *, follow_pointer: bool = True) -> tuple[str, ...]:
        if self.kind == "pointer":
            return (
                (identifier(self.body["pointee_type_id"], "pointer pointee"),)
                if follow_pointer
                else ()
            )
        if self.kind in {"array", "vector", "complex"}:
            return (identifier(self.body["element_type_id"], "element type"),)
        if self.kind == "enum":
            return (identifier(self.body["underlying_type_id"], "enum underlying type"),)
        if self.kind == "function":
            return (
                identifier(self.body["result_type_id"], "function result type"),
                *(identifier(item, "function parameter type") for item in self.body["parameter_type_ids"]),
            )
        if self.kind in {"record", "union"}:
            return tuple(
                identifier(object_(item, "type field")["type_id"], "field type")
                for item in self.body["fields"]
            )
        return ()


def _type_fields(kind: str) -> set[str]:
    return {
        "void": set(),
        "bool": {"width_bits"},
        "integer": {"width_bits", "signed"},
        "float": {"format", "value_bits"},
        "complex": {"element_type_id"},
        "enum": {"underlying_type_id", "enumerators"},
        "pointer": {"pointee_type_id", "qualifiers"},
        "function": {
            "result_type_id",
            "parameter_type_ids",
            "variadic",
            "calling_convention",
        },
        "array": {"element_type_id", "element_count"},
        "record": {"nominal_id", "fields"},
        "union": {"nominal_id", "fields"},
        "vector": {"element_type_id", "element_count"},
        "opaque": {"nominal_id"},
    }[kind]


def _validate_type_body(kind: str, body: Mapping[str, object], context: str) -> None:
    if kind in {"bool", "integer"}:
        uint(body["width_bits"], f"{context} width", minimum=1)
    if kind == "integer":
        boolean(body["signed"], f"{context} signed")
    if kind == "float":
        fmt = text(body["format"], f"{context} floating format")
        if fmt not in FLOAT_FORMATS:
            raise CallProtocolError(f"{context} floating format is unsupported")
        width = uint(body["value_bits"], f"{context} value bits", minimum=1)
        expected = {"binary16": 16, "binary32": 32, "binary64": 64, "x87-extended80": 80}[fmt]
        if width != expected:
            raise CallProtocolError(f"{context} floating width disagrees with its format")
    if kind in {"complex", "array", "vector"}:
        identifier(body["element_type_id"], f"{context} element type")
    if kind in {"array", "vector"}:
        uint(body["element_count"], f"{context} element count", minimum=1)
    if kind == "enum":
        identifier(body["underlying_type_id"], f"{context} underlying type")
        rows = array(body["enumerators"], f"{context} enumerators")
        names: list[str] = []
        for index, item in enumerate(rows):
            enum = object_(item, f"{context} enumerator {index}")
            exact(enum, {"id", "value"}, f"{context} enumerator {index}")
            names.append(identifier(enum["id"], f"{context} enumerator id"))
            if not isinstance(enum["value"], int) or isinstance(enum["value"], bool):
                raise CallProtocolError(f"{context} enumerator value must be an integer")
        if names != sorted(set(names)):
            raise CallProtocolError(f"{context} enumerators must be unique and ordered")
    if kind == "pointer":
        identifier(body["pointee_type_id"], f"{context} pointee type")
        qualifiers = tuple(text(item, f"{context} qualifier") for item in array(body["qualifiers"], f"{context} qualifiers"))
        if any(item not in QUALIFIERS for item in qualifiers) or qualifiers != tuple(sorted(set(qualifiers))):
            raise CallProtocolError(f"{context} qualifiers must be supported, unique, and ordered")
    if kind == "function":
        identifier(body["result_type_id"], f"{context} result type")
        parameters = tuple(identifier(item, f"{context} parameter type") for item in array(body["parameter_type_ids"], f"{context} parameter types"))
        boolean(body["variadic"], f"{context} variadic")
        convention = text(body["calling_convention"], f"{context} calling convention")
        if convention not in CALLING_CONVENTIONS:
            raise CallProtocolError(f"{context} calling convention is unsupported")
        if len(parameters) > 4096:
            raise CallProtocolError(f"{context} has an unreasonable parameter count")
    if kind in {"record", "union"}:
        identifier(body["nominal_id"], f"{context} nominal id")
        fields = array(body["fields"], f"{context} fields")
        names: list[str] = []
        for index, item in enumerate(fields):
            field = object_(item, f"{context} field {index}")
            exact(field, {"id", "type_id", "bit_width"}, f"{context} field {index}")
            names.append(identifier(field["id"], f"{context} field id"))
            identifier(field["type_id"], f"{context} field type")
            if field["bit_width"] is not None:
                uint(field["bit_width"], f"{context} bit-field width", minimum=1)
        if len(names) != len(set(names)):
            raise CallProtocolError(f"{context} field ids are duplicated")
    if kind == "opaque":
        identifier(body["nominal_id"], f"{context} nominal id")


@dataclass(frozen=True)
class PortableTypeGraphV1:
    graph_id: str
    nodes: tuple[PortableTypeNodeV1, ...]

    @classmethod
    def create(cls, nodes: Sequence[PortableTypeNodeV1 | Mapping[str, object]]) -> "PortableTypeGraphV1":
        parsed = tuple(
            item if isinstance(item, PortableTypeNodeV1) else PortableTypeNodeV1.parse(item, f"portable type {index}")
            for index, item in enumerate(nodes)
        )
        ordered = tuple(sorted(parsed, key=lambda item: item.identity))
        ids = [item.identity for item in ordered]
        if not ordered or ids != sorted(set(ids)):
            raise CallProtocolError("portable type ids must be nonempty, unique, and ordered")
        known = set(ids)
        for node in ordered:
            missing = set(node.references()) - known
            if missing:
                raise CallProtocolError(f"portable type {node.identity!r} references unknown types {sorted(missing)!r}")
        _reject_direct_cycles(ordered)
        core = {"format": PORTABLE_TYPE_GRAPH_V1_FORMAT, "types": [item.to_payload() for item in ordered]}
        return cls(content_id("portable-type-graph-v1", core), ordered)

    @classmethod
    def parse(cls, value: object) -> "PortableTypeGraphV1":
        row = object_(value, "portable type graph")
        exact(row, {"format", "id", "types"}, "portable type graph")
        if row["format"] != PORTABLE_TYPE_GRAPH_V1_FORMAT:
            raise CallProtocolError("unsupported portable type graph format")
        result = cls.create([PortableTypeNodeV1.parse(item, f"portable type {index}") for index, item in enumerate(array(row["types"], "portable types"))])
        verify_content_id(row["id"], "portable-type-graph-v1", {"format": PORTABLE_TYPE_GRAPH_V1_FORMAT, "types": [item.to_payload() for item in result.nodes]}, "portable type graph")
        return result

    @property
    def index(self) -> dict[str, PortableTypeNodeV1]:
        return {item.identity: item for item in self.nodes}

    def to_payload(self) -> dict[str, object]:
        return {"format": PORTABLE_TYPE_GRAPH_V1_FORMAT, "id": self.graph_id, "types": [item.to_payload() for item in self.nodes]}


def _reject_direct_cycles(nodes: Sequence[PortableTypeNodeV1]) -> None:
    index = {item.identity: item for item in nodes}
    active: set[str] = set()
    done: set[str] = set()

    def visit(identity: str) -> None:
        if identity in done:
            return
        if identity in active:
            raise CallProtocolError("portable type graph contains a non-pointer recursive value")
        active.add(identity)
        for reference in index[identity].references(follow_pointer=False):
            visit(reference)
        active.remove(identity)
        done.add(identity)

    for identity in sorted(index):
        visit(identity)


@dataclass(frozen=True)
class LayoutFieldV1:
    identity: str
    offset_bits: int
    storage_bits: int
    value_bits: int

    @classmethod
    def parse(cls, value: object, context: str) -> "LayoutFieldV1":
        row = object_(value, context)
        exact(row, {"id", "offset_bits", "storage_bits", "value_bits"}, context)
        storage = uint(row["storage_bits"], f"{context} storage bits", minimum=1)
        useful = uint(row["value_bits"], f"{context} value bits", minimum=1)
        if useful > storage:
            raise CallProtocolError(f"{context} value bits exceed storage")
        return cls(identifier(row["id"], f"{context} id"), uint(row["offset_bits"], f"{context} offset"), storage, useful)

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "offset_bits": self.offset_bits, "storage_bits": self.storage_bits, "value_bits": self.value_bits}


@dataclass(frozen=True)
class PaddingRangeV1:
    offset_bits: int
    width_bits: int

    @classmethod
    def parse(cls, value: object, context: str) -> "PaddingRangeV1":
        row = object_(value, context)
        exact(row, {"offset_bits", "width_bits"}, context)
        return cls(uint(row["offset_bits"], f"{context} offset"), uint(row["width_bits"], f"{context} width", minimum=1))

    def to_payload(self) -> dict[str, object]:
        return {"offset_bits": self.offset_bits, "width_bits": self.width_bits}


@dataclass(frozen=True)
class TypeLayoutV1:
    type_id: str
    size_bits: int
    alignment_bits: int
    value_bits: int
    array_stride_bits: int | None
    fields: tuple[LayoutFieldV1, ...]
    padding: tuple[PaddingRangeV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "TypeLayoutV1":
        row = object_(value, context)
        exact(row, {"type_id", "size_bits", "alignment_bits", "value_bits", "array_stride_bits", "fields", "padding"}, context)
        size = uint(row["size_bits"], f"{context} size")
        alignment = uint(row["alignment_bits"], f"{context} alignment", minimum=1)
        useful = uint(row["value_bits"], f"{context} value bits")
        if useful > size:
            raise CallProtocolError(f"{context} value bits exceed storage size")
        stride = None if row["array_stride_bits"] is None else uint(row["array_stride_bits"], f"{context} array stride", minimum=1)
        fields = tuple(LayoutFieldV1.parse(item, f"{context} field {index}") for index, item in enumerate(array(row["fields"], f"{context} fields")))
        padding = tuple(PaddingRangeV1.parse(item, f"{context} padding {index}") for index, item in enumerate(array(row["padding"], f"{context} padding")))
        if len({item.identity for item in fields}) != len(fields):
            raise CallProtocolError(f"{context} fields must be unique")
        padding_ranges = [(item.offset_bits, item.offset_bits + item.width_bits) for item in padding]
        if padding_ranges != sorted(set(padding_ranges)) or any(
            right[0] < left[1]
            for left, right in zip(padding_ranges, padding_ranges[1:])
        ):
            raise CallProtocolError(f"{context} padding must be unique, ordered, and nonoverlapping")
        for offset, width, label in [*( (item.offset_bits, item.storage_bits, f"field {item.identity}") for item in fields), *( (item.offset_bits, item.width_bits, "padding") for item in padding)]:
            if offset + width > size:
                raise CallProtocolError(f"{context} {label} exceeds the type size")
        return cls(identifier(row["type_id"], f"{context} type id"), size, alignment, useful, stride, fields, padding)

    def to_payload(self) -> dict[str, object]:
        return {
            "type_id": self.type_id,
            "size_bits": self.size_bits,
            "alignment_bits": self.alignment_bits,
            "value_bits": self.value_bits,
            "array_stride_bits": self.array_stride_bits,
            "fields": [item.to_payload() for item in self.fields],
            "padding": [item.to_payload() for item in self.padding],
        }


@dataclass(frozen=True)
class TargetLayoutSetV1:
    layout_id: str
    target: str
    abi_dialect: str
    byte_order: str
    pointer_width_bits: int
    packing: str
    type_graph_sha256: str
    layouts: tuple[TypeLayoutV1, ...]

    @classmethod
    def create(
        cls,
        *,
        target: str,
        abi_dialect: str,
        byte_order: str,
        pointer_width_bits: int,
        packing: str,
        type_graph: PortableTypeGraphV1,
        layouts: Sequence[TypeLayoutV1 | Mapping[str, object]],
    ) -> "TargetLayoutSetV1":
        if byte_order not in {"little", "big"}:
            raise CallProtocolError("target layout byte order is unsupported")
        parsed = tuple(item if isinstance(item, TypeLayoutV1) else TypeLayoutV1.parse(item, f"type layout {index}") for index, item in enumerate(layouts))
        ordered = tuple(sorted(parsed, key=lambda item: item.type_id))
        ids = [item.type_id for item in ordered]
        if ids != sorted(set(ids)):
            raise CallProtocolError("type layouts must be unique and ordered")
        unknown = set(ids) - set(type_graph.index)
        if unknown:
            raise CallProtocolError(f"target layouts reference unknown types {sorted(unknown)!r}")
        _validate_layout_overlaps(type_graph, ordered)
        core = {
            "format": TARGET_LAYOUT_SET_V1_FORMAT,
            "target": identifier(target, "target layout target"),
            "abi_dialect": identifier(abi_dialect, "target layout ABI dialect"),
            "byte_order": byte_order,
            "pointer_width_bits": uint(pointer_width_bits, "target pointer width", minimum=1),
            "packing": identifier(packing, "target layout packing"),
            "type_graph_sha256": type_graph.graph_id.split(":", 1)[1],
            "layouts": [item.to_payload() for item in ordered],
        }
        return cls(content_id("target-layout-set-v1", core), str(core["target"]), str(core["abi_dialect"]), byte_order, int(core["pointer_width_bits"]), str(core["packing"]), str(core["type_graph_sha256"]), ordered)

    @classmethod
    def parse(cls, value: object, *, type_graph: PortableTypeGraphV1) -> "TargetLayoutSetV1":
        row = object_(value, "target layout set")
        exact(row, {"format", "id", "target", "abi_dialect", "byte_order", "pointer_width_bits", "packing", "type_graph_sha256", "layouts"}, "target layout set")
        if row["format"] != TARGET_LAYOUT_SET_V1_FORMAT:
            raise CallProtocolError("unsupported target layout set format")
        if row["type_graph_sha256"] != type_graph.graph_id.split(":", 1)[1]:
            raise CallProtocolError("target layout set names a different type graph")
        result = cls.create(target=str(row["target"]), abi_dialect=str(row["abi_dialect"]), byte_order=str(row["byte_order"]), pointer_width_bits=int(row["pointer_width_bits"]), packing=str(row["packing"]), type_graph=type_graph, layouts=[TypeLayoutV1.parse(item, f"type layout {index}") for index, item in enumerate(array(row["layouts"], "type layouts"))])
        if row["id"] != result.layout_id:
            raise CallProtocolError("target layout set id does not bind its contents")
        return result

    @property
    def index(self) -> dict[str, TypeLayoutV1]:
        return {item.type_id: item for item in self.layouts}

    def to_payload(self) -> dict[str, object]:
        return {
            "format": TARGET_LAYOUT_SET_V1_FORMAT,
            "id": self.layout_id,
            "target": self.target,
            "abi_dialect": self.abi_dialect,
            "byte_order": self.byte_order,
            "pointer_width_bits": self.pointer_width_bits,
            "packing": self.packing,
            "type_graph_sha256": self.type_graph_sha256,
            "layouts": [item.to_payload() for item in self.layouts],
        }


def _validate_layout_overlaps(graph: PortableTypeGraphV1, layouts: Sequence[TypeLayoutV1]) -> None:
    types = graph.index
    for layout in layouts:
        node = types[layout.type_id]
        field_ids = [item["id"] for item in node.body.get("fields", [])] if node.kind in {"record", "union"} else []
        if [item.identity for item in layout.fields] != field_ids:
            if field_ids or layout.fields:
                raise CallProtocolError(f"layout for {layout.type_id!r} does not cover its declared fields")
        if node.kind != "union":
            ranges = sorted((item.offset_bits, item.offset_bits + item.storage_bits) for item in layout.fields)
            if any(right[0] < left[1] for left, right in zip(ranges, ranges[1:])):
                raise CallProtocolError(f"layout for {layout.type_id!r} has overlapping non-union fields")
            padding = [(item.offset_bits, item.offset_bits + item.width_bits) for item in layout.padding]
            if any(
                max(field_start, padding_start) < min(field_end, padding_end)
                for field_start, field_end in ranges
                for padding_start, padding_end in padding
            ):
                raise CallProtocolError(f"layout for {layout.type_id!r} overlaps fields and padding")
            if node.kind == "record":
                coverage = sorted((*ranges, *padding))
                cursor = 0
                for start, end in coverage:
                    if start != cursor:
                        raise CallProtocolError(f"layout for {layout.type_id!r} has undeclared storage bits")
                    cursor = end
                if cursor != layout.size_bits:
                    raise CallProtocolError(f"layout for {layout.type_id!r} does not cover its storage")


__all__ = [
    "LayoutFieldV1",
    "PaddingRangeV1",
    "PortableTypeGraphV1",
    "PortableTypeNodeV1",
    "TargetLayoutSetV1",
    "TypeLayoutV1",
]
