"""Canonical target-neutral boundary values and target data layouts."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.formats import (
    BOUNDARY_SCHEMA_V1_FORMAT,
    TARGET_DATA_LAYOUT_V1_FORMAT,
)
from ._canonical import (
    BoundaryModelError,
    array,
    boolean,
    canonical,
    content_sha256,
    exact,
    identifier,
    object_,
    ordered_identifiers,
    text,
    uint,
)


BOUNDARY_SCHEMA_V1 = BOUNDARY_SCHEMA_V1_FORMAT
TARGET_DATA_LAYOUT_V1 = TARGET_DATA_LAYOUT_V1_FORMAT
TYPE_KINDS = frozenset({
    "void", "bool", "integer", "float", "complex", "enum", "pointer",
    "function", "array", "record", "union", "vector", "opaque",
})
CALLING_CONVENTIONS = frozenset(
    {"cdecl", "stdcall", "fastcall", "thiscall", "vectorcall", "custom"}
)
QUALIFIERS = frozenset({"const", "restrict", "volatile", "atomic"})
INTERPRETATIONS = frozenset({"value", "reference", "view", "resource", "callback"})
ACCESS_KINDS = frozenset({"none", "read", "write", "read_write"})
EXTENT_KINDS = frozenset({"none", "fixed", "value", "nul_terminated"})


@dataclass(frozen=True)
class BoundaryTypeV1:
    identity: str
    kind: str
    body: Mapping[str, object]

    @classmethod
    def parse(cls, value: object, context: str = "boundary type") -> "BoundaryTypeV1":
        row = object_(value, context)
        identity = identifier(row.get("id"), f"{context} id")
        kind = text(row.get("kind"), f"{context} kind")
        if kind not in TYPE_KINDS:
            raise BoundaryModelError(f"{context} kind is unsupported")
        fields = _type_fields(kind)
        exact(row, {"id", "kind", *fields}, context)
        body = {key: canonical(row[key]) for key in sorted(fields)}
        _validate_type(kind, body, context)
        return cls(identity, kind, body)

    def references(self, *, follow_pointer: bool = True) -> tuple[str, ...]:
        if self.kind == "pointer":
            return (str(self.body["pointee_type_id"]),) if follow_pointer else ()
        if self.kind in {"array", "vector", "complex"}:
            return (str(self.body["element_type_id"]),)
        if self.kind == "enum":
            return (str(self.body["underlying_type_id"]),)
        if self.kind == "function":
            return (
                str(self.body["result_type_id"]),
                *(str(item) for item in self.body["parameter_type_ids"]),
            )
        if self.kind in {"record", "union"}:
            return tuple(str(object_(item, "boundary field")["type_id"]) for item in self.body["fields"])
        return ()

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "kind": self.kind, **canonical(dict(self.body))}


@dataclass(frozen=True)
class BoundaryValueV1:
    identity: str
    type_id: str
    interpretation: str
    nullable: bool
    access: str
    extent: Mapping[str, object]
    resource_kind: str | None
    provider_domain: str | None

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundaryValueV1":
        row = object_(value, context)
        exact(
            row,
            {"id", "type_id", "interpretation", "nullable", "access", "extent", "resource_kind", "provider_domain"},
            context,
        )
        interpretation = text(row["interpretation"], f"{context} interpretation")
        access = text(row["access"], f"{context} access")
        if interpretation not in INTERPRETATIONS or access not in ACCESS_KINDS:
            raise BoundaryModelError(f"{context} interpretation or access is unsupported")
        extent_row = object_(row["extent"], f"{context} extent")
        exact(extent_row, {"kind", "bytes", "value_id"}, f"{context} extent")
        extent_kind = text(extent_row["kind"], f"{context} extent kind")
        if extent_kind not in EXTENT_KINDS:
            raise BoundaryModelError(f"{context} extent kind is unsupported")
        size = extent_row["bytes"]
        extent_value = extent_row["value_id"]
        if extent_kind == "fixed":
            uint(size, f"{context} fixed extent", minimum=1)
        elif size is not None:
            raise BoundaryModelError(f"{context} non-fixed extent carries bytes")
        if extent_kind == "value":
            identifier(extent_value, f"{context} extent value")
        elif extent_value is not None:
            raise BoundaryModelError(f"{context} extent carries an unrelated value")
        resource = None if row["resource_kind"] is None else identifier(row["resource_kind"], f"{context} resource kind")
        provider = None if row["provider_domain"] is None else identifier(row["provider_domain"], f"{context} provider domain")
        if interpretation == "resource" and (resource is None or provider is None):
            raise BoundaryModelError(f"{context} resource lacks kind or provider")
        if interpretation != "resource" and (resource is not None or provider is not None):
            raise BoundaryModelError(f"{context} non-resource carries resource metadata")
        if interpretation == "value" and (access != "none" or extent_kind != "none"):
            raise BoundaryModelError(f"{context} plain value carries memory-view metadata")
        if interpretation == "resource" and access not in {
            "none", "write", "read_write"
        }:
            raise BoundaryModelError(
                f"{context} resource access must be none, write, or read_write"
            )
        if interpretation == "resource" and extent_kind != "none":
            raise BoundaryModelError(f"{context} resource carries an extent")
        return cls(
            identifier(row["id"], f"{context} id"),
            identifier(row["type_id"], f"{context} type"),
            interpretation,
            boolean(row["nullable"], f"{context} nullable"),
            access,
            dict(extent_row),
            resource,
            provider,
        )

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "type_id": self.type_id,
            "interpretation": self.interpretation,
            "nullable": self.nullable,
            "access": self.access,
            "extent": dict(self.extent),
            "resource_kind": self.resource_kind,
            "provider_domain": self.provider_domain,
        }


@dataclass(frozen=True)
class BoundarySignatureV1:
    identity: str
    function_type_id: str
    parameters: tuple[BoundaryValueV1, ...]
    results: tuple[BoundaryValueV1, ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "BoundarySignatureV1":
        row = object_(value, context)
        exact(row, {"id", "function_type_id", "parameters", "results"}, context)
        parameters = tuple(BoundaryValueV1.parse(item, f"{context} parameter {index}") for index, item in enumerate(array(row["parameters"], f"{context} parameters")))
        results = tuple(BoundaryValueV1.parse(item, f"{context} result {index}") for index, item in enumerate(array(row["results"], f"{context} results")))
        identities = [item.identity for item in (*parameters, *results)]
        if len(identities) != len(set(identities)):
            raise BoundaryModelError(f"{context} value ids are duplicated")
        return cls(identifier(row["id"], f"{context} id"), identifier(row["function_type_id"], f"{context} function type"), parameters, results)

    def to_payload(self) -> dict[str, object]:
        return {
            "id": self.identity,
            "function_type_id": self.function_type_id,
            "parameters": [item.to_payload() for item in self.parameters],
            "results": [item.to_payload() for item in self.results],
        }


@dataclass(frozen=True)
class BoundarySchemaV1:
    schema_id: str
    types: tuple[BoundaryTypeV1, ...]
    signatures: tuple[BoundarySignatureV1, ...]
    schema_sha256: str

    @classmethod
    def create(
        cls,
        *,
        schema_id: str,
        types: Sequence[BoundaryTypeV1 | Mapping[str, object]],
        signatures: Sequence[BoundarySignatureV1 | Mapping[str, object]],
    ) -> "BoundarySchemaV1":
        parsed_types = tuple(sorted((item if isinstance(item, BoundaryTypeV1) else BoundaryTypeV1.parse(item, f"boundary type {index}") for index, item in enumerate(types)), key=lambda item: item.identity))
        parsed_signatures = tuple(sorted((item if isinstance(item, BoundarySignatureV1) else BoundarySignatureV1.parse(item, f"boundary signature {index}") for index, item in enumerate(signatures)), key=lambda item: item.identity))
        type_ids = [item.identity for item in parsed_types]
        signature_ids = [item.identity for item in parsed_signatures]
        if not parsed_types or type_ids != sorted(set(type_ids)) or signature_ids != sorted(set(signature_ids)):
            raise BoundaryModelError("boundary types and signatures must be unique and ordered")
        index = {item.identity: item for item in parsed_types}
        for node in parsed_types:
            missing = set(node.references()) - set(index)
            if missing:
                raise BoundaryModelError(f"boundary type {node.identity!r} references unknown types {sorted(missing)!r}")
        _reject_value_cycles(parsed_types)
        for signature in parsed_signatures:
            function = index.get(signature.function_type_id)
            if function is None or function.kind != "function":
                raise BoundaryModelError(f"boundary signature {signature.identity!r} lacks a function type")
            parameter_types = tuple(str(item) for item in function.body["parameter_type_ids"])
            if parameter_types != tuple(item.type_id for item in signature.parameters):
                raise BoundaryModelError(f"boundary signature {signature.identity!r} parameters disagree with its function type")
            result_type = str(function.body["result_type_id"])
            result_types = tuple(item.type_id for item in signature.results)
            result_is_void = index[result_type].kind == "void"
            if (result_is_void and result_types) or (
                not result_is_void and result_types != (result_type,)
            ):
                raise BoundaryModelError(f"boundary signature {signature.identity!r} results disagree with its function type")
            missing_values = {item.type_id for item in (*signature.parameters, *signature.results)} - set(index)
            if missing_values:
                raise BoundaryModelError(f"boundary signature {signature.identity!r} uses unknown value types")
            for item in (*signature.parameters, *signature.results):
                value_type = index[item.type_id]
                if item.interpretation in {"reference", "view", "callback"} and value_type.kind != "pointer":
                    raise BoundaryModelError(
                        f"boundary value {item.identity!r} interpretation requires a pointer type"
                    )
                if item.interpretation == "callback":
                    pointee = index[str(value_type.body["pointee_type_id"])]
                    if pointee.kind != "function":
                        raise BoundaryModelError(
                            f"boundary callback {item.identity!r} does not point to a function"
                        )
                if item.access != "none" and item.interpretation not in {
                    "reference", "view", "resource"
                }:
                    raise BoundaryModelError(
                        f"boundary value {item.identity!r} access is inapplicable"
                    )
            value_ids = {item.identity for item in signature.parameters}
            for item in signature.parameters:
                if item.extent["kind"] == "value" and item.extent["value_id"] not in value_ids:
                    raise BoundaryModelError(f"boundary signature {signature.identity!r} has an unknown extent value")
        core = {
            "format": BOUNDARY_SCHEMA_V1,
            "schema_id": identifier(schema_id, "boundary schema id"),
            "types": [item.to_payload() for item in parsed_types],
            "signatures": [item.to_payload() for item in parsed_signatures],
        }
        return cls(str(core["schema_id"]), parsed_types, parsed_signatures, content_sha256(core))

    @classmethod
    def parse(cls, value: object) -> "BoundarySchemaV1":
        row = object_(value, "boundary schema")
        exact(row, {"format", "schema_id", "types", "signatures", "schema_sha256"}, "boundary schema")
        if row["format"] != BOUNDARY_SCHEMA_V1:
            raise BoundaryModelError("unsupported boundary schema format")
        result = cls.create(schema_id=str(row["schema_id"]), types=[BoundaryTypeV1.parse(item, f"boundary type {index}") for index, item in enumerate(array(row["types"], "boundary types"))], signatures=[BoundarySignatureV1.parse(item, f"boundary signature {index}") for index, item in enumerate(array(row["signatures"], "boundary signatures"))])
        if row["schema_sha256"] != result.schema_sha256:
            raise BoundaryModelError("boundary schema digest is stale")
        return result

    @property
    def type_index(self) -> dict[str, BoundaryTypeV1]:
        return {item.identity: item for item in self.types}

    @property
    def signature_index(self) -> dict[str, BoundarySignatureV1]:
        return {item.identity: item for item in self.signatures}

    def to_payload(self) -> dict[str, object]:
        return {
            "format": BOUNDARY_SCHEMA_V1,
            "schema_id": self.schema_id,
            "types": [item.to_payload() for item in self.types],
            "signatures": [item.to_payload() for item in self.signatures],
            "schema_sha256": self.schema_sha256,
        }


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
        storage = uint(row["storage_bits"], f"{context} storage", minimum=1)
        useful = uint(row["value_bits"], f"{context} value", minimum=1)
        if useful > storage:
            raise BoundaryModelError(f"{context} value exceeds storage")
        return cls(identifier(row["id"], f"{context} id"), uint(row["offset_bits"], f"{context} offset"), storage, useful)

    def to_payload(self) -> dict[str, object]:
        return {"id": self.identity, "offset_bits": self.offset_bits, "storage_bits": self.storage_bits, "value_bits": self.value_bits}


@dataclass(frozen=True)
class TypeLayoutV1:
    type_id: str
    size_bits: int
    alignment_bits: int
    value_bits: int
    abi_class: str | None
    fields: tuple[LayoutFieldV1, ...]
    padding: tuple[tuple[int, int], ...]

    @classmethod
    def parse(cls, value: object, context: str) -> "TypeLayoutV1":
        row = object_(value, context)
        exact(row, {"type_id", "size_bits", "alignment_bits", "value_bits", "abi_class", "fields", "padding"}, context)
        size = uint(row["size_bits"], f"{context} size")
        alignment = uint(row["alignment_bits"], f"{context} alignment", minimum=1)
        useful = uint(row["value_bits"], f"{context} value")
        if useful > size:
            raise BoundaryModelError(f"{context} value exceeds size")
        fields = tuple(LayoutFieldV1.parse(item, f"{context} field {index}") for index, item in enumerate(array(row["fields"], f"{context} fields")))
        padding: list[tuple[int, int]] = []
        for index, item in enumerate(array(row["padding"], f"{context} padding")):
            pad = object_(item, f"{context} padding {index}")
            exact(pad, {"offset_bits", "width_bits"}, f"{context} padding {index}")
            padding.append((uint(pad["offset_bits"], f"{context} padding offset"), uint(pad["width_bits"], f"{context} padding width", minimum=1)))
        return cls(identifier(row["type_id"], f"{context} type"), size, alignment, useful, None if row["abi_class"] is None else identifier(row["abi_class"], f"{context} ABI class"), fields, tuple(padding))

    def to_payload(self) -> dict[str, object]:
        return {
            "type_id": self.type_id,
            "size_bits": self.size_bits,
            "alignment_bits": self.alignment_bits,
            "value_bits": self.value_bits,
            "abi_class": self.abi_class,
            "fields": [item.to_payload() for item in self.fields],
            "padding": [{"offset_bits": offset, "width_bits": width} for offset, width in self.padding],
        }


@dataclass(frozen=True)
class TargetDataLayoutV1:
    target: str
    abi_dialect: str
    byte_order: str
    pointer_width_bits: int
    packing: str
    schema_id: str
    schema_sha256: str
    layouts: tuple[TypeLayoutV1, ...]
    layout_sha256: str

    @classmethod
    def create(cls, *, target: str, abi_dialect: str, byte_order: str, pointer_width_bits: int, packing: str, schema: BoundarySchemaV1, layouts: Sequence[TypeLayoutV1 | Mapping[str, object]]) -> "TargetDataLayoutV1":
        if byte_order not in {"little", "big"}:
            raise BoundaryModelError("target data-layout byte order is unsupported")
        parsed = tuple(sorted((item if isinstance(item, TypeLayoutV1) else TypeLayoutV1.parse(item, f"type layout {index}") for index, item in enumerate(layouts)), key=lambda item: item.type_id))
        ids = [item.type_id for item in parsed]
        required_type_ids = {
            item.identity
            for item in schema.types
            if item.kind not in {"void", "function", "opaque"}
        }
        allowed_type_ids = {
            item.identity
            for item in schema.types
            if item.kind not in {"void", "function"}
        }
        if (
            ids != sorted(set(ids))
            or not required_type_ids <= set(ids)
            or not set(ids) <= allowed_type_ids
        ):
            raise BoundaryModelError(
                "target data layout must cover every complete stored boundary type exactly once"
            )
        _validate_layouts(schema, parsed, pointer_width_bits)
        core = {
            "format": TARGET_DATA_LAYOUT_V1,
            "target": identifier(target, "data-layout target"),
            "abi_dialect": identifier(abi_dialect, "data-layout ABI dialect"),
            "byte_order": byte_order,
            "pointer_width_bits": uint(pointer_width_bits, "data-layout pointer width", minimum=1),
            "packing": identifier(packing, "data-layout packing"),
            "schema_id": schema.schema_id,
            "schema_sha256": schema.schema_sha256,
            "layouts": [item.to_payload() for item in parsed],
        }
        return cls(str(core["target"]), str(core["abi_dialect"]), byte_order, int(core["pointer_width_bits"]), str(core["packing"]), schema.schema_id, schema.schema_sha256, parsed, content_sha256(core))

    @classmethod
    def parse(cls, value: object, *, schema: BoundarySchemaV1) -> "TargetDataLayoutV1":
        row = object_(value, "target data layout")
        exact(row, {"format", "target", "abi_dialect", "byte_order", "pointer_width_bits", "packing", "schema_id", "schema_sha256", "layouts", "layout_sha256"}, "target data layout")
        if row["format"] != TARGET_DATA_LAYOUT_V1 or row["schema_id"] != schema.schema_id or row["schema_sha256"] != schema.schema_sha256:
            raise BoundaryModelError("target data layout binds another schema or format")
        result = cls.create(target=str(row["target"]), abi_dialect=str(row["abi_dialect"]), byte_order=str(row["byte_order"]), pointer_width_bits=int(row["pointer_width_bits"]), packing=str(row["packing"]), schema=schema, layouts=[TypeLayoutV1.parse(item, f"type layout {index}") for index, item in enumerate(array(row["layouts"], "type layouts"))])
        if row["layout_sha256"] != result.layout_sha256:
            raise BoundaryModelError("target data-layout digest is stale")
        return result

    @property
    def index(self) -> dict[str, TypeLayoutV1]:
        return {item.type_id: item for item in self.layouts}

    def to_payload(self) -> dict[str, object]:
        return {
            "format": TARGET_DATA_LAYOUT_V1,
            "target": self.target,
            "abi_dialect": self.abi_dialect,
            "byte_order": self.byte_order,
            "pointer_width_bits": self.pointer_width_bits,
            "packing": self.packing,
            "schema_id": self.schema_id,
            "schema_sha256": self.schema_sha256,
            "layouts": [item.to_payload() for item in self.layouts],
            "layout_sha256": self.layout_sha256,
        }


def _type_fields(kind: str) -> set[str]:
    return {
        "void": set(), "bool": {"width_bits"}, "integer": {"width_bits", "signed"},
        "float": {"format", "value_bits"}, "complex": {"element_type_id"},
        "enum": {"underlying_type_id", "enumerators"},
        "pointer": {"pointee_type_id", "qualifiers"},
        "function": {"result_type_id", "parameter_type_ids", "variadic", "calling_convention"},
        "array": {"element_type_id", "element_count"},
        "record": {"nominal_id", "fields"}, "union": {"nominal_id", "fields"},
        "vector": {"element_type_id", "element_count"}, "opaque": {"nominal_id"},
    }[kind]


def _validate_type(kind: str, body: Mapping[str, object], context: str) -> None:
    if kind in {"bool", "integer"}:
        uint(body["width_bits"], f"{context} width", minimum=1)
    if kind == "integer":
        boolean(body["signed"], f"{context} signed")
    if kind == "float":
        if body["format"] not in {"binary16", "binary32", "binary64", "x87-extended80"}:
            raise BoundaryModelError(f"{context} float format is unsupported")
        uint(body["value_bits"], f"{context} float width", minimum=1)
    if kind in {"complex", "array", "vector"}:
        identifier(body["element_type_id"], f"{context} element type")
    if kind in {"array", "vector"}:
        uint(body["element_count"], f"{context} element count", minimum=1)
    if kind == "enum":
        identifier(body["underlying_type_id"], f"{context} underlying type")
        ids = []
        for index, item in enumerate(array(body["enumerators"], f"{context} enumerators")):
            row = object_(item, f"{context} enumerator {index}")
            exact(row, {"id", "value"}, f"{context} enumerator {index}")
            ids.append(identifier(row["id"], f"{context} enumerator id"))
            if not isinstance(row["value"], int) or isinstance(row["value"], bool):
                raise BoundaryModelError(f"{context} enumerator value is invalid")
        if ids != sorted(set(ids)):
            raise BoundaryModelError(f"{context} enumerators must be unique and ordered")
    if kind == "pointer":
        identifier(body["pointee_type_id"], f"{context} pointee type")
        qualifiers = ordered_identifiers(body["qualifiers"], f"{context} qualifiers")
        if any(item not in QUALIFIERS for item in qualifiers):
            raise BoundaryModelError(f"{context} qualifier is unsupported")
    if kind == "function":
        identifier(body["result_type_id"], f"{context} result type")
        for item in array(body["parameter_type_ids"], f"{context} parameters"):
            identifier(item, f"{context} parameter type")
        boolean(body["variadic"], f"{context} variadic")
        if body["calling_convention"] not in CALLING_CONVENTIONS:
            raise BoundaryModelError(f"{context} calling convention is unsupported")
    if kind in {"record", "union"}:
        identifier(body["nominal_id"], f"{context} nominal id")
        ids = []
        for index, item in enumerate(array(body["fields"], f"{context} fields")):
            row = object_(item, f"{context} field {index}")
            exact(row, {"id", "type_id", "bit_width"}, f"{context} field {index}")
            ids.append(identifier(row["id"], f"{context} field id"))
            identifier(row["type_id"], f"{context} field type")
            if row["bit_width"] is not None:
                uint(row["bit_width"], f"{context} bit-field width", minimum=1)
        if len(ids) != len(set(ids)):
            raise BoundaryModelError(f"{context} field ids are duplicated")
    if kind == "opaque":
        identifier(body["nominal_id"], f"{context} nominal id")


def _reject_value_cycles(types: Sequence[BoundaryTypeV1]) -> None:
    index = {item.identity: item for item in types}
    active: set[str] = set()
    done: set[str] = set()
    def visit(identity: str) -> None:
        if identity in done:
            return
        if identity in active:
            raise BoundaryModelError("boundary schema contains a non-pointer value cycle")
        active.add(identity)
        for reference in index[identity].references(follow_pointer=False):
            visit(reference)
        active.remove(identity)
        done.add(identity)
    for identity in sorted(index):
        visit(identity)


def _validate_layouts(
    schema: BoundarySchemaV1,
    layouts: Sequence[TypeLayoutV1],
    pointer_width_bits: int,
) -> None:
    types = schema.type_index
    layout_index = {item.type_id: item for item in layouts}
    for layout in layouts:
        node = types[layout.type_id]
        if layout.alignment_bits & (layout.alignment_bits - 1):
            raise BoundaryModelError(
                f"layout for {layout.type_id!r} has non-power-of-two alignment"
            )
        if node.kind == "pointer" and layout.size_bits != pointer_width_bits:
            raise BoundaryModelError(f"layout for {layout.type_id!r} has an invalid pointer size")
        fields = list(node.body.get("fields", [])) if node.kind in {"record", "union"} else []
        if [item.identity for item in layout.fields] != [object_(item, "type field")["id"] for item in fields]:
            raise BoundaryModelError(f"layout for {layout.type_id!r} does not cover its declared fields")
        field_ranges = sorted((item.offset_bits, item.offset_bits + item.storage_bits) for item in layout.fields)
        padding_ranges = sorted((offset, offset + width) for offset, width in layout.padding)
        if any(end > layout.size_bits for _, end in (*field_ranges, *padding_ranges)):
            raise BoundaryModelError(f"layout for {layout.type_id!r} exceeds its size")
        if node.kind != "union" and any(right[0] < left[1] for left, right in zip(field_ranges, field_ranges[1:])):
            raise BoundaryModelError(f"layout for {layout.type_id!r} overlaps fields")
        if node.kind != "union" and any(max(a, c) < min(b, d) for a, b in field_ranges for c, d in padding_ranges):
            raise BoundaryModelError(f"layout for {layout.type_id!r} overlaps fields and padding")
        if any(right[0] < left[1] for left, right in zip(padding_ranges, padding_ranges[1:])):
            raise BoundaryModelError(f"layout for {layout.type_id!r} overlaps padding")
        if node.kind in {"record", "union"}:
            storage_ranges = (
                field_ranges
                if node.kind == "record"
                else [(0, max((end for _, end in field_ranges), default=0))]
            )
        else:
            storage_ranges = [(0, layout.value_bits)] if layout.value_bits else []
        occupied = _merge_ranges(padding_ranges + storage_ranges)
        if occupied != ([(0, layout.size_bits)] if layout.size_bits else []):
            raise BoundaryModelError(
                f"layout for {layout.type_id!r} does not explicitly cover storage and padding"
            )
        if node.kind not in {"record", "union"} and layout.fields:
            raise BoundaryModelError(
                f"non-aggregate layout for {layout.type_id!r} carries fields"
            )
        if node.kind == "pointer" and layout.value_bits != layout.size_bits:
            raise BoundaryModelError(
                f"pointer layout for {layout.type_id!r} has non-address bits"
            )
        if node.kind in {"array", "vector"}:
            element = layout_index[str(node.body["element_type_id"])]
            expected = element.size_bits * int(node.body["element_count"])
            if layout.size_bits != expected:
                raise BoundaryModelError(
                    f"layout for {layout.type_id!r} has an invalid element stride"
                )


def _merge_ranges(ranges: Sequence[tuple[int, int]]) -> list[tuple[int, int]]:
    merged: list[tuple[int, int]] = []
    for start, end in sorted(ranges):
        if start == end:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def resolve_field_path_type(
    schema: BoundarySchemaV1,
    type_id: str,
    fields: Sequence[str],
    *,
    context: str = "boundary value path",
) -> BoundaryTypeV1:
    """Resolve logical field selection, dereferencing pointer-backed references."""

    node = schema.type_index[type_id]
    for field_id in fields:
        while node.kind == "pointer":
            node = schema.type_index[str(node.body["pointee_type_id"])]
        if node.kind not in {"record", "union"}:
            raise BoundaryModelError(f"{context} traverses a non-aggregate")
        field = next(
            (
                object_(item, f"{context} field")
                for item in node.body["fields"]
                if object_(item, f"{context} field")["id"] == field_id
            ),
            None,
        )
        if field is None:
            raise BoundaryModelError(f"{context} names unknown field {field_id!r}")
        node = schema.type_index[str(field["type_id"])]
    return node


__all__ = [
    "BOUNDARY_SCHEMA_V1", "TARGET_DATA_LAYOUT_V1", "BoundaryModelError",
    "BoundarySchemaV1", "BoundarySignatureV1", "BoundaryTypeV1", "BoundaryValueV1",
    "LayoutFieldV1", "TargetDataLayoutV1", "TypeLayoutV1",
    "resolve_field_path_type",
]
