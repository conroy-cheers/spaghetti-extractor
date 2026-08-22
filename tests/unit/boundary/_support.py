from __future__ import annotations

from spaghetti_extractor.boundary import BoundarySchemaV1, TargetDataLayoutV1


def value(identity: str, type_id: str, *, interpretation: str = "value") -> dict[str, object]:
    return {
        "id": identity,
        "type_id": type_id,
        "interpretation": interpretation,
        "nullable": False,
        "access": "none",
        "extent": {"kind": "none", "bytes": None, "value_id": None},
        "resource_kind": None,
        "provider_domain": None,
    }


def schema(*, result_type: str = "pair") -> BoundarySchemaV1:
    results = [] if result_type == "unit" else [value("result", result_type)]
    return BoundarySchemaV1.create(
        schema_id="fixture-boundaries",
        types=[
            {"id": "unit", "kind": "void"},
            {"id": "u8", "kind": "integer", "width_bits": 8, "signed": False},
            {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
            {
                "id": "pair",
                "kind": "record",
                "nominal_id": "fixture-pair",
                "fields": [
                    {"id": "first", "type_id": "u32", "bit_width": None},
                    {"id": "second", "type_id": "u32", "bit_width": None},
                ],
            },
            {
                "id": "pair-pointer",
                "kind": "pointer",
                "pointee_type_id": "pair",
                "qualifiers": [],
            },
            {
                "id": "operation-type",
                "kind": "function",
                "result_type_id": result_type,
                "parameter_type_ids": ["pair"],
                "variadic": False,
                "calling_convention": "cdecl",
            },
        ],
        signatures=[
            {
                "id": "operation",
                "function_type_id": "operation-type",
                "parameters": [value("argument", "pair")],
                "results": results,
            }
        ],
    )


def layout(boundary_schema: BoundarySchemaV1) -> TargetDataLayoutV1:
    return TargetDataLayoutV1.create(
        target="i686-pc-windows-pe32",
        abi_dialect="pe32-i386-gnu-v1",
        byte_order="little",
        pointer_width_bits=32,
        packing="natural",
        schema=boundary_schema,
        layouts=[
            {
                "type_id": "u8", "size_bits": 8, "alignment_bits": 8,
                "value_bits": 8, "abi_class": "integer", "fields": [],
                "padding": [],
            },
            {
                "type_id": "u32", "size_bits": 32, "alignment_bits": 32,
                "value_bits": 32, "abi_class": "integer", "fields": [],
                "padding": [],
            },
            {
                "type_id": "pair", "size_bits": 64, "alignment_bits": 32,
                "value_bits": 64, "abi_class": "aggregate",
                "fields": [
                    {"id": "first", "offset_bits": 0, "storage_bits": 32, "value_bits": 32},
                    {"id": "second", "offset_bits": 32, "storage_bits": 32, "value_bits": 32},
                ],
                "padding": [],
            },
            {
                "type_id": "pair-pointer", "size_bits": 32,
                "alignment_bits": 32, "value_bits": 32,
                "abi_class": "pointer", "fields": [], "padding": [],
            },
        ],
    )


def subject() -> dict[str, object]:
    return {"kind": "function", "id": "fixture.operation", "image_selector": "main-image"}
