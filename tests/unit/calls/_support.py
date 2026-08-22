from __future__ import annotations

from spaghetti_extractor.calls.types import PortableTypeGraphV1, TargetLayoutSetV1
from spaghetti_extractor.calls.evidence import MachineCallEvidenceV1
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2


def graph(*, convention: str = "cdecl", result: str = "u64", parameters: tuple[str, ...] = ("u8", "u32"), variadic: bool = False) -> PortableTypeGraphV1:
    return PortableTypeGraphV1.create(
        [
            {"id": "void", "kind": "void"},
            {"id": "u8", "kind": "integer", "width_bits": 8, "signed": False},
            {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
            {"id": "u64", "kind": "integer", "width_bits": 64, "signed": False},
            {"id": "f32", "kind": "float", "format": "binary32", "value_bits": 32},
            {"id": "f64", "kind": "float", "format": "binary64", "value_bits": 64},
            {"id": "x80", "kind": "float", "format": "x87-extended80", "value_bits": 80},
            {"id": "p_u8", "kind": "pointer", "pointee_type_id": "u8", "qualifiers": []},
            {
                "id": "pair",
                "kind": "record",
                "nominal_id": "pair",
                "fields": [
                    {"id": "first", "type_id": "u32", "bit_width": None},
                    {"id": "second", "type_id": "u32", "bit_width": None},
                ],
            },
            {
                "id": "triple",
                "kind": "record",
                "nominal_id": "triple",
                "fields": [
                    {"id": "first", "type_id": "u32", "bit_width": None},
                    {"id": "second", "type_id": "u32", "bit_width": None},
                    {"id": "third", "type_id": "u32", "bit_width": None},
                ],
            },
            {
                "id": "call",
                "kind": "function",
                "result_type_id": result,
                "parameter_type_ids": list(parameters),
                "variadic": variadic,
                "calling_convention": convention,
            },
        ]
    )


def layouts(type_graph: PortableTypeGraphV1, *, dialect: str = "pe32-i386-gnu-v1") -> TargetLayoutSetV1:
    return TargetLayoutSetV1.create(
        target="i686-pc-windows-pe32",
        abi_dialect=dialect,
        byte_order="little",
        pointer_width_bits=32,
        packing="natural",
        type_graph=type_graph,
        layouts=[
            {"type_id": "u8", "size_bits": 8, "alignment_bits": 8, "value_bits": 8, "array_stride_bits": None, "fields": [], "padding": []},
            {"type_id": "u32", "size_bits": 32, "alignment_bits": 32, "value_bits": 32, "array_stride_bits": None, "fields": [], "padding": []},
            {"type_id": "u64", "size_bits": 64, "alignment_bits": 64, "value_bits": 64, "array_stride_bits": None, "fields": [], "padding": []},
            {"type_id": "f32", "size_bits": 32, "alignment_bits": 32, "value_bits": 32, "array_stride_bits": None, "fields": [], "padding": []},
            {"type_id": "f64", "size_bits": 64, "alignment_bits": 64, "value_bits": 64, "array_stride_bits": None, "fields": [], "padding": []},
            {"type_id": "x80", "size_bits": 96, "alignment_bits": 32, "value_bits": 80, "array_stride_bits": None, "fields": [], "padding": [{"offset_bits": 80, "width_bits": 16}]},
            {"type_id": "p_u8", "size_bits": 32, "alignment_bits": 32, "value_bits": 32, "array_stride_bits": None, "fields": [], "padding": []},
            {"type_id": "pair", "size_bits": 64, "alignment_bits": 32, "value_bits": 64, "array_stride_bits": None, "fields": [{"id": "first", "offset_bits": 0, "storage_bits": 32, "value_bits": 32}, {"id": "second", "offset_bits": 32, "storage_bits": 32, "value_bits": 32}], "padding": []},
            {"type_id": "triple", "size_bits": 96, "alignment_bits": 32, "value_bits": 96, "array_stride_bits": None, "fields": [{"id": "first", "offset_bits": 0, "storage_bits": 32, "value_bits": 32}, {"id": "second", "offset_bits": 32, "storage_bits": 32, "value_bits": 32}, {"id": "third", "offset_bits": 64, "storage_bits": 32, "value_bits": 32}], "padding": []},
        ],
    )


def subject() -> dict[str, object]:
    return {"kind": "function", "id": "fixture.call", "image_selector": "main-image"}


def machine_evidence(frame: PhysicalCallFrameV2) -> MachineCallEvidenceV1:
    return MachineCallEvidenceV1.from_frame(
        frame,
        producer="decoded-call-fixture-v1",
        binary_sha256="a" * 64,
    )
