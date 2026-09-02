from __future__ import annotations

import unittest

from spaghetti_extractor.boundary import (
    BoundaryLifecycleReceiptV1,
    BoundaryLifecycleV1,
    BoundaryProjectionReceiptV1,
    BoundaryProjectionV1,
    BoundarySchemaV1,
    TargetDataLayoutV1,
)
from spaghetti_extractor.calls.boundary_adapter import (
    reconcile_machine_call_evidence_v1,
    schema_from_call_v1,
)
from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.calls.evidence import MachineCallEvidenceV1
from spaghetti_extractor.calls.frame import PhysicalCallFrameV3
from spaghetti_extractor.calls.lifecycle import CallLifecycleV1
from spaghetti_extractor.calls.protocol_v2 import CheckedCallProtocolV2
from spaghetti_extractor.calls.types import PortableTypeGraphV1


def _value(identity: str, type_id: str) -> dict[str, object]:
    return {
        "id": identity, "type_id": type_id, "interpretation": "value",
        "nullable": False, "access": "none",
        "extent": {"kind": "none", "bytes": None, "value_id": None},
        "resource_kind": None, "provider_domain": None,
    }


def _schema(type_id: str = "jv") -> BoundarySchemaV1:
    return BoundarySchemaV1.create(
        schema_id=f"fixture-{type_id}",
        types=[
            {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
            {
                "id": type_id, "kind": "record", "nominal_id": type_id,
                "fields": [
                    {"id": f"word{index}", "type_id": "u32", "bit_width": None}
                    for index in range(4 if type_id == "jv" else 2)
                ],
            },
            {
                "id": "operation-type", "kind": "function",
                "result_type_id": type_id, "parameter_type_ids": [type_id],
                "variadic": False, "calling_convention": "cdecl",
            },
        ],
        signatures=[{
            "id": "operation", "function_type_id": "operation-type",
            "parameters": [_value("argument", type_id)],
            "results": [_value("result", type_id)],
        }],
    )


def _layout(schema: BoundarySchemaV1, *, aggregate_class: str) -> TargetDataLayoutV1:
    aggregate = next(item for item in schema.types if item.kind == "record")
    width = 32 * len(aggregate.body["fields"])
    return TargetDataLayoutV1.create(
        target="i686-pc-windows-pe32", abi_dialect="pe32-i386-gnu-v1",
        byte_order="little", pointer_width_bits=32, packing="natural",
        schema=schema,
        layouts=[
            {"type_id": "u32", "size_bits": 32, "alignment_bits": 32,
             "value_bits": 32, "abi_class": "integer", "fields": [], "padding": []},
            {"type_id": aggregate.identity, "size_bits": width,
             "alignment_bits": 32, "value_bits": width,
             "abi_class": aggregate_class,
             "fields": [
                 {"id": item["id"], "offset_bits": index * 32,
                  "storage_bits": 32, "value_bits": 32}
                 for index, item in enumerate(aggregate.body["fields"])
             ], "padding": []},
        ],
    )


def _checked_protocol() -> tuple[BoundarySchemaV1, CheckedCallProtocolV2]:
    schema = _schema()
    layout = _layout(schema, aggregate_class="aggregate-memory")
    checker = IA32DialectCheckerV1("pe32-i386-gnu-v1")
    frame = checker.lower_boundary(
        subject={"kind": "function", "id": "jq.jv-copy", "image_selector": "main-image"},
        schema=schema, layout=layout, signature_id="operation",
    )
    machine = MachineCallEvidenceV1.from_frame(
        frame.transport, producer="decoded-jq-call", binary_sha256="d" * 64
    )
    evidence = reconcile_machine_call_evidence_v1(
        expected=frame.transport, evidence=(machine,)
    )
    lifecycle = BoundaryLifecycleV1.create(
        schema=schema, signature_id="operation", bindings=[]
    )
    lifecycle_receipt = BoundaryLifecycleReceiptV1.check(
        lifecycle, checked_interaction_contract_ids=[]
    )
    projection = BoundaryProjectionV1.create(
        component_id="jq-output", operation_id="copy",
        schema=schema, signature_id="operation",
        source_values=[_value("argument", "jv"), _value("result", "jv")],
        entries=[
            {"source_id": "argument", "target": {"root": "parameter", "value_id": "argument", "fields": []}},
            {"source_id": "result", "target": {"root": "result", "value_id": "result", "fields": []}},
        ],
    )
    projection_receipt = BoundaryProjectionReceiptV1.check(
        projection, schema=schema
    )
    protocol = CheckedCallProtocolV2.create(
        schema=schema, layout=layout, signature_id="operation", frame=frame,
        evidence_receipt=evidence, lifecycle=lifecycle,
        lifecycle_receipt=lifecycle_receipt, projection=projection,
        projection_receipt=projection_receipt,
    )
    return schema, protocol


class CanonicalCallProtocolTests(unittest.TestCase):
    def test_legacy_root_resource_lifecycle_is_preserved_in_schema(self) -> None:
        graph = PortableTypeGraphV1.create([
            {"id": "ctx", "kind": "opaque", "nominal_id": "CTX"},
            {
                "id": "p_ctx", "kind": "pointer",
                "pointee_type_id": "ctx", "qualifiers": [],
            },
            {
                "id": "i32", "kind": "integer", "width_bits": 32,
                "signed": True,
            },
            {
                "id": "callback", "kind": "function",
                "result_type_id": "i32",
                "parameter_type_ids": ["p_ctx"],
                "variadic": False, "calling_convention": "stdcall",
            },
        ])
        lifecycle = CallLifecycleV1.create([{
            "id": "borrow.ctx",
            "path": {"slot_id": "arg0", "fields": []},
            "transition": "borrow_shared",
            "resource_kind": "exception_context",
            "provider_domain": "win32_exception_dispatch",
            "service_id": None,
            "condition": None,
        }])

        schema = schema_from_call_v1(
            graph, function_type_id="callback", schema_id="fixture-callback",
            lifecycle=lifecycle,
        )

        parameter = schema.signature_index["callback"].parameters[0]
        self.assertEqual(parameter.interpretation, "resource")
        self.assertEqual(parameter.resource_kind, "exception_context")
        self.assertEqual(
            parameter.provider_domain, "win32_exception_dispatch"
        )

    def test_jv_aggregate_return_uses_explicit_memory_class_and_hidden_sret(self) -> None:
        schema = _schema()
        layout = _layout(schema, aggregate_class="aggregate-memory")
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower_boundary(
            subject={"kind": "function", "id": "jq.jv-copy", "image_selector": "main-image"},
            schema=schema, layout=layout, signature_id="operation",
        )
        self.assertEqual(frame.transport.arguments[0].role, "hidden_sret")
        self.assertEqual(frame.transport.arguments[1].fragments[0].location.stack_offset_bytes, 8)
        self.assertEqual(frame.transport.results[0].pass_mode, "indirect")
        self.assertEqual(
            PhysicalCallFrameV3.parse(
                frame.to_payload(), schema=schema, layout=layout
            ),
            frame,
        )

    def test_small_aggregate_register_return_is_a_layout_class_not_size_guess(self) -> None:
        schema = _schema("pair")
        layout = _layout(schema, aggregate_class="aggregate-register")
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower_boundary(
            subject={"kind": "function", "id": "fixture.pair", "image_selector": "main-image"},
            schema=schema, layout=layout, signature_id="operation",
        )
        self.assertNotEqual(frame.transport.arguments[0].role, "hidden_sret")
        self.assertEqual(
            [item.location.name for item in frame.transport.results[0].fragments],
            ["eax", "edx"],
        )

    def test_checked_protocol_binds_shared_boundary_receipts(self) -> None:
        _schema_value, protocol = _checked_protocol()
        self.assertEqual(protocol.status, "complete")
        self.assertTrue(protocol.physical_frame_id.startswith("physical-call-frame-v3:"))

if __name__ == "__main__":
    unittest.main()
