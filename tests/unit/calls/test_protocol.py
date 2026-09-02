from __future__ import annotations

import unittest

from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.calls.lifecycle import CallLifecycleReceiptV1, CallLifecycleV1
from spaghetti_extractor.calls.protocol import CheckedCallProtocolV1
from spaghetti_extractor.calls.relation import CallFrameRelationReceiptV1, CallFrameRelationV1
from spaghetti_extractor.components.relation_solver import prove_binding_lens
from tests.unit.calls._support import graph, layouts, machine_evidence, subject


class CheckedCallProtocolTests(unittest.TestCase):
    def test_frame_compiles_through_shared_relation_ir(self) -> None:
        types = graph()
        layout_set = layouts(types)
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set)
        relation = CallFrameRelationV1.create(type_graph=types, layout_set=layout_set, frame=frame, machine_ir_sha256="1" * 64)
        receipt = CallFrameRelationReceiptV1.check(relation)
        self.assertEqual(CallFrameRelationV1.parse(relation.to_payload()), relation)
        self.assertEqual(
            CallFrameRelationReceiptV1.parse(receipt.to_payload()), receipt
        )
        self.assertNotIn("format", relation.relation_ir.to_payload())
        result = next(item for item in relation.relation_ir.operations[0].clauses if item.logical_path.identity == "result0")
        self.assertEqual(result.observe.op, "concat")
        self.assertEqual([item.kind for item in result.reads], ["register", "register"])
        self.assertTrue(
            all(
                prove_binding_lens(item).status == "checked"
                for item in relation.relation_ir.operations[0].clauses
            )
        )
        self.assertEqual(receipt.status, "complete")

    def test_lifecycle_is_bound_separately_from_payload_transport(self) -> None:
        lifecycle = CallLifecycleV1.create(
            [{"id": "release.arg1", "path": {"slot_id": "arg1", "fields": []}, "transition": "release", "resource_kind": "fixture-handle", "provider_domain": "fixture-provider", "service_id": "fixture.release", "condition": None}],
            interaction_contract_ids=("fixture.release-contract",),
        )
        self.assertEqual(CallLifecycleV1.parse(lifecycle.to_payload()), lifecycle)
        receipt = CallLifecycleReceiptV1.check(lifecycle)
        self.assertEqual(receipt.status, "complete")
        self.assertEqual(CallLifecycleReceiptV1.parse(receipt.to_payload()), receipt)

    def test_complete_protocol_binds_all_authority_layers(self) -> None:
        types = graph()
        layout_set = layouts(types)
        checker = IA32DialectCheckerV1("pe32-i386-gnu-v1")
        frame = checker.lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set)
        receipt = checker.check(proposed=frame, subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set, machine_evidence=(machine_evidence(frame),))
        relation = CallFrameRelationV1.create(type_graph=types, layout_set=layout_set, frame=frame, machine_ir_sha256="1" * 64)
        relation_receipt = CallFrameRelationReceiptV1.check(relation)
        lifecycle = CallLifecycleV1.create([])
        lifecycle_receipt = CallLifecycleReceiptV1.check(lifecycle)
        protocol = CheckedCallProtocolV1.create(status="complete", faithful_function_type_id="call", type_graph=types, layout_set=layout_set, frame=frame, frame_relation_receipt=relation_receipt, lifecycle=lifecycle, lifecycle_receipt=lifecycle_receipt, dialect_receipt_sha256=receipt.receipt_id.split(":", 1)[1], evidence_ids=receipt.machine_evidence_ids)
        self.assertEqual(CheckedCallProtocolV1.parse(protocol.to_payload(), type_graph=types, layout_set=layout_set, frame=frame, lifecycle=lifecycle, lifecycle_receipt=lifecycle_receipt, frame_relation_receipt=relation_receipt), protocol)

    def test_void_callback_frame_has_a_checked_structural_relation(self) -> None:
        types = graph(result="void", parameters=())
        layout_set = layouts(types)
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(
            subject={"kind": "callback", "id": "atexit.handler", "image_selector": "main-image"},
            function_type_id="call",
            type_graph=types,
            layout_set=layout_set,
        )
        relation = CallFrameRelationV1.create(type_graph=types, layout_set=layout_set, frame=frame, machine_ir_sha256="1" * 64)
        receipt = CallFrameRelationReceiptV1.check(relation)
        self.assertEqual(receipt.status, "complete")
        self.assertEqual(receipt.obligations[0]["code"], "empty_frame_structure_checked")


if __name__ == "__main__":
    unittest.main()
