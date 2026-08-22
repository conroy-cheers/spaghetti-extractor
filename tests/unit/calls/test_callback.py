from __future__ import annotations

import unittest

from spaghetti_extractor.calls.callback import CallbackProtocolV2
from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.calls.lifecycle import CallLifecycleReceiptV1, CallLifecycleV1
from spaghetti_extractor.calls.protocol import CheckedCallProtocolV1
from spaghetti_extractor.calls.relation import CallFrameRelationReceiptV1, CallFrameRelationV1
from tests.unit.calls._support import graph, layouts, machine_evidence, subject


def _invocation() -> CheckedCallProtocolV1:
    types = graph(result="u32", parameters=("u32",))
    layout_set = layouts(types)
    checker = IA32DialectCheckerV1("pe32-i386-gnu-v1")
    frame = checker.lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set)
    dialect = checker.check(proposed=frame, subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set, machine_evidence=(machine_evidence(frame),))
    relation = CallFrameRelationV1.create(type_graph=types, layout_set=layout_set, frame=frame, machine_ir_sha256="1" * 64)
    lifecycle = CallLifecycleV1.create([])
    return CheckedCallProtocolV1.create(status="complete", faithful_function_type_id="call", type_graph=types, layout_set=layout_set, frame=frame, frame_relation_receipt=CallFrameRelationReceiptV1.check(relation), lifecycle=lifecycle, lifecycle_receipt=CallLifecycleReceiptV1.check(lifecycle), dialect_receipt_sha256=dialect.receipt_id.split(":", 1)[1], evidence_ids=dialect.machine_evidence_ids)


class TypedCallbackProtocolTests(unittest.TestCase):
    def test_callback_references_checked_call_protocol_without_word_counts(self) -> None:
        invocation = _invocation()
        callback = CallbackProtocolV2.create(
            action="register",
            invocation_protocol=invocation,
            source_path={"slot_id": "arg0", "fields": []},
            instance_kind="singleton",
            instance_paths=(),
            previous_result_path=None,
            lifetime={"kind": "until_process_exit", "end_event": None},
            delivery={"timing": "deferred", "thread_relation": "provider_serialized", "reentrancy": "provider_serialized"},
            cardinality={"minimum": 0, "maximum": None, "scope": "process"},
            interaction_contract_id="callback.registration",
        )
        payload = callback.to_payload()
        self.assertNotIn("signature", payload)
        self.assertNotIn("argument_words", str(payload))
        self.assertEqual(CallbackProtocolV2.parse(payload, protocols={invocation.protocol_id: invocation}), callback)


if __name__ == "__main__":
    unittest.main()
