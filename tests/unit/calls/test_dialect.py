from __future__ import annotations

import unittest

from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1, IA32DialectReceiptV1
from spaghetti_extractor.calls.evidence import MachineCallEvidenceV1
from spaghetti_extractor.calls.frame import PhysicalCallFrameV2
from tests.unit.calls._support import graph, layouts, machine_evidence, subject


class IA32DialectTests(unittest.TestCase):
    def test_cdecl_scalar_transport_and_split_result(self) -> None:
        types = graph()
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layouts(types))
        self.assertEqual([item.fragments[0].location.stack_offset_bytes for item in frame.arguments], [4, 8])
        self.assertEqual([item.fragments[0].location.name for item in frame.results], ["eax"])
        self.assertEqual([item.location.name for item in frame.results[0].fragments], ["eax", "edx"])
        self.assertEqual(frame.stack.cleanup, "caller")
        self.assertEqual(PhysicalCallFrameV2.parse(frame.to_payload()), frame)

    def test_fastcall_uses_typed_register_fragments(self) -> None:
        types = graph(convention="fastcall", result="u32")
        frame = IA32DialectCheckerV1("pe32-i386-ms-v1").lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layouts(types, dialect="pe32-i386-ms-v1"))
        self.assertEqual([item.fragments[0].location.name for item in frame.arguments], ["ecx", "edx"])
        self.assertEqual(frame.arguments[0].pass_mode, "extended")
        self.assertEqual(frame.stack.cleanup_bytes, 0)

    def test_large_result_uses_hidden_sret_and_exact_cleanup(self) -> None:
        types = graph(convention="stdcall", result="triple", parameters=("u32",))
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layouts(types))
        self.assertEqual(frame.arguments[0].role, "hidden_sret")
        self.assertEqual(frame.results[0].pass_mode, "indirect")
        self.assertEqual(frame.results[0].fragments[0].location.memory_slot, "hidden_sret")
        self.assertEqual(frame.stack.cleanup_bytes, 8)

    def test_dialect_receipt_fails_closed_on_frame_disagreement(self) -> None:
        types = graph()
        layout_set = layouts(types)
        checker = IA32DialectCheckerV1("pe32-i386-gnu-v1")
        frame = checker.lower(subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set)
        payload = frame.to_payload()
        payload["stack"]["alignment_bytes"] = 8
        payload.pop("id")
        changed = PhysicalCallFrameV2.create(**{key: value for key, value in payload.items() if key != "format"})
        receipt = checker.check(proposed=changed, subject=subject(), function_type_id="call", type_graph=types, layout_set=layout_set, machine_evidence=(machine_evidence(frame),))
        self.assertEqual(receipt.status, "violated")

    def test_checked_legacy_callback_authority_migrates_to_exact_evidence(self) -> None:
        types = graph(convention="stdcall", result="u32", parameters=("p_u8",))
        layout_set = layouts(types)
        callback_subject = {
            "kind": "callback",
            "id": "win32-unhandled-exception-filter",
            "image_selector": "main-image",
        }
        frame = IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(
            subject=callback_subject,
            function_type_id="call",
            type_graph=types,
            layout_set=layout_set,
            transfer_kind="callback",
        )
        evidence = MachineCallEvidenceV1.from_pe32_callback_authority(
            frame,
            authority={
                "id": "callback-v3:" + "a" * 64,
                "status": "complete",
                "authorizing": True,
                "entry_state": {
                    "model": "pe32-callback-entry-v1",
                    "stack": {
                        "callee_cleanup_bytes": 4,
                        "arguments": [
                            {"index": 0, "offset": 4, "width": 4, "value": {}}
                        ],
                    },
                },
                "protocol": {
                    "id": callback_subject["id"],
                    "signature": {
                        "abi_template": "pe32-stdcall-v1",
                        "argument_words": 1,
                        "stack_cleanup_bytes": 4,
                        "result": {"kind": "word", "register": "eax"},
                    }
                },
            },
            binary_sha256="b" * 64,
        )
        self.assertTrue(evidence.complete)
        receipt = IA32DialectCheckerV1("pe32-i386-gnu-v1").check(
            proposed=frame,
            subject=callback_subject,
            function_type_id="call",
            type_graph=types,
            layout_set=layout_set,
            machine_evidence=(evidence,),
        )
        self.assertEqual(receipt.status, "complete")
        self.assertEqual(IA32DialectReceiptV1.parse(receipt.to_payload()), receipt)

    def test_complementary_partial_machine_evidence_completes_frame(self) -> None:
        types = graph()
        layout_set = layouts(types)
        checker = IA32DialectCheckerV1("pe32-i386-gnu-v1")
        frame = checker.lower(
            subject=subject(), function_type_id="call", type_graph=types,
            layout_set=layout_set,
        )
        payload = frame.to_payload()
        evidence = tuple(
            MachineCallEvidenceV1.create(
                producer=f"decoded-{field}", subject=frame.subject,
                binary_sha256="c" * 64,
                observed_fields={field: payload[field]},
            )
            for field in ("arguments", "results", "stack")
        )
        receipt = checker.check(
            proposed=frame, subject=subject(), function_type_id="call",
            type_graph=types, layout_set=layout_set,
            machine_evidence=evidence,
        )
        self.assertEqual(receipt.status, "complete")


if __name__ == "__main__":
    unittest.main()
