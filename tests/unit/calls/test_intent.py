from __future__ import annotations

import unittest

from spaghetti_extractor.calls._canonical import CallProtocolError
from spaghetti_extractor.calls.intent import CallProtocolIntentV1
from tests.unit.calls._support import graph, subject


class CallProtocolIntentTests(unittest.TestCase):
    def test_intent_contains_semantics_but_no_generated_authority(self) -> None:
        payload = {
            "format": "spaghetti-extractor-call-protocol-intent-v1",
            "id": "fixture-call",
            "subject": subject(),
            "abi_dialect": "pe32-i386-gnu-v1",
            "faithful_function_type_id": "call",
            "types": [item.to_payload() for item in graph().nodes],
            "source_names": {"types": {"u32": "word"}},
            "lifecycle": [],
            "idiomatic_projections": [],
            "rationale": "Reviewed against the public declaration and decoded call site.",
        }
        intent = CallProtocolIntentV1.parse(payload)
        self.assertEqual(intent.to_payload(), payload)
        self.assertEqual(intent.type_graph.index["call"].kind, "function")

    def test_generated_digest_is_rejected_anywhere_in_intent(self) -> None:
        payload = {
            "format": "spaghetti-extractor-call-protocol-intent-v1",
            "id": "fixture-call",
            "subject": subject(),
            "abi_dialect": "pe32-i386-gnu-v1",
            "faithful_function_type_id": "call",
            "types": [item.to_payload() for item in graph().nodes],
            "source_names": {"proposal_sha256": "0" * 64},
            "lifecycle": [],
            "idiomatic_projections": [],
            "rationale": "fixture",
        }
        with self.assertRaisesRegex(CallProtocolError, "generated authority"):
            CallProtocolIntentV1.parse(payload)


if __name__ == "__main__":
    unittest.main()
