from __future__ import annotations

import unittest

from spaghetti_extractor.candidate.callbacks import (
    CallbackDisposition,
    CallbackDispositionKind,
    CallbackInstanceState,
)
from spaghetti_extractor.components.capabilities import CapabilityStatus
from spaghetti_extractor.external.callback_protocols import parse_callback_protocol


def _protocol(*, maximum: int | None = None):
    return parse_callback_protocol(
        {
            "format": "spaghetti-extractor-callback-protocol-v1",
            "id": "fixture-handler",
            "action": "replace",
            "source": {
                "kind": "argument_word",
                "argument": 0,
                "sentinels": [{"word": 0, "kind": "null"}],
            },
            "signature": {
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 1,
                "stack_cleanup_bytes": 4,
                "result": {"kind": "word", "register": "eax"},
            },
            "instance": {"kind": "singleton"},
            "previous_result": {
                "register": "eax",
                "nullable": True,
                "sentinels": [{"word": 0, "kind": "null"}],
            },
            "lifetime": {"kind": "until_replaced_or_process_exit"},
            "delivery": {
                "timing": "deferred",
                "thread": "external_concurrent",
            },
            "cardinality": {
                "minimum": 0,
                "maximum": maximum,
                "scope": "registration_generation",
            },
            "provider_behavior": None,
        },
        registration_argument_words=1,
        context="fixture callback",
    )


class CallbackStateTests(unittest.TestCase):
    def test_replacement_does_not_invalidate_an_admitted_invocation(self) -> None:
        state, _ = CallbackInstanceState().replace(
            CallbackDisposition(CallbackDispositionKind.CALLABLE, "first")
        )
        state, admitted = state.admit(_protocol(), "singleton")
        assert admitted is not None
        state, previous = state.replace(
            CallbackDisposition(CallbackDispositionKind.CALLABLE, "second")
        )
        self.assertEqual(previous.target_id, "first")
        self.assertIn(admitted, state.in_flight)
        completed = state.complete(admitted)
        self.assertEqual(completed.completed_count, 1)
        self.assertEqual(completed.last_status, CapabilityStatus.OK)

    def test_cardinality_is_scoped_to_the_registration_generation(self) -> None:
        protocol = _protocol(maximum=1)
        state, _ = CallbackInstanceState().replace(
            CallbackDisposition(CallbackDispositionKind.CALLABLE, "first")
        )
        state, first = state.admit(protocol, "singleton")
        self.assertIsNotNone(first)
        state, rejected = state.admit(protocol, "singleton")
        self.assertIsNone(rejected)
        state, _ = state.replace(
            CallbackDisposition(CallbackDispositionKind.CALLABLE, "second")
        )
        state, admitted = state.admit(protocol, "singleton")
        self.assertIsNotNone(admitted)

    def test_expiration_rejects_future_admission_but_preserves_in_flight(self) -> None:
        state, _ = CallbackInstanceState().replace(
            CallbackDisposition(CallbackDispositionKind.CALLABLE, "handler")
        )
        state, admitted = state.admit(_protocol(), "singleton")
        assert admitted is not None
        expired = state.expire()
        self.assertIn(admitted, expired.in_flight)
        expired, rejected = expired.admit(_protocol(), "singleton")
        self.assertIsNone(rejected)
        self.assertEqual(expired.last_status, CapabilityStatus.EXPIRED)


if __name__ == "__main__":
    unittest.main()
