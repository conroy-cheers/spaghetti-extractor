from __future__ import annotations

import unittest
from pathlib import Path

from spaghetti_extractor.calls.dialects.ia32 import IA32DialectCheckerV1
from spaghetti_extractor.calls.transfer_callback import (
    derive_transfer_callback_evidence_v1,
)
from spaghetti_extractor.transfer.model import _Action, _Call, _Node, _Transfer
from tests.unit.calls._support import graph, layouts


_ROOT = Path(__file__).resolve().parents[3]
_PROFILE = _ROOT / "profiles" / "pe32-kernel32-runtime-v1.json"
_SUBJECT = {
    "kind": "callback",
    "id": "win32-unhandled-exception-filter",
    "image_selector": "main-image",
}


def _frame():
    types = graph(convention="stdcall", result="u32", parameters=("p_u8",))
    return IA32DialectCheckerV1("pe32-i386-gnu-v1").lower(
        subject=_SUBJECT,
        function_type_id="call",
        type_graph=types,
        layout_set=layouts(types),
        transfer_kind="callback",
    )


def _transfer(*, exact_store: bool) -> _Transfer:
    nodes = (
        _Node("reg", aux=7, immediate=1),
        _Node("const", immediate=0x40A9A0),
        _Node("const", immediate=0),
        _Node("add32", args=(0, 2)),
        _Node("load", args=(3,), aux=4),
    )
    call = _Call(
        kind="external_call",
        instruction_rva=0x113E,
        call_index=0,
        target_node=None,
        target_rva=0,
        return_rva=0x1144,
        dll="kernel32.dll",
        symbol="SetUnhandledExceptionFilter",
        ordinal=None,
        register_nodes=(),
        flag_nodes=(),
        argument_nodes=(),
        stack_inputs=((0, 4, 4),),
    )
    actions = (
        ((_Action("memory_write", args=(0, 1), aux=4),) if exact_store else ())
        + (_Action("call", args=(0,), aux=0),)
    )
    return _Transfer(
        identity="semantic-transfer:callback-test",
        contract_sha256="a" * 64,
        instruction_bytes_sha256="b" * 64,
        rva_start=0x1137,
        nodes=nodes,
        x87_nodes=(),
        actions=actions,
        calls=(call,),
        x87_operations=(),
    )


class TransferCallbackEvidenceTests(unittest.TestCase):
    def test_exact_stack_registration_yields_checked_frame_evidence(self) -> None:
        evidence, binding = derive_transfer_callback_evidence_v1(
            frame=_frame(),
            transfer_plan={
                "plan_sha256": "c" * 64,
                "bindings": {"pe_sha256": "d" * 64},
            },
            transfers=(_transfer(exact_store=True),),
            runtime_profile_packs=(_PROFILE,),
        )
        self.assertIsNotNone(evidence)
        assert evidence is not None
        self.assertTrue(evidence.complete)
        self.assertEqual(evidence.binary_sha256, "d" * 64)
        self.assertEqual(binding["status"], "complete")
        self.assertEqual(binding["occurrences"][0]["callback_word"], 0x40A9A0)

    def test_unknown_registration_value_fails_closed(self) -> None:
        evidence, binding = derive_transfer_callback_evidence_v1(
            frame=_frame(),
            transfer_plan={
                "plan_sha256": "c" * 64,
                "bindings": {"pe_sha256": "d" * 64},
            },
            transfers=(_transfer(exact_store=False),),
            runtime_profile_packs=(_PROFILE,),
        )
        self.assertIsNone(evidence)
        self.assertEqual(binding["status"], "incomplete")
        self.assertEqual(binding["blocker"], "exact_callback_binding_unresolved")


if __name__ == "__main__":
    unittest.main()
