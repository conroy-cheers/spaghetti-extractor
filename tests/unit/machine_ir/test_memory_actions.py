from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.machine_ir.memory_actions import (
    ARCHSEM_CONCURRENCY_COMMIT,
    MemoryActionError,
    adapt_v2_memory_action_graph,
    build_memory_action_graph,
    concurrency_signature,
    signatures_equivalent,
    validate_memory_action_graph,
)


def _const(value: int) -> dict[str, object]:
    return {"op": "const", "value": value, "width": 32}


def _instruction(mnemonic: str = "lock cmpxchg") -> dict[str, object]:
    return {
        "rva_start": 0x1052,
        "mnemonic": mnemonic,
        "operands": [
            {
                "kind": "memory",
                "segment": None,
                "base": None,
                "index": None,
                "scale": 1,
                "displacement": 0x430324,
                "width_bits": 32,
            },
            {"kind": "register", "name": "ebx", "width_bits": 32},
        ],
    }


def _events() -> list[dict[str, object]]:
    address = _const(0x430324)
    observed = {"op": "load", "address": address, "width": 4}
    return [
        {"kind": "read", "address": address, "width": 4},
        {
            "kind": "write",
            "address": address,
            "width": 4,
            "value": {
                "op": "ite",
                "args": [
                    {"op": "eq", "args": [observed, {"op": "reg", "name": "eax", "width": 32}]},
                    {"op": "reg", "name": "ebx", "width": 32},
                    observed,
                ],
            },
        },
    ]


class MemoryActionGraphTests(unittest.TestCase):
    def test_compare_exchange_is_one_rmw_with_unconditional_write_cycle(self) -> None:
        graph = build_memory_action_graph(
            instructions=[_instruction()], memory_events=_events()
        )

        validate_memory_action_graph(graph, require_authoritative=True)
        self.assertEqual(len(graph["actions"]), 1)
        action = graph["actions"][0]
        self.assertEqual(action["kind"], "rmw")
        self.assertEqual(action["operation"], "compare_exchange")
        self.assertEqual(action["transition"]["write_occurs"], "always")
        self.assertEqual(
            action["compare"]["expected"],
            {"op": "reg", "name": "eax", "width": 32},
        )
        self.assertEqual(action["source_memory_event_indices"], [0, 1])
        self.assertEqual(
            graph["model_receipt"]["archsem"]["commit"],
            ARCHSEM_CONCURRENCY_COMMIT,
        )

    def test_compare_inputs_come_from_checked_transition_not_decoder(self) -> None:
        events = _events()
        written = events[1]["value"]
        written["args"][0]["args"][1] = _const(0)  # type: ignore[index]
        graph = build_memory_action_graph(
            instructions=[_instruction()], memory_events=events
        )

        self.assertEqual(graph["status"], "complete")
        self.assertEqual(graph["actions"][0]["compare"]["expected"], _const(0))

    def test_memory_xchg_has_implicit_atomicity(self) -> None:
        instruction = _instruction("xchg")
        graph = build_memory_action_graph(
            instructions=[instruction], memory_events=_events()
        )
        self.assertEqual(graph["status"], "complete")
        self.assertEqual(graph["actions"][0]["operation"], "exchange")
        self.assertEqual(graph["actions"][0]["atomicity"], "x86_locked")

    def test_v2_adapter_can_inspect_but_cannot_authorize(self) -> None:
        graph = adapt_v2_memory_action_graph(
            {
                "format": "spaghetti-extractor-machine-ir-v2",
                "instructions": [_instruction()],
                "semantics": {"memory_events": _events(), "ordered_events": []},
            }
        )
        self.assertFalse(graph["authority"]["authoritative"])
        with self.assertRaises(MemoryActionError):
            validate_memory_action_graph(graph, require_authoritative=True)

    def test_unproved_alignment_fails_closed(self) -> None:
        instruction = _instruction()
        instruction["operands"][0]["base"] = "ecx"  # type: ignore[index]
        instruction["operands"][0]["displacement"] = 0  # type: ignore[index]
        address = {"op": "reg", "name": "ecx", "width": 32}
        events = _events()
        for event in events:
            event["address"] = address
        graph = build_memory_action_graph(
            instructions=[instruction], memory_events=events
        )
        self.assertEqual(graph["status"], "incomplete")
        with self.assertRaises(MemoryActionError):
            concurrency_signature(graph)

    def test_signature_compares_labels_not_generated_ids(self) -> None:
        graph = build_memory_action_graph(
            instructions=[_instruction()], memory_events=_events()
        )
        left = concurrency_signature(graph)
        renamed = copy.deepcopy(left)
        old = renamed["actions"][0]["id"]
        renamed["actions"][0]["id"] = "renamed"
        for edge in renamed["edges"]:
            if edge["before"] == old:
                edge["before"] = "renamed"
            if edge["after"] == old:
                edge["after"] = "renamed"
        self.assertTrue(signatures_equivalent(left, renamed))


if __name__ == "__main__":
    unittest.main()
