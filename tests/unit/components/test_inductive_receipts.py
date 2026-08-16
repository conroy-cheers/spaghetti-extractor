from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.components.inductive_receipts import (
    CheckedInductiveMachineReceiptV1,
    InductiveReceiptError,
    build_inductive_machine_receipt,
)


def _unit(identity: str, rva: int, targets: list[int]) -> dict[str, object]:
    return {
        "id": identity,
        "source": {"original": {"rva_start": rva, "rva_end": rva + 1}},
        "semantics": {
            "edge_conditions": [
                {
                    "target_rva": target,
                    "condition": (
                        {"op": "parameter", "name": "continue"}
                        if index == 0 and len(targets) > 1
                        else (
                            {
                                "op": "not",
                                "args": [{"op": "parameter", "name": "continue"}],
                            }
                            if len(targets) > 1
                            else {"op": "true"}
                        )
                    ),
                }
                for index, target in enumerate(targets)
            ],
            "outcome": (
                {"kind": "return"}
                if not targets
                else {"kind": "jump", "target_rva": targets[0]}
            ),
            "register_writes": [],
            "flag_writes": [],
            "memory_events": [],
            "external_events": [],
            "faults": [],
        },
    }


def _operation() -> dict[str, object]:
    return {
        "operation_id": "count",
        "entry_unit_ids": ["entry"],
        "exit_unit_ids": ["exit"],
        "units": [
            _unit("entry", 0x1000, [0x1010]),
            _unit("head", 0x1010, [0x1020, 0x1030]),
            _unit("body", 0x1020, [0x1010]),
            _unit("exit", 0x1030, []),
        ],
    }


class InductiveReceiptTests(unittest.TestCase):
    def test_machine_receipt_replays_exact_operation_and_round_trips(self) -> None:
        operation = _operation()
        receipt = build_inductive_machine_receipt(
            operation=operation,
            semantic_contract_sha256="a" * 64,
            cutpoint_unit_ids=["head"],
        )

        reparsed = CheckedInductiveMachineReceiptV1.parse(
            receipt.to_payload(), exact_operation=operation
        )
        self.assertEqual(reparsed, receipt)
        self.assertEqual(
            len(reparsed.segment_inventory.to_value()["segments"]), 3
        )

    def test_corrupted_segment_fails_even_with_rehashed_envelope(self) -> None:
        operation = _operation()
        payload = build_inductive_machine_receipt(
            operation=operation,
            semantic_contract_sha256="a" * 64,
            cutpoint_unit_ids=["head"],
        ).to_payload()
        payload = copy.deepcopy(payload)
        payload["segment_inventory"]["segments"][0]["edges"] = []
        from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3

        inventory = payload["segment_inventory"]
        inventory_core = dict(inventory)
        inventory_core.pop("inventory_sha256")
        inventory["inventory_sha256"] = canonical_sha256_v3(inventory_core)
        core = dict(payload)
        core.pop("receipt_sha256")
        payload["receipt_sha256"] = canonical_sha256_v3(core)
        with self.assertRaisesRegex(
            InductiveReceiptError, "segment identity|edge closure"
        ):
            CheckedInductiveMachineReceiptV1.parse(payload)

    def test_different_exact_operation_invalidates_receipt(self) -> None:
        operation = _operation()
        payload = build_inductive_machine_receipt(
            operation=operation,
            semantic_contract_sha256="a" * 64,
            cutpoint_unit_ids=["head"],
        ).to_payload()
        changed = copy.deepcopy(operation)
        changed["units"][2]["semantics"]["register_writes"] = [
            {
                "register": "eax",
                "value": {"op": "const", "value": 1, "width": 32},
            }
        ]
        with self.assertRaisesRegex(InductiveReceiptError, "binding is stale"):
            CheckedInductiveMachineReceiptV1.parse(
                payload, exact_operation=changed
            )


if __name__ == "__main__":
    unittest.main()
