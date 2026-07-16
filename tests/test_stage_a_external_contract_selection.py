from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.relational.analyses.external import (
    _select_machine_import_call_contract,
)


class StageAExternalContractSelectionTests(unittest.TestCase):
    @staticmethod
    def _contract() -> dict:
        return {
            "id": 7,
            "import": {"dll": "generic.dll", "symbol": "machine_entry"},
            "stack_argument_offsets": [0, 4],
            "stack_result_delta": 8,
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
            "memory_effect": "argumentRanges",
            "memory_footprints": [{
                "access": "write",
                "base_argument": 0,
                "offset": 0,
                "size": {"kind": "fixed", "bytes": 4},
                "nullable": False,
            }],
            "world_effect": "none",
        }

    def test_selects_one_exact_explicit_machine_contract(self):
        contract = self._contract()
        target = ("generic.dll", "symbol", "machine_entry")

        selected, reason = _select_machine_import_call_contract(
            [contract], target, target
        )

        self.assertIs(selected, contract)
        self.assertIsNone(reason)

    def test_rejects_ambiguous_abi_argument_and_footprint_evidence(self):
        target = ("generic.dll", "symbol", "machine_entry")
        variants = {
            "abi": {"stack_result_delta": 0},
            "argument": {"stack_argument_offsets": [0]},
            "footprint": {"memory_effect": "none", "memory_footprints": []},
        }
        for evidence, changes in variants.items():
            with self.subTest(evidence=evidence):
                first = self._contract()
                second = copy.deepcopy(first)
                second["id"] = 8
                second.update(changes)

                selected, reason = _select_machine_import_call_contract(
                    [first, second], target, target
                )

                self.assertIsNone(selected)
                self.assertIn("ambiguous", reason or "")

    def test_rejects_missing_or_nonexact_identity_evidence(self):
        target = ("generic.dll", "symbol", "machine_entry")
        other = ("generic.dll", "symbol", "other_entry")

        missing, missing_reason = _select_machine_import_call_contract(
            [], target, target
        )
        mismatched, mismatch_reason = _select_machine_import_call_contract(
            [self._contract()], target, other
        )

        self.assertIsNone(missing)
        self.assertIn("no explicit contract", missing_reason or "")
        self.assertIsNone(mismatched)
        self.assertIn("not exact", mismatch_reason or "")


if __name__ == "__main__":
    unittest.main()
