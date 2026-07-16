from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.relational.analyses.external import (
    _machine_call_argument_count_blocker,
    _machine_import_call_contract_analysis,
)


class StageAExternalProtocolTests(unittest.TestCase):
    @staticmethod
    def _memcpy_contract() -> dict:
        profile_path = (
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-msvcrt-lockstep-v1.json"
        )
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        raw = next(
            contract
            for contract in profile["machine_import_call_contracts"]
            if contract["import"].get("symbol") == "memcpy"
        )
        return {
            "id": raw["id"],
            "import": raw["import"],
            "stack_argument_offsets": [0, 4, 8],
            "stack_result_delta": 0,
            "preserved_registers": ["ebp", "ebx", "edi", "esi"],
            "clobbered_registers": ["eax", "ecx", "edx"],
            "result_register_relations": raw["result_register_relations"],
            "disposition": "returns",
            "memory_effect": raw["memory_effect"],
            "memory_footprints": raw["memory_footprints"],
            "world_effect": raw["world_effect"],
        }

    @staticmethod
    def _external_jump(arguments: list[dict]) -> dict:
        imported = {
            "dll": list(b"msvcrt.dll"),
            "name": {"op": "symbol", "bytes": list(b"memcpy")},
        }
        return {"outcome": {
            "op": "external_jump",
            "import": imported,
            "arguments": arguments,
        }}

    def test_memcpy_profile_declares_argument_sized_read_write_footprints(self):
        contract = self._memcpy_contract()
        self.assertEqual(contract["stack_argument_offsets"], [0, 4, 8])
        self.assertEqual(contract["result_register_relations"], [
            {"register": "eax", "relation": "related_word"},
        ])
        self.assertEqual(contract["memory_effect"], "argumentRanges")
        self.assertEqual(
            [footprint["access"] for footprint in contract["memory_footprints"]],
            ["write", "read"],
        )
        self.assertEqual(
            [footprint["base_argument"] for footprint in contract["memory_footprints"]],
            [0, 1],
        )
        self.assertTrue(all(
            footprint["size"]
            == {"kind": "argument", "argument": 2, "scale": 1}
            for footprint in contract["memory_footprints"]
        ))

    def test_machine_contract_argument_count_accepts_only_complete_pair(self):
        contract = self._memcpy_contract()
        arguments = [{"op": "constant", "value": value} for value in (1, 2, 3)]
        self.assertIsNone(
            _machine_call_argument_count_blocker(contract, arguments, arguments)
        )
        self.assertEqual(
            _machine_call_argument_count_blocker(contract, arguments[:2], arguments),
            "machine import contract expects 3 argument words; recovered 2 original "
            "and 3 candidate",
        )
        self.assertIn(
            "not recovered as expression lists",
            _machine_call_argument_count_blocker(contract, None, arguments),
        )

    def test_machine_call_analysis_fails_closed_on_missing_extent_argument(self):
        contract = self._memcpy_contract()
        complete = [{"op": "constant", "value": value} for value in (1, 2, 8)]
        incomplete = complete[:2]
        behaviors = [
            {
                "original_ir": self._external_jump(complete),
                "candidate_ir": self._external_jump(complete),
            },
            {
                "original_ir": self._external_jump(incomplete),
                "candidate_ir": self._external_jump(incomplete),
            },
        ]
        analysis = _machine_import_call_contract_analysis(
            {
                "regions": [{"id": "complete"}, {"id": "incomplete"}],
                "machine_import_call_contracts": [contract],
            },
            behaviors,
        )
        self.assertEqual(
            [call["status"] for call in analysis["calls"]],
            ["candidate_requires_lean_replay", "incomplete"],
        )
        self.assertEqual(analysis["counts"]["contracted_call_sites"], 2)
        self.assertEqual(analysis["counts"]["argument_recovery_candidates"], 1)
        self.assertEqual(analysis["counts"]["incomplete_call_sites"], 1)


if __name__ == "__main__":
    unittest.main()
