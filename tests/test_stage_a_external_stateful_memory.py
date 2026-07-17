from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.relational.contract import (
    _machine_import_call_contracts,
)
from spaghetti_extractor.relational.lean.expressions import (
    _lean_machine_import_call_contract,
)
from spaghetti_extractor.stage_binary import StageAImport


class StageAExternalStatefulMemoryTests(unittest.TestCase):
    @staticmethod
    def _binary() -> SimpleNamespace:
        return SimpleNamespace(imports=(StageAImport(
            dll="msvcrt.dll",
            symbol="fflush",
            ordinal=None,
            thunk_rva=0x2000,
        ),))

    @staticmethod
    def _contract() -> dict:
        return {
            "id": 11,
            "import": {"dll": "msvcrt.dll", "symbol": "fflush"},
            "abi_template": "pe32-cdecl-v1",
            "argument_words": 1,
            "result_register_relations": [{
                "register": "eax",
                "relation": "exact",
            }],
            "memory_effect": "relationalState",
            "memory_footprints": [],
            "world_effect": "none",
        }

    @staticmethod
    def _iob_contract() -> dict:
        return {
            "id": 12,
            "import": {"dll": "msvcrt.dll", "symbol": "__p__iob"},
            "abi_template": "pe32-cdecl-v1",
            "argument_words": 0,
            "result_register_relations": [{
                "register": "eax",
                "relation": "dynamic_range_base",
                "size": {"kind": "fixed", "bytes": 96},
                "minimum_size": 96,
                "required_words": [],
                "nullable": False,
            }],
            "memory_effect": "none",
            "memory_footprints": [],
            "world_effect": "dynamicRanges",
        }

    def test_relational_state_contract_normalizes_without_footprints(self):
        binary = self._binary()
        issues: list[dict] = []

        normalized = _machine_import_call_contracts(
            [self._contract()], binary, binary, issues
        )

        self.assertEqual(issues, [])
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["memory_effect"], "relationalState")
        self.assertEqual(normalized[0]["memory_footprints"], [])
        self.assertEqual(normalized[0]["stack_argument_offsets"], [0])
        self.assertEqual(normalized[0]["result_register_relations"], [{
            "register": "eax",
            "relation": "exact",
        }])
        self.assertIn(
            "memoryEffect := .relationalState",
            _lean_machine_import_call_contract(normalized[0]),
        )

    def test_relational_state_contract_rejects_explicit_footprints(self):
        binary = self._binary()
        contract = copy.deepcopy(self._contract())
        contract["memory_footprints"] = [{
            "access": "write",
            "base_argument": 0,
            "offset": 0,
            "size": {"kind": "fixed", "bytes": 4},
            "nullable": False,
        }]
        issues: list[dict] = []

        normalized = _machine_import_call_contracts(
            [contract], binary, binary, issues
        )

        self.assertEqual(normalized, [])
        self.assertEqual(
            [issue["category"] for issue in issues],
            ["machine_import_call_contract_invalid"],
        )

    def test_relational_state_contract_rejects_nonreturning_disposition(self):
        binary = self._binary()
        contract = {**self._contract(), "disposition": "protocol"}
        issues: list[dict] = []

        normalized = _machine_import_call_contracts(
            [contract], binary, binary, issues
        )

        self.assertEqual(normalized, [])
        self.assertEqual(
            [issue["category"] for issue in issues],
            ["machine_import_call_contract_invalid"],
        )

    def test_msvcrt_profile_has_unique_stateful_fflush_contract(self):
        profile_path = (
            Path(__file__).parents[1]
            / "profiles"
            / "pe32-msvcrt-lockstep-v1.json"
        )
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        contracts = profile["machine_import_call_contracts"]
        ids = [contract["id"] for contract in contracts]
        fflush = [
            contract for contract in contracts
            if contract["import"].get("symbol") == "fflush"
        ]

        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(fflush, [self._contract()])

        iob = [
            contract for contract in contracts
            if contract["import"].get("symbol") == "__p__iob"
        ]
        self.assertEqual(iob, [self._iob_contract()])

    def test_iob_contract_normalizes_as_paired_nonnull_stream_range(self):
        binary = SimpleNamespace(imports=(StageAImport(
            dll="msvcrt.dll",
            symbol="__p__iob",
            ordinal=None,
            thunk_rva=0x2000,
        ),))
        issues: list[dict] = []

        normalized = _machine_import_call_contracts(
            [self._iob_contract()], binary, binary, issues
        )

        self.assertEqual(issues, [])
        self.assertEqual(len(normalized), 1)
        self.assertEqual(normalized[0]["stack_argument_offsets"], [])
        self.assertEqual(normalized[0]["preserved_registers"], [
            "ebp", "ebx", "edi", "esi",
        ])
        self.assertEqual(normalized[0]["result_register_relations"], [{
            "register": "eax",
            "relation": "dynamic_range_base",
            "size": {"kind": "fixed", "bytes": 96},
            "minimum_size": 96,
            "required_words": [],
            "nullable": False,
        }])


if __name__ == "__main__":
    unittest.main()
