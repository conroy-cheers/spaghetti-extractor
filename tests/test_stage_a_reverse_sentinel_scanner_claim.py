from __future__ import annotations

import copy
import unittest
from types import MappingProxyType
from typing import Any

from spaghetti_extractor.relational.lean.scanner import (
    _lean_reverse_sentinel_scanner_claim,
)
from spaghetti_extractor.stage_binary import StageAInputError


def _claim() -> dict[str, Any]:
    return {
        "table": {
            "value_target_id": 4,
            "table_offset": 8,
            "original_base": 0x402000,
            "candidate_base": 0x503000,
            "layout": "sentinelTerminatedReverseCount",
            "upper_exclusive": 3,
            "original_index_register": "eax",
            "candidate_index_register": "ebx",
            "continuation_target_id": 9,
            "rows": [
                {"original_index": 1, "target_id": 10},
                {"original_index": 2, "target_id": 11},
            ],
        },
        "original_scanner_register": "ecx",
        "candidate_scanner_register": "edx",
        "original_count_register": "esi",
        "candidate_count_register": "edi",
        "original_loaded_register": "ebp",
        "candidate_loaded_register": "esp",
        "test_target_id": 12,
        "scanner_target_id": 13,
        "bridge_target_id": 14,
        "zero_flag_bit": 6,
    }


class StageAReverseSentinelScannerClaimSerializationTests(unittest.TestCase):
    def test_emits_complete_reverse_sentinel_scanner_claim_literal(self) -> None:
        literal = _lean_reverse_sentinel_scanner_claim(_claim())

        self.assertEqual(
            literal,
            "{ table := { valueTargetId := 4, tableOffset := 8, "
            "originalBase := 4202496, candidateBase := 5255168, "
            "layout := .sentinelTerminatedReverseCount, upperExclusive := 3, "
            "originalIndexRegister := .eax, candidateIndexRegister := .ebx, "
            "continuationTargetId := 9, rows := "
            "[{ index := 1, targetId := 10 }, { index := 2, targetId := 11 }] }, "
            "originalScannerRegister := .ecx, candidateScannerRegister := .edx, "
            "originalCountRegister := .esi, candidateCountRegister := .edi, "
            "originalLoadedRegister := .ebp, candidateLoadedRegister := .esp, "
            "testTargetId := 12, scannerTargetId := 13, bridgeTargetId := 14, "
            "zeroFlagBit := 6 }",
        )

    def test_accepts_generic_read_only_mappings(self) -> None:
        claim = _claim()
        claim["table"] = MappingProxyType(claim["table"])

        literal = _lean_reverse_sentinel_scanner_claim(MappingProxyType(claim))

        self.assertIn("table := { valueTargetId := 4", literal)

    def test_rejects_malformed_top_level_claims(self) -> None:
        missing = _claim()
        del missing["test_target_id"]
        unexpected = _claim()
        unexpected["profile"] = "bounded_reverse_sentinel_scanner_cluster_v1"
        malformed = {
            "not_an_object": [],
            "missing_field": missing,
            "unexpected_field": unexpected,
        }

        for name, claim in malformed.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(
                    StageAInputError, "reverse sentinel scanner claim"
                ):
                    _lean_reverse_sentinel_scanner_claim(claim)  # type: ignore[arg-type]

    def test_rejects_malformed_nested_table_and_rows(self) -> None:
        malformed: dict[str, dict[str, Any]] = {}

        missing_table_field = _claim()
        del missing_table_field["table"]["table_offset"]
        malformed["missing_table_field"] = missing_table_field

        extra_table_field = _claim()
        extra_table_field["table"]["source_region_index"] = 2
        malformed["extra_table_field"] = extra_table_field

        rows_not_array = _claim()
        rows_not_array["table"]["rows"] = tuple(rows_not_array["table"]["rows"])
        malformed["rows_not_array"] = rows_not_array

        row_not_object = _claim()
        row_not_object["table"]["rows"][0] = []
        malformed["row_not_object"] = row_not_object

        extra_row_field = _claim()
        extra_row_field["table"]["rows"][0]["candidate_index"] = 1
        malformed["extra_row_field"] = extra_row_field

        for name, claim in malformed.items():
            with self.subTest(name=name):
                with self.assertRaisesRegex(StageAInputError, "table claim"):
                    _lean_reverse_sentinel_scanner_claim(claim)

    def test_rejects_invalid_naturals_registers_layout_and_flag(self) -> None:
        mutations = {
            "boolean_natural": ("test_target_id", True),
            "negative_natural": ("test_target_id", -1),
            "invalid_register": ("original_loaded_register", "eip"),
            "lean_injection": ("candidate_scanner_register", "eax }\naxiom bad : False"),
            "wrong_zero_flag": ("zero_flag_bit", 0),
        }
        for name, (field, value) in mutations.items():
            with self.subTest(name=name):
                claim = _claim()
                claim[field] = value
                with self.assertRaises(StageAInputError):
                    _lean_reverse_sentinel_scanner_claim(claim)

        table_mutations = {
            "boolean_table_natural": ("upper_exclusive", True),
            "negative_row_natural": ("row.original_index", -1),
            "invalid_table_register": ("original_index_register", "rax"),
            "wrong_layout": ("layout", "zeroBasedBounded"),
            "unknown_layout": ("layout", "sentinelTerminatedReverseCount }"),
        }
        for name, (field, value) in table_mutations.items():
            with self.subTest(name=name):
                claim = copy.deepcopy(_claim())
                if field == "row.original_index":
                    claim["table"]["rows"][0]["original_index"] = value
                else:
                    claim["table"][field] = value
                with self.assertRaises(StageAInputError):
                    _lean_reverse_sentinel_scanner_claim(claim)


if __name__ == "__main__":
    unittest.main()
