from __future__ import annotations

import copy
import unittest

from spaghetti_extractor.indirect_target_dependency_v2 import (
    IndirectTargetDependencyV2Error,
    build_bounded_selector_dependency_v2,
    has_value_independent_target_set_v2,
    validate_bounded_selector_dependency_v2,
)


def recovery() -> dict[str, object]:
    result: dict[str, object] = {
        "status": "recovered",
        "closure": "checked_finite_target_inventory",
        "kind": "indirect_jump",
        "recovery_kind": "pe32_indexed_absolute_jump_table",
        "failure": None,
        "index": {
            "expression": {"op": "reg", "name": "eax", "width": 32},
            "lower_inclusive": 0,
            "upper_exclusive": 2,
            "values": [0, 1],
            "value_count": 2,
            "dataflow_evidence": None,
            "remap": None,
            "bound_evidence": [
                {
                    "source_unit_id": "bound",
                    "upper_exclusive": 2,
                    "sources": ["guard"],
                }
            ],
        },
        "table": {
            "entry_width": 4,
            "entry_count": 2,
            "index_values": [0, 1],
            "contiguous": True,
            "bytes_sha256": "a" * 64,
            "inventory_sha256": "b" * 64,
        },
        "entries": [
            {"index": 0, "entry_rva": 0x3000, "target_rva": 0x2000},
            {"index": 1, "entry_rva": 0x3004, "target_rva": 0x2100},
        ],
        "target_rvas": [0x2000, 0x2100],
        "target_unit_ids": ["target-a", "target-b"],
        "unit_binding": {
            "status": "complete",
            "resolved_target_rvas": [0x2000, 0x2100],
            "unmaterialized_target_rvas": [],
        },
    }
    result["target_set_dependency"] = build_bounded_selector_dependency_v2(result)
    return result


class IndirectTargetDependencyV2Tests(unittest.TestCase):
    def test_bounded_selector_certificate_round_trips(self) -> None:
        value = recovery()

        self.assertTrue(has_value_independent_target_set_v2(value))
        self.assertEqual(
            validate_bounded_selector_dependency_v2(value),
            value["target_set_dependency"],
        )
        self.assertFalse(
            value["target_set_dependency"]["requires_selector_value_provenance"]
        )

    def test_changed_target_invalidates_certificate(self) -> None:
        value = recovery()
        value["target_rvas"] = [0x2000]

        self.assertFalse(has_value_independent_target_set_v2(value))
        with self.assertRaises(IndirectTargetDependencyV2Error):
            validate_bounded_selector_dependency_v2(value)

    def test_changed_bound_invalidates_certificate(self) -> None:
        value = recovery()
        value["index"]["bound_evidence"][0]["upper_exclusive"] = 3

        self.assertFalse(has_value_independent_target_set_v2(value))

    def test_changed_certificate_digest_invalidates_certificate(self) -> None:
        value = recovery()
        altered = copy.deepcopy(value)
        altered["target_set_dependency"]["table_bytes_sha256"] = "c" * 64

        self.assertFalse(has_value_independent_target_set_v2(altered))

    def test_changed_recovery_mechanism_invalidates_certificate(self) -> None:
        value = recovery()
        value["recovery_kind"] = "operator_target_inventory"

        self.assertFalse(has_value_independent_target_set_v2(value))

    def test_unbound_target_unit_inventory_is_rejected(self) -> None:
        value = recovery()
        value.pop("target_set_dependency")
        value["unit_binding"]["unmaterialized_target_rvas"] = [0x2100]

        with self.assertRaises(IndirectTargetDependencyV2Error):
            build_bounded_selector_dependency_v2(value)


if __name__ == "__main__":
    unittest.main()
