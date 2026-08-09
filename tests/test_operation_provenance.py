from __future__ import annotations

import unittest

from spaghetti_extractor.operation_provenance import operation_provenance_view


class OperationProvenanceViewTests(unittest.TestCase):
    def test_checked_static_control_closes_matching_operation_frontier(self) -> None:
        result = operation_provenance_view(
            {
                "status": "incomplete",
                "resolutions": [{
                    "id": "exit:1",
                    "status": "incomplete",
                    "closure": "unresolved",
                    "target_rvas": [],
                    "target_unit_ids": [],
                    "external_targets": [],
                    "failure": {"code": "operation_view_origin_missing"},
                }],
                "issues": [],
                "counts": {},
            },
            checked_control_exits=[{
                "id": "exit:1",
                "closure": "checked_finite_target_inventory",
                "target_rvas": [0x1234],
                "target_unit_ids": ["unit:1234"],
                "external_targets": [],
                "recovery": {"kind": "indexed_static_jump_table"},
            }],
        )

        self.assertEqual(result["status"], "complete")
        self.assertEqual(
            result["resolutions"][0]["closure"],
            "checked_static_control_inventory",
        )
        self.assertEqual(result["counts"]["checked_static_control_exits"], 1)

    def test_provenance_control_is_not_reclassified_as_static(self) -> None:
        result = operation_provenance_view(
            {
                "status": "incomplete",
                "resolutions": [{
                    "id": "exit:1",
                    "status": "incomplete",
                    "closure": "unresolved",
                }],
                "issues": [],
                "counts": {},
            },
            checked_control_exits=[{
                "id": "exit:1",
                "closure": "checked_finite_target_inventory",
                "target_rvas": [],
                "target_unit_ids": [],
                "external_targets": [{"import": {"dll": "x", "symbol": "y"}}],
                "recovery": {"kind": "bounded_value_provenance"},
            }],
        )

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(result["resolutions"][0]["closure"], "unresolved")
        self.assertEqual(result["counts"]["checked_static_control_exits"], 0)


if __name__ == "__main__":
    unittest.main()
