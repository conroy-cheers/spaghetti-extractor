from __future__ import annotations

import unittest

from spaghetti_extractor.abi.extraction import extract_checked_abi_evidence
from tests.unit.abi._integration_support import parametric_summary


class CheckedAbiExtractionTests(unittest.TestCase):
    def test_incomplete_machine_summary_remains_incomplete(self) -> None:
        unit_ids = ("block.entry", "block.return")
        result = extract_checked_abi_evidence(
            summaries=(parametric_summary(unit_ids, status="incomplete"),),
        )

        self.assertEqual(result.status, "incomplete")
        self.assertEqual(result.subjects, {unit_id: "function" for unit_id in unit_ids})
        self.assertEqual(result.evidence, ())
        self.assertEqual(result.facts, ())
        self.assertEqual(
            {issue["subject_id"] for issue in result.issues},
            set(unit_ids),
        )
        self.assertTrue(
            all(
                issue["code"] == "abi_checked_summary_not_authorizing"
                and issue["status"] == "incomplete"
                for issue in result.issues
            )
        )

    def test_return_cleanup_is_exact_without_inventing_other_fields(self) -> None:
        unit_ids = ("block.entry", "block.return")
        result = extract_checked_abi_evidence(
            summaries=(
                parametric_summary(
                    unit_ids,
                    status="complete",
                    cleanup_bytes=4,
                ),
            ),
        )
        return_facts = {
            fact.field: fact
            for fact in result.facts
            if fact.subject_id == "block.return"
        }

        self.assertEqual(result.status, "complete")
        self.assertEqual(return_facts["stack_cleanup"].status, "exact")
        self.assertEqual(
            return_facts["calling_convention"].values,
            ("fastcall", "stdcall", "thiscall"),
        )
        self.assertFalse(
            {"arguments", "results", "variadic", "preserved_state"}
            & set(return_facts)
        )


if __name__ == "__main__":
    unittest.main()
