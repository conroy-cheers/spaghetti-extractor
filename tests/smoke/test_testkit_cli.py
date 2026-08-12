from __future__ import annotations

import unittest

from spaghetti_extractor.testkit import plan_test_scaffold


class TestkitSmokeTests(unittest.TestCase):
    def test_supported_test_scaffold_is_immediately_classifiable(self) -> None:
        plan = plan_test_scaffold(subsystem="control", name="branch_targets")

        self.assertEqual(plan.files[0].path, "tests/unit/control/test_branch_targets.py")
        self.assertIn("unittest.TestCase", plan.files[0].content)


if __name__ == "__main__":
    unittest.main()
