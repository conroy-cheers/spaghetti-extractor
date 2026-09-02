from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from tests.unit.candidate.test_runtime_canonical import _inputs

from spaghetti_extractor.candidate.runtime_canonical import (
    plan_module_runtime_from_canonical,
)


class CanonicalRuntimeBridgeTests(unittest.TestCase):
    def test_runtime_bridge_model_comes_only_from_canonical_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            inputs = _inputs(Path(temporary))
            plan = plan_module_runtime_from_canonical(**inputs)
            self.assertEqual(plan.status, "ready", plan.blockers)
            self.assertEqual(plan.input_mode, "executable_transfer_plan_v2")
            self.assertEqual(plan.transfer_count, 2)
            self.assertEqual(plan.external_sites, ())
            self.assertEqual(len(plan.guest_dispatch_domains), 1)
            self.assertEqual(len(plan.guest_dispatch_sites), 1)
            self.assertEqual(
                plan.guest_dispatch_domains[0].target_rvas, (0x1000,)
            )
            self.assertNotIn(
                0x2000, plan.guest_dispatch_domains[0].target_rvas
            )
            self.assertEqual(
                plan.guest_dispatch_sites[0].domain_sha256,
                plan.guest_dispatch_domains[0].domain_sha256,
            )
            receipt = plan.implementation_dispatch_receipt.payload()
            self.assertEqual(receipt["status"], "complete")
            self.assertEqual(
                receipt["entries"][0]["implementation_class"],
                "generated_behavioral_c",
            )


if __name__ == "__main__":
    unittest.main()
