from __future__ import annotations

import unittest
from pathlib import Path

from spaghetti_extractor.target_intent import load_target_bundle


TESTKIT = {"resources": ["targets/dxball"]}


class DxBallBundleTests(unittest.TestCase):
    def test_authored_bundle_is_self_contained(self) -> None:
        bundle = load_target_bundle(Path("targets/dxball"))

        self.assertEqual(bundle.identity.target_id, "dxball")


if __name__ == "__main__":
    unittest.main()
