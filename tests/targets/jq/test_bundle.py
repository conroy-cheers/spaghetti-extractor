from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.target_intent import load_target_bundle


TESTKIT = {"resources": ["flake.nix", "targets/jq"]}


class JqBundleTests(unittest.TestCase):
    def test_authored_bundle_is_self_contained(self) -> None:
        bundle = load_target_bundle(Path("targets/jq"))

        self.assertEqual(bundle.identity.target_id, "jq")

    def test_authority_wiring_uses_exact_original(self) -> None:
        target_root = Path("targets/jq")
        metadata = json.loads((target_root / "target.json").read_text(encoding="utf-8"))
        nix = (target_root / "default.nix").read_text(encoding="utf-8")

        self.assertIn("${target.input.expected_sha256}", nix)
        self.assertEqual(
            metadata["input"]["expected_sha256"],
            "5020eab56380107673165fdd1a7ee0532d926d614fab06fd6134394e0030b685",
        )
        self.assertIn("inherit original analysis analysisV3;", nix)
        self.assertIn('machineIr = "${analysis.machineIr}/machine-ir.jsonl";', nix)
        self.assertIn("binary = originalPe;", nix)
        self.assertIn('binaryIdentity = "jq.exe";', nix)
        self.assertIn(
            '"${profileSource}/pe32-msvcrt-machine-runtime-v1.json";', nix
        )
        self.assertNotIn("binary = idiomaticCandidate", nix)

        flake = Path("flake.nix").read_text(encoding="utf-8")
        self.assertIn(
            "jq-final-authority-v3 = jqTarget.analysisV3.finalAuthority;",
            flake,
        )
        self.assertIn("test-target-jq = jqTargetGate;", flake)
        self.assertIn(
            "final-authority-v3\"; path = jqTarget.analysisV3.finalAuthority;",
            flake,
        )

if __name__ == "__main__":
    unittest.main()
