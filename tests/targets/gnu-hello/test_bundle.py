from __future__ import annotations

import json
import unittest
from pathlib import Path

from spaghetti_extractor.target_intent import load_target_bundle


TESTKIT = {"resources": ["flake.nix", "targets/gnu-hello"]}


class GnuHelloBundleTests(unittest.TestCase):
    def test_authored_bundle_is_self_contained(self) -> None:
        bundle = load_target_bundle(Path("targets/gnu-hello"))

        self.assertEqual(bundle.identity.target_id, "gnu-hello")

    def test_authority_wiring_uses_exact_original(self) -> None:
        target_root = Path("targets/gnu-hello")
        metadata = json.loads((target_root / "target.json").read_text(encoding="utf-8"))
        nix = (target_root / "default.nix").read_text(encoding="utf-8")

        self.assertIn("${target.input.expected_sha256}", nix)
        self.assertEqual(
            metadata["input"]["expected_sha256"],
            "71b228f2babc9d3b4095ecf355db676c8ed8b45a7c8a7d350f47e962b4bf554c",
        )
        self.assertIn(
            "inherit original analysis analysisV3 linkedLibraries runtimeLock;", nix
        )
        self.assertIn('machineIr = "${analysis.machineIr}/machine-ir.jsonl";', nix)
        self.assertIn("binary = originalPe;", nix)
        self.assertIn('binaryIdentity = "hello.exe";', nix)
        self.assertIn(
            '"${profileSource}/pe32-msvcrt-machine-runtime-v1.json";', nix
        )
        self.assertNotIn("binary = idiomaticCandidate", nix)

        flake = Path("flake.nix").read_text(encoding="utf-8")
        self.assertIn(
            "gnu-hello-final-authority-v3 = gnuHello.analysisV3.finalAuthority;",
            flake,
        )
        self.assertIn(
            "test-target-gnu-hello = targetSuites.gnu-hello.aggregate;", flake
        )
        self.assertIn(
            "gnu-hello-final-authority-v3-gate =",
            flake,
        )
        self.assertIn(
            "gnu-hello-linked-islands = gnuHello.linkedLibraries.linkedIslands;",
            flake,
        )
        self.assertIn(
            "gnu-hello-lift-workbench = gnuHello.liftWorkbench;",
            flake,
        )
        self.assertIn(
            "gnu-hello-lift-workflow = gnuHello.liftWorkflow;",
            flake,
        )
        self.assertIn("nixpkgs-aarch64-multiplatform-stdenv", nix)
        self.assertIn("portableCompletionReceipt", nix)
        self.assertIn("liftWorkbench", nix)
        self.assertIn("source-iteration-audit", nix)
        self.assertIn("completion-receipt-v2", nix)

if __name__ == "__main__":
    unittest.main()
