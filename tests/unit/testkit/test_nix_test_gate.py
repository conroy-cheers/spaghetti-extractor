from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class NixTestGateArchitectureTests(unittest.TestCase):
    def test_suite_plan_is_pure_manifest_loading(self) -> None:
        module = (ROOT / "nix/test-suite-plan.nix").read_text(encoding="utf-8")

        self.assertIn("test-suite-manifest.json", module)
        self.assertIn("builtins.readFile manifest", module)
        self.assertNotIn("pkgs.runCommand", module)
        self.assertNotIn("python -m", module)
        self.assertNotIn("unsafeDiscardStringContext", module)

    def test_suite_does_not_read_a_derivation_output_during_evaluation(self) -> None:
        module = (ROOT / "nix/test-suite.nix").read_text(encoding="utf-8")

        self.assertNotIn('builtins.readFile "${plan}', module)
        self.assertNotIn("unsafeDiscardStringContext", module)
        self.assertIn("planPayload ? null", module)

    def test_flake_gate_checks_repository_metadata_freshness_once(self) -> None:
        module = (ROOT / "nix/flake-modules/checks.nix").read_text(encoding="utf-8")

        self.assertIn("repositoryMetadataFreshness", module)
        self.assertIn("spaghetti-extractor-dev --repository ${testSource} refresh --check", module)
        self.assertIn("repository-metadata = repositoryMetadataFreshness", module)
        self.assertNotIn("testManifestFreshness", module)


if __name__ == "__main__":
    unittest.main()
