from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class StageBUpstreamShellSuiteNixTests(unittest.TestCase):
    def test_generic_runner_is_candidate_only_sharded_and_content_addressed(self) -> None:
        source = (ROOT / "nix" / "stage-b-upstream-shell-suite.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("mkCase =", source)
        self.assertIn("cases = map mkCase tests", source)
        self.assertIn("__contentAddressed = true", source)
        self.assertIn("stage-b-upstream-shell-case-report-v1", source)
        self.assertIn("stage-b-upstream-shell-suite-report-v1", source)
        self.assertIn("executes_original_binary: false", source)
        self.assertIn("original_runtime_observations: false", source)
        self.assertIn("candidate_binary_sha256", source)
        self.assertIn("script_sha256", source)
        self.assertIn("environment_sha256", source)

    def test_stable_target_sdk_exports_the_generic_runner(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        sdk = (ROOT / "nix" / "target-sdk-v2.nix").read_text(encoding="utf-8")
        package = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("mkTargetSdkV2", flake)
        self.assertIn("upstreamShellSuite", sdk)
        self.assertIn("stage-b-upstream-shell-suite.nix", sdk)
        self.assertIn('"nix/stage-b-upstream-shell-suite.nix"', package)


if __name__ == "__main__":
    unittest.main()
