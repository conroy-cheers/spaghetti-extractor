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

    def test_gnu_hello_runs_all_upstream_scripts_under_headless_wine(self) -> None:
        lane = (ROOT / "nix" / "gnu-hello-roundtrip.nix").read_text(
            encoding="utf-8"
        )

        for test in (
            "hello-1",
            "greeting-1",
            "greeting-2",
            "traditional-1",
            "operand-1",
            "last-1",
            "atexit-1",
        ):
            self.assertIn(f'"{test}"', lane)
        self.assertIn("exec xvfb-run -a wine cmd /d /c hello", lane)
        self.assertIn("2026 003 00 00 00", lane)
        self.assertIn("idiomaticUpstreamSuite}/upstream-suite-report.json", lane)
        self.assertIn(".functional.upstream_suite.counts.cases == 7", lane)

    def test_flake_exports_the_generic_runner_and_gnu_suite(self) -> None:
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        package = (ROOT / "pyproject.toml").read_text(encoding="utf-8")

        self.assertIn("mkStageBUpstreamShellSuite", flake)
        self.assertIn("stage-b-gnu-hello-idiomatic-upstream-suite", flake)
        self.assertIn('"nix/stage-b-upstream-shell-suite.nix"', package)


if __name__ == "__main__":
    unittest.main()
