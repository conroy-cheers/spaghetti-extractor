from __future__ import annotations

import unittest
import io
import json
import tempfile
import textwrap
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[3]
TESTKIT = {"resources": ("targets/flake.nix",)}


class NixTestGateArchitectureTests(unittest.TestCase):
    def test_large_source_inventory_is_read_from_a_bound_file(self) -> None:
        module = (ROOT / "nix/test-suite-shard.nix").read_text(encoding="utf-8")
        program = textwrap.dedent(module.split("<<'PY'\n")[1].split("    PY", 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / 'source.txt'
            source.write_text('bound contents')
            rows = [{'path': 'inputs/' + str(i).zfill(4) + '-' + 'x' * 90,
                     'source': str(source)} for i in range(1400)]
            manifest = root / 'source-rows.json'
            manifest.write_text(json.dumps(rows))
            self.assertGreater(manifest.stat().st_size, 131072)
            work = root / 'work'
            with patch('sys.argv', ['-', str(work), str(manifest)]):
                exec(compile(program, 'test-suite-shard.nix', 'exec'), {})
            self.assertEqual(len(list((work / 'inputs').iterdir())), len(rows))
            self.assertEqual((work / rows[-1]['path']).read_text(), 'bound contents')

    def _run_shard_report(self, peak_rss_kib: int, *, fail: bool = False):
        module = (ROOT / "nix/test-suite-shard.nix").read_text(encoding="utf-8")
        program = textwrap.dedent(module.split("<<'PY'\n")[-1].rsplit("    PY", 1)[0])
        for key, value in {
            "id": "native-report-fixture",
            "input_sha256": "a" * 64,
            "resource_class": "medium",
        }.items():
            program = program.replace("${builtins.toJSON shard." + key + "}", json.dumps(value))
        self.assertNotIn("${", program)

        def check():
            if fail:
                raise AssertionError("fixture test failure")

        suite = unittest.TestSuite([unittest.FunctionTestCase(check)])
        stderr = io.StringIO()
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            with (
                patch("sys.argv", ["-", '["tests/fixture.py"]', str(report_path)]),
                patch("sys.stderr", stderr),
                patch.object(unittest.TestLoader, "loadTestsFromNames", return_value=suite),
                patch.object(Path, "read_text", return_value=f"VmHWM:\t{peak_rss_kib} kB\n"),
            ):
                if fail:
                    with self.assertRaises(SystemExit) as error:
                        exec(compile(program, "test-suite-shard.nix", "exec"), {})
                    self.assertEqual(error.exception.code, 1)
                else:
                    exec(compile(program, "test-suite-shard.nix", "exec"), {})
            return report_path.read_bytes(), stderr.getvalue()

    def test_shard_report_is_identical_when_measured_memory_changes(self) -> None:
        first, first_log = self._run_shard_report(1024)
        second, second_log = self._run_shard_report(8192)
        self.assertEqual(first, second)
        self.assertEqual(json.loads(first)["tests_run"], 1)
        self.assertNotIn("peak_rss_kib", json.loads(first))
        self.assertIn('"peak_rss_kib": 1024', first_log)
        self.assertIn('"peak_rss_kib": 8192', second_log)

    def test_deterministic_shard_report_preserves_test_failure(self) -> None:
        report, _ = self._run_shard_report(1024, fail=True)
        payload = json.loads(report)
        self.assertEqual(payload["status"], "fail")
        self.assertEqual(payload["failures"], 1)
        self.assertEqual(payload["tests_run"], 1)

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

    def test_target_acceptance_consumer_contains_native_package_inputs(self) -> None:
        module = (ROOT / "targets/flake.nix").read_text(encoding="utf-8")

        self.assertIn("consumerSource = pkgs.lib.fileset.toSource", module)
        self.assertIn("../native", module)
        self.assertIn("../src", module)


if __name__ == "__main__":
    unittest.main()
