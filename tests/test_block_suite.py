import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from haloce_catalog.block_suite import gate_block_suite, generate_block_suite
from haloce_catalog.target import target_config_from_mapping
from haloce_catalog.util import json_dumps, sha256_file


class BlockSuiteWorkflowTests(unittest.TestCase):
    def test_generate_block_suite_filters_traces_and_accepts_explicit_external_modules(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = self._write_binary(root, "toy.exe")
            module_sha = sha256_file(binary)
            trace = root / "trace.jsonl"
            external_sha = "e" * 64
            self._write_trace(
                trace,
                [
                    self._module("toy.exe", module_sha, module_path=str(binary)),
                    self._module("KERNEL32.dll", external_sha, module_path=r"C:\WINDOWS\System32\KERNEL32.dll"),
                    self._block_entry(module_sha, 0x1000),
                    self._block_exit(module_sha, 0x1000),
                    self._block_entry(external_sha, 0x1000),
                ],
            )
            target = self._target(external_modules=[{"names": ["KERNEL32.dll"], "kind": "os_component", "source": "Windows"}])

            def fake_run(command, **kwargs):
                suite_dir = Path(command[command.index("--out") + 1])
                suite_dir.mkdir(parents=True)
                (suite_dir / "coverage.json").write_text(
                    json_dumps(
                        {
                            "format": "wincr-block-coverage-report-v1",
                            "status": "pass",
                            "required_blocks": 1,
                            "characterized_blocks": 1,
                            "waived_blocks": 0,
                            "uncovered_blocks": [],
                            "side_effect_incomplete_blocks": [],
                            "complete_cases": 1,
                            "pending_cases": 0,
                            "issues": [],
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch("haloce_catalog.block_suite.subprocess.run", side_effect=fake_run) as run:
                result = generate_block_suite(
                    target_config=target,
                    binary_root=root,
                    trace_dir=None,
                    traces=[trace],
                    out_dir=root / "suite",
                    wincr_block="wincr-block",
                )

            self.assertTrue(result["ok"], result["gaps"])
            self.assertEqual(result["external_modules"]["status"], "pass")
            filtered_trace = Path(run.call_args.args[0][run.call_args.args[0].index("--trace") + 1])
            filtered_text = filtered_trace.read_text(encoding="utf-8")
            self.assertIn(module_sha, filtered_text)
            self.assertNotIn(external_sha, filtered_text)
            self.assertEqual(gate_block_suite(root / "suite")["status"], "pass")

    def test_generate_block_suite_fails_closed_on_unknown_loaded_module(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = self._write_binary(root, "toy.exe")
            module_sha = sha256_file(binary)
            trace = root / "trace.jsonl"
            self._write_trace(
                trace,
                [
                    self._module("toy.exe", module_sha, module_path=str(binary)),
                    self._module("mystery.dll", "a" * 64, module_path=r"C:\Game\mystery.dll"),
                    self._block_entry(module_sha, 0x1000),
                    self._block_exit(module_sha, 0x1000),
                ],
            )

            with mock.patch("haloce_catalog.block_suite.subprocess.run", side_effect=self._write_passing_coverage):
                result = generate_block_suite(
                    target_config=self._target(),
                    binary_root=root,
                    trace_dir=None,
                    traces=[trace],
                    out_dir=root / "suite",
                    wincr_block="wincr-block",
                )

            self.assertFalse(result["ok"])
            self.assertEqual(result["external_modules"]["status"], "fail")
            self.assertTrue(any(gap["kind"] == "unknown_loaded_module" for gap in result["gaps"]["gaps"]))
            self.assertTrue(any(item["kind"] == "fix_external_provenance" for item in result["next_traces"]["suggestions"]))
            self.assertEqual(gate_block_suite(root / "suite")["status"], "fail")

    def test_generate_block_suite_reports_coverage_gaps_and_next_trace_plan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = self._write_binary(root, "toy.exe")
            module_sha = sha256_file(binary)
            trace = root / "trace.jsonl"
            self._write_trace(trace, [self._module("toy.exe", module_sha, module_path=str(binary))])

            def fake_run(command, **kwargs):
                suite_dir = Path(command[command.index("--out") + 1])
                suite_dir.mkdir(parents=True)
                (suite_dir / "coverage.json").write_text(
                    json_dumps(
                        {
                            "format": "wincr-block-coverage-report-v1",
                            "status": "fail",
                            "required_blocks": 2,
                            "characterized_blocks": 1,
                            "waived_blocks": 0,
                            "uncovered_blocks": ["bb_00001000_00001005"],
                            "side_effect_incomplete_blocks": ["bb_00001005_00001009"],
                            "complete_cases": 1,
                            "pending_cases": 0,
                            "issues": ["1 block obligations are uncovered and unwaived"],
                        }
                    ),
                    encoding="utf-8",
                )
                return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

            with mock.patch("haloce_catalog.block_suite.subprocess.run", side_effect=fake_run):
                result = generate_block_suite(
                    target_config=self._target(),
                    binary_root=root,
                    trace_dir=None,
                    traces=[trace],
                    out_dir=root / "suite",
                    wincr_block="wincr-block",
                )

            kinds = {gap["kind"] for gap in result["gaps"]["gaps"]}
            self.assertFalse(result["ok"])
            self.assertIn("uncovered_block", kinds)
            self.assertIn("incomplete_side_effects", kinds)
            self.assertIn("capture_more_block_state_traces", {item["kind"] for item in result["next_traces"]["suggestions"]})

    def _target(self, *, external_modules=None):
        return target_config_from_mapping(
            {
                "project": {"id": "toy", "name": "Toy"},
                "binary_rules": [
                    {
                        "names": ["toy.exe"],
                        "role": "closed_runtime",
                        "scope": "included",
                        "reason": "toy target",
                    }
                ],
                "trace_targets": [{"id": "startup", "executable": "toy.exe", "expected_filename": "toy.exe"}],
                "external_modules": external_modules or [],
            }
        )

    def _write_binary(self, root: Path, name: str) -> Path:
        path = root / name
        path.write_bytes(b"MZtoy")
        return path

    def _write_trace(self, path: Path, records: list[dict]) -> None:
        path.write_text("\n".join(json_dumps(record) for record in records) + "\n", encoding="utf-8")

    def _module(self, name: str, sha256: str, *, module_path: str) -> dict:
        return {
            "kind": "module",
            "test_id": "startup",
            "module_name": name,
            "module_path": module_path,
            "module_sha256": sha256,
        }

    def _block_entry(self, sha256: str, rva: int) -> dict:
        return {
            "kind": "block_entry",
            "test_id": "startup",
            "module_name": "toy.exe",
            "module_sha256": sha256,
            "rva": rva,
            "rva_end": rva + 5,
            "state": {"registers": {}},
        }

    def _block_exit(self, sha256: str, rva: int) -> dict:
        return {
            "kind": "block_exit",
            "test_id": "startup",
            "module_name": "toy.exe",
            "module_sha256": sha256,
            "rva": rva,
            "rva_end": rva + 5,
            "state": {"registers": {}},
            "successor_rva": rva + 5,
            "side_effects": {
                "format": "wincr-block-side-effects-v1",
                "capture_status": "complete",
                "limitations": [],
                "api_calls": [],
                "external_events": [],
                "dropped": {"api_calls": 0, "memory_reads": 0, "memory_writes": 0, "pending_writes": 0, "syscalls": 0},
            },
        }

    def _write_passing_coverage(self, command, **kwargs):
        suite_dir = Path(command[command.index("--out") + 1])
        suite_dir.mkdir(parents=True)
        (suite_dir / "coverage.json").write_text(
            json_dumps(
                {
                    "format": "wincr-block-coverage-report-v1",
                    "status": "pass",
                    "required_blocks": 1,
                    "characterized_blocks": 1,
                    "waived_blocks": 0,
                    "uncovered_blocks": [],
                    "side_effect_incomplete_blocks": [],
                    "complete_cases": 1,
                    "pending_cases": 0,
                    "issues": [],
                }
            ),
            encoding="utf-8",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


if __name__ == "__main__":
    unittest.main()
