from __future__ import annotations

import hashlib
import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
DRIVER_PATH = ROOT / "nix" / "gnu-hello-constructive-source-coverage.py"
SPEC = importlib.util.spec_from_file_location(
    "gnu_hello_constructive_source_coverage", DRIVER_PATH
)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = DRIVER
SPEC.loader.exec_module(DRIVER)


def _write(path: Path, value: object) -> None:
    path.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class GnuHelloConstructiveSourceCoverageTests(unittest.TestCase):
    def _fixture(self, root: Path) -> tuple[Path, Path, Path, Path]:
        state_hash = "11" * 32
        candidate_hash = "22" * 32
        mixed = root / "mixed.json"
        reach = root / "reach.json"
        data = root / "data.json"
        kernel = root / "kernel.json"
        _write(
            mixed,
            {
                "format": DRIVER.MIXED_PLAN_FORMAT,
                "state_machine_sha256": state_hash,
                "entry_rva": 5152,
                "counts": {"reachable_targets": 3},
            },
        )
        _write(
            reach,
            {
                "format": DRIVER.STATIC_REACHABILITY_FORMAT,
                "acceptance_authority": False,
                "inputs": {
                    "state_machine_sha256": state_hash,
                    "mixed_original_plan": {"sha256": _sha256(mixed)},
                },
                "counts": {"reachable_targets": 3},
            },
        )
        _write(
            data,
            {
                "format": DRIVER.KERNEL_DATA_FORMAT,
                "acceptance_authority": False,
                "candidate_sha256": candidate_hash,
                "state_machine_sha256": state_hash,
                "counts": {"records": 5},
            },
        )
        _write(
            kernel,
            {
                "format": DRIVER.COMPILED_KERNEL_FORMAT,
                "acceptance_authority": False,
                "candidate": {"pe_sha256": candidate_hash},
                "program": {"transfer_count": 5},
                "kernel_functions": [
                    {"role": "interpreterStep", "rva_start": 307914}
                ],
            },
        )
        return mixed, reach, data, kernel

    def test_emits_checked_coverage_and_exact_rule_inventory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mixed, reach, data, kernel = self._fixture(root)
            out = root / "out"
            DRIVER.generate(
                mixed_original_plan=mixed,
                static_reachability_plan=reach,
                kernel_data_inventory=data,
                kernel_plan=kernel,
                out=out,
            )
            coverage = (out / "StageA" / f"{DRIVER.COVERAGE_MODULE}.lean").read_text()
            rules = (out / "StageA" / f"{DRIVER.RULES_MODULE}.lean").read_text()
            manifest = json.loads((out / "phase-manifest.json").read_text())
            self.assertIn("checked := by decide +kernel", coverage)
            self.assertIn("constructiveSemanticRulesWithLaunch", rules)
            self.assertIn("generatedRulesTargetIds", rules)
            self.assertIn("generatedInvariant", rules)
            self.assertIn("generatedClassifier", rules)
            self.assertIn("constructiveMixedKernelSourceClassifier", rules)
            self.assertIn("entryRva := 307914", rules)
            self.assertIn("candidateRootRva := 5152", rules)
            self.assertFalse(manifest["acceptance_authority"])
            self.assertEqual(manifest["counts"]["reachable_targets"], 3)
            self.assertNotIn(
                "constructive_source_classification",
                manifest["remaining_proof_premises"],
            )

    def test_rejects_cross_candidate_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mixed, reach, data, kernel = self._fixture(root)
            payload = json.loads(kernel.read_text())
            payload["candidate"]["pe_sha256"] = "33" * 32
            _write(kernel, payload)
            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceCoverageError,
                "different candidate PEs",
            ):
                DRIVER.generate(
                    mixed_original_plan=mixed,
                    static_reachability_plan=reach,
                    kernel_data_inventory=data,
                    kernel_plan=kernel,
                    out=root / "out",
                )

    def test_rejects_unbound_reachability(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mixed, reach, data, kernel = self._fixture(root)
            payload = json.loads(reach.read_text())
            payload["inputs"]["mixed_original_plan"]["sha256"] = "44" * 32
            _write(reach, payload)
            with self.assertRaisesRegex(
                DRIVER.GnuHelloConstructiveSourceCoverageError,
                "does not bind",
            ):
                DRIVER.generate(
                    mixed_original_plan=mixed,
                    static_reachability_plan=reach,
                    kernel_data_inventory=data,
                    kernel_plan=kernel,
                    out=root / "out",
                )


if __name__ == "__main__":
    unittest.main()
