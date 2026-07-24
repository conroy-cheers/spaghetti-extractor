from __future__ import annotations

import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_operation import (
    INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
)
from tests import (
    test_stage_a_relational_interpreter_kernel_invoke_operation as invoke_fixture,
)
from tests import (
    test_stage_a_relational_interpreter_kernel_run_operation as run_fixture,
)


class StageAGnuRoundtripOperationFrontierPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[1]
        self.driver = self.repo / "nix/gnu-hello-roundtrip-driver.py"
        self.lane = self.repo / "nix/gnu-hello-roundtrip.nix"

    def _run_driver(self, arguments: list[str]) -> None:
        process = subprocess.run(
            [sys.executable, str(self.driver), *arguments],
            cwd=self.repo,
            env={
                **os.environ,
                "PYTHONPATH": f"{self.repo}:{self.repo / 'src'}",
            },
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)

    def test_run_function_source_phase_keeps_six_frontiers_explicit(
        self,
    ) -> None:
        fixture = (
            run_fixture.StageARelationalInterpreterKernelRunOperationTests(
                "runTest"
            )
        )
        fixture.setUp()
        try:
            out = fixture.root / "driver-out"
            self._run_driver(
                [
                    "kernel-run-operation",
                    "--candidate",
                    str(fixture.candidate),
                    "--kernel-plan",
                    str(fixture.kernel),
                    "--kernel-data-inventory",
                    str(fixture.data),
                    "--abi-plan",
                    str(fixture.abi),
                    "--run-native-plan",
                    str(fixture.run_native),
                    "--step-operation-plan",
                    str(fixture.step_operation),
                    "--out",
                    str(out),
                ]
            )
            manifest = json.loads(
                (out / "phase-manifest.json").read_text(encoding="utf-8")
            )
            source = (
                out
                / "StageA/"
                "GeneratedRelationalInterpreterKernelRunOperation.lean"
            ).read_text(encoding="ascii")
        finally:
            fixture.tearDown()

        self.assertEqual(
            manifest["phase"], "compiled-kernel-run-function-operation"
        )
        self.assertFalse(manifest["proof_authority"])
        self.assertEqual(manifest["failure_mode"], "incomplete")
        self.assertEqual(
            manifest["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_RUN_OPERATION_REMAINING_PREMISES),
        )
        self.assertEqual(
            manifest["theorem"], INTERPRETER_KERNEL_RUN_OPERATION_THEOREM
        )
        self.assertIn(
            "theorem generatedRunFunctionOperationRefinesUsing", source
        )

    def test_invoke_call_source_phase_keeps_four_frontiers_explicit(
        self,
    ) -> None:
        fixture = (
            invoke_fixture.StageARelationalInterpreterKernelInvokeOperationTests(
                "runTest"
            )
        )
        fixture.setUp()
        try:
            out = fixture.root / "driver-out"
            self._run_driver(
                [
                    "kernel-invoke-operation",
                    "--candidate",
                    str(fixture.candidate),
                    "--kernel-plan",
                    str(fixture.kernel),
                    "--kernel-data-inventory",
                    str(fixture.data),
                    "--abi-plan",
                    str(fixture.abi),
                    "--callback-plan",
                    str(fixture.callback),
                    "--invoke-native-plan",
                    str(fixture.invoke),
                    "--out",
                    str(out),
                ]
            )
            manifest = json.loads(
                (out / "phase-manifest.json").read_text(encoding="utf-8")
            )
            source = (
                out
                / "StageA/"
                "GeneratedRelationalInterpreterKernelInvokeOperation.lean"
            ).read_text(encoding="ascii")
        finally:
            fixture.tearDown()

        self.assertEqual(
            manifest["phase"], "compiled-kernel-invoke-call-operation"
        )
        self.assertFalse(manifest["proof_authority"])
        self.assertEqual(manifest["failure_mode"], "incomplete")
        self.assertEqual(
            manifest["remaining_proof_premises"],
            list(INTERPRETER_KERNEL_INVOKE_OPERATION_REMAINING_PREMISES),
        )
        self.assertEqual(
            manifest["theorem"], INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM
        )
        self.assertIn(
            "theorem generatedInvokeCallOperationRefinesUsing", source
        )

    def test_nix_graph_has_independent_operation_source_boundaries(self) -> None:
        lane = self.lane.read_text(encoding="utf-8")
        proof_sources = lane[
            lane.index("proofSources = mkPhase") :
            lane.index("proofModules =", lane.index("proofSources = mkPhase"))
        ]

        for phase, command, source in (
            (
                "kernelRunOperationLean",
                "kernel-run-operation",
                "--source ${kernelRunOperationLean}",
            ),
            (
                "kernelInvokeOperationLean",
                "kernel-invoke-operation",
                "--source ${kernelInvokeOperationLean}",
            ),
        ):
            self.assertIn(f"{phase} = mkPhase", lane)
            self.assertIn(command, lane)
            self.assertIn(source, proof_sources)
            self.assertRegex(lane, rf"(?s){phase} = mkPhase.*?proof_authority")


if __name__ == "__main__":
    unittest.main()
