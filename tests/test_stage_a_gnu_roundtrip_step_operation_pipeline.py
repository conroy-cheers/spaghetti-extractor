from __future__ import annotations

import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)


class StageAGnuRoundtripStepOperationPipelineTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).resolve().parents[1]
        self.driver = (
            self.repo / "targets/gnu-hello/nix/gnu-hello-roundtrip-driver.py"
        ).read_text(encoding="utf-8")
        self.lane = (self.repo / "targets/gnu-hello/default.nix").read_text(
            encoding="utf-8"
        )
        self.flake = (self.repo / "flake.nix").read_text(encoding="utf-8")

    def test_driver_emits_hash_bound_non_authoritative_phase(self) -> None:
        function_start = self.driver.index("def _kernel_step_operation")
        function_end = self.driver.index("def _kernel_run", function_start)
        function = self.driver[function_start:function_end]
        parser_start = self.driver.index(
            'command = sub.add_parser("kernel-step-operation")'
        )
        parser_end = self.driver.index(
            'command = sub.add_parser("kernel-run")', parser_start
        )
        parser = self.driver[parser_start:parser_end]

        for role in (
            "candidate",
            "kernel_plan",
            "kernel_data_inventory",
            "abi_plan",
            "step_native_plan",
            "callback_plan",
            "lookup_native_plan",
            "lookup_operation_plan",
            "invoke_native_plan",
            "x87_replay_plan",
        ):
            self.assertIn(f'"{role}"', function)
            self.assertIn(f'--{role.replace("_", "-")}', parser)
        self.assertIn("proof_authority=False", function)
        self.assertIn("remaining_proof_premises", function)
        self.assertIn("INTERPRETER_KERNEL_STEP_OPERATION_THEOREM", function)

    def test_nix_phase_is_source_only_cached_and_exported(self) -> None:
        phase_start = self.lane.index("kernelStepOperationLean = mkPhase")
        phase_end = self.lane.index(
            "mixedCandidateAuthorityLean =", phase_start
        )
        phase = self.lane[phase_start:phase_end]
        proof_start = self.lane.index("proofSources = mkPhase")
        proof_end = self.lane.index("proofModules =", proof_start)
        proof_sources = self.lane[proof_start:proof_end]

        for required in (
            "kernel-step-operation",
            "${candidate}/candidate.exe",
            "${kernelLean}/interpreter-kernel-plan.json",
            "${kernelDataLean}/module-inventory.json",
            "${kernelAbiLean}/interpreter-kernel-abi-plan.json",
            "${kernelStepNativeLean}/interpreter-kernel-step-native-plan.json",
            "${kernelCallbackLean}/interpreter-kernel-callback-plan.json",
            "${kernelLookupNativeLean}/"
            "interpreter-kernel-lookup-native-plan.json",
            "${kernelLookupOperationLean}/"
            "interpreter-kernel-program-lookup-operation-plan.json",
            "${kernelInvokeNativeLean}/"
            "interpreter-kernel-invoke-native-plan.json",
            "${x87ReplayBridgeTargetLean}/x87-replay-bridge-target-plan.json",
            INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
        ):
            self.assertIn(required, phase)
        for premise in INTERPRETER_KERNEL_STEP_OPERATION_REMAINING_PREMISES:
            self.assertIn(f'"{premise}"', phase)
        self.assertIn("--source ${kernelStepOperationLean}", proof_sources)
        self.assertIn(
            "stage-a-gnu-hello-roundtrip-kernel-step-operation-source",
            self.flake,
        )


if __name__ == "__main__":
    unittest.main()
