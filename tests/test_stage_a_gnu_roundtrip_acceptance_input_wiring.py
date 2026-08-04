from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.interpreter_kernel_invoke_operation import (
    INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_program_lookup_operation import (
    INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_run_operation import (
    INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_kernel_step_operation import (
    INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_original_static_reachability import (
    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME,
    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM,
)
from spaghetti_extractor.relational.lean.interpreter_x87_replay_bridge_runtime import (
    X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES,
)


_PHASE_FORMAT = "stage-a-relational-phase-v1"
_CANDIDATE_SHA256 = "11" * 32
_STATE_MACHINE_SHA256 = "22" * 32
_X87_PREMISES = list(X87_REPLAY_FIXED_TEMPLATE_REMAINING_PREMISES)


class StageAGnuRoundtripAcceptanceInputWiringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.repo = Path(__file__).resolve().parents[1]
        self.driver = self.repo / "targets/gnu-hello/nix/gnu-hello-roundtrip-driver.py"
        self.payloads = self._payloads()
        self.paths = {
            role: self.root / f"{role}.json" for role in self.payloads
        }
        self._write_payloads()

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def _operation_manifest(
        phase: str,
        theorem: str,
        premises: list[str],
    ) -> dict[str, object]:
        return {
            "format": _PHASE_FORMAT,
            "phase": phase,
            "status": "source-ready",
            "proof_authority": False,
            "failure_mode": "incomplete",
            "theorem": theorem,
            "remaining_proof_premises": premises,
            "inputs": {
                "candidate": {
                    "path": "candidate.exe",
                    "sha256": _CANDIDATE_SHA256,
                }
            },
        }

    def _payloads(self) -> dict[str, dict[str, object]]:
        return {
            "kernel_block_manifest": {"targets": []},
            "mixed_original_manifest": {
                "phase": "mixed-original-final-lean",
                "proof_authority": False,
                "remaining_frontiers": [
                    {"reason_code": "runtime_indirect_a"},
                    {"reason_code": "runtime_indirect_b"},
                ],
                "authorizing_lean_terms": [],
                "counts": {"blockers": 2},
            },
            "original_carrier_manifest": {
                "phase": "mixed-original-carrier-binding-lean",
                "status": "source-ready",
                "proof_authority": False,
                "targets": [
                    "GeneratedRelationalInterpreterOriginalCarrierBinding"
                ],
                "exact_mixed_binding": (
                    "StageA.GeneratedRelational."
                    "InterpreterOriginalCarrierBinding."
                    "generatedOriginalExactMixedProgramBinding"
                ),
            },
            "native_launch_request": {
                "format": "stage-a-native-launch-route-request-v1",
                "status": "incomplete",
                "acceptance_authority": False,
                "candidate_sha256": _CANDIDATE_SHA256,
                "canonical_sources": [
                    {"kind": "entry", "index": None, "rva": 4096}
                ],
                "required_path_shapes": ["entry wrapper"],
                "forbidden_authority": ["JSON status"],
            },
            "static_reachability_manifest": {
                "format": _PHASE_FORMAT,
                "phase": "mixed-original-static-reachability",
                "status": "typed-interface-ready",
                "proof_authority": False,
                "failure_mode": "incomplete",
                "theorem": (
                    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM
                ),
                "targets": [
                    Path(
                        INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME
                    ).stem
                ],
                "counts": {
                    "reachable_targets": 3,
                    "runtime_indirect_frontiers": 2,
                },
                "runtime_indirect_control": {
                    "status": "incomplete",
                    "closed_by_this_artifact": False,
                    "required_at": "mixed-component-composition",
                },
            },
            "native_launch_graph_manifest": {
                "format": "stage-a-gnu-hello-native-launch-graph-v1",
                "phase": "native-launch-graph",
                "status": "source-ready",
                "acceptance_authority": False,
                "failure_mode": "incomplete",
                "candidate_sha256": _CANDIDATE_SHA256,
                "counts": {
                    "canonical_roots": 1,
                    "cutpoints": 4,
                    "routes": 4,
                    "decoded_nodes": 12,
                },
            },
            "universal_paired_external_environment_manifest": {
                "format": _PHASE_FORMAT,
                "phase": "universal-paired-external-environment",
                "status": "source-ready",
                "proof_authority": False,
                "inputs": {"candidate_sha256": _CANDIDATE_SHA256},
                "remaining_premises": ["universal_a", "universal_b"],
                "counts": {
                    "required_imports": 3,
                    "machine_contracts": 3,
                    "candidate_pe_byte_packs": 1,
                },
            },
            "constructive_source_coverage_manifest": {
                "format": (
                    "stage-a-gnu-hello-constructive-source-coverage-v1"
                ),
                "phase": "constructive-source-coverage",
                "status": "source-ready",
                "acceptance_authority": False,
                "failure_mode": "incomplete",
                "candidate_sha256": _CANDIDATE_SHA256,
                "state_machine_sha256": _STATE_MACHINE_SHA256,
                "counts": {
                    "candidate_records": 5,
                    "reachable_targets": 3,
                },
                "remaining_proof_premises": ["coverage_a"],
            },
            "canonical_relation_core_manifest": {
                "format": "stage-a-gnu-hello-canonical-relation-core-v1",
                "phase": "canonical-relation-core",
                "status": "source-ready",
                "acceptance_authority": False,
                "failure_mode": "incomplete",
                "candidate_sha256": _CANDIDATE_SHA256,
                "state_machine_sha256": _STATE_MACHINE_SHA256,
                "inputs": {
                    "mixed_original_plan": "33" * 32,
                    "static_reachability_plan": "44" * 32,
                    "kernel_data_inventory": "55" * 32,
                },
                "outputs": {
                    "binding_module": (
                        "StageA/"
                        "GeneratedGnuHelloCanonicalRelationCoreBindings.lean"
                    ),
                    "core_module": (
                        "StageA/GeneratedGnuHelloCanonicalRelationCore.lean"
                    ),
                    "core_plan": "interpreter-mixed-relation-core-plan.json",
                },
            },
            "kernel_program_lookup_operation_manifest": self._operation_manifest(
                "compiled-kernel-program-lookup-operation",
                INTERPRETER_KERNEL_PROGRAM_LOOKUP_OPERATION_THEOREM,
                [],
            ),
            "kernel_step_operation_manifest": self._operation_manifest(
                "compiled-kernel-interpreter-step-operation",
                INTERPRETER_KERNEL_STEP_OPERATION_THEOREM,
                ["step_a", "step_b"],
            ),
            "kernel_run_operation_manifest": self._operation_manifest(
                "compiled-kernel-run-function-operation",
                INTERPRETER_KERNEL_RUN_OPERATION_THEOREM,
                ["run_a"],
            ),
            "kernel_invoke_operation_manifest": self._operation_manifest(
                "compiled-kernel-invoke-call-operation",
                INTERPRETER_KERNEL_INVOKE_OPERATION_THEOREM,
                ["invoke_a", "invoke_b", "invoke_c"],
            ),
            "x87_kernel_execution_manifest": {
                "format": _PHASE_FORMAT,
                "phase": "x87-kernel-execution-lean",
                "status": "source-ready",
                "diagnostic_status": "kernel_execution_closed",
                "proof_authority": False,
                "failure_mode": "none",
                "candidate_sha256": _CANDIDATE_SHA256,
                "runtime_targets": 1,
                "theorem": (
                    "StageA.GeneratedRelational."
                    "InterpreterKernelX87Execution."
                    "generatedX87ReplayBridgeKernelExecutionClosed"
                ),
                "remaining_authority": {"lean_type": "ExactX87Authority"},
                "remaining_proof_premises": _X87_PREMISES,
                "targets": [
                    "GeneratedRelationalInterpreterKernelX87Execution"
                ],
            },
        }

    def _write_payloads(self) -> None:
        for role, payload in self.payloads.items():
            self.paths[role].write_text(
                json.dumps(payload, sort_keys=True) + "\n",
                encoding="utf-8",
            )

    def _run(self) -> subprocess.CompletedProcess[str]:
        arguments = ["acceptance-sources"]
        for role in (
            "kernel_block_manifest",
            "mixed_original_manifest",
            "original_carrier_manifest",
            "native_launch_request",
            "static_reachability_manifest",
            "native_launch_graph_manifest",
            "universal_paired_external_environment_manifest",
            "constructive_source_coverage_manifest",
            "canonical_relation_core_manifest",
            "kernel_program_lookup_operation_manifest",
            "kernel_step_operation_manifest",
            "kernel_run_operation_manifest",
            "kernel_invoke_operation_manifest",
            "x87_kernel_execution_manifest",
        ):
            arguments.extend(
                [f"--{role.replace('_', '-')}", str(self.paths[role])]
            )
        arguments.extend(["--out", str(self.root / "out")])
        return subprocess.run(
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

    def test_derives_diagnostics_without_claiming_acceptance(self) -> None:
        process = self._run()
        self.assertEqual(process.returncode, 0, process.stderr)
        manifest = json.loads(
            (self.root / "out/phase-manifest.json").read_text(encoding="utf-8")
        )
        obligations = json.loads(
            (self.root / "out/acceptance-obligations.json").read_text(
                encoding="utf-8"
            )
        )
        requirements = (
            self.root
            / "out/StageA/GeneratedGnuHelloRoundTripRequirements.lean"
        ).read_text(encoding="utf-8")
        acceptance = (
            self.root
            / "out/StageA/GeneratedRelationalInterpreterMixedKernelBinding.lean"
        ).read_text(encoding="utf-8")

        blocker_ids = [row["id"] for row in manifest["semantic_blockers"]]
        self.assertEqual(
            blocker_ids,
            [
                (
                    "mixed_original_static_reachability_"
                    "runtime_frontiers_remaining"
                ),
                (
                    "universal_paired_external_environment_"
                    "premises_remaining"
                ),
                "constructive_source_coverage_premises_remaining",
                (
                    "compiled_kernel_interpreter_step_operation_"
                    "premises_remaining"
                ),
                (
                    "compiled_kernel_run_function_operation_"
                    "premises_remaining"
                ),
                (
                    "compiled_kernel_invoke_call_operation_"
                    "premises_remaining"
                ),
            ],
        )
        self.assertEqual(manifest["counts"]["diagnostic_blockers"], 6)
        self.assertEqual(manifest["counts"]["remaining_diagnostic_items"], 11)
        self.assertEqual(
            manifest["counts"]["remaining_x87_kernel_execution_premises"],
            len(_X87_PREMISES),
        )
        self.assertEqual(
            manifest["counts"]["remaining_diagnostic_items_by_phase"][
                "compiled-kernel-program-lookup-operation"
            ],
            0,
        )
        self.assertEqual(
            obligations["blocking_obligations"],
            manifest["semantic_blockers"],
        )
        validated_roles = {
            row["role"] for row in manifest["validated_phase_manifests"]
        }
        self.assertIn("native_launch_graph", validated_roles)
        self.assertIn("canonical_relation_core", validated_roles)
        self.assertIsNone(manifest["acceptance_theorem"])
        self.assertEqual(manifest["diagnostic_status"], "incomplete")
        self.assertEqual(
            manifest["acceptance_blocker"]["id"],
            "gnu_hello_round_trip_required_terms_uninhabited",
        )
        self.assertTrue(
            {
                "mixed_original_exact_reachability_missing",
                "exact_candidate_native_launch_wrapper_missing",
                "universal_paired_environment_refinement_missing",
                "x87_replay_kernel_execution_premises_missing",
            }.isdisjoint(blocker_ids)
        )
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterMixedOriginal",
            requirements,
        )
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterMixedAuthority",
            requirements,
        )
        self.assertIn("originalCallableEnvironment", requirements)
        self.assertIn("decodedWorldProgramWithCallable", requirements)
        self.assertIn("originalCallableBinding", requirements)
        self.assertEqual(
            obligations["required_parameter"]["lean_type"],
            "StageA.GeneratedGnuHelloRoundTripRequirements."
            "GnuHelloRoundTripRequiredTerms",
        )
        for exact_binding in (
            "originalContextExact",
            "originalAuthorityExact",
            "originalProgramExact",
            "originalProgramBindingExact",
            "candidateProgramExact",
            "candidateAuthorityExact",
            "kernelABIExact : HEq core.concrete_abi",
        ):
            self.assertIn(exact_binding, requirements)
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterNativeLaunchGraph",
            requirements,
        )
        self.assertIn(
            "ExactCanonicalMixedLaunchWrapperRefinementBinding", requirements
        )
        self.assertIn(
            "NativeLaunchGraph.generatedCheckedNativeLaunchGraph", requirements
        )
        self.assertIn("core.launch_wrapper_refinements", requirements)
        self.assertNotIn("candidateNativeLaunchCertificate", requirements)
        self.assertNotIn("ExactNativeLaunchWrapperCertificate", requirements)
        self.assertIn(
            "(requirements : StageA.GeneratedGnuHelloRoundTripRequirements."
            "GnuHelloRoundTripRequiredTerms)",
            acceptance,
        )
        self.assertIn("canonicalMixedWorldProgramsEquivalent", acceptance)

    def test_rejects_phase_manifest_that_claims_authority(self) -> None:
        self.payloads["native_launch_graph_manifest"][
            "acceptance_authority"
        ] = True
        self._write_payloads()

        process = self._run()

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("claims proof authority", process.stderr)
        self.assertFalse((self.root / "out/phase-manifest.json").exists())

    def test_rejects_stale_static_frontier_count(self) -> None:
        static = self.payloads["static_reachability_manifest"]
        counts = static["counts"]
        assert isinstance(counts, dict)
        counts["runtime_indirect_frontiers"] = 1
        self._write_payloads()

        process = self._run()

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("disagrees with mixed-original frontiers", process.stderr)

    def test_rejects_candidate_identity_mismatch(self) -> None:
        self.payloads["canonical_relation_core_manifest"][
            "candidate_sha256"
        ] = "aa" * 32
        self._write_payloads()

        process = self._run()

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("disagrees with constructive source coverage", process.stderr)


if __name__ == "__main__":
    unittest.main()
