import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from hashlib import sha256
from pathlib import Path


class StageARoundtripNixTests(unittest.TestCase):
    def setUp(self) -> None:
        self.repo = Path(__file__).parents[1]
        self.corpus_nix = self.repo / "nix" / "stage-a-roundtrip-corpus.nix"
        self.smoke_nix = self.repo / "nix" / "stage-a-roundtrip-smoke.nix"
        self.builders_file = self.repo / "nix" / "stage-a-builders"
        self.flake_nix = self.repo / "flake.nix"
        self.gnu_hello_nix = self.repo / "nix" / "gnu-hello-roundtrip.nix"
        self.gnu_hello_driver = (
            self.repo / "nix" / "gnu-hello-roundtrip-driver.py"
        )
        self.gnu_hello_diagnostic_driver = (
            self.repo / "nix" / "gnu-hello-roundtrip-diagnostic.py"
        )

    def test_direct_call_summary_resources_limit_recursive_lean_nodes(
        self,
    ) -> None:
        specification = importlib.util.spec_from_file_location(
            "gnu_hello_roundtrip_driver_resources",
            self.gnu_hello_driver,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        driver = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(driver)
        classify = driver._internal_direct_call_summary_module_resource
        child_import = (
            "\nimport StageA."
            "GeneratedRelationalInternalDirectCallSummaryNode0123456789abcdef"
        )

        self.assertEqual(classify("namespace StageA\nend StageA\n"), {
            "resource_class": "light",
            "estimated_memory_mb": 768,
        })
        self.assertEqual(classify(child_import), {
            "resource_class": "medium",
            "estimated_memory_mb": 4096,
        })
        self.assertEqual(classify(child_import * 4), {
            "resource_class": "large-memory",
            "estimated_memory_mb": 24576,
        })
        self.assertEqual(classify(child_import * 8), {
            "resource_class": "large-memory",
            "estimated_memory_mb": 24576,
        })
        self.assertEqual(classify("x" * (90 * 1024)), {
            "resource_class": "high-memory",
            "estimated_memory_mb": 76800,
        })

    def test_gnu_hello_lane_is_phase_separated_static_and_manifest_driven(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        driver = self.gnu_hello_driver.read_text(encoding="utf-8")
        diagnostic_driver = self.gnu_hello_diagnostic_driver.read_text(
            encoding="utf-8"
        )

        for phase in (
            "staticExport",
            "interpreter",
            "nativeEngine",
            "nativeRuntime",
            "candidate",
            "engineSegments",
            "nativeLaunchGraphLean",
            "nativeLaunchGraphProofSources",
            "nativeLaunchGraphProof",
            "staticMachineImportContractsLean",
            "mixedOriginalWritableSlotAuthorityLean",
            "mixedOriginalLean",
            "normalizationLean",
            "x87Lean",
            "x87ScheduleBenchmark",
            "definednessLean",
            "kernelLean",
            "kernelDataLean",
            "kernelAbiLean",
            "x87CandidateReplayLean",
            "kernelBlockLean",
            "kernelLoopLean",
            "kernelCallbackLean",
            "kernelLookupNativeLean",
            "kernelStepNativeLean",
            "kernelStepOperationLean",
            "kernelOperationFrameParametricLean",
            "kernelFrameExecutorLean",
            "kernelRunOperationLean",
            "kernelRunOperationProof",
            "kernelInvokeOperationLean",
            "constructiveSourceCoverageLean",
            "constructiveSourceCoverageProofSources",
            "constructiveSourceCoverageProof",
            "canonicalRelationCoreLean",
            "canonicalRelationCoreProofSources",
            "canonicalRelationCoreProof",
            "proofSources",
            "x87CandidateReplayFragments",
            "x87CandidateReplayProofSources",
            "acceptanceLean",
            "finalProofSources",
        ):
            self.assertRegex(lane, rf"(?m)^  {phase} =")
        self.assertIn('builtins.readFile "${proofSources}/standalone-modules.json"', lane)
        self.assertIn('builtins.readFile "${proofSources}/proof-targets.json"', lane)
        self.assertIn("standaloneModuleResources = proofResources", lane)
        self.assertIn(
            'module.startswith("GeneratedInterpreterX87Schedule")', driver
        )
        self.assertIn(
            'module.startswith("GeneratedInterpreterX87CandidateReplay")', driver
        )
        self.assertIn("x87-candidate-replay-sources", driver)
        self.assertIn(
            '{"resource_class": "medium", "estimated_memory_mb": 4096}',
            driver,
        )
        self.assertIn("measureResources = true", lane)
        self.assertIn("GeneratedInterpreterX87Schedule0034", lane)
        self.assertIn("targetNodes = proofTargets", lane)
        self.assertRegex(
            lane,
            r"(?s)mixedOriginalRegisterIndirectAuthorityProof = mkLeanGraph \{"
            r".*?targetNodes = \[\s*"
            r'"GeneratedRegisterIndirectControlAuthorities"\s*'
            r'"GeneratedRelationalInterpreterMixedOriginalBase"\s*'
            r"\];",
        )
        self.assertIn("preferLocalBuild = false", lane)
        self.assertIn("allowSubstitutes = true", lane)
        self.assertIn("contentAddressed = false", lane)
        self.assertIn('"executes_original_binary": False', driver)
        self.assertIn('"executes_candidate_binary": False', driver)
        self.assertIn("externalize_artifacts=True", driver)
        self.assertIn("kernel-lookup-native", lane)
        self.assertIn("kernel-step-native", lane)
        self.assertIn("kernel-abi", lane)
        self.assertIn(
            "kernelLean = mkPhaseWithSource kernelDataPythonSource", lane
        )
        self.assertIn("${compiledKernelDriver}", lane)
        self.assertIn("static-machine-import-contracts", lane)
        self.assertIn("mixed-original", lane)
        self.assertRegex(
            lane,
            r"--lean-source-root\s+\\?\s*\$\{(?:leanSourceRoot|kernelDataLeanSource)\}",
        )
        flake = self.flake_nix.read_text(encoding="utf-8")
        for output in (
            "stage-a-gnu-hello-roundtrip-static-machine-import-source",
            "stage-a-gnu-hello-roundtrip-compiled-kernel-source",
            "stage-a-gnu-hello-roundtrip-mixed-original-source",
            (
                "stage-a-gnu-hello-roundtrip-"
                "mixed-original-writable-slot-authority-lean"
            ),
            "stage-a-gnu-hello-roundtrip-kernel-data-source",
            "stage-a-gnu-hello-roundtrip-kernel-abi-source",
            (
                "stage-a-gnu-hello-roundtrip-"
                "constructive-source-coverage-source"
            ),
            (
                "stage-a-gnu-hello-roundtrip-"
                "constructive-source-coverage-proof"
            ),
            (
                "stage-a-gnu-hello-roundtrip-"
                "canonical-relation-core-source"
            ),
            (
                "stage-a-gnu-hello-roundtrip-"
                "canonical-relation-core-proof"
            ),
            "stage-a-gnu-hello-roundtrip-native-launch-graph-source",
            "stage-a-gnu-hello-roundtrip-native-launch-graph-proof",
            "stage-a-gnu-hello-roundtrip-kernel-run-operation-source",
            "stage-a-gnu-hello-roundtrip-kernel-run-operation-proof",
            "stage-a-gnu-hello-roundtrip-kernel-invoke-operation-source",
            (
                "stage-a-gnu-hello-roundtrip-"
                "kernel-operation-frame-parametric-source"
            ),
            "stage-a-gnu-hello-roundtrip-kernel-frame-executor-source",
        ):
            self.assertIn(output, flake)
        self.assertNotRegex(
            (lane + "\n" + driver).lower(),
            r"(?m)^\s*(wine|wineserver|qemu)(\s|$)",
        )

    def test_gnu_hello_kernel_abi_is_a_narrow_deterministic_phase(self) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        driver = self.gnu_hello_driver.read_text(encoding="utf-8")
        phase_start = lane.index(
            'kernelAbiLean = mkPhase "stage-a-gnu-hello-roundtrip-kernel-abi-lean"'
        )
        phase_end = lane.index("x87CandidateReplayLean =", phase_start)
        phase = lane[phase_start:phase_end]

        self.assertIn("write_relational_interpreter_kernel_abi_bundle", driver)
        self.assertIn('sub.add_parser("kernel-abi")', driver)
        self.assertIn("proposal_sha256=abi_plan_payload_sha256(plan)", driver)
        self.assertIn("--kernel-plan ${kernelLean}/interpreter-kernel-plan.json", phase)
        self.assertIn(
            "--kernel-data-inventory ${kernelDataLean}/module-inventory.json",
            phase,
        )
        self.assertIn("--engine-layout ${candidate}/engine-layout.bin", phase)
        self.assertIn("GeneratedRelationalInterpreterKernelABI.lean", phase)
        self.assertIn("interpreter-kernel-abi-plan.json", phase)
        for forbidden in (
            "${originalPe}",
            "${originalMap}",
            "${staticExport}",
            "${sourceRoot}",
            "candidate.exe",
            "payload.map",
        ):
            self.assertNotIn(forbidden, phase)
        self.assertIn("--source ${kernelAbiLean}", lane)
        self.assertIn("roundTripPythonSource", lane)
        self.assertIn("lib.fileset.difference", lane)
        self.assertNotIn("export PYTHONPATH=${sourceRoot}/src", lane)

    def test_gnu_hello_rooted_import_and_mixed_original_phases_are_narrow(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        driver = self.gnu_hello_driver.read_text(encoding="utf-8")
        diagnostic_driver = self.gnu_hello_diagnostic_driver.read_text(
            encoding="utf-8"
        )
        static_start = lane.index(
            'staticMachineImportContractsLean = mkPhase'
        )
        static_end = lane.index(
            'universalPairedExternalEnvironmentLean = mkPhase', static_start
        )
        diagnostic_start = lane.index(
            'mixedOriginalDiagnostic = mkPhase',
            lane.index('staticMachineImportProofSources = mkPhase', static_end),
        )
        mixed_start = lane.index('mixedOriginalLean = mkPhase', diagnostic_start)
        program_start = lane.index('programLean = mkPhase', mixed_start)
        static_phase = lane[static_start:static_end]
        diagnostic_phase = lane[diagnostic_start:mixed_start]
        mixed_phase = lane[mixed_start:program_start]

        self.assertIn("machineRuntimeProfileSource = lib.fileset.toSource", lane)
        for profile in (
            "pe32-msvcrt-machine-runtime-v1.json",
            "pe32-kernel32-lockstep-v1.json",
            "pe32-msvcrt-lockstep-v1.json",
        ):
            self.assertIn(f"../profiles/{profile}", lane)
        for required in (
            "--original ${originalPe}",
            "--reference-contract ${staticExport}/reference-contract.json",
            "--state-machine ${staticExport}/state-machine.jsonl",
            "--load-image-contract ${staticExport}/load-image-contract.json",
            "--profile ${machineRuntimeProfile}",
            "GeneratedStaticMachineImportContracts.lean",
        ):
            self.assertIn(required, static_phase)
        for forbidden in (
            "${candidate}",
            "${kernelLean}",
            "${kernelDataLean}",
            "${originalPeLean}",
            "${proofSources}",
            "candidate.exe",
            "engine-layout.bin",
        ):
            self.assertNotIn(forbidden, static_phase)

        self.assertIn(
            "${staticMachineImportContractsLean}/"
            "machine-import-contract-report.json",
            mixed_phase,
        )
        self.assertIn(
            "GeneratedRelationalInterpreterMixedOriginal.lean", mixed_phase
        )
        for forbidden in (
            "${candidate}",
            "${kernelLean}",
            "${kernelDataLean}",
            "${proofSources}",
            "candidate.exe",
            "engine-layout.bin",
        ):
            self.assertNotIn(forbidden, mixed_phase)

        self.assertIn(
            'sub.add_parser("static-machine-import-contracts")', driver
        )
        self.assertIn('sub.add_parser("mixed-original")', driver)
        self.assertIn("plan_interpreter_mixed_original", diagnostic_driver)
        self.assertIn("mixedOriginalDiagnostic = mkPhase", lane)
        self.assertIn(
            '"authorizing_term": None', diagnostic_driver
        )
        self.assertIn(".status == \"ready\" or .status == \"incomplete\"", diagnostic_phase)
        self.assertIn(".authorizing_term == null", diagnostic_phase)
        self.assertNotIn("GeneratedRelationalInterpreterMixedOriginal.lean", diagnostic_phase)
        self.assertIn(
            '"generatedMachineImportBoundaryContracts"', driver
        )
        self.assertIn('"generatedMachineImportBoundaries"', driver)
        self.assertIn(
            '"generatedMachineImportBoundaryCallContracts"', driver
        )
        self.assertIn("QualifiedLeanSymbol(", driver)
        self.assertIn(
            "--source ${staticMachineImportContractsLean}", lane
        )
        self.assertIn("--source ${mixedOriginalLean}", lane)
        self.assertNotIn("acceptance_theorem=", static_phase + mixed_phase)

    def test_gnu_hello_final_graph_requires_acceptance_symbolic_and_blocks(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        driver = self.gnu_hello_driver.read_text(encoding="utf-8")
        flake = self.flake_nix.read_text(encoding="utf-8")

        self.assertIn('"RelationalSymbolicSoundness"', flake)
        self.assertIn("stage-a-roundtrip-lean-symbolic-soundness", flake)
        self.assertIn("--target RelationalSymbolicSoundness", lane)
        self.assertIn("acceptance-sources", lane)
        self.assertIn("finalProofSources", lane)
        self.assertIn("targetNodes = finalProofTargets", lane)
        self.assertIn("final = mkLeanGraph", lane)
        self.assertIn("StageA.RelationalSymbolicSoundness", driver)
        self.assertIn("InterpreterMixedKernelBindingSpec", driver)
        self.assertIn("write_relational_interpreter_mixed_kernel_binding", driver)
        self.assertIn("kernel_block_manifest", driver)
        self.assertIn("GnuHelloRoundTripRequiredTerms", driver)
        self.assertIn("MixedKernelBindingRequirements", driver)
        self.assertIn("originalContextExact", driver)
        self.assertIn("candidateAuthorityExact", driver)
        self.assertIn("generatedMixedWorldProgramsEquivalent", driver)
        self.assertIn("gnu_hello_round_trip_required_terms_uninhabited", driver)
        self.assertIn("acceptance_theorem=None", driver)
        self.assertIn("#print axioms {theorem}", driver)
        self.assertNotIn("opaque GnuHelloRoundTripRequiredTerms", driver)
        self.assertNotIn("axiom GnuHelloRoundTripRequiredTerms", driver)
        self.assertNotIn("InterpreterWorldBridgeSpec", driver)

    def test_gnu_hello_x87_schedule_modules_use_pack_sized_resources(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            (source / "GeneratedInterpreterX87Schedule0000.lean").write_text(
                "namespace StageA\nend StageA\n", encoding="ascii"
            )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_driver),
                    "aggregate",
                    "--source",
                    str(source.parent),
                    "--out",
                    str(output),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            resources = json.loads(
                (output / "module-resources.json").read_text(encoding="utf-8")
            )

        self.assertEqual(
            resources["GeneratedInterpreterX87Schedule0000"],
            {"resource_class": "medium", "estimated_memory_mb": 4096},
        )

    def test_gnu_hello_aggregate_preserves_declared_high_memory_resources(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            stage_a = source / "StageA"
            stage_a.mkdir(parents=True)
            module = "GeneratedInterpreterKernelDataShard0000"
            (stage_a / f"{module}.lean").write_text(
                "namespace StageA\nend StageA\n", encoding="ascii"
            )
            (source / "module-resources.json").write_text(
                json.dumps({module: {
                    "resource_class": "high-memory",
                    "estimated_memory_mb": 49152,
                }}),
                encoding="utf-8",
            )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_driver),
                    "aggregate",
                    "--source",
                    str(source),
                    "--out",
                    str(output),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            resources = json.loads(
                (output / "module-resources.json").read_text(encoding="utf-8")
            )

        self.assertEqual(resources[module], {
            "resource_class": "high-memory",
            "estimated_memory_mb": 49152,
        })

    def test_gnu_hello_mixed_original_aggregates_use_measured_resources(
        self,
    ) -> None:
        expected = {
            "GeneratedRelationalInterpreterMixedOriginalBase": 76800,
            "GeneratedRelationalInterpreterMixedOriginal": 76800,
            "GeneratedRelationalInterpreterOriginalCarrierBinding": 16384,
        }
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            for module in expected:
                (source / f"{module}.lean").write_text(
                    "namespace StageA\nend StageA\n", encoding="ascii"
                )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_driver),
                    "aggregate",
                    "--source",
                    str(source.parent),
                    "--out",
                    str(output),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            resources = json.loads(
                (output / "module-resources.json").read_text(encoding="utf-8")
            )

        for module, memory_mb in expected.items():
            self.assertEqual(resources[module], {
                "resource_class": "high-memory",
                "estimated_memory_mb": memory_mb,
            })

    def test_gnu_hello_acceptance_driver_emits_typed_uninhabited_frontier(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            block_manifest = root / "block-manifest.json"
            block_manifest.write_text(
                json.dumps({"targets": []}),
                encoding="utf-8",
            )
            mixed_original_manifest = root / "mixed-original-manifest.json"
            mixed_original_manifest.write_text(
                json.dumps(
                    {
                        "phase": "mixed-original-final-lean",
                        "proof_authority": False,
                        "remaining_frontiers": [{"reason_code": "test_frontier"}],
                        "authorizing_lean_terms": [],
                        "counts": {"blockers": 1},
                    }
                ),
                encoding="utf-8",
            )
            native_launch_request = root / "native-launch-request.json"
            native_launch_request.write_text(
                json.dumps(
                    {
                        "format": "stage-a-native-launch-route-request-v1",
                        "status": "incomplete",
                        "acceptance_authority": False,
                        "candidate_sha256": "00" * 32,
                        "canonical_sources": [],
                        "required_path_shapes": [],
                        "forbidden_authority": [],
                    }
                ),
                encoding="utf-8",
            )
            original_carrier_manifest = root / "original-carrier-manifest.json"
            original_carrier_manifest.write_text(
                json.dumps(
                    {
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
                    }
                ),
                encoding="utf-8",
            )
            x87_kernel_execution_manifest = (
                root / "x87-kernel-execution-manifest.json"
            )
            x87_kernel_execution_manifest.write_text(
                json.dumps(
                    {
                        "phase": "x87-kernel-execution-lean",
                        "status": "source-ready",
                        "diagnostic_status": "semantic_premises_required",
                        "proof_authority": False,
                        "failure_mode": "incomplete",
                        "candidate_sha256": "11" * 32,
                        "runtime_targets": 1,
                        "theorem": (
                            "StageA.GeneratedRelational."
                            "InterpreterKernelX87Execution."
                            "generatedX87ReplayBridgeKernelExecution"
                        ),
                        "remaining_authority": {
                            "lean_type": (
                                "ExactNativeX87ReplayKernelEndpointAuthority "
                                "inventory program handler sourceInvariant"
                            )
                        },
                        "remaining_proof_premises": [
                            "program_binding.peExact",
                            "program_binding.importsExact",
                            "program_binding.targetInventory",
                            "endpoint_certificate.handlerResult",
                            "endpoint_certificate.callTarget",
                            "endpoint_certificate.callRun",
                            "endpoint_certificate.entryRun",
                            "endpoint_certificate.instructionRun",
                            "endpoint_certificate.captureRun",
                            "endpoint_certificate.returnRun",
                            "endpoint_certificate.frameEffect",
                        ],
                        "targets": [
                            "GeneratedRelationalInterpreterKernelX87Execution"
                        ],
                    }
                ),
                encoding="utf-8",
            )
            output = root / "acceptance"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_driver),
                    "acceptance-sources",
                    "--kernel-block-manifest",
                    str(block_manifest),
                    "--mixed-original-manifest",
                    str(mixed_original_manifest),
                    "--original-carrier-manifest",
                    str(original_carrier_manifest),
                    "--native-launch-request",
                    str(native_launch_request),
                    "--x87-kernel-execution-manifest",
                    str(x87_kernel_execution_manifest),
                    "--out",
                    str(output),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            manifest = json.loads(
                (output / "phase-manifest.json").read_text(encoding="utf-8")
            )
            inventory = json.loads(
                (output / "acceptance-obligations.json").read_text(
                    encoding="utf-8"
                )
            )
            requirements = (
                output / "StageA/GeneratedGnuHelloRoundTripRequirements.lean"
            ).read_text(encoding="utf-8")
            acceptance = (
                output
                / "StageA/GeneratedRelationalInterpreterMixedKernelBinding.lean"
            ).read_text(encoding="utf-8")

        self.assertIsNone(manifest["acceptance_theorem"])
        self.assertEqual(
            manifest["acceptance_blocker"]["id"],
            "gnu_hello_round_trip_required_terms_uninhabited",
        )
        self.assertFalse(inventory["closed_acceptance"])
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterMixedOriginal",
            requirements,
        )
        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterMixedAuthority",
            requirements,
        )
        self.assertIn(
            "import StageA.GeneratedCallableExternalProgram",
            requirements,
        )
        self.assertIn("originalCallableEnvironment", requirements)
        self.assertIn("decodedWorldProgramWithCallable", requirements)
        self.assertIn("originalCallableBinding", requirements)
        self.assertEqual(
            inventory["required_parameter"]["lean_type"],
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
            "candidateNativeLaunchCertificate : ExactNativeLaunchGraphCertificate",
            requirements,
        )
        self.assertNotIn("ExactNativeLaunchWrapperCertificate", requirements)
        for required_surface in (
            "original_context : OriginalDecodedStaticContext",
            "candidate_program : ExactNativeWorldProgram",
            "candidate_root : DirectExactCandidateNativeLaunchRoot",
            "external_boundary_chunk :",
        ):
            self.assertIn(required_surface, requirements)
        self.assertIn(
            "(requirements : StageA.GeneratedGnuHelloRoundTripRequirements."
            "GnuHelloRoundTripRequiredTerms)",
            acceptance,
        )
        self.assertIn("canonicalMixedWorldProgramsEquivalent", acceptance)

    def test_gnu_hello_carrier_binding_is_a_separate_checked_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mixed_original = root / "mixed-original"
            stage_a = mixed_original / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "GeneratedRelationalInterpreterMixedOriginal.lean").write_text(
                "namespace StageA\nend StageA\n", encoding="ascii"
            )
            (mixed_original / "phase-manifest.json").write_text(
                json.dumps(
                    {
                        "phase": "mixed-original-final-lean",
                        "proof_authority": False,
                        "counts": {"regions": 521, "addresses": 524},
                    }
                ),
                encoding="utf-8",
            )
            output = root / "carrier"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_driver),
                    "mixed-original-carrier-binding",
                    "--mixed-original",
                    str(mixed_original),
                    "--out",
                    str(output),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)
            manifest = json.loads(
                (output / "phase-manifest.json").read_text(encoding="utf-8")
            )
            source = (
                output
                / "StageA/GeneratedRelationalInterpreterOriginalCarrierBinding.lean"
            ).read_text(encoding="utf-8")

        self.assertEqual(manifest["counts"], {"targets": 521, "addresses": 524})
        self.assertIn("generatedOriginalCarrierBindingChecked", source)
        self.assertIn("generatedOriginalExactMixedProgramBinding", source)
        self.assertNotIn("native_decide", source)

    def test_gnu_hello_smoke_is_lazy_and_does_not_reference_heavy_phases(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        smoke_start = lane.index(
            'smoke = mkPhase "stage-a-gnu-hello-roundtrip-smoke"'
        )
        smoke_end = lane.index(
            'staticExport = mkPhase "stage-a-gnu-hello-roundtrip-static-export"'
        )
        smoke = lane[smoke_start:smoke_end]

        self.assertIn("gnu-hello-roundtrip-driver.py", lane)
        self.assertIn(" smoke \\", smoke)
        for forbidden in (
            "staticExport",
            "interpreter",
            "${candidate}",
            "proofSources",
            "mkLeanGraph",
            "lean ",
        ):
            self.assertNotIn(forbidden, smoke)

    def test_static_smoke_has_no_runtime_executor_and_precedes_proofs(self) -> None:
        smoke = self.smoke_nix.read_text(encoding="utf-8")
        corpus = self.corpus_nix.read_text(encoding="utf-8")
        flake = self.flake_nix.read_text(encoding="utf-8")

        self.assertIn("stage-a-fuzz-run", smoke)
        self.assertIn("stage-a-fuzz-generate", corpus)
        self.assertIn("--stop-after-static-preflight", smoke)
        self.assertIn("expected-case-ids.json", smoke)
        self.assertIn("stage-a-relational-static-preflight-v1", smoke)
        self.assertIn('find "$out/corpus" -type f -exec chmod a-x', smoke)
        self.assertNotIn("prepared-proof.json", smoke)
        self.assertNotIn('mkdir -p "$out/prepared', smoke)
        self.assertNotRegex(smoke.lower(), r"(?m)^\s*(wine|wineserver|qemu)(\s|$)")
        self.assertIn(
            '"${smoke}/smoke/cases/${member.reference.id}/static-preflight.json"',
            corpus,
        )
        self.assertIn('"reran_proofs": False', corpus)
        self.assertIn('"executes_original_binary": False', corpus)
        self.assertNotIn("stage-a-build-relational", corpus)
        self.assertNotIn("nix build", corpus)
        self.assertIn("casePreparations", corpus)
        self.assertIn("preparationGraphBundle", corpus)
        self.assertIn("caseProofDags", corpus)
        self.assertIn("caseAudits", corpus)
        self.assertIn("caseResultBundle", corpus)
        self.assertIn("packResultBundle", corpus)
        self.assertIn("builtins.readFile args.preparationGraph", flake)
        self.assertNotIn(
            'builtins.readFile (args.preparation + "/module-graph.json")',
            flake,
        )
        self.assertIn('builtins.toFile "${caseId}-case-result.json"', corpus)
        self.assertIn(
            'builtins.toFile "${name}-${pack.id}-result.json"', corpus
        )
        self.assertGreaterEqual(
            corpus.count("builtins.unsafeDiscardStringContext"), 2
        )

    def test_flake_exports_stable_roundtrip_interfaces(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")

        self.assertIn("mkStageARoundtripCorpus", flake)
        self.assertIn("mkStageARoundtripSmoke", flake)
        self.assertIn("stage-a-roundtrip-static-smoke", flake)
        self.assertIn("stage-a-roundtrip-proof-smoke", flake)
        self.assertIn("stage-a-roundtrip-spike-corpus", flake)
        self.assertIn("stage-a-roundtrip-spike-pack-plan", flake)
        self.assertIn("stage-a-roundtrip-spike-check", flake)
        self.assertIn("stage-a-roundtrip-spike-corpus-root", flake)
        self.assertIn("stage-a-roundtrip-promoted-corpus", flake)
        self.assertIn("stage-a-roundtrip-promoted-pack-plan", flake)
        self.assertIn("stage-a-roundtrip-promoted-check", flake)
        self.assertIn("count = 75", flake)
        self.assertIn("pass = 50", flake)
        self.assertIn("violated = 25", flake)
        self.assertNotIn("root@acacia", flake)
        self.assertNotIn("root@banksia", flake)
        checks = flake[flake.index("checks = forAllSystems") :]
        self.assertIn("stage-a-roundtrip-spike-check", checks)
        self.assertIn("stage-a-roundtrip-promoted-check", checks)

    def test_roundtrip_remote_path_is_input_addressed_and_portable(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        builders = self.builders_file.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(builders), 4)
        self.assertTrue(any("acacia.tail738663.ts.net" in line for line in builders))
        self.assertTrue(any("banksia.tail738663.ts.net" in line for line in builders))
        self.assertTrue(all("big-parallel" in line for line in builders))
        memory_lanes = [
            line.split()
            for line in builders
            if "large-memory" in line.split()[5].split(",")
            and "benchmark" in line.split()[5].split(",")
        ]
        self.assertEqual(len(memory_lanes), 2)
        self.assertTrue(all(fields[3] == "1" for fields in memory_lanes))
        self.assertTrue(all(fields[6] == "-" for fields in memory_lanes))
        self.assertTrue(all("ca-derivations" not in line for line in builders))
        self.assertIn("stage-a-roundtrip-lean-remote-smoke", flake)
        self.assertIn(
            "export SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED=false",
            flake,
        )
        self.assertIn('--builders "@${./nix/stage-a-builders}"', flake)
        self.assertNotIn("--builders @nix/stage-a-builders", flake)
        self.assertNotIn("stage-a-roundtrip-lean-kernel-cache-ca", flake)

    def test_flake_wires_real_non_recursive_proof_callbacks(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        start = flake.index("mkRoundtripCasePreparation =")
        end = flake.index("mkStageARoundtripQualification =", start)
        callbacks = flake[start:end]

        self.assertIn("stage-a-prepare-relational", callbacks)
        self.assertIn("import ./nix/stage-a-lean-compact.nix", callbacks)
        self.assertIn(
            "precompiledKernel = stage-a-relational-kernel-cache;", callbacks
        )
        self.assertIn('targetNode = negativeNode;', callbacks)
        self.assertIn('"relationalcounterexample"', callbacks)
        self.assertIn('"whole_program_lean"', callbacks)
        self.assertIn('__contentAddressed = true;', callbacks)
        self.assertNotIn("stage-a-fuzz-run", callbacks)
        self.assertNotIn("stage-a-build-relational", callbacks)
        self.assertNotIn("nix build", callbacks)
        self.assertNotIn("nix-store", callbacks)

        qualification_start = flake.index("mkStageARoundtripQualification =")
        qualification_end = flake.index(
            "stageARoundtripProofSmokeQualification =", qualification_start
        )
        qualification = flake[qualification_start:qualification_end]
        self.assertIn(
            "mkCasePreparation = mkRoundtripCasePreparation;", qualification
        )
        self.assertIn("mkCaseProofDag = mkRoundtripCaseProofDag;", qualification)
        self.assertIn("mkCaseAudit = mkRoundtripCaseAudit;", qualification)
        self.assertIn("caseMeasurementDefaults = {", qualification)
        self.assertIn('resourceClass = "whole-program-proof";', qualification)
        self.assertIn('resourceClass = "checked-witness";', qualification)
        self.assertIn(
            'measurementSource = "compact-spike-calibration-2026-07-22";',
            qualification,
        )

    def test_lean_graph_retains_focused_logs_and_axiom_metadata(self) -> None:
        graph = (self.repo / "nix" / "stage-a-lean-graph.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn('mkdir -p "$out/StageA" "$out/logs"', graph)
        self.assertIn('compile_stdout": f"logs/{module}.stdout"', graph)
        self.assertIn('compile_stderr": f"logs/{module}.stderr"', graph)
        self.assertIn('"maximum_resident_kib"', graph)
        self.assertIn('"resource_usage": resource_usage', graph)
        self.assertIn("measureResources ? false", graph)
        self.assertIn('"axiom_audit": {', graph)
        self.assertIn('"complete": all(value is not None', graph)
        self.assertIn('cp -L "${source}"/logs/* "$out/logs/"', graph)
        self.assertIn('contentAddressed ? true', graph)
        self.assertIn(
            'lib.optionalAttrs contentAddressed { __contentAddressed = true; }',
            graph,
        )
        self.assertIn('2> >(tee "$out/logs/${module}.stderr" >&2)', graph)

    def test_target_bundle_can_fail_closed_on_unapproved_axioms(self) -> None:
        graph = (self.repo / "nix" / "stage-a-lean-graph.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn("targetAxiomAudit ? null", graph)
        self.assertIn("target theorem depends on unapproved axioms", graph)
        self.assertIn("target axiom audit declaration was not emitted", graph)
        self.assertIn('"unexpected_axioms": unexpected', graph)

    def test_qualification_accepts_only_supported_whole_program_theorems(self) -> None:
        corpus = self.corpus_nix.read_text(encoding="utf-8")

        self.assertIn("candidatePE32ProgramsEquivalent\"", corpus)
        self.assertIn("candidatePE32ProgramsEquivalentLinked\"", corpus)
        self.assertNotIn(
            'acceptance.get("theorem")\n                    ==',
            corpus,
        )
        self.assertIn('"supported_acceptance_theorems"', corpus)

    @unittest.skipUnless(shutil.which("nix-instantiate"), "Nix is unavailable")
    def test_importable_nix_functions_parse(self) -> None:
        compact_nix = self.repo / "nix" / "stage-a-lean-compact.nix"
        for path in (
            self.smoke_nix,
            self.corpus_nix,
            compact_nix,
            self.gnu_hello_nix,
        ):
            process = subprocess.run(
                ["nix-instantiate", "--parse", str(path)],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr)

    @unittest.skipUnless(shutil.which("nix"), "Nix is unavailable")
    def test_pack_plan_is_deterministic_and_measurement_aware(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = self._write_corpus(root / "corpus")
            expression = root / "plan.nix"
            expression.write_text(
                self._expression(corpus=corpus, result="qualification.packPlanPayload"),
                encoding="utf-8",
            )
            process = subprocess.run(
                ["nix", "eval", "--impure", "--json", "--file", str(expression)],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-4000:])
            plan = json.loads(process.stdout)

        self.assertEqual(plan["format"], "stage-a-roundtrip-nix-pack-plan-v1")
        self.assertEqual(len(plan["packs"]), 3)
        self.assertEqual(
            [pack["cases"][0]["id"] for pack in plan["packs"]],
            ["case-a", "case-b", "case-c"],
        )
        self.assertTrue(all(pack["estimatedSeconds"] == 6 for pack in plan["packs"]))
        self.assertEqual(
            [pack["resourceClass"] for pack in plan["packs"]],
            ["standard", "standard", "high-memory"],
        )

    @unittest.skipUnless(shutil.which("nix"), "Nix is unavailable")
    def test_promoted_plan_represents_fifty_pass_and_twenty_five_violated(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = self._write_promoted_corpus(root / "corpus")
            expression = root / "promoted-plan.nix"
            expression.write_text(
                self._expression(
                    corpus=corpus,
                    result="qualification.packPlanPayload",
                    with_measurements=False,
                ),
                encoding="utf-8",
            )
            process = subprocess.run(
                ["nix", "eval", "--impure", "--json", "--file", str(expression)],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-4000:])
            plan = json.loads(process.stdout)

        cases = [case for pack in plan["packs"] for case in pack["cases"]]
        self.assertEqual(len(cases), 75)
        self.assertEqual(sum(case["expected"] == "pass" for case in cases), 50)
        self.assertEqual(sum(case["expected"] == "violated" for case in cases), 25)
        self.assertTrue(all(len(pack["cases"]) <= 4 for pack in plan["packs"]))

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for the Nix build fixture",
    )
    def test_smoke_packs_and_aggregate_build_without_rerunning_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            corpus = self._write_corpus(root / "corpus")
            expression = root / "build.nix"
            expression.write_text(
                self._expression(
                    corpus=corpus,
                    result="qualification.check",
                    with_fake_proofs=True,
                ),
                encoding="utf-8",
            )
            process = subprocess.run(
                [
                    "nix",
                    "build",
                    "--impure",
                    "--no-link",
                    "--json",
                    "--file",
                    str(expression),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(process.returncode, 0, process.stderr[-8000:])
            output = Path(json.loads(process.stdout)[0]["outputs"]["out"])
            report = json.loads(
                (output / "run-result.json").read_text(encoding="utf-8")
            )
            plan = json.loads((output / "pack-plan.json").read_text(encoding="utf-8"))

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["counts"]["cases"], 3)
        self.assertEqual(report["counts"]["pass"], 2)
        self.assertEqual(report["counts"]["violated"], 1)
        self.assertTrue(report["counts"]["declared_expectations_match_manifest"])
        self.assertFalse(report["reran_proofs"])
        self.assertFalse(report["executes_original_binary"])
        self.assertEqual(len(report["packs"]), 3)
        self.assertTrue(all(
            pack["store_path"].startswith("/nix/store/")
            and pack["derivation_path"].endswith(".drv")
            for pack in report["packs"]
        ), report["packs"])
        self.assertTrue(all(
            case["preparation_store_path"].startswith("/nix/store/")
            and case["preparation_derivation_path"].endswith(".drv")
            and case["proof_dag_store_path"].startswith("/nix/store/")
            and case["proof_dag_derivation_path"].endswith(".drv")
            and case["audit_store_path"].startswith("/nix/store/")
            and case["audit_derivation_path"].endswith(".drv")
            for case in report["cases"]
        ))
        self.assertTrue(all(
            len({
                case["preparation_derivation_path"],
                case["proof_dag_derivation_path"],
                case["audit_derivation_path"],
            }) == 3
            for case in report["cases"]
        ))
        self.assertEqual(len(plan["packs"]), 3)

    @unittest.skipUnless(
        shutil.which("nix")
        and os.environ.get("SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION") == "1",
        "set SPAGHETTI_EXTRACTOR_RUN_NIX_INTEGRATION=1 for the real PE smoke",
    )
    def test_real_flake_smoke_generates_and_preflights_pe32_without_proof(self) -> None:
        process = subprocess.run(
            [
                "nix",
                "build",
                "--no-link",
                "--json",
                ".#stage-a-roundtrip-static-smoke",
            ],
            cwd=self.repo,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr[-8000:])
        output = Path(json.loads(process.stdout)[0]["outputs"]["out"])
        report = json.loads(
            (output / "smoke" / "run-result.json").read_text(encoding="utf-8")
        )
        manifest = json.loads(
            (output / "corpus" / "corpus.json").read_text(encoding="utf-8")
        )

        self.assertEqual(report["status"], "pass")
        self.assertEqual(report["stopped_after"], "static-preflight")
        self.assertEqual(len(report["cases"]), 4)
        self.assertEqual(len(manifest["cases"]), 4)
        for reference in manifest["cases"]:
            case = json.loads(
                (output / "corpus" / reference["path"]).read_text(encoding="utf-8")
            )
            for role in ("original_pe", "candidate_pe"):
                artifact = next(item for item in case["artifacts"] if item["role"] == role)
                binary = output / "corpus" / Path(reference["path"]).parent / artifact["path"]
                self.assertEqual(binary.read_bytes()[:2], b"MZ")
            phases = next(
                item["phases"] for item in report["cases"]
                if item["case_id"] == reference["id"]
            )
            self.assertFalse(any(
                phase["id"] in {"proof-preparation", "proof-build-and-audit"}
                for phase in phases
            ))

    def _write_corpus(self, root: Path) -> Path:
        root.mkdir(parents=True)
        specifications = (
            ("case-a", "pass", 0),
            ("case-b", "violated", 0),
            ("case-c", "pass", 1),
        )
        references = []
        for case_id, disposition, shard in specifications:
            case_root = root / "cases" / case_id
            case_root.mkdir(parents=True)
            case = {
                "format": "stage-a-roundtrip-case-v1",
                "id": case_id,
                "expectation": {"disposition": disposition},
                "shard": shard,
            }
            case_path = case_root / "case.json"
            encoded = json.dumps(case, indent=2, sort_keys=True) + "\n"
            case_path.write_text(encoded, encoding="utf-8")
            references.append({
                "id": case_id,
                "path": f"cases/{case_id}/case.json",
                "sha256": sha256(encoded.encode()).hexdigest(),
                "shard": shard,
            })
        manifest = {
            "format": "stage-a-roundtrip-corpus-v1",
            "generator_version": "nix-test-v1",
            "root_seed": 7,
            "capability_profile": "nix-test-profile",
            "toolchain": {
                "id": "nix-test",
                "target": "i686-windows",
                "compiler": "test",
                "compiler_version": "1",
                "linker": "test",
                "linker_version": "1",
            },
            "cases": references,
            "expected_counts": {"pass": 2, "violated": 1, "incomplete": 0},
            "shard_count": 2,
        }
        (root / "corpus.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return root

    def _write_promoted_corpus(self, root: Path) -> Path:
        root.mkdir(parents=True)
        references = []
        for index in range(75):
            case_id = f"promoted-{index:03d}"
            disposition = "violated" if index >= 50 else "pass"
            case_root = root / "cases" / case_id
            case_root.mkdir(parents=True)
            case = {
                "format": "stage-a-roundtrip-case-v1",
                "id": case_id,
                "expectation": {"disposition": disposition},
                "shard": index % 8,
            }
            case_path = case_root / "case.json"
            encoded = json.dumps(case, indent=2, sort_keys=True) + "\n"
            case_path.write_text(encoded, encoding="utf-8")
            references.append({
                "id": case_id,
                "path": f"cases/{case_id}/case.json",
                "sha256": sha256(encoded.encode()).hexdigest(),
                "shard": index % 8,
            })
        manifest = {
            "format": "stage-a-roundtrip-corpus-v1",
            "generator_version": "nix-promoted-test-v1",
            "root_seed": 11,
            "capability_profile": "nix-test-profile",
            "toolchain": {
                "id": "nix-test",
                "target": "i686-windows",
                "compiler": "test",
                "compiler_version": "1",
                "linker": "test",
                "linker_version": "1",
            },
            "cases": references,
            "expected_counts": {"pass": 50, "violated": 25, "incomplete": 0},
            "shard_count": 8,
        }
        (root / "corpus.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return root

    def _expression(
        self,
        *,
        corpus: Path,
        result: str,
        with_fake_proofs: bool = False,
        with_measurements: bool = True,
    ) -> str:
        fake_proofs = ""
        callbacks = ""
        if with_fake_proofs:
            fake_proofs = textwrap.dedent(
                """
                mkCasePreparation = args: pkgs.runCommand
                  ("roundtrip-preparation-" + args.caseId)
                  { }
                  ''
                    test -f ${args.staticPreflight}
                    mkdir -p "$out"
                    printf '%s\\n' ${builtins.toJSON args.caseId} \\
                      > "$out/prepared-proof.json"
                    printf '%s\\n' '{{}}' > "$out/module-graph.json"
                  '';
                mkCaseProofDag = args: pkgs.runCommand
                  ("roundtrip-proof-dag-" + args.caseId)
                  { }
                  ''
                    test -f ${args.preparation}/prepared-proof.json
                    mkdir -p "$out"
                    printf '%s\\n' ${builtins.toJSON args.caseId} \\
                      > "$out/proof-dag.json"
                  '';
                mkCaseAudit = args: pkgs.runCommand
                  ("roundtrip-audit-" + args.caseId)
                  { }
                  ''
                    test -f ${args.preparation}/prepared-proof.json
                    test -f ${args.proofDag}/proof-dag.json
                    mkdir -p "$out"
                    cat > "$out/result.json" <<'JSON'
                    {
                      "format": "stage-a-roundtrip-case-result-v1",
                      "case_id": ${builtins.toJSON args.caseId},
                      "mode": "proof-core",
                      "expected_disposition": ${builtins.toJSON args.case.expectation.disposition},
                      "actual_disposition": ${builtins.toJSON args.case.expectation.disposition},
                      "expectation_matched": true,
                      "phases": ${
                        if args.case.expectation.disposition == "pass"
                        then builtins.toJSON [{
                          id = "proof-build-and-audit";
                          status = "pass";
                        }]
                        else builtins.toJSON [{
                          id = "checked-violation-replay";
                          status = "violated";
                        }]
                      },
                      "acceptance": ${
                        if args.case.expectation.disposition == "pass"
                        then builtins.toJSON {
                          theorem = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalent";
                          authority = "whole_program_lean";
                        }
                        else builtins.toJSON {
                          theorem = null;
                          authority = null;
                        }
                      },
                      "frontiers": [],
                      "violation": ${
                        if args.case.expectation.disposition == "violated"
                        then builtins.toJSON {
                          format = "stage-a-checked-violation-result-v1";
                          status = "violated";
                          checks = { replay_checked = true; };
                          trust = {
                            role = "checked_inequivalence_witness";
                            can_authorize_pass = false;
                            raw_solver_status_sufficient = false;
                          };
                        }
                        else "null"
                      },
                      "error": null
                    }
                    JSON
                  '';
                """
            )
            callbacks = (
                "inherit mkCasePreparation mkCaseProofDag mkCaseAudit;"
            )
        measurements = ""
        if with_measurements:
            measurements = textwrap.dedent(
                """
                caseMeasurements = {
                  case-a = {
                    estimatedSeconds = 6;
                    estimatedMemoryMB = 1024;
                    resourceClass = "standard";
                  };
                  case-b = {
                    estimatedSeconds = 6;
                    estimatedMemoryMB = 2048;
                    resourceClass = "standard";
                  };
                  case-c = {
                    estimatedSeconds = 6;
                    estimatedMemoryMB = 8192;
                    resourceClass = "high-memory";
                  };
                };
                """
            )
        return textwrap.dedent(
            f"""
            let
              # Use the caller's pinned NIX_PATH.  Evaluating this orchestration
              # must not evaluate every output of the repository flake.
              pkgs = import <nixpkgs> {{ system = builtins.currentSystem; }};
              fakeTool = pkgs.writeShellScriptBin "spaghetti-extractor" ''
                set -euo pipefail
                command="$1"
                shift
                test "$command" = stage-a-fuzz-run
                output=""
                while [ "$#" -gt 0 ]; do
                  case "$1" in
                    --out) output="$2"; shift 2 ;;
                    *) shift ;;
                  esac
                done
                mkdir -p "$output"
                for case_id in case-a case-b case-c; do
                  mkdir -p "$output/cases/$case_id"
                  printf '%s\\n' '{{"format":"stage-a-relational-static-preflight-v1","status":"ready","acceptance_authority":false}}' \\
                    > "$output/cases/$case_id/static-preflight.json"
                done
                cat > "$output/run-result.json" <<'JSON'
                {{
                  "format": "stage-a-roundtrip-run-result-v1",
                  "status": "pass",
                  "mode": "proof-core",
                  "counts": {{"cases": 3}},
                  "cases": [
                    {{"case_id":"case-a","actual_disposition":"incomplete","acceptance":{{"authority":null}},"phases":[{{"id":"static-preflight","status":"ready"}}]}},
                    {{"case_id":"case-b","actual_disposition":"incomplete","acceptance":{{"authority":null}},"phases":[{{"id":"static-preflight","status":"ready"}}]}},
                    {{"case_id":"case-c","actual_disposition":"incomplete","acceptance":{{"authority":null}},"phases":[{{"id":"static-preflight","status":"ready"}}]}}
                  ],
                  "trust": {{"runner_has_proof_authority":false,"positive_pass_requires":"whole_program_lean"}},
                  "stopped_after": "static-preflight",
                  "expectations_evaluated": false,
                  "static_preflight_failure_case_ids": []
                }}
                JSON
                cat "$output/run-result.json"
              '';
              {fake_proofs}
              qualification = import {self.corpus_nix} {{
                inherit pkgs;
                spaghettiExtractor = fakeTool;
                corpusRoot = builtins.path {{
                  path = {corpus};
                  name = "stage-a-roundtrip-nix-test-corpus";
                }};
                {measurements}
                packPolicy = {{ maxEstimatedSeconds = 10; maxCases = 4; }};
                {callbacks}
              }};
            in
            {result}
            """
        )


if __name__ == "__main__":
    unittest.main()
