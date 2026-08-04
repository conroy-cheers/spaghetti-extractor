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
        self.gnu_hello_nix = self.repo / "targets" / "gnu-hello" / "default.nix"
        self.gnu_hello_driver = (
            self.repo / "targets" / "gnu-hello" / "nix" / "gnu-hello-roundtrip-driver.py"
        )
        self.gnu_hello_direct_call_semantics_driver = (
            self.repo / "targets" / "gnu-hello" / "nix" / "gnu-hello-direct-call-semantics.py"
        )
        self.gnu_hello_direct_call_fixed_point_driver = (
            self.repo / "targets" / "gnu-hello" / "nix" / "gnu-hello-direct-call-fixed-point.py"
        )
        self.gnu_hello_stack_dynamic_hints = (
            self.repo / "targets" / "gnu-hello" / "nix" / "gnu-hello-stack-dynamic-hints.json"
        )
        self.gnu_hello_stack_dynamic_driver = (
            self.repo / "targets" / "gnu-hello" / "nix" / "gnu-hello-stack-dynamic-authority.py"
        )
        self.proof_source_aggregate_driver = (
            self.repo / "nix" / "stage-a-proof-source-aggregate.py"
        )
        self.gnu_hello_diagnostic_driver = (
            self.repo / "targets" / "gnu-hello" / "nix" / "gnu-hello-roundtrip-diagnostic.py"
        )

    @staticmethod
    def _hermetic_nix_eval_env(root: Path) -> dict[str, str]:
        config = root / "nixpkgs-config.nix"
        config.write_text("{}\n", encoding="ascii")
        environment = os.environ.copy()
        environment["NIXPKGS_CONFIG"] = str(config)
        return environment

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

    def test_direct_call_integration_modules_are_callsite_stable(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "gnu_hello_roundtrip_driver_integration_names",
            self.gnu_hello_driver,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        driver = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(driver)
        module_for = driver._direct_call_integration_module

        self.assertEqual(
            module_for(0x18DB, 190),
            "GeneratedRelationalInternalDirectCallMixedOriginalIntegration"
            "000018dbEdge000000be",
        )
        self.assertNotEqual(
            module_for(0x18DB, 190),
            module_for(0x18DB, 191),
        )
        self.assertNotEqual(
            module_for(0x18DB, 190),
            module_for(0x18C0, 190),
        )
        with self.assertRaises(ValueError):
            module_for(-1, 190)
        with self.assertRaises(ValueError):
            module_for(0x18DB, -1)

    def test_direct_call_contract_ids_are_callsite_stable(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "gnu_hello_roundtrip_driver_contract_ids",
            self.gnu_hello_driver,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        driver = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(driver)
        contract_id = driver._direct_call_contract_id

        first = contract_id(0x18DB)
        self.assertEqual(first, contract_id(0x18DB))
        self.assertNotEqual(first, contract_id(0x1FDC))
        self.assertGreaterEqual(first, 0x80000000)
        self.assertLess(first, 2**32)
        for invalid in (-1, 2**32, True):
            with self.assertRaises(ValueError):
                contract_id(invalid)

    def test_direct_call_semantics_has_a_narrow_invalidation_boundary(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        driver = self.gnu_hello_direct_call_semantics_driver.read_text(
            encoding="utf-8"
        )
        source_start = lane.index(
            "directCallSemanticsPythonSource = lib.fileset.toSource"
        )
        source_end = lane.index(
            "kernelDataPythonSource = lib.fileset.toSource",
            source_start,
        )
        source_closure = lane[source_start:source_end]

        self.assertIn(
            "internal_direct_call_semantics_bundle.py",
            source_closure,
        )
        self.assertIn(
            "internal_direct_call_register_control_authority.py",
            source_closure,
        )
        self.assertNotIn("../src\n", source_closure)
        self.assertNotIn("interpreter_mixed_original.py", source_closure)
        self.assertNotIn("gnu-hello-roundtrip-driver.py", driver)
        self.assertIn(
            "write_mixed_original_direct_call_semantics",
            driver,
        )
        self.assertEqual(
            lane.count(
                "mkPhaseWithSource\n"
                "    directCallSemanticsPythonSource\n"
            ),
            4,
        )
        self.assertEqual(
            lane.count("${python} ${directCallSemanticsDriver}"),
            4,
        )
        proposal_start = lane.index(
            "mixedOriginalDirectCallProposalsLean ="
        )
        proposal_end = lane.index(
            "mixedOriginalDirectCallProposalTargets =",
            proposal_start,
        )
        self.assertNotIn(
            "directCallSemanticsDriver",
            lane[proposal_start:proposal_end],
        )

    def test_direct_call_semantics_cli_matches_package_emitter(self) -> None:
        from spaghetti_extractor.relational.lean.internal_direct_call_semantics_bundle import (
            write_mixed_original_direct_call_semantics,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            original = root / "original.exe"
            state_machine = root / "state-machine.jsonl"
            proposal = root / "proposals.json"
            package_out = root / "package"
            cli_out = root / "cli"
            original.write_bytes(b"test-pe")
            state_machine.write_text("{}\n", encoding="utf-8")
            proposal.write_text(
                json.dumps(
                    {
                        "format": (
                            "stage-a-mixed-original-direct-call-proposals-v1"
                        ),
                        "inputs": {
                            "original_sha256": sha256(
                                original.read_bytes()
                            ).hexdigest(),
                            "state_machine_sha256": sha256(
                                state_machine.read_bytes()
                            ).hexdigest(),
                        },
                        "proposal_modules": [],
                        "request_plan": {"chains": []},
                    }
                ),
                encoding="utf-8",
            )

            write_mixed_original_direct_call_semantics(
                original=original,
                state_machine=state_machine,
                proposal_report=proposal,
                out=package_out,
            )
            subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_direct_call_semantics_driver),
                    "--original",
                    str(original),
                    "--state-machine",
                    str(state_machine),
                    "--proposal-report",
                    str(proposal),
                    "--out",
                    str(cli_out),
                ],
                check=True,
            )

            package_files = {
                path.relative_to(package_out): path.read_bytes()
                for path in package_out.rglob("*")
                if path.is_file()
            }
            cli_files = {
                path.relative_to(cli_out): path.read_bytes()
                for path in cli_out.rglob("*")
                if path.is_file()
            }
            self.assertEqual(cli_files, package_files)

    def test_gnu_hello_lane_is_phase_separated_static_and_manifest_driven(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        driver = self.gnu_hello_driver.read_text(encoding="utf-8")
        aggregate_driver = self.proof_source_aggregate_driver.read_text(
            encoding="utf-8"
        )
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
        self.assertIn("proofSourceAggregateDriver", lane)
        self.assertIn('aggregatePython = "${pkgs.python3}/bin/python3"', lane)
        self.assertNotIn(
            "${python} ${proofSourceAggregateDriver}",
            lane,
        )
        self.assertNotIn("${python} ${driver} aggregate", lane)
        self.assertNotIn("spaghetti_extractor", aggregate_driver)
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
        self.assertNotIn("measureResources", lane)
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
        self.assertIn("contentAddressed = true", lane)
        self.assertIn("__contentAddressed = true;", lane)
        self.assertIn("stackDynamicProofPythonFiles", lane)
        self.assertIn("stackDynamicAuthorityPythonSource", lane)
        self.assertIn(
            "mixedOriginalStackDynamicAuthorityLean =\n"
            "    mkPhaseWithSource stackDynamicAuthorityPythonSource",
            lane,
        )
        self.assertIn(
            "proofPythonFiles = lib.fileset.unions",
            lane,
        )
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
            (
                "stage-a-gnu-hello-roundtrip-"
                "mixed-original-stack-dynamic-authority-proof"
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

    def test_gnu_hello_proof_python_source_keeps_cli_import_closure(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        start = lane.index("proofPythonFiles = lib.fileset.unions")
        end = lane.index("proofPythonSource =", start)
        proof_files = lane[start:end]

        self.assertNotIn(
            "../src/spaghetti_extractor/relational/build.py",
            proof_files,
        )
        self.assertNotIn(
            "../../src/spaghetti_extractor/machine_abi.py",
            proof_files,
        )
        self.assertIn(
            "fileset = proofPythonFiles;",
            lane[lane.index("proofPythonSource ="):],
        )
        self.assertIn(
            'engineSegments = mkPhase "stage-a-gnu-hello-roundtrip-engine-segments"',
            lane,
        )
        self.assertIn("${python} -m spaghetti_extractor", lane)

    def test_gnu_hello_acceptance_interface_nix_wiring_is_current(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")

        requirements_start = lane.index("acceptanceRequirementsLean =")
        requirements_end = lane.index(
            "acceptanceRequirementsProofSources =", requirements_start
        )
        requirements = lane[requirements_start:requirements_end]
        self.assertIn(
            "(.dynamic_evidence_fields | length) == 13",
            requirements,
        )

        launch_source_start = lane.index("launchBindingPythonSource =")
        launch_source_end = lane.index(
            "externalComponentPythonSource =", launch_source_start
        )
        launch_source = lane[launch_source_start:launch_source_end]
        self.assertIn("gnu_hello_acceptance_requirements.py", launch_source)
        self.assertIn("gnu_hello_launch_binding.py", launch_source)
        self.assertIn("interpreter_mixed_kernel_binding.py", launch_source)

        external_start = lane.index("externalComponentLean =")
        external_end = lane.index(
            "mixedSemanticOperationComponentLean =", external_start
        )
        external = lane[external_start:external_end]
        self.assertIn("stage-a-gnu-hello-external-component-v3", external)
        self.assertIn("(.remaining_premises | length) == 1", external)
        self.assertIn("(.blocking_obligations | length) == 1", external)
        self.assertIn(
            "generatedExternalBoundaryChunkFactoryOfOperationBridge",
            external,
        )
        self.assertNotIn(
            "generatedCanonicalExternalBoundaryChunkFactory",
            external,
        )

        mixed_start = lane.index("mixedSemanticOperationComponentLean =")
        mixed_end = lane.index(
            "runtimeIndirectCompositionLean =", mixed_start
        )
        mixed = lane[mixed_start:mixed_end]
        self.assertIn("__contentAddressed = true;", mixed)
        self.assertIn('.status == "incomplete"', mixed)
        self.assertIn("(.acceptance_authority | not)", mixed)
        self.assertIn("(.proof_authority | not)", mixed)
        self.assertIn(
            "mixedSemanticOperationComponentInterfaceProof =",
            mixed,
        )
        self.assertIn("mkGeneratedClosureProof", mixed)
        self.assertIn("leanSourceRoot", mixed)
        self.assertIn(
            "generatedSemanticChunkFactory",
            mixed,
        )
        self.assertIn("candidateRootRva : Nat", mixed)
        self.assertIn(
            "candidateAuthority program candidateRootRva invariant",
            mixed,
        )
        self.assertNotIn("candidateAuthority program 0 invariant", mixed)

        proof_start = lane.index(
            'proofSources = mkPhase "stage-a-gnu-hello-roundtrip-proof-sources"'
        )
        proof_end = lane.index(
            "# The generated module inventory", proof_start
        )
        proof_sources = lane[proof_start:proof_end]
        for phase, module in (
            (
                "kernelStepOperationLean",
                "GeneratedRelationalInterpreterKernelStepOperation.lean",
            ),
            (
                "kernelRunOperationLean",
                "GeneratedRelationalInterpreterKernelRunOperation.lean",
            ),
            (
                "kernelInvokeOperationLean",
                "GeneratedRelationalInterpreterKernelInvokeOperation.lean",
            ),
        ):
            self.assertIn(f"--source ${{{phase}}}", proof_sources)
            phase_start = lane.index(f"{phase} =")
            phase_end = lane.index("\n  '';", phase_start)
            self.assertIn(
                f'test -s \\\n      "$out/StageA/{module}"',
                lane[phase_start:phase_end],
            )

        invoke_start = lane.index("kernelInvokeOperationLean =")
        invoke_end = lane.index(
            "mixedCandidateAuthorityLean =", invoke_start
        )
        invoke = lane[invoke_start:invoke_end]
        self.assertIn(
            "stage-a-relational-interpreter-kernel-invoke-operation-plan-v4",
            invoke,
        )
        self.assertIn(
            "external_arm_exact_route_and_result_closure",
            invoke,
        )
        self.assertNotIn(
            "checked_run_native_evidence_at_exact_nested_frames",
            invoke,
        )

    def test_native_source_proof_lane_has_explicit_fail_closed_inputs(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")

        for argument in (
            "nativeSourceOriginalExecutionEvidence ? null",
            "nativeSourceCompiledAuthorityEvidence ? null",
            "nativeSourceEnvironmentFamilyEvidence ? null",
            "nativeSourceApprovedToolchainAxiom ?",
        ):
            self.assertIn(argument, lane)
        self.assertIn("mkMissingNativeSourceEvidence =", lane)
        self.assertIn(
            "stage-a-gnu-hello-source-execution-evidence-v2; exact combined invariant",
            lane,
        )
        self.assertIn(
            "stage-a-gnu-hello-native-source-compiled-authority-evidence-v1",
            lane,
        )
        self.assertIn(
            "sourceCompiledAuthorityProducedEvidence = mkPhase",
            lane,
        )
        self.assertIn(
            "else\n      sourceCompiledAuthorityProducedEvidence;",
            lane,
        )
        self.assertIn("--offline-nix-inspection", lane)
        self.assertIn(
            "stage-a-native-source-acceptance-declarations-v1",
            lane,
        )
        self.assertIn(
            "sole approved toolchain axiom ${nativeSourceApprovedToolchainAxiom}",
            lane,
        )
        self.assertIn(
            "JSON status\" >&2",
            lane,
        )
        self.assertNotIn("fakeNativeSource", lane)

    def test_native_source_execution_and_acceptance_are_checked_dag_nodes(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        execution_start = lane.index("sourceExecutionLean =")
        compiled_start = lane.index("sourceCompiledAuthorityLean =")
        acceptance_start = lane.index("sourceConditionalAcceptanceLean =")
        runtime_start = lane.index("sourceRuntimeFunctionalSuite =")

        execution = lane[execution_start:compiled_start]
        compiled = lane[compiled_start:acceptance_start]
        acceptance = lane[acceptance_start:runtime_start]
        self.assertIn("native-source-execution", execution)
        self.assertIn("--evidence-manifest", execution)
        self.assertIn(".counts.frontiers == 31", execution)
        self.assertIn("sourceExecutionClosure = mkGeneratedClosureProof", execution)
        self.assertIn("sourceExecutionAudit = mkCheckedProofAudit", execution)

        self.assertIn("native-source-compiled-authority", compiled)
        self.assertIn("--project-nix-provenance", compiled)
        self.assertIn("--profile-nix-provenance", compiled)
        self.assertIn("--build-nix-provenance", compiled)
        self.assertIn(
            "sourceCompiledAuthorityClosure = mkGeneratedClosureProof",
            compiled,
        )
        self.assertIn(
            "sourceCompiledAuthorityAudit = mkCheckedProofAudit",
            compiled,
        )

        self.assertIn("native-source-acceptance", acceptance)
        self.assertIn(
            "generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence",
            acceptance,
        )
        self.assertIn(
            "sourceConditionalAcceptanceClosure = mkGeneratedClosureProof",
            acceptance,
        )
        self.assertIn(
            "sourceConditionalAcceptanceAudit = mkCheckedProofAudit",
            acceptance,
        )
        self.assertIn(
            "standardLogicalAxioms ++ [ nativeSourceApprovedToolchainAxiom ]",
            acceptance,
        )
        self.assertIn(
            "requiredAxioms = [ nativeSourceApprovedToolchainAxiom ]",
            acceptance,
        )
        self.assertIn(
            "approved_toolchain_axiom: $approved_toolchain_axiom",
            acceptance,
        )
        self.assertIn("sourceConditionalAcceptanceChecked =", acceptance)
        self.assertIn("__contentAddressed = true;", acceptance)

    def test_native_source_runtime_is_candidate_only_and_theorem_gated(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        start = lane.index("sourceRuntimeFunctionalSuite =")
        end = lane.index(
            'interpreter = mkPhase "stage-b-gnu-hello-roundtrip-interpreter"',
            start,
        )
        runtime = lane[start:end]
        cli = (self.repo / "src/spaghetti_extractor/cli.py").read_text(
            encoding="utf-8"
        )

        self.assertIn("${sourceConditionalAcceptanceChecked}", runtime)
        self.assertIn("stage-b-run-functional-suite", runtime)
        self.assertIn(
            '--candidate-binary "$runtime_dir/hello.exe"', runtime
        )
        self.assertIn(
            'ln -s ${sourceCandidate}/candidate.exe "$runtime_dir/hello.exe"',
            runtime,
        )
        self.assertIn("export FONTCONFIG_FILE=${wineFontsConf}", runtime)
        self.assertIn('export XDG_CACHE_HOME="$TMPDIR/cache"', runtime)
        self.assertIn(
            "-- xvfb-run -a wine cmd /d /c hello.exe", runtime
        )
        self.assertIn(".oracle.original_runtime_observations | not", runtime)
        self.assertIn(".counts.cases == 11", runtime)
        self.assertIn(
            'functional.add_argument("--candidate-binary", type=Path)',
            cli,
        )
        self.assertIn(
            'functional.add_argument("candidate_command", nargs=argparse.REMAINDER)',
            cli,
        )
        for forbidden in ("${originalPe}", "${originalMap}", "reference-contract"):
            self.assertNotIn(forbidden, runtime)
        self.assertIn("sourceEquivalenceFinalReport =", runtime)
        self.assertIn('verdict == "conditional_pass"', runtime)
        self.assertIn("${sourceRuntimeFunctionalSuite}", runtime)
        self.assertIn("original_runtime_executions == 0", runtime)

    def test_flake_exposes_complete_native_source_proof_lane(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        self.assertIn(
            'nativeSourceApprovedToolchainAxiom =\n'
            '              "StageA.GeneratedRelational.'
            'GnuHelloNativeSourceEnvironmentFamily.'
            'pinnedCompilerLoweringCorrect";',
            flake,
        )
        for attribute in (
            "stage-a-gnu-hello-native-source-original-execution-evidence",
            "stage-a-gnu-hello-native-source-execution-proof",
            "stage-a-gnu-hello-native-source-execution-audit",
            "stage-a-gnu-hello-native-source-compiled-authority-proof",
            "stage-a-gnu-hello-native-source-compiled-authority-audit",
            "stage-a-gnu-hello-native-source-conditional-acceptance-proof",
            "stage-a-gnu-hello-native-source-conditional-acceptance-audit",
            "stage-a-gnu-hello-native-source-conditional-acceptance-checked",
            "stage-a-gnu-hello-native-source-equivalence-report",
            "stage-b-gnu-hello-native-source-functional-suite",
        ):
            self.assertGreaterEqual(flake.count(attribute), 2, attribute)

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

    def test_gnu_hello_exact_isa_phases_export_form_summaries(self) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        flake = self.flake_nix.read_text(encoding="utf-8")
        phase_start = lane.index("mkExactLeanIsa =")
        phase_end = lane.index(
            'smoke = mkPhase "stage-a-gnu-hello-roundtrip-smoke"',
            phase_start,
        )
        phase = lane[phase_start:phase_end]

        self.assertIn(
            'format: "stage-a-relational-side-isa-summary-v1"',
            phase,
        )
        self.assertIn('status: "lean-decoder-inventory-complete"', phase)
        self.assertIn(
            "unique_forms: ([.regions[].occurrences[].form] | unique | length)",
            phase,
        )
        self.assertIn(
            "forms: ([.regions[].occurrences[].form] | unique | sort)",
            phase,
        )
        self.assertIn('> "$out/summary.json"', phase)
        self.assertIn(
            ".counts.unique_forms == (.forms | length)",
            phase,
        )
        for output in (
            "stage-a-gnu-hello-roundtrip-original-isa",
            "stage-a-gnu-hello-roundtrip-candidate-isa",
            "stage-a-gnu-hello-roundtrip-original-isa-summary",
            "stage-a-gnu-hello-roundtrip-candidate-isa-summary",
            "stage-a-gnu-hello-roundtrip-isa-coverage",
            "stage-a-gnu-hello-roundtrip-semantic-coverage",
        ):
            self.assertIn(output, flake)
        self.assertIn(
            'format: "stage-a-gnu-hello-roundtrip-isa-coverage-v1"',
            lane,
        )
        self.assertIn(
            'status: "lean-decoder-coverage-inventory-complete"',
            lane,
        )
        self.assertIn(
            "acceptance_exact_pe_decode_replay_required: true",
            lane,
        )
        self.assertIn(
            "semantic_conformance_authority: false",
            lane,
        )
        self.assertIn(
            "whole_program_acceptance_authority: false",
            lane,
        )
        self.assertIn(
            'ln -s ${isaCoverage} "$out/isa-coverage"',
            lane,
        )
        self.assertIn(
            '"stage-a-gnu-hello-roundtrip-semantic-coverage"',
            lane,
        )
        self.assertIn(
            "--original-isa ${originalIsa}/isa.json",
            lane,
        )
        self.assertIn(
            "--candidate-isa ${candidateIsa}/isa.json",
            lane,
        )
        self.assertIn(
            'ln -s ${semanticCoverage} "$out/semantic-coverage"',
            lane,
        )

    def test_gnu_hello_side_isa_and_typed_access_fault_are_fail_closed(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        flake = self.flake_nix.read_text(encoding="utf-8")
        closure_start = lane.index(
            "isaSideAdapterPythonSource = lib.fileset.toSource"
        )
        closure_end = lane.index(
            "semanticCoveragePythonSource = lib.fileset.toSource",
            closure_start,
        )
        closure = lane[closure_start:closure_end]
        adapter_start = lane.index(
            "sideIsaQualificationAdapter = mkPhaseWithSource"
        )
        adapter_end = lane.index("isaCoverage = mkAnalysisPhase", adapter_start)
        adapter = lane[adapter_start:adapter_end]
        enrichment_source_start = lane.index(
            "isaCatalogEnrichmentPythonSource = lib.fileset.toSource"
        )
        enrichment_source_end = lane.index(
            "semanticCoveragePythonSource = lib.fileset.toSource",
            enrichment_source_start,
        )
        enrichment_source = lane[
            enrichment_source_start:enrichment_source_end
        ]
        enrichment_start = lane.index(
            "sideIsaCatalogEnrichment = mkAnalysisPhase"
        )
        enrichment_end = lane.index(
            "isaCoverage = mkAnalysisPhase", enrichment_start
        )
        enrichment = lane[enrichment_start:enrichment_end]
        semantic_start = lane.index(
            "semanticCoverage = mkPhaseWithSource"
        )
        semantic_end = lane.index(
            "nativeLaunchRequest = mkPhase", semantic_start
        )
        semantic = lane[semantic_start:semantic_end]

        for source in (
            "isa_side_adapter.py",
            "isa_catalog.py",
            "isa_conformance.py",
            "isa_semantic_forms.py",
            "isa_requirements.py",
            "preflight.py",
            "side_extraction_artifact.py",
            "side_isa_artifact.py",
            "Formal.lean",
            "ISAQualification.lean",
            "X87.lean",
        ):
            self.assertIn(source, closure)
        self.assertNotIn("proofPythonFiles", closure)
        self.assertNotIn("../src/spaghetti_extractor/cli.py", closure)
        self.assertIn(
            "from spaghetti_extractor.isa_side_adapter import",
            adapter,
        )
        self.assertIn("${originalIsa}/isa.json ${originalPe}", adapter)
        self.assertIn(
            "${candidateIsa}/isa.json ${candidate}/candidate.exe",
            adapter,
        )
        self.assertIn('requirements_out=output / "requirements.json"', adapter)
        self.assertIn(
            'catalog_out=output / "catalog-proposal.json"',
            adapter,
        )
        for schema in (
            "stage-a-isa-requirement-inventory-v1",
            "stage-a-side-isa-executable-catalog-proposal-v1",
            "stage-a-side-isa-qualification-adapter-result-v1",
        ):
            self.assertIn(schema, adapter)
        self.assertIn(
            ".counts.canonical_occurrences == $expected_occurrences",
            adapter,
        )
        self.assertIn(
            ".status == \"incomplete_missing_effect_enrichment\"",
            adapter,
        )
        self.assertIn("(.trust.proof_authority | not)", adapter)
        self.assertIn(
            "stage-a-gnu-hello-roundtrip-side-isa-adapter", flake
        )
        for source in (
            "isa_catalog_enrichment.py",
            "relational/lean/compiler.py",
            "Formal.lean",
            "ISAQualification.lean",
            "X87.lean",
        ):
            self.assertIn(source, enrichment_source)
        self.assertNotIn("proofPythonFiles", enrichment_source)
        self.assertIn(
            "write_enriched_side_isa_catalog",
            enrichment,
        )
        self.assertIn(
            "stage-a-side-isa-executable-catalog-enrichment-v1",
            enrichment,
        )
        self.assertIn(
            "spaghetti-extractor stage-a-generate-isa-corpus",
            enrichment,
        )
        self.assertIn(
            "import ../../nix/stage-a-isa-qualification-graph.nix",
            enrichment,
        )
        self.assertIn(
            "sideIsaQualificationEvidence = "
            "sideIsaQualification.qualification",
            enrichment,
        )
        self.assertIn(
            "sideIsaQualificationBundle = sideIsaQualification.bundle",
            enrichment,
        )
        for package in (
            "stage-a-gnu-hello-roundtrip-side-isa-enrichment",
            "stage-a-gnu-hello-roundtrip-side-isa-corpus",
            "stage-a-gnu-hello-roundtrip-side-isa-evidence",
            "stage-a-gnu-hello-roundtrip-side-isa-qualification",
        ):
            self.assertIn(package, flake)
        self.assertIn(
            'ln -s ${sideIsaQualificationAdapter} \\',
            lane,
        )
        self.assertIn('"side_isa_qualification_adapter": {', lane)

        self.assertNotIn("accessDomainReceipts ? null", lane)
        self.assertNotIn("accessDomainReceiptProposals ? null", lane)
        self.assertIn(
            "../src/spaghetti_extractor/relational/access_domain_receipts.py",
            lane,
        )
        self.assertNotIn("--access-domain-receipts", semantic)
        self.assertNotIn("--access-domain-receipt-proposals", semantic)
        self.assertIn(
            ".access_domain_receipts.accepted_receipts == []",
            semantic,
        )
        self.assertIn("accepted: 0", semantic)
        self.assertIn(
            '.counts.by_access_fault_domain["requires-proof"] > 0',
            semantic,
        )
        self.assertNotIn("access-domain-receipts.json", adapter)
        access_source_start = lane.index(
            "accessFaultQualificationPythonSource = lib.fileset.toSource"
        )
        access_source_end = lane.index(
            "kernelDataPythonSource = lib.fileset.toSource",
            access_source_start,
        )
        access_source = lane[access_source_start:access_source_end]
        self.assertIn("access_domain_receipts.py", access_source)
        self.assertNotIn("proofPythonFiles", access_source)
        access_phase_start = lane.index(
            "accessFaultQualificationLean ="
        )
        access_phase_end = lane.index(
            "kernelAbiLean = mkPhase", access_phase_start
        )
        access_phase = lane[access_phase_start:access_phase_end]
        for required in (
            "--original-isa ${originalIsa}/isa.json",
            "--state-machine ${proofStateMachinePath}",
            "${mixedOriginalBaseLean}/interpreter-mixed-original-base-plan.json",
            "--kernel-data-inventory ${kernelDataLean}/module-inventory.json",
            "stage-a-typed-access-fault-qualification-v1",
            ".counts.by_qualification_kind.x87 > 0",
            ".counts.blocked_regions == 0",
            ".counts.by_blocker_reason == {}",
            "--explicit-targets-only",
            "--target-closure-only",
            "contentAddressed = true",
            "targetNodes = accessFaultQualificationTargets",
        ):
            self.assertIn(required, access_phase)
        self.assertIn(
            "accessFaultQualificationProof",
            lane[lane.rindex("\nin\n"):],
        )

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
            "--state-machine ${proofStateMachinePath}",
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
                    str(self.proof_source_aggregate_driver),
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

    def test_aggregate_can_ignore_inherited_targets_for_focused_proofs(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source"
            stage_a = source / "StageA"
            stage_a.mkdir(parents=True)
            (stage_a / "Base.lean").write_text(
                "namespace StageA\nend StageA\n",
                encoding="ascii",
            )
            (stage_a / "Inherited.lean").write_text(
                "import StageA.Base\nnamespace StageA\nend StageA\n",
                encoding="ascii",
            )
            (stage_a / "Focused.lean").write_text(
                "import StageA.Base\nnamespace StageA\nend StageA\n",
                encoding="ascii",
            )
            (source / "phase-manifest.json").write_text(
                json.dumps({"targets": ["Inherited"]}),
                encoding="utf-8",
            )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
                    "--source",
                    str(source),
                    "--target",
                    "Focused",
                    "--explicit-targets-only",
                    "--target-closure-only",
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
            self.assertEqual(
                json.loads(
                    (output / "standalone-modules.json").read_text(
                        encoding="utf-8"
                    )
                ),
                ["Base", "Focused"],
            )
            manifest = json.loads(
                (output / "phase-manifest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(manifest["targets"], ["Focused"])
            self.assertTrue(manifest["explicit_targets_only"])
            self.assertTrue(manifest["target_closure_only"])

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
                    str(self.proof_source_aggregate_driver),
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

    def test_gnu_hello_aggregate_emits_canonical_build_pack_layout(
        self,
    ) -> None:
        node = (
            "GeneratedRelationalInternalDirectCallSummaryNode"
            + "a" * 64
        )
        modules = (
            node,
            f"{node}Data",
            f"{node}StructureShape",
            f"{node}StructureDecode",
            "RelationalDecode",
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            for module in modules:
                (source / f"{module}.lean").write_text(
                    f"def {module.lower()} := true\n",
                    encoding="ascii",
                )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
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
            build_packs = json.loads(
                (output / "module-build-packs.json").read_text(
                    encoding="utf-8"
                )
            )
            manifest = json.loads(
                (output / "phase-manifest.json").read_text(encoding="utf-8")
            )

            self.assertEqual(
                {path.name for path in output.iterdir()},
                {
                    "StageA",
                    "module-build-packs.json",
                    "module-resources.json",
                    "phase-manifest.json",
                    "proof-targets.json",
                    "standalone-modules.json",
                },
            )
            self.assertEqual(
                {path.name for path in (output / "StageA").iterdir()},
                {f"{module}.lean" for module in modules},
            )
            self.assertEqual(
                build_packs["modules"][f"{node}StructureShape"],
                build_packs["modules"][f"{node}StructureDecode"],
            )
            self.assertEqual(
                build_packs["modules"][node],
                build_packs["modules"][f"{node}Data"],
            )
            self.assertNotEqual(
                build_packs["modules"][node],
                build_packs["modules"]["RelationalDecode"],
            )
            self.assertEqual(manifest["counts"]["modules"], len(modules))
            self.assertEqual(
                manifest["counts"]["build_packs"],
                len(build_packs["packs"]),
            )
            self.assertEqual(
                manifest["public_outputs"],
                {"module_build_packs": "module-build-packs.json"},
            )
            self.assertNotIn("source_packs", manifest["counts"])
            self.assertFalse((output / "module-source-packs.json").exists())
            self.assertFalse((output / "source-packs").exists())
            self.assertFalse(
                (output / "StageA" / "module-source-packs.json").exists()
            )
            self.assertFalse(
                (output / "StageA" / "module-build-packs.json").exists()
            )
            self.assertFalse((output / "StageA" / "source-packs").exists())
            for module in modules:
                self.assertEqual(
                    (output / "StageA" / f"{module}.lean").read_bytes(),
                    (source / f"{module}.lean").read_bytes(),
                )

    def test_gnu_hello_aggregate_orders_dependent_modules_in_one_build_pack(
        self,
    ) -> None:
        node = (
            "GeneratedRelationalInternalDirectCallSummaryNode"
            + "b" * 64
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            decode = f"{node}StructureDecode"
            shape = f"{node}StructureShape"
            (source / f"{decode}.lean").write_text(
                "def decodeChecked := true\n",
                encoding="ascii",
            )
            (source / f"{shape}.lean").write_text(
                f"import StageA.{decode}\ndef shapeChecked := true\n",
                encoding="ascii",
            )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
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
            build_packs = json.loads(
                (output / "module-build-packs.json").read_text(
                    encoding="utf-8"
                )
            )
            pack_id = build_packs["modules"][decode]
            self.assertEqual(build_packs["modules"][shape], pack_id)
            self.assertEqual(build_packs["packs"][pack_id], [decode, shape])

    def test_gnu_hello_aggregate_keeps_a_direct_call_family_in_one_pack(
        self,
    ) -> None:
        node = (
            "GeneratedRelationalInternalDirectCallSummaryNode"
            + "d" * 64
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            data = f"{node}Data"
            replay_modules = [
                f"{node}StructureControlCandidatePack{index:04d}"
                for index in range(9)
            ]
            control = f"{node}StructureControl"
            (source / f"{data}.lean").write_text(
                "def dataChecked := true\n",
                encoding="ascii",
            )
            for index, replay in enumerate(replay_modules):
                (source / f"{replay}.lean").write_text(
                    f"import StageA.{data}\ndef replayChecked{index} := true\n",
                    encoding="ascii",
                )
            (source / f"{control}.lean").write_text(
                "\n".join(
                    [f"import StageA.{replay}" for replay in replay_modules]
                    + ["def controlChecked := true", ""]
                ),
                encoding="ascii",
            )
            (source / f"{node}.lean").write_text(
                f"import StageA.{control}\ndef nodeChecked := true\n",
                encoding="ascii",
            )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
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
            build_packs = json.loads(
                (output / "module-build-packs.json").read_text(
                    encoding="utf-8"
                )
            )
            replay_pack_ids = {
                build_packs["modules"][module] for module in replay_modules
            }
            self.assertEqual(len(replay_pack_ids), 1)
            pack_id = replay_pack_ids.pop()
            self.assertEqual(build_packs["modules"][data], pack_id)
            self.assertEqual(build_packs["modules"][control], pack_id)
            self.assertEqual(build_packs["modules"][node], pack_id)
            self.assertEqual(
                set(build_packs["packs"][pack_id]),
                {data, control, node, *replay_modules},
            )

    def test_gnu_hello_aggregate_coarsens_independent_proof_families(
        self,
    ) -> None:
        families = [
            "GeneratedRelationalInternalDirectCallSummaryNode" + f"{index:064x}"
            for index in range(8)
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            for module in families:
                (source / f"{module}.lean").write_text(
                    f"def {module.lower()} := true\n",
                    encoding="ascii",
                )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
                    "--source",
                    str(source.parent),
                    "--coarse-build-packs",
                    "--emit-module-graph",
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
            build_packs = json.loads(
                (output / "module-build-packs.json").read_text(
                    encoding="utf-8"
                )
            )
            manifest = json.loads(
                (output / "phase-manifest.json").read_text(encoding="utf-8")
            )
            graph = json.loads(
                (output / "module-graph.json").read_text(encoding="utf-8")
            )
            self.assertLessEqual(len(build_packs["packs"]), 8)
            self.assertEqual(
                set(build_packs["modules"]),
                set(families),
            )
            self.assertTrue(manifest["coarse_build_packs"])
            self.assertTrue(manifest["precomputed_module_graph"])
            self.assertEqual(len(graph["modules"]), len(families))
            self.assertEqual(len(graph["nodes"]), len(build_packs["packs"]))
            for module, metadata in graph["modules"].items():
                self.assertEqual(
                    (
                        output
                        / metadata["source"]
                    ).read_bytes(),
                    (source / f"{module}.lean").read_bytes(),
                )
                pack = json.loads(
                    (
                        output
                        / "source-pack-data"
                        / f"{metadata['source_pack']}.json"
                    ).read_text(encoding="utf-8")
                )
                self.assertEqual(
                    pack["modules"][module],
                    (source / f"{module}.lean").read_text(encoding="ascii"),
                )

    def test_gnu_hello_aggregate_bounds_coarse_pack_resource_work(
        self,
    ) -> None:
        modules: list[str] = []
        candidate = 0
        while len(modules) < 10:
            module = f"GeneratedMediumCertificate{candidate:04d}"
            bucket = int(sha256(module.encode("ascii")).hexdigest()[:8], 16) % 8
            if bucket == 0:
                modules.append(module)
            candidate += 1
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source_root = root / "source"
            source = source_root / "StageA"
            source.mkdir(parents=True)
            for module in modules:
                (source / f"{module}.lean").write_text(
                    f"def {module.lower()} := true\n",
                    encoding="ascii",
                )
            (source_root / "module-resources.json").write_text(
                json.dumps(
                    {
                        module: {
                            "resource_class": "medium",
                            "estimated_memory_mb": 4096,
                        }
                        for module in modules
                    }
                ),
                encoding="ascii",
            )
            output = root / "aggregate"
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
                    "--source",
                    str(source_root),
                    "--coarse-build-packs",
                    "--emit-module-graph",
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
            build_packs = json.loads(
                (output / "module-build-packs.json").read_text(
                    encoding="utf-8"
                )
            )
            selected_packs = {
                build_packs["modules"][module] for module in modules
            }
            self.assertEqual(
                sorted(
                    len(build_packs["packs"][pack_id])
                    for pack_id in selected_packs
                ),
                [2, 4, 4],
            )

    def test_gnu_hello_aggregate_rejects_a_cycle_inside_one_build_pack(
        self,
    ) -> None:
        node = (
            "GeneratedRelationalInternalDirectCallSummaryNode"
            + "c" * 64
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "source" / "StageA"
            source.mkdir(parents=True)
            decode = f"{node}StructureDecode"
            shape = f"{node}StructureShape"
            (source / f"{decode}.lean").write_text(
                f"import StageA.{shape}\ndef decodeChecked := true\n",
                encoding="ascii",
            )
            (source / f"{shape}.lean").write_text(
                f"import StageA.{decode}\ndef shapeChecked := true\n",
                encoding="ascii",
            )
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.proof_source_aggregate_driver),
                    "--source",
                    str(source.parent),
                    "--out",
                    str(root / "aggregate"),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("contains an import cycle", process.stderr)

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
                    str(self.proof_source_aggregate_driver),
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

    def test_gnu_hello_carrier_binding_accepts_checked_base_carrier(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mixed_original = root / "mixed-original"
            stage_a = mixed_original / "StageA"
            stage_a.mkdir(parents=True)
            module = "GeneratedRelationalInterpreterMixedOriginalBase"
            (stage_a / f"{module}.lean").write_text(
                "namespace StageA\nend StageA\n", encoding="ascii"
            )
            (mixed_original / "phase-manifest.json").write_text(
                json.dumps(
                    {
                        "phase": "mixed-original-base-lean",
                        "proof_authority": False,
                        "counts": {"regions": 5790, "addresses": 5792},
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
            source = (
                output
                / "StageA/GeneratedRelationalInterpreterOriginalCarrierBinding.lean"
            ).read_text(encoding="utf-8")

        self.assertIn(
            "import StageA.GeneratedRelationalInterpreterMixedOriginalBase",
            source,
        )
        self.assertIn(
            "InterpreterMixedOriginalBase.generatedOriginalStaticContext",
            source,
        )

    def test_gnu_hello_carrier_binding_rejects_unknown_carrier_phase(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            mixed_original = root / "mixed-original"
            mixed_original.mkdir()
            (mixed_original / "phase-manifest.json").write_text(
                json.dumps(
                    {
                        "phase": "untrusted-carrier",
                        "proof_authority": False,
                        "counts": {"regions": 1, "addresses": 1},
                    }
                ),
                encoding="utf-8",
            )
            process = subprocess.run(
                [
                    sys.executable,
                    str(self.gnu_hello_driver),
                    "mixed-original-carrier-binding",
                    "--mixed-original",
                    str(mixed_original),
                    "--out",
                    str(root / "carrier"),
                ],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )

        self.assertNotEqual(process.returncode, 0)
        self.assertIn("carrier input manifest is malformed", process.stderr)

    def test_gnu_hello_smoke_is_lazy_and_does_not_reference_heavy_phases(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        smoke_start = lane.index(
            'smoke = mkPhase "stage-a-gnu-hello-roundtrip-smoke"'
        )
        smoke_end = lane.index("opaqueOriginalInventory =", smoke_start)
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

    def test_gnu_hello_static_export_excludes_candidate_runtime_sources(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        phase_start = lane.index(
            "staticExport = mkPhaseWithSource opaqueStaticPythonSource"
        )
        phase_end = lane.index("sourceStateMachine =", phase_start)
        phase = lane[phase_start:phase_end]

        self.assertIn("${runtimeDriver} static-export", phase)
        self.assertNotIn("runtimePythonSource", phase)
        self.assertIn(
            "../src/spaghetti_extractor/stage_b_native_runtime.py",
            lane,
        )
        opaque_start = lane.index("opaqueStaticPythonSource =")
        opaque_end = lane.index("stackDynamicProofPythonFiles =", opaque_start)
        opaque_source = lane[opaque_start:opaque_end]
        for excluded in (
            "callable_external_runtime.py",
            "stage_b_api_catalog.py",
            "stage_b_c_backend.py",
            "stage_b_engine_layout.py",
            "stage_b_functional.py",
            "stage_b_interpreter_backend.py",
            "stage_b_interpreter_native_build.py",
            "stage_b_native_binding.py",
            "stage_b_native_build.py",
            "stage_b_native_engine.py",
            "stage_b_native_runtime.py",
            "stage_b_pe_composer.py",
        ):
            self.assertNotIn(excluded, opaque_source)

    def test_semantic_component_hybrid_has_candidate_only_functional_suite(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        self.assertIn(
            "semanticComponentHybridFunctionalSuite = "
            "mkReconstructionFunctionalSuite",
            lane,
        )
        self.assertIn(
            "candidate = semanticComponentHybridCandidate;",
            lane,
        )
        self.assertIn(
            "componentRegistry = semanticComponentRegistry;",
            lane,
        )
        self.assertIn(
            '.activation_policy == "qualified_components_only"',
            lane,
        )
        self.assertIn(
            ".coverage.qualified_units + .coverage.remaining_units",
            lane,
        )
        self.assertIn(
            '(.status == "qualified" or .status == "incomplete")',
            lane,
        )
        self.assertNotIn(
            ".control.counts.indirect_exits == "
            ".control.counts.closed_indirect_exits",
            lane,
        )
        self.assertIn(
            '"xvfb-run", "-a", "wine", "cmd", "/d", "/c", "hello.exe"',
            lane,
        )
        self.assertIn("stage_b_run_functional_case", lane)
        self.assertIn("stage_b_aggregate_functional_cases", lane)
        self.assertIn("stage-b-native-object-graph.nix", lane)
        self.assertIn("precompiled_objects=precompiled_objects", lane)
        self.assertIn("nativeBuildPythonSource", lane)
        self.assertIn("export FONTCONFIG_FILE=${wineFontsConf}", lane)
        self.assertIn('export XDG_CACHE_HOME="$TMPDIR/cache"', lane)

        component_dag = (
            self.repo / "nix" / "stage-b-semantic-component-workspaces.nix"
        ).read_text(encoding="utf-8")
        self.assertIn("componentSlices =", component_dag)
        self.assertIn(
            'pkgs.runCommand "${namePrefix}-component-slices-v1"',
            component_dag,
        )
        self.assertIn("regionalKernel =", component_dag)
        self.assertIn(
            'pkgs.runCommand "${namePrefix}-regional-interpreter-kernel-v1"',
            component_dag,
        )
        self.assertIn("component_slice=package / matches[0][\"path\"]", component_dag)
        self.assertIn("regional_kernel=pathlib.Path(sys.argv[4])", component_dag)

        flake = self.flake_nix.read_text(encoding="utf-8")
        self.assertIn("./nix/stage-b-native-object-graph.nix", flake)
        self.assertIn("stage-b-gnu-hello-component-slices", flake)
        self.assertIn("stage-b-gnu-hello-regional-interpreter-kernel", flake)

        proof_start = lane.index("proofPythonFiles =")
        proof_end = lane.index("proofPythonSource =", proof_start)
        proof_source = lane[proof_start:proof_end]
        for runtime_only in (
            "callable_external_runtime.py",
            "stage_b_interpreter_native_build.py",
            "stage_b_native_engine.py",
            "stage_b_native_runtime.py",
        ):
            self.assertIn(runtime_only, proof_source)

    def test_reconstruction_runtime_is_gated_while_lifting_evidence_is_first_class(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        qualification_start = lane.index("reconstructionQualification =")
        qualification_end = lane.index("staticExport =", qualification_start)
        qualification = lane[qualification_start:qualification_end]
        runtime_start = lane.index("mkReconstructionFunctionalSuite =")
        runtime_end = lane.index("reconstructionAssurance =", runtime_start)
        runtime = lane[runtime_start:runtime_end]
        assurance_start = lane.index("reconstructionAssurance =")
        assurance_end = lane.index("interpreter = mkPhase", assurance_start)
        assurance = lane[assurance_start:assurance_end]

        self.assertIn(
            "${reconstructionEntryReplacementValidation}/validation-report.json",
            qualification,
        )
        self.assertIn("regional replacement validation is not closed", qualification)
        self.assertIn("qualification ? null", runtime)
        self.assertIn("${qualification}/reconstruction-qualification.json", runtime)
        self.assertIn("qualification = reconstructionQualification", runtime)
        self.assertIn("xvfb-run", runtime)
        self.assertNotIn("${originalPe}", runtime)
        self.assertIn('"evidence_classes": ["differential"]', assurance)
        self.assertIn('"evidence_classes": ["integration"]', assurance)
        self.assertIn('"assumption_ids": []', assurance)

        flake = self.flake_nix.read_text(encoding="utf-8")
        checks_start = flake.index("checks = forAllSystems")
        checks_end = flake.index("devShells = forAllSystems", checks_start)
        self.assertIn(
            "stage-b-gnu-hello-lifting-evidence",
            flake[checks_start:checks_end],
        )
        self.assertNotIn(
            "stage-a-gnu-hello-reconstruction-assurance",
            flake[checks_start:checks_end],
        )
        machine_start = lane.index("machineIr = pkgs.runCommand")
        machine_end = lane.index("reconstructionInterpreter =", machine_start)
        machine = lane[machine_start:machine_end]
        self.assertIn('.status == "incomplete"', machine)
        self.assertIn('.control.counts.closed_indirect_exits == 4', machine)

    def test_candidate_kernel_closures_do_not_depend_on_global_proof_sources(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        helper_start = lane.index("mkGeneratedClosureProof =")
        helper_end = lane.index("mkLeanTermReceipts =", helper_start)
        helper = lane[helper_start:helper_end]
        self.assertIn("--coarse-build-packs", helper)
        self.assertIn("--emit-module-graph", helper)
        self.assertIn(
            'graphFile = proofSources + "/module-graph.json"', helper
        )
        self.assertIn("bundleContentAddressed = true", helper)
        self.assertNotIn("standaloneSourceRoot", helper)

        boundary_start = lane.index("candidateKernelProofSourceInputs = [")
        boundary_end = lane.index(
            "interpreterStepProgramLookupProjectionClosure =", boundary_start
        )
        boundary = lane[boundary_start:boundary_end]

        self.assertIn("leanSourceRoot", boundary)
        self.assertIn("kernelOperationInstantiationLean", boundary)
        for forbidden in (
            "proofSources",
            "originalPeLean",
            "mixedOriginalLean",
            "mixedOriginalStaticReachabilityLean",
            "canonicalRelationCoreLean",
            "kernelCdeclEpilogueLean",
            "kernelFrameExecutorLean",
        ):
            self.assertNotIn(forbidden, boundary)

        for name, end_marker in (
            (
                "programLookupNativeWorldBridgeClosure =",
                "programLookupNativeWorldBridgeProofSources =",
            ),
            (
                "interpreterStepWorldProgramLookupClosure =",
                "interpreterStepWorldProgramLookupProofSources =",
            ),
            (
                "kernelOperationInstantiationClosure =",
                "kernelOperationInstantiationProofSources =",
            ),
        ):
            start = lane.index(name)
            closure = lane[start : lane.index(end_marker, start)]
            self.assertIn("candidateKernel", closure)
            self.assertNotIn("proofSources", closure)

    def test_gnu_hello_phases_use_reproducible_timestamps(self) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")

        self.assertIn("commonEnvironment = pythonSource:", lane)
        self.assertIn("export SOURCE_DATE_EPOCH=1", lane)

    def test_gnu_hello_direct_call_fixed_point_is_semantic(self) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        start = lane.index("mixedOriginalDirectCallFixedPointCheck =")
        end = lane.index("mixedOriginalLean = mkPhase", start)
        fixed_point = lane[start:end]

        self.assertIn("${directCallFixedPointDriver}", fixed_point)
        self.assertIn("--proposal-report", fixed_point)
        self.assertIn("--authority-report", fixed_point)
        self.assertIn(
            ".format == \"stage-a-direct-call-closure-fixed-point-v2\"",
            fixed_point,
        )
        self.assertIn(".counts.remaining_frontiers == 0", fixed_point)
        self.assertIn(
            ".counts.semantic_contracts == .counts.proposal_modules",
            fixed_point,
        )
        self.assertIn(
            "mixedOriginalDirectCallFixedPointProposalsLean =\n"
            "    mixedOriginalDirectCallClosureProposalsLean",
            lane,
        )
        self.assertIn(
            "mixedOriginalDirectCallFixedPointSemanticsLean =\n"
            "    mixedOriginalDirectCallClosureSemanticsLean",
            lane,
        )
        self.assertEqual(
            fixed_point.count("mixed-original-direct-call-proposals"),
            0,
        )
        self.assertNotIn("diff -qr", fixed_point)

    def test_gnu_hello_kernel_receipt_bundles_have_stable_nix_paths(
        self,
    ) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        receipt_start = lane.index("mkLeanTermReceipts =")
        receipt_end = lane.index("mkStaticBinaryInventory =", receipt_start)
        receipt_helper = lane[receipt_start:receipt_end]

        self.assertIn("pkgs.runCommand name", receipt_helper)
        self.assertNotIn("mkAnalysisPhase name", receipt_helper)
        self.assertNotIn("__contentAddressed", receipt_helper)

        for proof_name in (
            "mixedOriginalDirectCallSemanticsProof",
            "mixedOriginalStaticStackAuthorityProof",
            "mixedOriginalStackDynamicAuthorityProof",
        ):
            start = lane.index(f"{proof_name} = mkLeanGraph")
            end = lane.index("};", start)
            proof = lane[start:end]
            self.assertIn("contentAddressed = true;", proof)
            self.assertIn("bundleContentAddressed = false;", proof)
            self.assertIn("targetBundle = true;", proof)

        start = lane.index(
            "mixedOriginalDirectCallClosureSemanticsProof = mkLeanGraph"
        )
        end = lane.index("};", start)
        closure_proof = lane[start:end]
        self.assertIn("contentAddressed = false;", closure_proof)
        self.assertIn("bundleContentAddressed = true;", closure_proof)
        self.assertIn("targetBundle = true;", closure_proof)

    def test_gnu_hello_direct_call_fixed_point_fails_closed(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "gnu_hello_direct_call_fixed_point",
            self.gnu_hello_direct_call_fixed_point_driver,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        driver = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(driver)

        proposal = {
            "format": "stage-a-mixed-original-direct-call-proposals-v1",
            "authority": {
                "proposal_only": True,
                "standalone_acceptance_authority": False,
                "authorizing_lean_term": None,
            },
            "inputs": {
                "original_sha256": "original",
                "state_machine_sha256": "state-machine",
            },
            "request_plan": {
                "frontiers": [],
                "requests": [{
                    "callsite_rva": 0x1010,
                    "caller_rva": 0x1000,
                    "registers": ["ebx"],
                }],
                "finite_origin_entry_requests": [{
                    "callsite_rva": 0x2010,
                    "caller_rva": 0x2000,
                    "registers": ["eax"],
                }],
            },
            "planner": {
                "blockers": [],
                "proposals": [
                    {"request": {
                        "callsite_rva": 0x1010,
                        "caller_rva": 0x1000,
                        "registers": ["ebx"],
                    }},
                    {"request": {
                        "callsite_rva": 0x2010,
                        "caller_rva": 0x2000,
                        "registers": ["eax"],
                    }},
                ],
            },
            "proposal_modules": [
                {
                    "callsite_rva": 0x1010,
                    "continuation_rva": 0x1015,
                    "continuation_target_id": 2,
                    "contract_id": 0x80001010,
                    "edge_index": 10,
                    "source_rva": 0x1000,
                    "source_target_id": 1,
                },
                {
                    "callsite_rva": 0x2010,
                    "continuation_rva": 0x2015,
                    "continuation_target_id": 4,
                    "contract_id": 0x80002010,
                    "edge_index": 20,
                    "source_rva": 0x2000,
                    "source_target_id": 3,
                },
            ],
        }
        contracts = [
            {
                **module,
                "preserved_registers": (
                    []
                    if origin == "checked_finite_origin_call_summary"
                    else registers
                ),
                "callee_preserved_registers": registers,
                "target_carried_registers": (
                    registers
                    if origin == "checked_finite_origin_call_summary"
                    else []
                ),
                "preserved_caller_frame_word_offsets": [],
                "remaining_semantic_premises": [],
                "origin": origin,
                "authorizing_lean_term": {
                    "module": f"GeneratedCall{module['callsite_rva']:x}",
                    "namespace": "StageA",
                    "symbol": f"checkedCall{module['callsite_rva']:x}",
                },
            }
            for module, registers, origin in (
                (
                    proposal["proposal_modules"][0],
                    ["ebx"],
                    "checked_direct_call_summary",
                ),
                (
                    proposal["proposal_modules"][1],
                    ["eax"],
                    "checked_finite_origin_call_summary",
                ),
            )
        ]

        def check(
            proposal_payload: dict,
            contracts_payload: list[dict],
            *,
            authority_mutation=None,
        ):
            with tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                proposal_path = root / "proposal.json"
                authority_path = root / "authority.json"
                stack_dynamic_path = root / "stack-dynamic.json"
                proposal_path.write_text(
                    json.dumps(proposal_payload, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                stack_dynamic_path.write_text(
                    json.dumps({
                        "format": "stage-a-stack-dynamic-control-ir-v1",
                        "inputs": {
                            "original_pe_sha256": "original",
                            "state_machine_sha256": "state-machine",
                        },
                        "indirect_sites": [{
                            "source_rva": 0x3000,
                            "instruction_rva": 0x3010,
                            "continuation_rva": 0x3015,
                            "is_call": True,
                        }],
                    }, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                authority = {
                    "format": (
                        "stage-a-mixed-original-direct-call-"
                        "authority-bindings-v2"
                    ),
                    "report_authority": False,
                    "authority_source": "named Lean terms only",
                    "inputs": {
                        "proposal_report_sha256": sha256(
                            proposal_path.read_bytes()
                        ).hexdigest(),
                        "original_sha256": "original",
                        "state_machine_sha256": "state-machine",
                    },
                    "contracts": contracts_payload,
                }
                if authority_mutation is not None:
                    authority_mutation(authority)
                authority_path.write_text(
                    json.dumps(authority, sort_keys=True) + "\n",
                    encoding="utf-8",
                )
                return driver.check_fixed_point(
                    proposal_path, authority_path, stack_dynamic_path
                )

        self.assertEqual(
            check(proposal, contracts)["counts"]["semantic_contracts"],
            2,
        )
        finite_frame_proposal = json.loads(json.dumps(proposal))
        finite_frame_proposal["request_plan"][
            "finite_origin_entry_requests"
        ][0]["caller_frame_word_offsets"] = [32]
        finite_frame_proposal["planner"]["proposals"][1]["request"][
            "caller_frame_word_offsets"
        ] = [32]
        finite_frame_contracts = json.loads(json.dumps(contracts))
        finite_frame_contracts[1]["origin"] = (
            "checked_finite_origin_call_caller_frame_word_summary"
        )
        finite_frame_contracts[1][
            "preserved_caller_frame_word_offsets"
        ] = [32]
        self.assertEqual(
            check(finite_frame_proposal, finite_frame_contracts)["counts"][
                "semantic_contracts"
            ],
            2,
        )
        finite_frame_contracts[1][
            "preserved_caller_frame_word_offsets"
        ] = []
        with self.assertRaisesRegex(
            driver.FixedPointError,
            "does not preserve requested caller frame words",
        ):
            check(finite_frame_proposal, finite_frame_contracts)
        delegated = json.loads(json.dumps(proposal))
        delegated["request_plan"]["frontiers"] = [{
            "reason_code": (
                "caller_frame_word_requires_finite_origin_entry_authority"
            ),
            "source_rva": 0x3000,
            "instruction_rva": 0x3010,
            "target_rva": 0x3015,
        }]
        self.assertEqual(
            check(delegated, contracts)["counts"][
                "delegated_stack_dynamic_frontiers"
            ],
            1,
        )
        deferred = json.loads(json.dumps(proposal))
        deferred["request_plan"]["frontiers"] = [{
            "reason_code": "finite_origin_entry_deferred_until_checked",
            "caller_rva": 0x3000,
            "callsite_rva": 0x3010,
            "registers": [],
            "caller_frame_word_offsets": [32],
        }]
        self.assertEqual(
            check(deferred, contracts)["counts"][
                "delegated_stack_dynamic_frontiers"
            ],
            1,
        )

        corruptions = []
        missing_contract = json.loads(json.dumps(contracts))
        missing_contract.pop()
        corruptions.append(("missing contract", proposal, missing_contract, None))
        wrong_source = json.loads(json.dumps(contracts))
        wrong_source[0]["source_rva"] = 0x9999
        corruptions.append(("wrong source", proposal, wrong_source, None))
        missing_term = json.loads(json.dumps(contracts))
        missing_term[0]["authorizing_lean_term"] = None
        corruptions.append(("missing term", proposal, missing_term, None))
        frontiers = json.loads(json.dumps(proposal))
        frontiers["request_plan"]["frontiers"] = [{"reason": "unresolved"}]
        corruptions.append(("frontier", frontiers, contracts, None))
        reused_callsite = json.loads(json.dumps(proposal))
        reused_callsite["request_plan"]["finite_origin_entry_requests"][0][
            "callsite_rva"
        ] = 0x1010
        reused_callsite["planner"]["proposals"][1]["request"][
            "callsite_rva"
        ] = 0x1010
        corruptions.append(
            ("reused callsite", reused_callsite, contracts, None)
        )
        corruptions.append((
            "hash mismatch",
            proposal,
            contracts,
            lambda authority: authority["inputs"].__setitem__(
                "proposal_report_sha256", "wrong"
            ),
        ))

        for name, proposal_payload, contracts_payload, mutation in corruptions:
            with self.subTest(name=name):
                with self.assertRaises(driver.FixedPointError):
                    check(
                        proposal_payload,
                        contracts_payload,
                        authority_mutation=mutation,
                    )

    def test_gnu_hello_stack_dynamic_authority_is_fail_closed(self) -> None:
        lane = self.gnu_hello_nix.read_text(encoding="utf-8")
        lane_driver = self.gnu_hello_driver.read_text(encoding="utf-8")
        driver = self.gnu_hello_stack_dynamic_driver.read_text(
            encoding="utf-8"
        )
        hints = json.loads(
            self.gnu_hello_stack_dynamic_hints.read_text(encoding="utf-8")
        )
        start = lane.index("mixedOriginalStackDynamicAuthorityLean =")
        end = lane.index("mixedOriginalLean = mkPhase", start)
        phase = lane[start:end]

        self.assertEqual(
            hints["format"],
            "stage-a-stack-dynamic-closure-hints-v2",
        )
        self.assertEqual(len(hints["stack_hints"]), 1)
        self.assertEqual(len(hints["dynamic_hints"]), 1)
        self.assertEqual(len(hints["runtime_value_carry_routes"]), 1)
        self.assertIn("parser = argparse.ArgumentParser()", driver)
        self.assertIn("--proof-input", driver)
        self.assertIn("--direct-call-authority", driver)
        self.assertNotIn("--lane-driver", driver)
        self.assertNotIn("_mixed_original_plan_with_contracts", driver)
        self.assertIn(
            "${mixedOriginalDirectCallFixedPointProposalsLean}"
            "/stack-dynamic-control-input.json",
            phase,
        )
        self.assertIn("analyze_stack_dynamic_indirect_controls", driver)
        self.assertIn("plan_original_stack_dynamic_control_closure", driver)
        self.assertNotIn("stack_dynamic_indirect_control", lane_driver)
        self.assertIn("${stackDynamicAuthorityDriver}", phase)
        self.assertIn(".status == \"runtime-premises-required\"", phase)
        self.assertIn("(.report_status_is_authority | not)", phase)
        self.assertIn(".runtime_closure_required", phase)
        self.assertIn(".counts.runtime_premises_required == .counts.sites", phase)
        self.assertIn(
            ".counts.runtime_value_carry_required_transfers == 0",
            phase,
        )
        self.assertIn(".proof_ready", phase)
        self.assertIn("runtime-value-carry-ir.json", phase)
        self.assertIn(
            "mixedOriginalStackDynamicAuthorityProof = mkLeanGraph",
            lane,
        )
        self.assertIn("contentAddressed = true", lane)
        final = lane[end:lane.index(
            "mixedOriginalStaticReachabilityLean =", end
        )]
        self.assertIn(
            "test -e ${mixedOriginalStackDynamicAuthorityProof}",
            final,
        )
        self.assertIn("--stack-dynamic-authority-report", final)
        self.assertIn(
            "${mixedOriginalStackDynamicAuthorityLean}"
            "/original-stack-dynamic-control-closure.json",
            final,
        )
        self.assertIn(
            ".counts.stack_dynamic_runtime_premises ==",
            final,
        )
        proof_sources = lane[lane.index("proofSources = mkPhase"):]
        self.assertIn(
            "--source ${mixedOriginalStackDynamicAuthorityLean}",
            proof_sources,
        )

    def test_mixed_original_rejects_unchecked_stack_dynamic_report(self) -> None:
        specification = importlib.util.spec_from_file_location(
            "gnu_hello_roundtrip_driver_stack_dynamic",
            self.gnu_hello_driver,
        )
        self.assertIsNotNone(specification)
        self.assertIsNotNone(specification.loader)
        driver = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(driver)
        original_sha256 = "1" * 64
        state_machine_sha256 = "2" * 64
        payload = {
            "format": "stage-a-original-stack-dynamic-control-closure-v1",
            "status": "incomplete",
            "artifact_role": {
                "acceptance_authority": False,
                "report_status_closes_obligations": False,
                "runtime_premises_embedded": False,
                "static_authority_generated": True,
            },
            "inputs": {
                "original_pe_sha256": original_sha256,
                "state_machine_sha256": state_machine_sha256,
            },
            "counts": {
                "sites": 1,
                "static_authorities": 1,
                "runtime_premises_required": 1,
            },
            "sites": [{
                "stable_id": "stack-dynamic-example",
                "source_rva": 0x1000,
                "instruction_rva": 0x1004,
                "source_target_id": 7,
                "premise_type": "CompleteStackCarryPremise",
                "premise_status": "required",
                "static_authority": "lean_checked",
            }],
        }
        with tempfile.TemporaryDirectory() as temporary:
            report = Path(temporary) / "report.json"
            report.write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            checked = driver._checked_stack_dynamic_authority_report(
                report,
                original_sha256=original_sha256,
                state_machine_sha256=state_machine_sha256,
            )
            self.assertEqual(len(checked["sites"]), 1)

            payload["artifact_role"]["report_status_closes_obligations"] = True
            report.write_text(
                json.dumps(payload, sort_keys=True),
                encoding="utf-8",
            )
            with self.assertRaisesRegex(
                ValueError,
                "stack/dynamic authority report is malformed",
            ):
                driver._checked_stack_dynamic_authority_report(
                    report,
                    original_sha256=original_sha256,
                    state_machine_sha256=state_machine_sha256,
                )

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
        self.assertNotIn("caseResultBundle", corpus)
        self.assertNotIn("packResultBundle", corpus)
        self.assertIn("builtins.readFile args.preparationGraph", flake)
        self.assertNotIn(
            'builtins.readFile (args.preparation + "/module-graph.json")',
            flake,
        )
        self.assertIn(
            'result = "${caseAudits.${caseId}}/${caseResultFile}";',
            corpus,
        )
        self.assertIn(
            'result = "${proofPacks.${pack.id}}/pack-result.json";',
            corpus,
        )
        self.assertIn("args.proofDag.verdict", flake)
        self.assertNotIn('"preparation_store_path"', corpus)
        self.assertNotIn('"proof_dag_store_path"', corpus)
        self.assertNotIn('"audit_store_path"', corpus)
        self.assertNotIn('"store_path"', corpus)
        self.assertNotIn('"derivation_path"', corpus)
        self.assertNotIn("builtins.unsafeDiscardStringContext", corpus)

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

    def test_roundtrip_remote_path_is_ca_enabled_and_portable(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        builders = self.builders_file.read_text(encoding="utf-8").splitlines()

        self.assertEqual(len(builders), 2)
        self.assertTrue(
            any("acacia.tail738663.ts.net" in line for line in builders)
        )
        self.assertTrue(
            any("banksia.tail738663.ts.net" in line for line in builders)
        )
        self.assertTrue(all("big-parallel" in line for line in builders))
        memory_lanes = [
            line.split()
            for line in builders
            if "large-memory" in line.split()[5].split(",")
            and "benchmark" in line.split()[5].split(",")
        ]
        self.assertEqual(len(memory_lanes), 2)
        self.assertTrue(all(fields[3] == "16" for fields in memory_lanes))
        self.assertTrue(all(fields[6] == "-" for fields in memory_lanes))
        self.assertTrue(all("ca-derivations" in line for line in builders))
        self.assertIn("stage-a-roundtrip-lean-remote-smoke", flake)
        self.assertIn(
            "export SPAGHETTI_EXTRACTOR_STAGE_A_NIX_CONTENT_ADDRESSED=true",
            flake,
        )
        self.assertIn('--builders "@${./nix/stage-a-builders}"', flake)
        self.assertNotIn("--builders @nix/stage-a-builders", flake)
        self.assertNotIn("stage-a-roundtrip-lean-kernel-cache-ca", flake)

    def test_lean_kernel_profiles_use_exact_import_closures(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        graph = (self.repo / "nix" / "stage-a-lean-graph.nix").read_text(
            encoding="utf-8"
        )
        compact = (self.repo / "nix" / "stage-a-lean-compact.nix").read_text(
            encoding="utf-8"
        )
        profile_start = flake.index("relationalAcceptanceKernelRoots =")
        profile_end = flake.index(
            "relationalRoundtripKernelResources =", profile_start
        )
        profiles = flake[profile_start:profile_end]

        self.assertIn('"RelationalPEWorldExecution"', profiles)
        self.assertIn('"RelationalStaticTree"', profiles)
        self.assertIn('"RelationalInterpreterWholeProgramAcceptance"', profiles)
        self.assertIn(
            '"RelationalInterpreterKernelProgramLookupFrameExecutor"', profiles
        )
        self.assertIn('"RelationalInterpreterKernelProgramLookupOperation"', profiles)
        self.assertNotIn("hasPrefix", profiles)
        self.assertNotIn("builtins.filter", profiles)
        self.assertIn("selectedTargetClosureNodes", graph)
        self.assertIn('"stage-a-lean-target-bundle-v2"', graph)
        self.assertIn("target_nodes = json.loads(sys.argv[8])", graph)
        self.assertIn('"closure_nodes": sorted(closure_ids)', graph)
        self.assertIn(
            '"stage-a-direct-dependencies"',
            graph,
        )
        self.assertNotIn(
            ") (lib.imap0 (index: value: { inherit index value; }) "
            "selectedTargetClosureNodes)}",
            graph,
        )
        for executor in (graph, compact):
            self.assertIn(
                "LinkedWorldExternalProtocolEnvironmentsRefine",
                executor,
            )
            self.assertGreaterEqual(
                executor.count("AcceptanceExternalEnvironmentsRefine"),
                2,
            )
            self.assertNotIn("PE32RawProgramsObservationallyEquivalent", executor)
            self.assertNotIn("ordinaryAcceptanceReady", executor)
            self.assertNotIn(
                "linked final-theorem audit does not support protocol environments",
                executor,
            )

    def test_flake_wires_real_non_recursive_proof_callbacks(self) -> None:
        flake = self.flake_nix.read_text(encoding="utf-8")
        start = flake.index("mkRoundtripCasePreparation =")
        end = flake.index("mkStageARoundtripQualification =", start)
        callbacks = flake[start:end]

        self.assertIn(
            "import ./nix/stage-a-relational-analysis-graph.nix", callbacks
        )
        self.assertIn(
            "analysisKernelCache = "
            "stage-a-relational-analysis-ifd-kernel-cache;",
            callbacks,
        )
        self.assertNotIn("stage-a-prepare-relational", callbacks)
        self.assertIn("import ./nix/stage-a-lean-graph.nix", callbacks)
        self.assertIn('schedulingMode = "dag";', callbacks)
        self.assertIn(
            "precompiledKernel = stage-a-relational-acceptance-kernel-cache;",
            callbacks,
        )
        self.assertIn("dataflowFineGrained = false;", callbacks)
        self.assertIn("dataflowContentAddressed = false;", callbacks)
        self.assertIn("args.proofDag.verdict", callbacks)
        self.assertIn("spaghetti-extractor-roundtrip", callbacks)
        self.assertIn('targetNodes = [ negativeNode ];', callbacks)
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
        self.assertIn(
            "spaghettiExtractor = spaghetti-extractor-roundtrip;",
            qualification,
        )
        self.assertIn("spaghettiExtractorRoundtripSource =", flake)
        self.assertIn(
            "pkgs.lib.fileset.difference ./src ./src/spaghetti_extractor/lean",
            flake,
        )
        self.assertIn("caseMeasurementDefaults = {", qualification)
        self.assertIn('resourceClass = "whole-program-proof";', qualification)
        self.assertIn('resourceClass = "checked-witness";', qualification)
        self.assertIn(
            'measurementSource = "compact-spike-calibration-2026-07-22";',
            qualification,
        )

    def test_lean_graph_keeps_ca_nodes_deterministic_and_axiom_checked(self) -> None:
        graph = (self.repo / "nix" / "stage-a-lean-graph.nix").read_text(
            encoding="utf-8"
        )

        self.assertIn('outputs = [ "out" ];', graph)
        self.assertNotIn('"audit"\n                    ];', graph)
        self.assertNotIn('compile_stdout": f"logs/{module}.stdout"', graph)
        self.assertNotIn('compile_stderr": f"logs/{module}.stderr"', graph)
        self.assertNotIn('"maximum_resident_kib"', graph)
        self.assertNotIn('"resource_usage": resource_usage', graph)
        self.assertIn("${pkgs.time}/bin/time -v", graph)
        self.assertIn("Stage A Lean resource summary:", graph)
        self.assertNotIn("measureResources", graph)
        self.assertIn('"axiom_audit": {', graph)
        self.assertIn('"complete": all(value is not None', graph)
        self.assertIn(
            'ln -s "${semantic}" "$out/proof-node-root"',
            graph,
        )
        self.assertIn(
            'ln -s "${semantic}" "$out/proof-node-roots/${toString index}"',
            graph,
        )
        self.assertIn("pending = sorted(roots.iterdir())", graph)
        self.assertIn("pending.extend(", graph)
        self.assertIn("semantic Lean interface output mismatch", graph)
        self.assertIn(
            'os.symlink(dependency, roots / f"{index:06d}")',
            graph,
        )
        self.assertIn('"materialized_oleans": 0', graph)
        self.assertIn('"archive_bytes": 0', graph)
        self.assertIn('"stage-a-relational-proof-verdict-v1"', graph)
        self.assertIn('"compact proof verdict retained Nix store references', graph)
        self.assertIn('"out"\n            "verdict"', graph)
        self.assertIn('cp "$out/audit.json" "$verdict/audit.json"', graph)
        self.assertNotIn("dependency-pack", graph)
        self.assertIn('contentAddressed ? true', graph)
        self.assertIn(
            'bundleContentAddressed ? contentAddressed',
            graph,
        )
        self.assertIn(
            'lib.optionalAttrs bundleContentAddressed '
            '{ __contentAddressed = true; }',
            graph,
        )
        self.assertIn("self.${dependency}.stable", graph)
        self.assertNotIn('"stage-a-lean-${node.id}-stable"', graph)
        self.assertIn("stable = rawDrv.out;", graph)
        self.assertNotIn("stableAudit", graph)
        self.assertIn(
            ': > "$out/nix-support/stage-a-direct-dependencies"', graph
        )
        self.assertIn("module-build-packs.json", graph)
        self.assertIn("stage-a-lean-build-packs-v1", graph)
        self.assertRegex(graph, r"standaloneSource\s*=\s*module:")
        self.assertIn("builtins.toFile", graph)
        self.assertIn("builtins.unsafeDiscardStringContext", graph)
        self.assertNotIn("passAsFile = sourceNames", graph)
        self.assertIn('"stage-a-source-pack-${packId}")', graph)
        self.assertIn('sourceRoot + "/source-pack-data/${packId}.json"', graph)
        self.assertIn('"stage-a-lean-source-pack-v1"', graph)
        self.assertNotIn(
            '"${standaloneRoot}/source-packs/${packId}/." "$out/"',
            graph,
        )
        self.assertRegex(
            graph,
            r"if standalone then\s+standaloneSource module\s+"
            r"else if metadata \? source_pack then",
        )
        self.assertIn(
            'lib.optionalAttrs contentAddressed { __contentAddressed = true; }',
            graph,
        )
        self.assertIn('2> >(tee "logs/${module}.stderr" >&2)', graph)

    def test_lean_graph_metadata_reads_only_the_aggregate_source_root(
        self,
    ) -> None:
        graph = (self.repo / "nix" / "stage-a-lean-graph.nix").read_text(
            encoding="utf-8"
        )

        self.assertRegex(
            graph,
            r'standaloneMetadataSource\s*=\s*module:\s*'
            r'standaloneSourceRoot \+ "/\$\{module\}\.lean";',
        )
        self.assertIn(
            "builtins.readFile (standaloneMetadataSource module)",
            graph,
        )
        self.assertIn(
            'builtins.hashFile "sha256" (standaloneMetadataSource module)',
            graph,
        )
        self.assertNotIn(
            "builtins.readFile (standaloneSource module)",
            graph,
        )
        self.assertNotIn(
            'builtins.hashFile "sha256" (standaloneSource module)',
            graph,
        )
    @unittest.skipUnless(shutil.which("nix"), "Nix is unavailable")
    def test_lean_graph_evaluation_forces_only_target_canonical_source(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            aggregate = root / "aggregate"
            sources = aggregate / "StageA"
            sources.mkdir(parents=True)
            target_source = "def targetValue := true\n"
            unrelated_source = "def unrelatedValue := true\n"
            (sources / "Target.lean").write_text(
                target_source,
                encoding="ascii",
            )
            (sources / "Unrelated.lean").write_text(
                unrelated_source,
                encoding="ascii",
            )
            build_packs = {
                "format": "stage-a-lean-build-packs-v1",
                "modules": {
                    "Target": "target-pack",
                    "Unrelated": "unrelated-pack",
                },
                "packs": {
                    "target-pack": ["Target"],
                    "unrelated-pack": ["Unrelated"],
                },
            }
            (aggregate / "module-build-packs.json").write_text(
                json.dumps(build_packs),
                encoding="ascii",
            )
            expression = root / "target-node.nix"
            expression.write_text(
                textwrap.dedent(
                    f"""
                    let
                      pkgs = import <nixpkgs> {{
                        system = builtins.currentSystem;
                      }};
                      results = import {self.repo / "nix" / "stage-a-lean-graph.nix"} {{
                        inherit pkgs;
                        standaloneSourceRoot =
                          builtins.toPath {json.dumps(str(sources))};
                        standaloneModules = [ "Target" "Unrelated" ];
                        targetNodes = [ "Target" ];
                        contentAddressed = false;
                      }};
                    in
                    builtins.head results
                    """
                ),
                encoding="utf-8",
            )
            detached = subprocess.run(
                [
                    "nix",
                    "derivation",
                    "show",
                    "--impure",
                    "--file",
                    str(expression),
                ],
                cwd=self.repo,
                env=self._hermetic_nix_eval_env(root),
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(detached.returncode, 0, detached.stderr)
            detached_document = json.loads(detached.stdout)
            detached_derivations = detached_document.get(
                "derivations",
                detached_document,
            )
            self.assertFalse(
                any(
                    path.endswith(".drv") and "stage-a-source-pack-" in path
                    for path in detached_derivations
                ),
                list(detached_derivations),
            )
            detached_payloads = [
                payload
                for path, payload in detached_derivations.items()
                if path.endswith(
                    "-stage-a-lean-target-pack-detached.drv"
                )
            ]
            self.assertEqual(
                len(detached_payloads),
                1,
                list(detached_derivations),
            )
            detached_payload = detached_payloads[0]
            detached_input_drvs = (
                detached_payload["inputDrvs"]
                if "inputDrvs" in detached_payload
                else detached_payload["inputs"]["drvs"]
            )
            target_node_drvs = [
                path if path.startswith("/") else f"/nix/store/{path}"
                for path in detached_input_drvs
                if path.endswith("-stage-a-lean-target-pack.drv")
            ]
            self.assertEqual(len(target_node_drvs), 1)
            target_node = subprocess.run(
                ["nix", "derivation", "show", target_node_drvs[0]],
                cwd=self.repo,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
            self.assertEqual(target_node.returncode, 0, target_node.stderr)
            target_document = json.loads(target_node.stdout)
            target_derivations = target_document.get(
                "derivations",
                target_document,
            )
            target_payload = next(iter(target_derivations.values()))
            input_sources = (
                target_payload["inputSrcs"]
                if "inputSrcs" in target_payload
                else target_payload["inputs"]["srcs"]
            )
            self.assertTrue(
                any(
                    path.endswith("-stage-a-source-Target.lean")
                    for path in input_sources
                )
            )
            self.assertFalse(
                any(
                    path.endswith("-stage-a-source-Unrelated.lean")
                    for path in input_sources
                )
            )

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

        self.assertIn("candidatePE32ProgramsEquivalentLinked\"", corpus)
        self.assertNotIn("candidatePE32ProgramsEquivalent\"", corpus)
        self.assertIn(
            'acceptance.get("theorem")\n'
            '                    == "StageA.GeneratedRelational.'
            'candidatePE32ProgramsEquivalentLinked"',
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
                env=self._hermetic_nix_eval_env(root),
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
                env=self._hermetic_nix_eval_env(root),
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
            "store_path" not in pack
            and "derivation_path" not in pack
            for pack in report["packs"]
        ), report["packs"])
        self.assertTrue(all(
            "preparation_store_path" not in case
            and "preparation_derivation_path" not in case
            and "proof_dag_store_path" not in case
            and "proof_dag_derivation_path" not in case
            and "audit_store_path" not in case
            and "audit_derivation_path" not in case
            for case in report["cases"]
        ))
        self.assertEqual(len(plan["packs"]), 3)
        references = subprocess.run(
            ["nix-store", "-q", "--references", str(output)],
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
        )
        self.assertEqual(references.returncode, 0, references.stderr)
        self.assertEqual(references.stdout.strip(), "")

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
                          theorem = "StageA.GeneratedRelational.candidatePE32ProgramsEquivalentLinked";
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
