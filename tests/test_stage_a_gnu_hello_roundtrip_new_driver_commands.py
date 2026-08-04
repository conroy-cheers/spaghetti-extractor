from __future__ import annotations

import contextlib
import importlib.util
import io
import unittest
from pathlib import Path
from unittest import mock


REPO = Path(__file__).parents[1]
DRIVER_PATH = REPO / "targets/gnu-hello/nix/gnu-hello-roundtrip-driver.py"
SPEC = importlib.util.spec_from_file_location(
    "gnu_hello_roundtrip_new_driver_commands", DRIVER_PATH
)
assert SPEC is not None and SPEC.loader is not None
DRIVER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRIVER)


class StageAGnuHelloRoundTripNewDriverCommandTests(unittest.TestCase):
    def _run(self, arguments: list[str]):
        args = DRIVER._parser().parse_args(arguments)
        args.run(args)
        return args

    @mock.patch.object(DRIVER, "generate_runtime_memory_access_proposal")
    def test_runtime_memory_proposal_routes_exact_inputs(self, generate) -> None:
        self._run(
            [
                "runtime-memory-access-proposal",
                "--state-machine",
                "state-machine.jsonl",
                "--mixed-original-plan",
                "mixed.json",
                "--source-target-effect-declarations",
                "effects.json",
                "--out",
                "result",
            ]
        )
        generate.assert_called_once_with(
            "result",
            state_machine="state-machine.jsonl",
            mixed_original_plan="mixed.json",
            source_target_effect_declarations="effects.json",
        )

    @mock.patch.object(DRIVER, "generate_original_target_control_evidence")
    def test_original_control_evidence_routes_exact_inputs(self, generate) -> None:
        self._run(
            [
                "original-target-control-evidence",
                "--source-target-effect-declarations",
                "effects.json",
                "--transition-index-manifest",
                "transition.json",
                "--state-machine",
                "state-machine.jsonl",
                "--combined-target-inventory",
                "combined.json",
                "--shard-size",
                "97",
                "--out",
                "result",
            ]
        )
        generate.assert_called_once_with(
            "result",
            source_target_effect_declarations="effects.json",
            transition_index_manifest="transition.json",
            state_machine="state-machine.jsonl",
            combined_target_inventory="combined.json",
            shard_size=97,
        )

    @mock.patch.object(
        DRIVER, "generate_gnu_hello_original_target_preservation"
    )
    def test_original_target_preservation_routes_checked_inputs(
        self, generate
    ) -> None:
        self._run(
            [
                "original-target-preservation",
                "--state-machine",
                "state-machine.jsonl",
                "--source-target-effect-declarations",
                "effects.json",
                "--transition-index-manifest",
                "transition.json",
                "--combined-inventory-manifest",
                "combined.json",
                "--authority",
                "runtime=runtime.json",
                "--authority",
                "control=control.json",
                "--shard-size",
                "97",
                "--out",
                "result",
            ]
        )
        generate.assert_called_once_with(
            "result",
            state_machine="state-machine.jsonl",
            source_target_effect_declarations="effects.json",
            transition_index_manifest="transition.json",
            combined_inventory_manifest="combined.json",
            authority_artifacts={
                "runtime": "runtime.json",
                "control": "control.json",
            },
            shard_size=97,
        )

    @mock.patch.object(DRIVER, "generate_original_source_launch_context")
    def test_original_source_launch_context_routes_checked_inputs(
        self, generate
    ) -> None:
        self._run(
            [
                "original-source-launch-context",
                "--combined-inventory-manifest",
                "combined.json",
                "--transition-index-manifest",
                "transition.json",
                "--compiled-authority-declarations",
                "compiled.json",
                "--runtime-foundation-manifest",
                "runtime.json",
                "--target-step-manifest",
                "steps.json",
                "--protocol-responses-declarations",
                "responses.json",
                "--preservation-input",
                "control=control.json",
                "--out",
                "result",
            ]
        )
        generate.assert_called_once_with(
            "result",
            combined_inventory_manifest="combined.json",
            transition_index_manifest="transition.json",
            compiled_authority_declarations="compiled.json",
            runtime_foundation_manifest="runtime.json",
            target_step_manifest="steps.json",
            protocol_responses_declarations="responses.json",
            preservation_inputs={"control": "control.json"},
        )

    def test_named_paths_rejects_duplicate_authority_names(self) -> None:
        with self.assertRaisesRegex(ValueError, "duplicate authority"):
            self._run(
                [
                    "original-target-preservation",
                    "--state-machine",
                    "state-machine.jsonl",
                    "--source-target-effect-declarations",
                    "effects.json",
                    "--transition-index-manifest",
                    "transition.json",
                    "--combined-inventory-manifest",
                    "combined.json",
                    "--authority",
                    "control=one.json",
                    "--authority",
                    "control=two.json",
                    "--out",
                    "result",
                ]
            )

    @mock.patch.object(DRIVER, "write_native_source_nested_compiler_premise")
    def test_nested_compiler_premise_routes_checked_type(self, write) -> None:
        self._run(
            [
                "native-source-nested-compiler-premise",
                "--response-family-module",
                "StageA.CheckedResponses",
                "--premise-type",
                "StageA.CheckedResponses.PinnedPremise",
                "--out",
                "result",
            ]
        )
        spec = write.call_args.args[1]
        self.assertEqual(write.call_args.args[0], "result")
        self.assertEqual(spec.response_family_module, "StageA.CheckedResponses")
        self.assertEqual(
            spec.premise_type, "StageA.CheckedResponses.PinnedPremise"
        )

    @mock.patch.object(DRIVER, "write_native_source_nested_acceptance")
    def test_nested_acceptance_routes_exact_terms(self, write) -> None:
        self._run(
            [
                "native-source-nested-acceptance",
                "--import",
                "StageA.CheckedResponses",
                "--import",
                "StageA.CompilerPremise",
                "--context",
                "StageA.CheckedResponses.context",
                "--classified-sites",
                "StageA.CheckedResponses.classifiedSites",
                "--ordinary-sites",
                "StageA.CheckedResponses.ordinarySites",
                "--static-compilation",
                "StageA.CheckedResponses.compilation",
                "--mixed-contract",
                "StageA.CheckedResponses.mixed",
                "--nested-frames",
                "StageA.CheckedResponses.frames",
                "--checked-response-family",
                "StageA.CheckedResponses.family",
                "--checked-response-family-completion",
                "StageA.CheckedResponses.completion",
                "--toolchain-correct",
                "StageA.CompilerPremise.pinnedCompilerLoweringCorrect",
                "--out",
                "result",
            ]
        )
        spec = write.call_args.args[1]
        self.assertEqual(write.call_args.args[0], "result")
        self.assertEqual(
            spec.imports,
            ("StageA.CheckedResponses", "StageA.CompilerPremise"),
        )
        self.assertEqual(
            spec.checked_response_family_completion,
            "StageA.CheckedResponses.completion",
        )
        self.assertEqual(
            spec.toolchain_correct,
            "StageA.CompilerPremise.pinnedCompilerLoweringCorrect",
        )

    @mock.patch.object(DRIVER, "generate_gnu_hello_source_transition_index")
    def test_source_transition_index_routes_exact_inputs(self, generate) -> None:
        self._run(
            [
                "source-transition-index",
                "--mixed-original-manifest",
                "mixed.json",
                "--source-program-manifest",
                "source.json",
                "--normalization-manifest",
                "normalization.json",
                "--x87-manifest",
                "x87.json",
                "--declaration-inventory",
                "declarations.json",
                "--out",
                "result",
            ]
        )
        generate.assert_called_once_with(
            "result",
            mixed_original_manifest="mixed.json",
            source_program_manifest="source.json",
            normalization_manifest="normalization.json",
            x87_manifest="x87.json",
            declaration_inventory="declarations.json",
        )

    @mock.patch.object(
        DRIVER, "generate_gnu_hello_source_target_effect_inputs"
    )
    def test_source_target_effect_inputs_routes_exact_artifacts(self, generate) -> None:
        self._run(
            [
                "source-target-effect-inputs",
                "--state-machine",
                "state-machine.jsonl",
                "--mixed-original-plan",
                "mixed.json",
                "--source-program-root",
                "source-root",
                "--source-program-manifest",
                "source.json",
                "--normalization-root",
                "normalization-root",
                "--normalization-inventory",
                "normalization.json",
                "--semantic-refinement-root",
                "semantic-root",
                "--semantic-refinement-inventory",
                "semantic.json",
                "--x87-root",
                "x87-root",
                "--x87-inventory",
                "x87.json",
                "--exact-original-root",
                "exact-original-root",
                "--shard-span",
                "97",
                "--out",
                "result",
            ]
        )
        generate.assert_called_once_with(
            "result",
            state_machine="state-machine.jsonl",
            mixed_original_plan="mixed.json",
            source_program_root="source-root",
            source_program_manifest="source.json",
            normalization_root="normalization-root",
            normalization_inventory="normalization.json",
            semantic_refinement_root="semantic-root",
            semantic_refinement_inventory="semantic.json",
            x87_root="x87-root",
            x87_inventory="x87.json",
            exact_original_root="exact-original-root",
            shard_span=97,
        )

    @mock.patch.object(
        DRIVER, "generate_gnu_hello_source_target_effect_inputs"
    )
    def test_source_target_effect_inputs_uses_stable_shard_default(
        self, generate
    ) -> None:
        self._run(
            [
                "source-target-effect-inputs",
                "--state-machine",
                "state-machine.jsonl",
                "--mixed-original-plan",
                "mixed.json",
                "--source-program-root",
                "source-root",
                "--source-program-manifest",
                "source.json",
                "--normalization-root",
                "normalization-root",
                "--normalization-inventory",
                "normalization.json",
                "--semantic-refinement-root",
                "semantic-root",
                "--semantic-refinement-inventory",
                "semantic.json",
                "--x87-root",
                "x87-root",
                "--x87-inventory",
                "x87.json",
                "--exact-original-root",
                "exact-original-root",
                "--out",
                "result",
            ]
        )
        self.assertEqual(generate.call_args.kwargs["shard_span"], 64)

    @mock.patch.object(DRIVER, "write_original_combined_inventory")
    def test_original_combined_inventory_routes_every_authority(self, write) -> None:
        self._run(
            [
                "original-combined-inventory",
                "--mixed-original-plan",
                "mixed.json",
                "--writable-authority-report",
                "writable-report.json",
                "--writable-authority-manifest",
                "writable-manifest.json",
                "--register-authority-report",
                "register-report.json",
                "--register-authority-manifest",
                "register-manifest.json",
                "--stack-dynamic-authority-report",
                "stack-report.json",
                "--stack-dynamic-authority-manifest",
                "stack-manifest.json",
                "--stack-combined-evidence-report",
                "stack-combined.json",
                "--reachability-declarations",
                "reachability.json",
                "--call-frame-declarations",
                "frames.json",
                "--value-flow-declarations",
                "flows.json",
                "--shard-size",
                "97",
                "--out",
                "result",
            ]
        )
        write.assert_called_once_with(
            Path("result"),
            mixed_original_plan=Path("mixed.json"),
            writable_authority_report=Path("writable-report.json"),
            writable_authority_manifest=Path("writable-manifest.json"),
            register_authority_report=Path("register-report.json"),
            register_authority_manifest=Path("register-manifest.json"),
            stack_dynamic_authority_report=Path("stack-report.json"),
            stack_dynamic_authority_manifest=Path("stack-manifest.json"),
            stack_combined_evidence_report=Path("stack-combined.json"),
            reachability_declarations=Path("reachability.json"),
            call_frame_declarations=Path("frames.json"),
            value_flow_declarations=Path("flows.json"),
            shard_size=97,
        )

    @mock.patch.object(
        DRIVER, "write_gnu_hello_native_source_compiled_authority_evidence"
    )
    @mock.patch.object(DRIVER.NixRealizationIdentity, "from_json")
    def test_compiled_authority_evidence_parses_realization_identities(
        self, parse_identity, write
    ) -> None:
        parse_identity.side_effect = lambda path: f"identity:{path}"
        self._run(
            [
                "native-source-compiled-authority-evidence",
                "--source-bundle",
                "bundle.json",
                "--compilation-attestation",
                "attestation.json",
                "--project-declarations",
                "project.json",
                "--candidate-static-authority",
                "static.json",
                "--runtime-declarations",
                "runtime.json",
                "--project-realization",
                "project-realization.json",
                "--profile-realization",
                "profile-realization.json",
                "--build-realization",
                "build-realization.json",
                "--out",
                "result",
            ]
        )
        self.assertEqual(
            parse_identity.call_args_list,
            [
                mock.call("project-realization.json"),
                mock.call("profile-realization.json"),
                mock.call("build-realization.json"),
            ],
        )
        write.assert_called_once_with(
            source_bundle="bundle.json",
            compilation_attestation="attestation.json",
            project_declarations="project.json",
            candidate_static_authority="static.json",
            runtime_declarations="runtime.json",
            project_realization="identity:project-realization.json",
            profile_realization="identity:profile-realization.json",
            build_realization="identity:build-realization.json",
            out="result",
        )

    @mock.patch.object(
        DRIVER, "write_gnu_hello_native_source_environment_family_inputs"
    )
    def test_environment_family_inputs_routes_exact_artifacts(self, write) -> None:
        self._run(
            [
                "native-source-environment-family-inputs",
                "--source-execution-manifest",
                "execution.json",
                "--compiled-authority-manifest",
                "authority.json",
                "--source-bundle-manifest",
                "bundle.json",
                "--candidate-runtime-declarations",
                "runtime.json",
                "--candidate-static-authority",
                "static.json",
                "--out",
                "result",
            ]
        )
        write.assert_called_once_with(
            "result",
            source_execution_manifest="execution.json",
            compiled_authority_manifest="authority.json",
            source_bundle_manifest="bundle.json",
            candidate_runtime_declarations="runtime.json",
            candidate_static_authority="static.json",
        )

    @mock.patch.object(DRIVER, "write_gnu_hello_native_source_environment_family")
    def test_environment_family_routes_adapter_and_evidence(self, write) -> None:
        self._run(
            [
                "native-source-environment-family",
                "--compiled-authority-manifest",
                "authority.json",
                "--source-execution-manifest",
                "execution.json",
                "--source-bundle-manifest",
                "bundle.json",
                "--environment-inputs",
                "environment.json",
                "--out",
                "result",
            ]
        )
        write.assert_called_once_with(
            "result",
            compiled_authority_manifest="authority.json",
            source_execution_manifest="execution.json",
            source_bundle_manifest="bundle.json",
            environment_inputs="environment.json",
        )

    @mock.patch(
        "spaghetti_extractor.relational.lean.source_equivalence_final_report."
        "write_source_equivalence_final_report"
    )
    def test_final_report_routes_checked_evidence(self, write) -> None:
        self._run(
            [
                "source-equivalence-final-report",
                "--checked-acceptance",
                "acceptance.json",
                "--detached-axiom-audit",
                "audit.json",
                "--source-bundle",
                "bundle.json",
                "--compilation-attestation",
                "attestation.json",
                "--candidate-pe-metadata",
                "candidate.json",
                "--functional-report",
                "functional.json",
                "--approved-toolchain-axiom",
                "StageA.Generated.CompilerCorrect",
                "--out",
                "result",
            ]
        )
        write.assert_called_once_with(
            out="result",
            checked_acceptance="acceptance.json",
            detached_axiom_audit="audit.json",
            source_bundle="bundle.json",
            compilation_attestation="attestation.json",
            candidate_pe_metadata="candidate.json",
            functional_report="functional.json",
            approved_toolchain_axiom="StageA.Generated.CompilerCorrect",
        )

    def test_required_semantic_inputs_fail_closed_at_the_parser(self) -> None:
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            DRIVER._parser().parse_args(
                [
                    "source-transition-index",
                    "--mixed-original-manifest",
                    "mixed.json",
                    "--out",
                    "result",
                ]
            )

        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            DRIVER._parser().parse_args(
                [
                    "source-target-effect-inputs",
                    "--state-machine",
                    "state-machine.jsonl",
                    "--out",
                    "result",
                ]
            )


if __name__ == "__main__":
    unittest.main()
