from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_exact_decoded_native_components import (
    INTERPRETER_EXACT_DECODED_NATIVE_COMPONENTS_MODULE,
    InterpreterExactDecodedNativeComponentsGenerationError,
    InterpreterExactDecodedNativeComponentsSpec,
    relational_interpreter_exact_decoded_native_components_source,
    write_relational_interpreter_exact_decoded_native_components,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


def _copy_module_closure(source_root: Path, destination: Path, module: str) -> None:
    pending = [module]
    copied: set[str] = set()
    while pending:
        current = pending.pop()
        if current in copied:
            continue
        source = source_root / f"{current}.lean"
        text = source.read_text(encoding="utf-8")
        shutil.copyfile(source, destination / source.name)
        copied.add(current)
        pending.extend(_IMPORT.findall(text))


def _spec(
    **changes: str | None,
) -> InterpreterExactDecodedNativeComponentsSpec:
    base = InterpreterExactDecodedNativeComponentsSpec(
        binding_module="StageA.Bindings",
        namespace="StageA.Generated.ExactDecodedNativeComponents",
        context="requirements.context",
        graph="requirements.graph",
        regions="requirements.regions",
        reachability="requirements.reachability",
        reachability_target_ids="requirements.reachabilityTargetIds",
        external_call_sites="requirements.externalCallSites",
        launch="requirements.launch",
        candidate_environment="requirements.candidateEnvironment",
        candidate_protocol_environment=(
            "requirements.candidateProtocolEnvironment"
        ),
        native_program="requirements.nativeProgram",
        candidate_pe_bound="requirements.candidatePeBound",
        candidate_imports_bound="requirements.candidateImportsBound",
        native_authority="requirements.nativeAuthority",
        program_table="requirements.programTable",
        kernel_core="requirements.kernelCore",
        operations="requirements.operations",
        candidate_root_rva="requirements.candidateRootRva",
        candidate_root="requirements.candidateRoot",
        frame_count="requirements.frameCount",
        invariant="requirements.invariant",
        classifier="requirements.classifier",
        roots_related="requirements.rootsRelated",
        launch_component="requirements.launchComponent",
        operation_component="requirements.operationComponent",
        external_component="requirements.externalComponent",
        x87_component="requirements.x87Component",
        requirement_parameter="requirements",
        requirement_type="StageA.Bindings.RequiredTerms",
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterExactDecodedNativeComponentsTests(
    unittest.TestCase
):
    def test_layer_checks_family_coverage_and_uses_typed_certificates(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterExactDecodedNativeComponents.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "exactDecodedNativeExecutableFamily?",
            "pe32WorldRegionBehaviorWithCalls",
            "exactDecodedNativeOperationAtNode?",
            "ExactDecodedNativeTotalClassifier",
            "ExactDecodedNativeLaunchComponentCertificate",
            "ReflectedNativeLaunchPathCertificate",
            "ExactDecodedNativeOperationComponentCertificate",
            "MixedKernelOperationComponentCertificate",
            "ExactDecodedNativeExternalComponentCertificate",
            "ExactMixedExternalInteractionChunk",
            "ExactDecodedNativeX87ComponentCertificate",
            "ExactNativeX87ReplayBridgeRun",
            "observationsExact",
            "afterRelated",
            "toComponentPremises",
        ):
            self.assertIn(required, source)

        source_cases = source.split(
            "inductive ExactDecodedNativeCheckedSourceCase", 1
        )[1].split("structure ExactDecodedNativeTotalClassifier", 1)[0]
        for forbidden_case in (
            "unknown",
            "fallback",
            "other",
            "blocked",
            "callbackRunning",
            "awaitingExternal",
        ):
            self.assertNotRegex(source_cases, rf"\|\s*{forbidden_case}\b")

        for forbidden in (
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\badmit\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_exposes_only_checked_family_inputs(self) -> None:
        source = relational_interpreter_exact_decoded_native_components_source(
            _spec()
        )

        for required in (
            "ExactDecodedNativeComponentAssembly",
            "invariant :=",
            "classifier :=",
            "launchComponent :=",
            "operationComponent :=",
            "externalComponent :=",
            "x87Component :=",
            "toComponentPremises",
            "toChunkAdapter",
        ):
            self.assertIn(required, source)
        for removed_broad_input in (
            "launchChunk :=",
            "kernelChunk :=",
            "externalBoundaryChunk :=",
            "x87ReplayChunk :=",
        ):
            self.assertNotIn(removed_broad_input, source)
        for forbidden in (r"\bsorry\b", r"\bstatus\b", r"\bverdict\b"):
            self.assertNotRegex(source, forbidden)

    def test_writer_is_deterministic(self) -> None:
        spec = _spec()
        expected = relational_interpreter_exact_decoded_native_components_source(
            spec
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_relational_interpreter_exact_decoded_native_components(
                root, spec
            )
            first_bytes = first.read_bytes()
            second = write_relational_interpreter_exact_decoded_native_components(
                root, spec
            )
            second_bytes = second.read_bytes()

        self.assertEqual(
            first.name,
            f"{INTERPRETER_EXACT_DECODED_NATIVE_COMPONENTS_MODULE}.lean",
        )
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_generator_rejects_malformed_names(self) -> None:
        for change in (
            {"binding_module": "Bindings"},
            {"namespace": "StageA.Bad-Namespace"},
            {"classifier": "requirements.bad term"},
            {"assembly_name": "StageA.assembly"},
            {"requirement_type": None},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    InterpreterExactDecodedNativeComponentsGenerationError
                ):
                    relational_interpreter_exact_decoded_native_components_source(
                        _spec(**change)
                    )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_layer_compiles_and_has_only_approved_axioms(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalInterpreterExactDecodedNativeComponents",
            )
            (
                stage_a
                / "RelationalInterpreterExactDecodedNativeComponentsAudit.lean"
            ).write_text(_AUDIT_FIXTURE, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle=(
                    "RelationalInterpreterExactDecodedNativeComponentsAudit"
                ),
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for theorem in (
            "exactDecodedNativeIdentityObservationLists_eq",
            "ExactComputedNonemptySegment.path",
            "ExactDecodedNativeLaunchComponentCertificate.toChunk",
            "ExactDecodedNativeOperationComponentCertificate.toChunk",
            "ExactDecodedNativeExternalComponentCertificate.toChunk",
            "ExactDecodedNativeX87ComponentCertificate.toChunk",
            "ExactDecodedNativeComponentAssembly.component",
            "ExactDecodedNativeComponentAssembly.toComponentPremises",
        ):
            self.assertIn(theorem, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_AUDIT_FIXTURE = r"""import StageA.RelationalInterpreterExactDecodedNativeComponents

namespace StageA.Relational.InterpreterExactDecodedNativeComponentsAudit

open StageA.Relational.InterpreterExactDecodedNativeComponents

#check exactDecodedNativeExecutableFamily?
#check ExactDecodedNativeCheckedSourceCase
#check ExactDecodedNativeTotalClassifier
#check ExactComputedNonemptySegment
#check ExactComputedNonemptySegment.path
#check ExactDecodedNativeLaunchComponentCertificate
#check ExactDecodedNativeOperationComponentCertificate
#check ExactDecodedNativeExternalComponentCertificate
#check ExactDecodedNativeX87ComponentCertificate
#check ExactDecodedNativeComponentAssembly
#check ExactDecodedNativeComponentAssembly.component
#check ExactDecodedNativeComponentAssembly.toComponentPremises

#print axioms exactDecodedNativeIdentityObservationLists_eq
#print axioms ExactComputedNonemptySegment.path
#print axioms ExactDecodedNativeLaunchComponentCertificate.toChunk
#print axioms ExactDecodedNativeOperationComponentCertificate.toChunk
#print axioms ExactDecodedNativeExternalComponentCertificate.toChunk
#print axioms ExactDecodedNativeX87ComponentCertificate.toChunk
#print axioms ExactDecodedNativeComponentAssembly.component
#print axioms ExactDecodedNativeComponentAssembly.toComponentPremises

end StageA.Relational.InterpreterExactDecodedNativeComponentsAudit
"""


if __name__ == "__main__":
    unittest.main()
