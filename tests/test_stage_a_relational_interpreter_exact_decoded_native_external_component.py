from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_exact_decoded_native_external_component import (
    INTERPRETER_EXACT_DECODED_NATIVE_EXTERNAL_COMPONENT_MODULE,
    InterpreterExactDecodedNativeExternalComponentGenerationError,
    InterpreterExactDecodedNativeExternalComponentSpec,
    relational_interpreter_exact_decoded_native_external_component_source,
    write_relational_interpreter_exact_decoded_native_external_component,
)
from spaghetti_extractor.relational.schema import RELATIONAL_APPROVED_AXIOMS


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOM_LINE = re.compile(r"depends on axioms: \[([^\]]*)\]", re.MULTILINE)


def _copy_module_closure(
    source_root: Path, destination: Path, module: str
) -> None:
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
) -> InterpreterExactDecodedNativeExternalComponentSpec:
    base = InterpreterExactDecodedNativeExternalComponentSpec(
        binding_module="StageA.Bindings",
        namespace="StageA.Generated.ExactDecodedNativeExternalComponent",
        decoded_template="requirements.decodedTemplate",
        native_template="requirements.nativeTemplate",
        invariant="requirements.invariant",
        program="requirements.program",
        launch="requirements.launch",
        frames="requirements.frames",
        remaining="requirements.remaining",
        requirement_parameter="requirements",
        requirement_type="StageA.Bindings.RequiredTerms",
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterExactDecodedNativeExternalComponentTests(
    unittest.TestCase
):
    def test_lean_bridge_keeps_only_exact_remaining_boundary_facts(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterExactDecodedNativeExternalComponent.lean"
        ).read_text(encoding="utf-8")

        premise_body = source.split(
            "structure ExactDecodedNativeExternalComponentRemainingPremises", 1
        )[1].split(
            "def exactDecodedNativeExternalComponentCertificateOfRefinement", 1
        )[0]
        for required in (
            "suspension : WorldExternalSuspension",
            "dispatch : ExactNativeExternalDispatch native",
            "originalDispatch : ExactOriginalExternalDispatch",
            "nativeBeforeExact : dispatch.before = nativeBefore",
            "boundaryRelated :",
            "frameBoundary : MixedExternalFrameBoundaryRelated",
            "afterRelated : invariant.holds",
        ):
            self.assertIn(required, premise_body)
        for redundant in (
            "callbacks :",
            "interaction :",
            "originalPath :",
            "candidatePath :",
            "observationsRelated :",
            "observationsExact :",
            "successorsRelated :",
            "actionsRelated :",
            "beforeRelated :",
            "classified :",
        ):
            self.assertNotIn(redundant, premise_body)

        for required in (
            "ExactOneToOneMixedExternalEnvironmentsRefine",
            "ExactMixedExternalInteractionChunk",
            "exactMixedExternalInteractionChunk",
            "callbacks := []",
            "ExactDecodedNativeExternalComponentCertificate",
            "exactDecodedNativeExecutableFamily?",
            "some .externalBoundary",
            "forall originalEnvironment candidateEnvironment",
            "decodedWorldProgramWithProtocolEnvironment",
            "exactNativeWorldProgramWithEnvironment",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\breport\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_emits_universal_refining_environment_theorem(
        self,
    ) -> None:
        source = (
            relational_interpreter_exact_decoded_native_external_component_source(
                _spec()
            )
        )

        for required in (
            "ExactDecodedNativeExternalBoundaryPremisesForRefiningEnvironments",
            "requirements.remaining",
            "ExactDecodedNativeExternalComponentFactoriesForRefiningEnvironments",
            "exactDecodedNativeExternalComponentFactoriesForRefiningEnvironments",
            "ExactDecodedNativeExternalComponentsForRefiningEnvironments",
            "exactDecodedNativeExternalComponentForRefiningEnvironments",
            "#print axioms",
        ):
            self.assertIn(required, source)
        for forbidden in (
            "originalEnvironment :=",
            "candidateEnvironment :=",
            "interaction :=",
            "originalPath :=",
            "candidatePath :=",
            "observationsExact :=",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\breport\b",
        ):
            if forbidden.startswith("\\b"):
                self.assertNotRegex(source, forbidden)
            else:
                self.assertNotIn(forbidden, source)

    def test_writer_is_deterministic(self) -> None:
        spec = _spec()
        expected = (
            relational_interpreter_exact_decoded_native_external_component_source(
                spec
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = (
                write_relational_interpreter_exact_decoded_native_external_component(
                    root, spec
                )
            )
            first_bytes = first.read_bytes()
            second = (
                write_relational_interpreter_exact_decoded_native_external_component(
                    root, spec
                )
            )
            second_bytes = second.read_bytes()

        self.assertEqual(
            first.name,
            f"{INTERPRETER_EXACT_DECODED_NATIVE_EXTERNAL_COMPONENT_MODULE}.lean",
        )
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_generator_rejects_malformed_names(self) -> None:
        for change in (
            {"binding_module": "Bindings"},
            {"namespace": "StageA.Bad-Namespace"},
            {"remaining": "requirements.remaining; false"},
            {"premises_name": "StageA.premises"},
            {"factories_name": "def"},
            {"theorem_name": "theorem"},
            {"requirement_type": None},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    InterpreterExactDecodedNativeExternalComponentGenerationError
                ):
                    relational_interpreter_exact_decoded_native_external_component_source(
                        _spec(**change)
                    )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_bridge_and_generated_theorem_compile_with_approved_axioms(
        self,
    ) -> None:
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
                "RelationalInterpreterExactDecodedNativeExternalComponent",
            )
            (stage_a / "Bindings.lean").write_text(
                _BINDINGS_FIXTURE, encoding="utf-8"
            )
            generated = (
                INTERPRETER_EXACT_DECODED_NATIVE_EXTERNAL_COMPONENT_MODULE
            )
            (stage_a / f"{generated}.lean").write_text(
                relational_interpreter_exact_decoded_native_external_component_source(
                    _spec()
                ),
                encoding="utf-8",
            )
            result = _run_lean_relational(root, bundle=generated)

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("native_decide.ax", output)
        for theorem in (
            "exactDecodedNativeExternalComponentCertificateOfRefinement",
            "exactDecodedNativeExternalComponentFactoryOfRefinement",
            "exactDecodedNativeExternalComponentFactoriesForRefiningEnvironments",
            "exactDecodedNativeExternalComponentForRefiningEnvironments",
            "generatedExactDecodedNativeExternalComponentFactories",
            "generatedExactDecodedNativeExternalComponentsForRefiningEnvironments",
        ):
            self.assertIn(theorem, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_BINDINGS_FIXTURE = r"""import StageA.RelationalInterpreterExactDecodedNativeExternalComponent

namespace StageA.Bindings

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterExactDecodedNativeComponents
open StageA.Relational.InterpreterExactDecodedNativeExternalComponent
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

structure RequiredTerms where
  decodedTemplate : DecodedWorldProgram
  nativeTemplate : ExactNativeWorldProgram
  reachabilityTargetIds : List Nat
  invariant : MixedExecutionInvariant reachabilityTargetIds
    exactDecodedNativeIdentityContract
  program : CompiledKernelProgram
  launch : PE32ConsoleLaunchV2
  frames : MixedExternalFrameContract
  remaining :
    ExactDecodedNativeExternalBoundaryPremisesForRefiningEnvironments
      decodedTemplate nativeTemplate invariant program launch frames

end StageA.Bindings
"""


if __name__ == "__main__":
    unittest.main()
