from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_whole_program_acceptance import (
    INTERPRETER_WHOLE_PROGRAM_ACCEPTANCE_MODULE,
    InterpreterWholeProgramAcceptanceGenerationError,
    InterpreterWholeProgramAcceptanceSpec,
    relational_interpreter_whole_program_acceptance_source,
    write_relational_interpreter_whole_program_acceptance,
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


def _spec(**changes: str | None) -> InterpreterWholeProgramAcceptanceSpec:
    base = InterpreterWholeProgramAcceptanceSpec(
        binding_module="StageA.Bindings",
        namespace="StageA.Generated.WholeProgramAcceptance",
        context="requirements.context",
        graph="requirements.graph",
        regions="requirements.regions",
        invariants="requirements.invariants",
        reachability="requirements.reachability",
        control="requirements.control",
        callback_targets="requirements.callbackTargets",
        external_call_sites="requirements.externalCallSites",
        launch="requirements.launch",
        original_environment="requirements.originalEnvironment",
        candidate_environment="requirements.candidateEnvironment",
        original_protocol_environment=(
            "requirements.originalProtocolEnvironment"
        ),
        candidate_protocol_environment=(
            "requirements.candidateProtocolEnvironment"
        ),
        native_program="requirements.nativeProgram",
        decoded_certificate="requirements.decodedCertificate",
        native_adapter="requirements.nativeAdapter",
        requirement_parameter="requirements",
        requirement_type="StageA.Bindings.RequiredTerms",
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterWholeProgramAcceptanceTests(
    unittest.TestCase
):
    def test_bridge_is_local_operational_and_fail_closed(self) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterWholeProgramAcceptance.lean"
        ).read_text(encoding="utf-8")

        for required in (
            "WholeProgramCertificate",
            "ExactDecodedNativeMacroStepAdapter",
            "ExactDecodedNativeChunkAdapter",
            "ExactNativeCandidateAuthority",
            "DirectExactCandidateNativeLaunchRoot",
            "candidateNativeLaunchCallFrames?",
            "NonemptyRelatedPath native.transitionSystem",
            "nativeObservations = decodedStep.observation.toList",
            "chunksRefineExact",
            "decodedObservations = nativeObservations",
            "lockstep_refines_nonempty_candidate_path",
            "pe32ProgramsEquivalent context",
            "ChunkedRelationalBisimulation original.pe32TransitionSystem",
            "pe32ProgramsEquivalent_exactNative",
        ):
            self.assertIn(required, source)

        adapter = source.split(
            "structure ExactDecodedNativeMacroStepAdapter", 1
        )[1].split(
            "structure ExactNativeWholeProgramAcceptanceBridge", 1
        )[0]
        self.assertIn("stepRefines", adapter)
        self.assertNotIn("ChunkedRelationalBisimulation", adapter)

        for forbidden in (
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\badmit\b",
            r"\bstatus\b",
            r"\bverdict\b",
            r"\ballStatesRefine\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_assembles_only_checked_bridge_terms(self) -> None:
        source = relational_interpreter_whole_program_acceptance_source(_spec())

        self.assertIn("ExactNativeWholeProgramAcceptanceBridge", source)
        self.assertIn("decodedCertificate :=", source)
        self.assertIn("nativeAdapter :=", source)
        self.assertIn("pe32ProgramsEquivalent_exactNative", source)
        for forbidden in (r"\bsorry\b", r"\bstatus\b", r"\bverdict\b"):
            self.assertNotRegex(source, forbidden)

    def test_writer_is_deterministic(self) -> None:
        spec = _spec()
        expected = relational_interpreter_whole_program_acceptance_source(spec)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = write_relational_interpreter_whole_program_acceptance(
                root, spec
            )
            first_bytes = first.read_bytes()
            second = write_relational_interpreter_whole_program_acceptance(
                root, spec
            )
            second_bytes = second.read_bytes()

        self.assertEqual(
            first.name, f"{INTERPRETER_WHOLE_PROGRAM_ACCEPTANCE_MODULE}.lean"
        )
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_generator_rejects_malformed_names(self) -> None:
        for change in (
            {"binding_module": "Bindings"},
            {"namespace": "StageA.Bad-Namespace"},
            {"native_adapter": "requirements.bad term"},
            {"bridge_name": "StageA.bridge"},
            {"requirement_type": None},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    InterpreterWholeProgramAcceptanceGenerationError
                ):
                    relational_interpreter_whole_program_acceptance_source(
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
                "RelationalInterpreterWholeProgramAcceptance",
            )
            (
                stage_a / "RelationalInterpreterWholeProgramAcceptanceAudit.lean"
            ).write_text(_AUDIT_FIXTURE, encoding="utf-8")
            result = _run_lean_relational(
                root,
                bundle="RelationalInterpreterWholeProgramAcceptanceAudit",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertNotIn("declaration uses 'sorry'", output)
        for theorem in (
            "relatedObservationLists_of_option",
            "relatedObservationLists_append",
            "lockstep_runRelatedSteps",
            "lockstep_refines_nonempty_candidate_path",
            "pe32ProgramsEquivalent_exactNative",
        ):
            self.assertIn(theorem, output)

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_AUDIT_FIXTURE = r"""import StageA.RelationalInterpreterWholeProgramAcceptance

namespace StageA.Relational.InterpreterWholeProgramAcceptanceAudit

open StageA.Relational.InterpreterWholeProgramAcceptance

#check ExactDecodedNativeMacroStepAdapter
#check ExactDecodedNativeChunkAdapter
#check ExactNativeWholeProgramAcceptanceBridge
#check PE32ProgramsExactNativeChunkObservationallyEquivalent
#check relatedObservationLists_of_option
#check relatedObservationLists_append
#check lockstep_runRelatedSteps
#check lockstep_refines_nonempty_candidate_path
#check pe32ProgramsEquivalent_exactNative

#print axioms relatedObservationLists_of_option
#print axioms relatedObservationLists_append
#print axioms lockstep_runRelatedSteps
#print axioms lockstep_refines_nonempty_candidate_path
#print axioms pe32ProgramsEquivalent_exactNative

end StageA.Relational.InterpreterWholeProgramAcceptanceAudit
"""


if __name__ == "__main__":
    unittest.main()
