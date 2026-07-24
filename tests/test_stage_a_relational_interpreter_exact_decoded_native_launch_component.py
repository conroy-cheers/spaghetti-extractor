from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.interpreter_exact_decoded_native_launch_component import (
    INTERPRETER_EXACT_DECODED_NATIVE_LAUNCH_COMPONENT_MODULE,
    InterpreterExactDecodedNativeLaunchComponentGenerationError,
    InterpreterExactDecodedNativeLaunchComponentSpec,
    relational_interpreter_exact_decoded_native_launch_component_source,
    write_relational_interpreter_exact_decoded_native_launch_component,
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
) -> InterpreterExactDecodedNativeLaunchComponentSpec:
    base = InterpreterExactDecodedNativeLaunchComponentSpec(
        binding_module="StageA.Bindings",
        namespace="StageA.Generated.ExactDecodedNativeLaunchComponent",
        decoded="requirements.decoded",
        native="requirements.native",
        relation="requirements.relation",
        decoded_before="requirements.decodedBefore",
        native_before="requirements.nativeBefore",
        cutpoints="requirements.cutpoints",
        reflected="requirements.reflected",
        replay="requirements.replay",
        replayed="requirements.replayed",
        decoded_after="requirements.decodedAfter",
        decoded_path="requirements.decodedPath",
        after_related="requirements.afterRelated",
        requirement_parameter="requirements",
        requirement_type="StageA.Bindings.RequiredTerms",
    )
    return dataclasses.replace(base, **changes)


class StageARelationalInterpreterExactDecodedNativeLaunchComponentTests(
    unittest.TestCase
):
    def test_lean_bridge_exposes_only_cross_system_remaining_premises(
        self,
    ) -> None:
        source = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA/"
            "RelationalInterpreterExactDecodedNativeLaunchComponent.lean"
        ).read_text(encoding="utf-8")

        premise_body = source.split(
            "structure ExactDecodedNativeLaunchComponentRemainingPremises", 1
        )[1].split(
            "noncomputable def exactDecodedNativeLaunchSegmentOfPath", 1
        )[0]
        self.assertIn("decodedPath : NonemptyRelatedPath", premise_body)
        self.assertIn(
            "afterRelated : relation decodedAfter replay.after", premise_body
        )
        for duplicated_native_fact in (
            "staticChecked",
            "sourceMatches",
            "destinationMatches",
            "nativePath",
            "nativeFuel",
            "observationsExact",
        ):
            self.assertNotIn(duplicated_native_fact, premise_body)

        for required in (
            "ReflectedNativeLaunchPathCertificate",
            "ReflectedNativeLaunchPathReplay",
            "replayed :",
            "exactDecodedNativeLaunchComponentCertificateOfCheckedReplay",
            "ExactDecodedNativeLaunchComponentCertificate",
            "Classical.choose",
        ):
            self.assertIn(required, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
            r"\breport\b",
            r"\bverdict\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_generator_packages_replay_and_exact_remaining_terms(self) -> None:
        source = (
            relational_interpreter_exact_decoded_native_launch_component_source(
                _spec()
            )
        )

        for required in (
            "ExactDecodedNativeLaunchComponentRemainingPremises",
            "decodedPath := requirements.decodedPath",
            "afterRelated := requirements.afterRelated",
            "exactDecodedNativeLaunchComponentCertificateOfCheckedReplay",
            "requirements.replayed",
        ):
            self.assertIn(required, source)
        for removed_input in (
            "staticChecked :=",
            "sourceMatches :=",
            "destinationMatches :=",
            "nativePath :=",
            "observationsExact :=",
        ):
            self.assertNotIn(removed_input, source)
        for forbidden in (
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\breport\b",
            r"\bstatus\b",
            r"\bverdict\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_writer_is_deterministic(self) -> None:
        spec = _spec()
        expected = (
            relational_interpreter_exact_decoded_native_launch_component_source(
                spec
            )
        )
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            first = (
                write_relational_interpreter_exact_decoded_native_launch_component(
                    root, spec
                )
            )
            first_bytes = first.read_bytes()
            second = (
                write_relational_interpreter_exact_decoded_native_launch_component(
                    root, spec
                )
            )
            second_bytes = second.read_bytes()

        self.assertEqual(
            first.name,
            f"{INTERPRETER_EXACT_DECODED_NATIVE_LAUNCH_COMPONENT_MODULE}.lean",
        )
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first_bytes, expected.encode("utf-8"))

    def test_generator_rejects_malformed_names(self) -> None:
        for change in (
            {"binding_module": "Bindings"},
            {"namespace": "StageA.Bad-Namespace"},
            {"decoded_path": "requirements.path; false"},
            {"premises_name": "StageA.premises"},
            {"certificate_name": "theorem"},
            {"requirement_type": None},
        ):
            with self.subTest(change=change):
                with self.assertRaises(
                    InterpreterExactDecodedNativeLaunchComponentGenerationError
                ):
                    relational_interpreter_exact_decoded_native_launch_component_source(
                        _spec(**change)
                    )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_bridge_and_generated_module_compile_with_approved_axioms(
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
                "RelationalInterpreterExactDecodedNativeLaunchComponent",
            )
            (stage_a / "Bindings.lean").write_text(
                _BINDINGS_FIXTURE, encoding="utf-8"
            )
            generated = (
                INTERPRETER_EXACT_DECODED_NATIVE_LAUNCH_COMPONENT_MODULE
            )
            (stage_a / f"{generated}.lean").write_text(
                relational_interpreter_exact_decoded_native_launch_component_source(
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
        self.assertIn(
            "generatedExactDecodedNativeLaunchComponent", output
        )

        observed: set[str] = set()
        for match in _AXIOM_LINE.finditer(result["stdout"]):
            observed.update(
                item.strip() for item in match.group(1).split(",") if item.strip()
            )
        self.assertTrue(observed)
        self.assertLessEqual(observed, RELATIONAL_APPROVED_AXIOMS)


_BINDINGS_FIXTURE = r"""import StageA.RelationalInterpreterExactDecodedNativeLaunchComponent

namespace StageA.Bindings

open StageA.Relational
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

structure RequiredTerms where
  decoded : DecodedWorldProgram
  native : ExactNativeWorldProgram
  relation : WorldExecution -> NativeWorldExecution -> Prop
  decodedBefore : WorldExecution
  nativeBefore : NativeWorldExecution
  cutpoints : List StableInterpreterCutpoint
  reflected : ReflectedNativeLaunchPathCertificate
  replay : ReflectedNativeLaunchPathReplay
  replayed :
    reflected.replay? native cutpoints nativeBefore = some replay
  decodedAfter : WorldExecution
  decodedPath : NonemptyRelatedPath decoded.pe32TransitionSystem decodedBefore
    replay.observations decodedAfter
  afterRelated : relation decodedAfter replay.after

end StageA.Bindings
"""


if __name__ == "__main__":
    unittest.main()
