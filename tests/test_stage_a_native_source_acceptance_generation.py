from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.native_source_acceptance import (
    NATIVE_SOURCE_ACCEPTANCE_AUDIT_MODULE,
    NATIVE_SOURCE_ACCEPTANCE_MODULE,
    NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_AUDIT_MODULE,
    NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_MODULE,
    NativeSourceAcceptanceGenerationError,
    NativeSourceAcceptanceSpec,
    NativeSourceFixedEnvironmentIntermediateSpec,
    native_source_acceptance_axiom_audit_source,
    native_source_acceptance_source,
    native_source_fixed_environment_intermediate_source,
    write_native_source_acceptance,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)


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


def _spec(**changes: object) -> NativeSourceAcceptanceSpec:
    fixture = "StageA.NativeSourceAcceptanceFixture"
    base = NativeSourceAcceptanceSpec(
        imports=(
            "StageA.NativeSourceAcceptanceFixture",
            "StageA.GeneratedSourceProjectCertificate",
        ),
        context=f"{fixture}.context",
        sites=f"{fixture}.sites",
        static_compilation=f"{fixture}.staticCompilation",
        static_authority=f"{fixture}.staticAuthority",
        pair_relation=f"{fixture}.PairRelated",
        admitted_pair_evidence=f"{fixture}.admittedPairEvidence",
        toolchain_correct=f"{fixture}.toolchainCorrect",
    )
    return dataclasses.replace(base, **changes)


def _fixed_spec(
    **changes: object,
) -> NativeSourceFixedEnvironmentIntermediateSpec:
    fixture = "StageA.NativeSourceFixedEnvironmentFixture"
    base = NativeSourceFixedEnvironmentIntermediateSpec(
        imports=("StageA.NativeSourceFixedEnvironmentFixture",),
        profile=f"{fixture}.profile",
        project=f"{fixture}.project",
        artifact=f"{fixture}.artifact",
        machine_authority=f"{fixture}.machineAuthority",
        source_family=f"{fixture}.sourceFamily",
        project_valid=f"{fixture}.projectValid",
        profile_pinned=f"{fixture}.profilePinned",
        profile_matches=f"{fixture}.profileMatches",
        built_from=f"{fixture}.builtFrom",
        launch_realizable=f"{fixture}.launchRealizable",
    )
    return dataclasses.replace(base, **changes)


class StageANativeSourceAcceptanceGenerationTests(unittest.TestCase):
    def test_assembles_environment_family_as_the_only_final_theorem(self) -> None:
        source = native_source_acceptance_source(_spec())

        self.assertLess(
            source.index("import StageA.GeneratedSourceProjectCertificate"),
            source.index("import StageA.NativeSourceAcceptanceFixture"),
        )
        self.assertEqual(
            source.count(
                "import StageA.RelationalNativeSourceEnvironmentFamilyEvidence"
            ),
            1,
        )
        for required in (
            "abbrev generatedStaticExactNativeCompilation",
            "sourceEnvironment : WorldExternalEnvironment",
            "nativeEnvironment : NativeWorldEnvironment",
            "StageA.NativeSourceAcceptanceFixture.PairRelated",
            "def generatedCheckedNativeSourceAdmittedEnvironmentFamily :",
            "CheckedNativeSourceAdmittedEnvironmentFamily",
            "staticAuthority := StageA.NativeSourceAcceptanceFixture.staticAuthority",
            "admittedPairs := StageA.NativeSourceAcceptanceFixture.admittedPairEvidence",
            "toolchainCorrectAt := StageA.NativeSourceAcceptanceFixture.toolchainCorrect",
            "ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence",
            "compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis",
        ):
            self.assertIn(required, source)

        theorem = source.split(
            "theorem generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence",
            1,
        )[1].split(
            "end StageA.GeneratedRelational.NativeSourceAcceptance", 1
        )[0]
        self.assertNotIn("ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence", theorem)
        self.assertNotIn("#print axioms", source)
        for hidden_fixed_input in (
            "profile :=",
            "project :=",
            "artifact :=",
            "machineAuthority :=",
            "sourceEnvironment :=",
            "nativeEnvironment :=",
        ):
            self.assertNotIn(hidden_fixed_input, source)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_audit_names_only_the_environment_family_theorem(self) -> None:
        source = native_source_acceptance_axiom_audit_source(_spec())

        self.assertEqual(
            source,
            "import StageA.GeneratedNativeSourceAcceptance\n\n"
            "#print axioms "
            "StageA.GeneratedRelational.NativeSourceAcceptance."
            "generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence\n",
        )
        self.assertEqual(source.count("#print axioms"), 1)

    def test_fixed_environment_path_is_clearly_intermediate(self) -> None:
        spec = _fixed_spec()
        source = native_source_fixed_environment_intermediate_source(spec)

        self.assertEqual(
            spec.output_module,
            NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_MODULE,
        )
        self.assertEqual(
            spec.audit_output_module,
            NATIVE_SOURCE_FIXED_ENVIRONMENT_INTERMEDIATE_AUDIT_MODULE,
        )
        self.assertIn("fixed-environment", source)
        self.assertIn("intermediate", source)
        self.assertIn(
            "ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence",
            source,
        )
        self.assertNotIn(
            "ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence",
            source,
        )
        self.assertNotIn("RelationalNativeSourceEnvironmentFamily", source)

    def test_all_submitted_declarations_and_modules_fail_closed(self) -> None:
        malformed = {
            "imports": ("Fixture",),
            "context": "context; axiom injected : False",
            "sites": "by exact sites",
            "static_compilation": "compilation()",
            "static_authority": "pair witness",
            "pair_relation": "sorry",
            "admitted_pair_evidence": "proof-term",
            "toolchain_correct": "native_decide",
            "namespace": "StageA.Generated; end StageA",
            "output_module": "../Escaped",
            "audit_output_module": "Audit.Module",
            "compilation_name": "StageA.compilation",
            "environment_family_name": "family -- accepted",
            "theorem_name": "unsafe",
        }
        for field, value in malformed.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    NativeSourceAcceptanceGenerationError,
                    "canonical",
                ):
                    native_source_acceptance_source(_spec(**{field: value}))

    def test_missing_family_evidence_and_hidden_environments_fail_schema(self) -> None:
        values = {
            field.name: getattr(_spec(), field.name)
            for field in dataclasses.fields(NativeSourceAcceptanceSpec)
            if field.default is dataclasses.MISSING
        }
        del values["admitted_pair_evidence"]
        with self.assertRaises(TypeError):
            NativeSourceAcceptanceSpec(**values)
        with self.assertRaises(TypeError):
            dataclasses.replace(
                _spec(), source_environment="StageA.Hidden.sourceEnvironment"
            )
        with self.assertRaises(TypeError):
            dataclasses.replace(
                _spec(), native_environment="StageA.Hidden.nativeEnvironment"
            )

    def test_ambiguous_or_missing_module_inventory_fails_closed(self) -> None:
        invalid = (
            _spec(imports=()),
            _spec(
                imports=(
                    "StageA.NativeSourceAcceptanceFixture",
                    "StageA.NativeSourceAcceptanceFixture",
                )
            ),
            _spec(
                output_module="GeneratedSameModule",
                audit_output_module="GeneratedSameModule",
            ),
            _spec(
                environment_family_name="generatedStaticExactNativeCompilation"
            ),
        )
        for spec in invalid:
            with self.subTest(spec=spec):
                with self.assertRaises(NativeSourceAcceptanceGenerationError):
                    native_source_acceptance_source(spec)

    def test_import_order_is_canonical(self) -> None:
        forward = _spec(imports=("StageA.ZProvider", "StageA.AProvider"))
        reverse = _spec(imports=("StageA.AProvider", "StageA.ZProvider"))
        self.assertEqual(
            native_source_acceptance_source(forward),
            native_source_acceptance_source(reverse),
        )

    def test_writer_is_byte_reproducible_and_ascii(self) -> None:
        spec = _spec(
            output_module="GeneratedAlternateNativeSourceAcceptance",
            audit_output_module="GeneratedAlternateNativeSourceAudit",
        )
        expected_acceptance = native_source_acceptance_source(spec).encode("ascii")
        expected_audit = native_source_acceptance_axiom_audit_source(spec).encode(
            "ascii"
        )
        with tempfile.TemporaryDirectory() as temporary:
            first = write_native_source_acceptance(temporary, spec)
            first_bytes = tuple(path.read_bytes() for path in first)
            second = write_native_source_acceptance(temporary, spec)
            second_bytes = tuple(path.read_bytes() for path in second)

        self.assertEqual(
            tuple(path.name for path in first),
            (
                "GeneratedAlternateNativeSourceAcceptance.lean",
                "GeneratedAlternateNativeSourceAudit.lean",
            ),
        )
        self.assertEqual(first_bytes, (expected_acceptance, expected_audit))
        self.assertEqual(second_bytes, first_bytes)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_acceptance_compiles_against_current_kernel_api(self) -> None:
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
                "RelationalNativeSourceEnvironmentFamilyEvidence",
            )
            (stage_a / "NativeSourceAcceptanceFixture.lean").write_text(
                _LEAN_FIXTURE,
                encoding="ascii",
            )
            (stage_a / "GeneratedSourceProjectCertificate.lean").write_text(
                "import StageA.NativeSourceAcceptanceFixture\n",
                encoding="ascii",
            )
            write_native_source_acceptance(root, _spec())
            acceptance = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_ACCEPTANCE_MODULE,
            )
            audit = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_ACCEPTANCE_AUDIT_MODULE,
            )

        self.assertEqual(acceptance["status"], "unchecked_marker", acceptance)
        self.assertEqual(audit["status"], "unchecked_marker", audit)
        output = (
            acceptance["stdout"]
            + acceptance["stderr"]
            + audit["stdout"]
            + audit["stderr"]
        )
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn("GeneratedNativeSourceAcceptance.lean:", output)
        self.assertNotIn("GeneratedNativeSourceAcceptanceAudit.lean:", output)
        self.assertIn(
            "generatedNativeSourceWholeProgramEnvironmentFamilyEquivalence",
            output,
        )


_LEAN_FIXTURE = r'''import StageA.RelationalNativeSourceEnvironmentFamilyEvidence

namespace StageA.NativeSourceAcceptanceFixture

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.NativeSource

axiom context : StaticProofContext
axiom sites : List OpaqueLockstepCallSite
axiom staticCompilation : ExactNativeCompilation
axiom staticAuthority :
  StaticNativeSourceEnvironmentFamilyAuthority context staticCompilation
axiom PairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop
axiom admittedPairEvidence :
  CheckedNativeSourceAdmittedPairEvidence context sites staticCompilation
    PairRelated
axiom toolchainCorrect : forall sourceEnvironment nativeEnvironment,
  PairRelated sourceEnvironment nativeEnvironment ->
  CorrectPinnedNativeSourceStackHypothesis
    (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
      nativeEnvironment)

end StageA.NativeSourceAcceptanceFixture
'''


if __name__ == "__main__":
    unittest.main()
