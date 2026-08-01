from __future__ import annotations

import dataclasses
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.native_source_nested_acceptance import (
    NATIVE_SOURCE_NESTED_ACCEPTANCE_AUDIT_MODULE,
    NATIVE_SOURCE_NESTED_ACCEPTANCE_MODULE,
    NativeSourceAcceptanceGenerationError,
    NativeSourceNestedAcceptanceSpec,
    native_source_nested_acceptance_axiom_audit_source,
    native_source_nested_acceptance_source,
    write_native_source_nested_acceptance,
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


def _spec(**changes: object) -> NativeSourceNestedAcceptanceSpec:
    fixture = "StageA.NativeSourceNestedAcceptanceFixture"
    base = NativeSourceNestedAcceptanceSpec(
        imports=(
            "StageA.NativeSourceNestedAcceptanceFixture",
            "StageA.GeneratedSourceProjectCertificate",
        ),
        context=f"{fixture}.context",
        classified_sites=f"{fixture}.classifiedSites",
        ordinary_sites=f"{fixture}.ordinarySites",
        static_compilation=f"{fixture}.staticCompilation",
        mixed_contract=f"{fixture}.mixedContract",
        nested_frames=f"{fixture}.nestedFrames",
        checked_response_family=f"{fixture}.responseFamily",
        checked_response_family_completion=f"{fixture}.responseCompletion",
        toolchain_correct=f"{fixture}.toolchainCorrect",
    )
    return dataclasses.replace(base, **changes)


class StageANativeSourceNestedAcceptanceGenerationTests(unittest.TestCase):
    def test_assembles_only_nested_whole_program_acceptance(self) -> None:
        spec = _spec()
        source = native_source_nested_acceptance_source(spec)

        self.assertLess(
            source.index("import StageA.GeneratedSourceProjectCertificate"),
            source.index("import StageA.NativeSourceNestedAcceptanceFixture"),
        )
        self.assertEqual(
            source.count(
                "import StageA.RelationalNativeSourceNestedAdmittedResponseFamily"
            ),
            1,
        )
        for required in (
            "abbrev generatedStaticExactNativeCompilation",
            "abbrev generatedCheckedProtocolResponseFamily",
            "CheckedWorldNativeAdmittedProtocolResponseFamily",
            "abbrev GeneratedNestedPairRelated",
            "SourceWorldResponseEnvironment",
            "NativeWorldResponseEnvironment",
            "def generatedCheckedNestedNativeSourceAdmittedEnvironmentFamily",
            "CheckedNestedNativeSourceAdmittedEnvironmentFamily",
            ".toNestedAcceptance",
            "ExactRawOriginalPENestedCompiledArtifactAdmittedEnvironmentFamilyEquivalence",
            "compiledNestedArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis",
        ):
            self.assertIn(required, source)

        theorem = source.split(
            "theorem generatedNativeSourceNestedWholeProgramEnvironmentFamilyEquivalence",
            1,
        )[1].split(
            "end StageA.GeneratedRelational.NativeSourceNestedAcceptance", 1
        )[0]
        self.assertNotIn(
            "ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence",
            theorem,
        )
        self.assertNotIn(
            "ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence", theorem
        )
        self.assertNotIn("#print axioms", source)
        self.assertEqual(source.count(spec.toolchain_correct), 1)
        for forbidden in (
            r"\baxiom\b",
            r"\bsorry\b",
            r"\badmit\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"\bGNU\b",
            r"\bhello\b",
        ):
            self.assertNotRegex(source, forbidden)

    def test_audit_is_detached_and_names_only_nested_theorem(self) -> None:
        source = native_source_nested_acceptance_axiom_audit_source(_spec())

        self.assertEqual(
            source,
            "import StageA.GeneratedNativeSourceNestedAcceptance\n\n"
            "#print axioms "
            "StageA.GeneratedRelational.NativeSourceNestedAcceptance."
            "generatedNativeSourceNestedWholeProgramEnvironmentFamilyEquivalence\n",
        )
        self.assertEqual(source.count("#print axioms"), 1)

    def test_all_submitted_declarations_and_modules_fail_closed(self) -> None:
        malformed = {
            "imports": ("Fixture",),
            "context": "context; axiom injected : False",
            "classified_sites": "by exact sites",
            "ordinary_sites": "sites()",
            "static_compilation": "compilation -- hidden",
            "mixed_contract": "sorry",
            "nested_frames": "proof-term",
            "checked_response_family": "native_decide",
            "checked_response_family_completion": "by exact completion",
            "toolchain_correct": "unsafe",
            "namespace": "StageA.Generated; end StageA",
            "output_module": "../Escaped",
            "audit_output_module": "Audit.Module",
            "response_family_name": "StageA.responseFamily",
            "pair_relation_name": "relation -- accepted",
            "theorem_name": "axiom",
        }
        for field, value in malformed.items():
            with self.subTest(field=field):
                with self.assertRaisesRegex(
                    NativeSourceAcceptanceGenerationError, "canonical"
                ):
                    native_source_nested_acceptance_source(
                        _spec(**{field: value})
                    )

    def test_missing_checked_evidence_or_compiler_premise_fails_schema(self) -> None:
        required = {
            field.name: getattr(_spec(), field.name)
            for field in dataclasses.fields(NativeSourceNestedAcceptanceSpec)
            if field.default is dataclasses.MISSING
        }
        for missing in (
            "checked_response_family",
            "checked_response_family_completion",
            "toolchain_correct",
        ):
            with self.subTest(missing=missing):
                values = dict(required)
                del values[missing]
                with self.assertRaises(TypeError):
                    NativeSourceNestedAcceptanceSpec(**values)

        with self.assertRaises(TypeError):
            dataclasses.replace(_spec(), status="pass")

    def test_ambiguous_module_or_generated_inventory_fails_closed(self) -> None:
        invalid = (
            _spec(imports=()),
            _spec(
                imports=(
                    "StageA.NativeSourceNestedAcceptanceFixture",
                    "StageA.NativeSourceNestedAcceptanceFixture",
                )
            ),
            _spec(
                output_module="GeneratedSameModule",
                audit_output_module="GeneratedSameModule",
            ),
            _spec(
                environment_family_name="generatedCheckedProtocolResponseFamily"
            ),
        )
        for spec in invalid:
            with self.subTest(spec=spec):
                with self.assertRaises(NativeSourceAcceptanceGenerationError):
                    native_source_nested_acceptance_source(spec)

    def test_import_order_is_canonical(self) -> None:
        forward = _spec(imports=("StageA.ZProvider", "StageA.AProvider"))
        reverse = _spec(imports=("StageA.AProvider", "StageA.ZProvider"))
        self.assertEqual(
            native_source_nested_acceptance_source(forward),
            native_source_nested_acceptance_source(reverse),
        )

    def test_writer_is_byte_reproducible_and_ascii(self) -> None:
        spec = _spec(
            output_module="GeneratedAlternateNestedAcceptance",
            audit_output_module="GeneratedAlternateNestedAcceptanceAudit",
        )
        expected_acceptance = native_source_nested_acceptance_source(spec).encode(
            "ascii"
        )
        expected_audit = native_source_nested_acceptance_axiom_audit_source(
            spec
        ).encode("ascii")
        with tempfile.TemporaryDirectory() as temporary:
            first = write_native_source_nested_acceptance(temporary, spec)
            first_bytes = tuple(path.read_bytes() for path in first)
            second = write_native_source_nested_acceptance(temporary, spec)
            second_bytes = tuple(path.read_bytes() for path in second)

        self.assertEqual(
            tuple(path.name for path in first),
            (
                "GeneratedAlternateNestedAcceptance.lean",
                "GeneratedAlternateNestedAcceptanceAudit.lean",
            ),
        )
        self.assertEqual(first_bytes, (expected_acceptance, expected_audit))
        self.assertEqual(second_bytes, first_bytes)

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_nested_acceptance_compiles_against_kernel_api(self) -> None:
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
                "RelationalNativeSourceNestedAdmittedResponseFamily",
            )
            (stage_a / "NativeSourceNestedAcceptanceFixture.lean").write_text(
                _LEAN_FIXTURE,
                encoding="ascii",
            )
            (stage_a / "GeneratedSourceProjectCertificate.lean").write_text(
                "import StageA.NativeSourceNestedAcceptanceFixture\n",
                encoding="ascii",
            )
            write_native_source_nested_acceptance(root, _spec())
            acceptance = _run_lean_relational(
                root, bundle=NATIVE_SOURCE_NESTED_ACCEPTANCE_MODULE
            )
            audit = _run_lean_relational(
                root, bundle=NATIVE_SOURCE_NESTED_ACCEPTANCE_AUDIT_MODULE
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
        self.assertNotIn("GeneratedNativeSourceNestedAcceptance.lean:", output)
        self.assertNotIn(
            "GeneratedNativeSourceNestedAcceptanceAudit.lean:", output
        )
        self.assertIn(
            "generatedNativeSourceNestedWholeProgramEnvironmentFamilyEquivalence",
            output,
        )


_LEAN_FIXTURE = r'''import StageA.RelationalNativeSourceNestedAdmittedResponseFamily

namespace StageA.NativeSourceNestedAcceptanceFixture

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.NativeSource

axiom context : StaticProofContext
axiom classifiedSites : List CheckedMachineExternalSite
axiom ordinarySites : List OpaqueLockstepCallSite
axiom staticCompilation : ExactNativeCompilation
axiom mixedContract : MixedRelationContract
axiom nestedFrames : MixedNestedExternalFrameContract
axiom responseFamily :
  CheckedWorldNativeAdmittedProtocolResponseFamily context classifiedSites
    ordinarySites staticCompilation mixedContract nestedFrames
axiom responseCompletion : responseFamily.Completion
axiom toolchainCorrect : forall sourceEnvironment nativeEnvironment,
  responseFamily.Related sourceEnvironment nativeEnvironment ->
    CorrectPinnedNestedNativeSourceStackHypothesis
      (exactNativeCompilationAtResponseEnvironments staticCompilation
        sourceEnvironment nativeEnvironment.ordinary)
      (exactNestedNativeCompilationAtResponseEnvironments staticCompilation
        sourceEnvironment nativeEnvironment)

end StageA.NativeSourceNestedAcceptanceFixture
'''


if __name__ == "__main__":
    unittest.main()
