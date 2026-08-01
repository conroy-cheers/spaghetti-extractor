from __future__ import annotations

import dataclasses
import json
import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational
from spaghetti_extractor.relational.lean.native_source_environment_family_evidence import (
    NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT,
    NATIVE_SOURCE_ENVIRONMENT_FAMILY_AXIOM_EXPECTATION_FORMAT,
    NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_AUDIT_MODULE,
    NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_MODULE,
    NativeSourceAcceptanceBindings,
    NativeSourceEnvironmentFamilyEvidenceGenerationError,
    NativeSourceEnvironmentFamilyEvidenceSpec,
    native_source_acceptance_declarations,
    native_source_environment_family_axiom_expectation,
    native_source_environment_family_evidence_source,
    write_native_source_environment_family_evidence,
)


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_DIGEST = "a" * 64


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


def _spec(**changes: object) -> NativeSourceEnvironmentFamilyEvidenceSpec:
    fixture = "StageA.NativeSourceEnvironmentFamilyEvidenceFixture"
    base = NativeSourceEnvironmentFamilyEvidenceSpec(
        imports=("StageA.NativeSourceEnvironmentFamilyEvidenceFixture",),
        context=f"{fixture}.context",
        sites=f"{fixture}.sites",
        static_compilation=f"{fixture}.staticCompilation",
        static_authority=f"{fixture}.staticAuthority",
        pair_relation=f"{fixture}.PairRelated",
        pair_realizable=f"{fixture}.pairRealizable",
        external_evidence_at=f"{fixture}.externalEvidenceAt",
        source_family_at=f"{fixture}.sourceFamilyAt",
        launch_realizable_at=f"{fixture}.launchRealizableAt",
        acceptance_bindings=NativeSourceAcceptanceBindings(
            compiled_authority_manifest_sha256=_DIGEST,
            source_bundle_sha256="b" * 64,
            attestation_core_sha256="c" * 64,
            candidate_sha256="d" * 64,
            source_entry_rva=0x1420,
            compiled_entry_rva=0x2050,
        ),
    )
    return dataclasses.replace(base, **changes)


class StageANativeSourceEnvironmentFamilyEvidenceGenerationTests(
    unittest.TestCase
):
    def test_emits_nonvacuous_machine_level_environment_family(self) -> None:
        source = native_source_environment_family_evidence_source(_spec())
        kernel = (
            Path(__file__).parents[1]
            / "src/spaghetti_extractor/lean/StageA"
            / "RelationalNativeSourceEnvironmentFamilyEvidence.lean"
        ).read_text(encoding="utf-8")

        self.assertIn("exactNativeCompilationAtEnvironments", source)
        self.assertIn("CheckedNativeSourceAdmittedPairEvidence", kernel)
        self.assertIn("ExactWorldNativeExternalEvidence", _FIXTURE)
        self.assertIn("externalEvidenceAt", source)
        self.assertIn("admittedPairEvidence", source)
        self.assertIn("pairRealizable", source)
        self.assertIn("CheckedNativeSourceAdmittedPairEvidence", source)
        self.assertIn("sourceFamilyAt :=", source)
        self.assertIn("launchRealizableAt :=", source)
        self.assertEqual(source.count("axiom pinnedCompilerLoweringCorrect"), 1)
        self.assertEqual(len(re.findall(r"(?m)^axiom\s", source)), 1)
        self.assertNotIn("sourceEnvironment = nativeEnvironment", source)
        self.assertNotRegex(source, r"(?m)^axiom (?!pinnedCompilerLoweringCorrect)")
        for forbidden in (r"\bsorry\b", r"\badmit\b", r"\bnative_decide\b", r"\bRuntimeClosure\b"):
            self.assertNotRegex(source, forbidden)

    def test_emits_current_acceptance_schema_and_exact_axiom_policy(self) -> None:
        spec = _spec()
        declarations = native_source_acceptance_declarations(spec)
        expectation = native_source_environment_family_axiom_expectation(spec)

        self.assertEqual(
            declarations["format"], NATIVE_SOURCE_ACCEPTANCE_DECLARATIONS_FORMAT
        )
        self.assertEqual(
            declarations["format"],
            "stage-a-gnu-hello-native-source-acceptance-declarations-v3",
        )
        self.assertEqual(
            set(declarations), {"format", "bindings", "lean"}
        )
        self.assertEqual(
            set(declarations["bindings"]),
            {
                "compiled_authority_manifest_sha256",
                "source_bundle_sha256",
                "attestation_core_sha256",
                "candidate_sha256",
                "source_entry_rva",
                "compiled_entry_rva",
            },
        )
        self.assertEqual(
            set(declarations["lean"]),
            {
                "imports",
                "context",
                "sites",
                "static_compilation",
                "static_authority",
                "pair_relation",
                "admitted_pair_evidence",
                "toolchain_correct",
                "namespace",
                "output_module",
                "audit_output_module",
                "compilation_name",
                "environment_family_name",
                "theorem_name",
            },
        )
        pinned = (
            f"{spec.namespace}.pinnedCompilerLoweringCorrect"
        )
        self.assertEqual(
            declarations["lean"]["toolchain_correct"], pinned
        )
        self.assertEqual(
            expectation["format"],
            NATIVE_SOURCE_ENVIRONMENT_FAMILY_AXIOM_EXPECTATION_FORMAT,
        )
        self.assertEqual(expectation["required_axioms"], [pinned])
        self.assertEqual(
            set(expectation["approved_axioms"]),
            {"propext", "Classical.choice", "Quot.sound", pinned},
        )

    def test_missing_or_ambiguous_evidence_fails_closed(self) -> None:
        required = {
            field.name: getattr(_spec(), field.name)
            for field in dataclasses.fields(
                NativeSourceEnvironmentFamilyEvidenceSpec
            )
            if field.default is dataclasses.MISSING
        }
        for missing in (
            "static_compilation",
            "static_authority",
            "pair_realizable",
            "external_evidence_at",
            "source_family_at",
            "launch_realizable_at",
        ):
            with self.subTest(missing=missing):
                incomplete = dict(required)
                del incomplete[missing]
                with self.assertRaises(TypeError):
                    NativeSourceEnvironmentFamilyEvidenceSpec(**incomplete)

        malformed = (
            _spec(imports=()),
            _spec(
                imports=(
                    "StageA.NativeSourceEnvironmentFamilyEvidenceFixture",
                    "StageA.NativeSourceEnvironmentFamilyEvidenceFixture",
                )
            ),
            _spec(external_evidence_at="by exact externalEvidence"),
            _spec(source_family_at="sorry"),
            _spec(toolchain_axiom_name="compilerCorrect"),
            _spec(static_compilation_name="admittedPairEvidence"),
            _spec(
                acceptance_bindings=dataclasses.replace(
                    _spec().acceptance_bindings,
                    candidate_sha256="not-a-digest",
                )
            ),
        )
        for spec in malformed:
            with self.subTest(spec=spec):
                with self.assertRaises(
                    NativeSourceEnvironmentFamilyEvidenceGenerationError
                ):
                    native_source_environment_family_evidence_source(spec)

    def test_writer_is_deterministic_ascii_and_complete(self) -> None:
        spec = _spec()
        with tempfile.TemporaryDirectory() as temporary:
            first = write_native_source_environment_family_evidence(
                temporary, spec
            )
            first_bytes = tuple(path.read_bytes() for path in first)
            second = write_native_source_environment_family_evidence(
                temporary, spec
            )
            second_bytes = tuple(path.read_bytes() for path in second)

        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(
            tuple(path.name for path in first),
            (
                f"{NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_MODULE}.lean",
                f"{NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_AUDIT_MODULE}.lean",
                "acceptance-declarations.json",
                "axiom-audit-expectation.json",
            ),
        )
        for payload in first_bytes:
            payload.decode("ascii")
        self.assertEqual(
            json.loads(first_bytes[2]),
            native_source_acceptance_declarations(spec),
        )

    @unittest.skipUnless(shutil.which("lean"), "Lean is required")
    def test_generated_evidence_elaborates_against_kernel(self) -> None:
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
            (stage_a / "NativeSourceEnvironmentFamilyEvidenceFixture.lean").write_text(
                _FIXTURE,
                encoding="ascii",
            )
            write_native_source_environment_family_evidence(root, _spec())
            checked = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_MODULE,
            )
            audit = _run_lean_relational(
                root,
                bundle=NATIVE_SOURCE_ENVIRONMENT_FAMILY_EVIDENCE_AUDIT_MODULE,
            )

        self.assertEqual(checked["status"], "unchecked_marker", checked)
        self.assertEqual(audit["status"], "unchecked_marker", audit)
        output = checked["stdout"] + checked["stderr"] + audit["stdout"] + audit["stderr"]
        self.assertNotIn("declaration uses 'sorry'", output)
        self.assertNotIn(
            "GeneratedNativeSourceEnvironmentFamilyEvidence.lean:", output
        )
        self.assertIn("pinnedCompilerLoweringCorrect", output)


_FIXTURE = r'''import StageA.RelationalNativeSourceEnvironmentFamilyEvidence

namespace StageA.NativeSourceEnvironmentFamilyEvidenceFixture

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
axiom pairRealizable : exists sourceEnvironment nativeEnvironment,
  PairRelated sourceEnvironment nativeEnvironment

axiom externalEvidenceAt : forall sourceEnvironment nativeEnvironment,
  PairRelated sourceEnvironment nativeEnvironment ->
  ExactWorldNativeExternalEvidence context
    (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
      nativeEnvironment).project.worldProgram
    (exactNativeCompilationAtEnvironments staticCompilation sourceEnvironment
      nativeEnvironment).machineAuthority.program sites sourceEnvironment

axiom sourceFamilyAt : forall sourceEnvironment nativeEnvironment,
  PairRelated sourceEnvironment nativeEnvironment ->
  CheckedNativeSourceLaunchFamily
    (nativeSourceProjectWithExternalEnvironment staticCompilation.project
      sourceEnvironment)

axiom launchRealizableAt : forall sourceEnvironment nativeEnvironment,
  PairRelated sourceEnvironment nativeEnvironment ->
  NativeCompilationLaunchRealizable
    (exactCompiledPE32AuthorityWithEnvironment staticCompilation.machineAuthority
      nativeEnvironment)

end StageA.NativeSourceEnvironmentFamilyEvidenceFixture
'''


if __name__ == "__main__":
    unittest.main()
