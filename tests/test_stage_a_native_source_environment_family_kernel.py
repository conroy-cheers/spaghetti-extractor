from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


_IMPORT = re.compile(r"^import StageA\.([A-Za-z0-9_]+)$", re.MULTILINE)
_AXIOMS = re.compile(r"depends on axioms:\s*\[([^]]*)\]", re.DOTALL)
_APPROVED_AXIOMS = {"propext", "Classical.choice", "Quot.sound"}


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageANativeSourceEnvironmentFamilyKernelTests(unittest.TestCase):
    def test_environment_family_is_checked_and_fixed_environment_reuse_fails(
        self,
    ) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (
            source_root / "RelationalNativeSourceEnvironmentFamily.lean"
        ).read_text(encoding="utf-8")
        evidence_text = (
            source_root
            / "RelationalNativeSourceEnvironmentFamilyEvidence.lean"
        ).read_text(encoding="utf-8")
        for forbidden in (
            r"^\s*axiom\b",
            r"\bsorry\b",
            r"\bunsafe\b",
            r"\bnative_decide\b",
            r"\bstatus\b",
            r"GNU|gnu",
        ):
            self.assertNotRegex(module_text, forbidden)
        for required in (
            "NativeSourceExternalEnvironmentCorrespondence",
            "sourceEnvironmentExact",
            "nativeEnvironmentExact",
            "ExactWorldNativeProgramBinding",
            "ExactWorldNativeExternalEvidence",
            "pairRealizable",
            "CorrectPinnedNativeSourceStackHypothesis",
            "ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence",
            (
                "compiledArtifactLaunchFamilyEquivalentUnderPinnedNativeSource"
                "StackHypothesis"
            ),
        ):
            self.assertIn(required, module_text)
        for required in (
            "CheckedNativeSourceAdmittedPairEvidence",
            "CheckedNativeSourceAdmittedEnvironmentFamily",
            "ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence",
            (
                "compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinned"
                "NativeSourceStackHypothesis"
            ),
        ):
            self.assertIn(required, evidence_text)

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(
                source_root,
                stage_a,
                "RelationalNativeSourceEnvironmentFamilyEvidence",
            )
            kernel_fixture = stage_a / "NativeSourceEnvironmentFamilyKernelFixture.lean"
            kernel_fixture.write_text(_KERNEL_FIXTURE, encoding="utf-8")
            checked = _run_lean_relational(
                root, bundle="NativeSourceEnvironmentFamilyKernelFixture"
            )

            rejection_fixture = (
                stage_a / "NativeSourceEnvironmentFamilyRejectionFixture.lean"
            )
            rejection_fixture.write_text(_REJECTION_FIXTURE, encoding="utf-8")
            rejected = _run_lean_relational(
                root, bundle="NativeSourceEnvironmentFamilyRejectionFixture"
            )

        self.assertEqual(checked["status"], "checked", checked)
        output = checked["stdout"] + checked["stderr"]
        self.assertNotIn("sorryAx", output)
        inventories = _AXIOMS.findall(output)
        self.assertGreaterEqual(len(inventories), 3, output)
        self.assertTrue(
            all(
                {name.strip() for name in inventory.split(",")}
                <= _APPROVED_AXIOMS
                for inventory in inventories
            ),
            output,
        )
        self.assertEqual(rejected["status"], "failed", rejected)
        rejection_output = rejected["stdout"] + rejected["stderr"]
        self.assertRegex(
            rejection_output, r"(?i)type mismatch|application type mismatch"
        )


_KERNEL_FIXTURE = r'''import StageA.RelationalNativeSourceEnvironmentFamilyEvidence

namespace StageA.NativeSourceEnvironmentFamilyKernelFixture

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.NativeSource

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilationAt : WorldExternalEnvironment -> NativeWorldEnvironment ->
      ExactNativeCompilation}
    (family : CheckedNativeSourceEnvironmentFamily context sites compilationAt) :
    ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence context sites
      compilationAt :=
  compiledArtifactEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    family

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (correspondence : NativeSourceExternalEnvironmentCorrespondence context sites
      compilation sourceEnvironment nativeEnvironment) :
    compilation.project.worldProgram.environment = sourceEnvironment :=
  correspondence.sourceProgramEnvironment

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (correspondence : NativeSourceExternalEnvironmentCorrespondence context sites
      compilation sourceEnvironment nativeEnvironment) :
    compilation.machineAuthority.program.environment = nativeEnvironment :=
  correspondence.compiledProgramEnvironment

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilationAt : WorldExternalEnvironment -> NativeWorldEnvironment ->
      ExactNativeCompilation}
    (family : CheckedNativeSourceEnvironmentFamily context sites compilationAt)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (correspondence : NativeSourceExternalEnvironmentCorrespondence context sites
      (compilationAt sourceEnvironment nativeEnvironment)
      sourceEnvironment nativeEnvironment) :
    ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence
      (compilationAt sourceEnvironment nativeEnvironment) := by
  exact
    (compiledArtifactEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
      family).2 sourceEnvironment nativeEnvironment correspondence

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {PairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop}
    (pairRealizable : exists sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment)
    (externalEvidenceAt : forall sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment ->
      ExactWorldNativeExternalEvidence context
        (exactNativeCompilationAtEnvironments compilation sourceEnvironment
          nativeEnvironment).project.worldProgram
        (exactNativeCompilationAtEnvironments compilation sourceEnvironment
          nativeEnvironment).machineAuthority.program sites sourceEnvironment)
    (sourceFamilyAt : forall sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment ->
      CheckedNativeSourceLaunchFamily
        (nativeSourceProjectWithExternalEnvironment compilation.project
          sourceEnvironment))
    (launchRealizableAt : forall sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment ->
      NativeCompilationLaunchRealizable
        (exactCompiledPE32AuthorityWithEnvironment compilation.machineAuthority
          nativeEnvironment)) :
    CheckedNativeSourceAdmittedPairEvidence context sites compilation
      PairRelated := {
  pairRealizable := pairRealizable
  externalEvidenceAt := externalEvidenceAt
  sourceFamilyAt := sourceFamilyAt
  launchRealizableAt := launchRealizableAt
}

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {PairRelated : WorldExternalEnvironment -> NativeWorldEnvironment -> Prop}
    (staticAuthority :
      StaticNativeSourceEnvironmentFamilyAuthority context compilation)
    (admittedPairs : CheckedNativeSourceAdmittedPairEvidence context sites
      compilation PairRelated)
    (toolchainCorrectAt : forall sourceEnvironment nativeEnvironment,
      PairRelated sourceEnvironment nativeEnvironment ->
      CorrectPinnedNativeSourceStackHypothesis
        (exactNativeCompilationAtEnvironments compilation sourceEnvironment
          nativeEnvironment)) :
    ExactRawOriginalPECompiledArtifactAdmittedEnvironmentFamilyEquivalence
      context sites compilation PairRelated := by
  exact
    compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
      {
        staticAuthority := staticAuthority
        admittedPairs := admittedPairs
        toolchainCorrectAt := toolchainCorrectAt
      }

#print axioms NativeSourceExternalEnvironmentCorrespondence.compiledProgramEnvironment
#print axioms ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence
#print axioms compiledArtifactEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
#print axioms compiledArtifactAdmittedEnvironmentFamilyEquivalentUnderPinnedNativeSourceStackHypothesis

end StageA.NativeSourceEnvironmentFamilyKernelFixture
'''


_REJECTION_FIXTURE = r'''import StageA.RelationalNativeSourceEnvironmentFamily

namespace StageA.NativeSourceEnvironmentFamilyRejectionFixture

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.NativeSource

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilationAt : WorldExternalEnvironment -> NativeWorldEnvironment ->
      ExactNativeCompilation}
    {sourceEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (fixed : ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence
      (compilationAt sourceEnvironment nativeEnvironment)) :
    ExactRawOriginalPECompiledArtifactEnvironmentFamilyEquivalence context sites
      compilationAt := by
  exact fixed

example {context : StaticProofContext} {sites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {sourceEnvironment replacementEnvironment : WorldExternalEnvironment}
    {nativeEnvironment : NativeWorldEnvironment}
    (correspondence : NativeSourceExternalEnvironmentCorrespondence context sites
      compilation sourceEnvironment nativeEnvironment) :
    compilation.project.worldProgram.environment = replacementEnvironment := by
  exact correspondence.sourceEnvironmentExact

end StageA.NativeSourceEnvironmentFamilyRejectionFixture
'''


if __name__ == "__main__":
    unittest.main()
