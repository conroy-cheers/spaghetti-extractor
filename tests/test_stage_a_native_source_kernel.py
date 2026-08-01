from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.relational.lean.compiler import _run_lean_relational


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


@unittest.skipUnless(shutil.which("lean"), "Lean is required for kernel checks")
class StageANativeSourceKernelTests(unittest.TestCase):
    def test_native_compilation_composes_through_checked_domain(self) -> None:
        source_root = (
            Path(__file__).parents[1] / "src/spaghetti_extractor/lean/StageA"
        )
        module_text = (source_root / "RelationalNativeSource.lean").read_text(
            encoding="utf-8"
        )
        self.assertIsNone(re.search(r"^\s*axiom\b", module_text, re.MULTILINE))
        self.assertNotIn("sorry", module_text)
        self.assertIn("CheckedExecutionDomain original root", module_text)
        self.assertIn("CorrectPinnedNativeSourceStackHypothesis", module_text)
        self.assertIn("structure ExactNativeCompilation", module_text)
        self.assertIn("structure CheckedNativeSourceProject", module_text)
        self.assertIn("structure CanonicalNativeProgramIR", module_text)
        self.assertIn("structure CheckedNativeProgramInput", module_text)
        self.assertIn("structure ExactCompiledPE32Authority", module_text)
        self.assertIn("(compiledProgram : ExactNativeWorldProgram)", module_text)
        self.assertIn("def NativeSourceProject.program", module_text)
        self.assertIn("def ExactCompiledPE32Authority.program", module_text)
        self.assertNotIn("SourceArtifactsBindProgram", module_text)
        self.assertNotIn("CompiledArtifact.BindsProgram", module_text)
        compilation = module_text.split(
            "structure ExactNativeCompilation where", 1
        )[1].split(
            "/-- The sole semantic hypothesis admitted", 1
        )[0]
        self.assertNotRegex(compilation, r"(?m)^\s+sourceRoot\s*:")
        self.assertNotRegex(compilation, r"(?m)^\s+compiledRoot\s*:")
        hypothesis = module_text.split(
            "structure CorrectPinnedNativeSourceStackHypothesis", 1
        )[1].split(
            "/-- The fixed mediated state relation", 1
        )[0]
        self.assertIn("compiledLaunch : forall compiledRoot", hypothesis)
        self.assertIn("sourceLaunch : forall sourceRoot", hypothesis)
        self.assertIn("CheckedNativeCompilationLaunch", hypothesis)
        native_project = module_text.split("structure NativeSourceProject where", 1)[1]
        native_project = native_project.split("def NativeSourceProject.program", 1)[0]
        self.assertNotRegex(native_project, r"(?m)^\s+program\s*:")
        self.assertNotIn("def CorrectPinnedNativeCompilation", module_text)
        self.assertNotIn(
            "compiledArtifactEquivalentAssumingCorrectPinnedNativeToolchain",
            module_text,
        )

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            stage_a = root / "StageA"
            stage_a.mkdir()
            _copy_module_closure(source_root, stage_a, "RelationalNativeSource")
            (stage_a / "NativeSourceKernelFixture.lean").write_text(
                _KERNEL_FIXTURE,
                encoding="utf-8",
            )
            result = _run_lean_relational(
                root,
                bundle="NativeSourceKernelFixture",
            )

            (stage_a / "NativeSourceSwapRejectionFixture.lean").write_text(
                _SWAP_REJECTION_FIXTURE,
                encoding="utf-8",
            )
            rejected = _run_lean_relational(
                root,
                bundle="NativeSourceSwapRejectionFixture",
            )

        self.assertEqual(result["status"], "checked", result)
        output = result["stdout"] + result["stderr"]
        self.assertNotIn("sorryAx", output)
        self.assertIn(
            "CheckedNativeSourceProject.sourceEquivalent",
            output,
        )
        self.assertIn(
            "compiledArtifactEquivalentUnderPinnedNativeSourceStackHypothesis",
            output,
        )
        self.assertEqual(rejected["status"], "failed", rejected)
        rejection_output = rejected["stdout"] + rejected["stderr"]
        self.assertGreaterEqual(
            rejection_output.count("Type mismatch"),
            3,
            rejection_output,
        )


_KERNEL_FIXTURE = r'''import StageA.RelationalNativeSource

namespace StageA.NativeSourceKernelFixture

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.NativeSource

def tinySourceIdentity : ArtifactIdentity := {
  role := "source"
  sha256 := "41cf6794ba4200b839c53531555f0f3998df4cbb01a4d5cb0b94e3ca5e23947d"
  byteLength := 6
}

def tinySourceArtifact : ExactSourceArtifact := {
  identity := tinySourceIdentity
  bytes := [115, 111, 117, 114, 99, 101]
  identityValid := by
    refine ⟨by decide, ?_, by decide⟩
    native_decide
  byteLengthExact := by rfl
  sha256Exact := by native_decide
}

example : tinySourceArtifact.identity = tinySourceIdentity := rfl

example (project : NativeSourceProject) :
    project.program = project.checkedInput.program := rfl

example (worldProgram : DecodedWorldProgram)
    (input : CheckedNativeProgramInput worldProgram) :
    input.program.worldProgram = worldProgram := rfl

example (worldProgram : DecodedWorldProgram)
    (input : CheckedNativeProgramInput worldProgram) :
    input.program.records = input.ir.records := rfl

example (worldProgram : DecodedWorldProgram)
    (input : CheckedNativeProgramInput worldProgram) :
    input.program.x87SourceRvas = input.ir.x87SourceRvas := rfl

example (worldProgram : DecodedWorldProgram)
    (input : CheckedNativeProgramInput worldProgram) :
    input.program.x87Provider = exactX87Provider input.ir.x87Witnesses := rfl

example (reason : ExecutionBlock) (compiled : NativeWorldExecution) :
    Not (ExecutionPhaseMatches (.blocked reason) compiled) := by
  cases compiled <;> simp [ExecutionPhaseMatches]

example (bytes : ByteTree) (pe : PE32)
    (identity : ArtifactIdentity) (valid : identity.Valid)
    (buildIdentity : NixRealizationIdentity)
    (sourceProjectNarHash toolchainNarHash : String)
    (lengthExact : identity.byteLength = bytes.length)
    (parsed : parsePE32Tree bytes = some pe) (peBytes : pe.bytes = bytes) :
    CompiledArtifact := {
  identity
  buildIdentity
  sourceProjectNarHash
  toolchainNarHash
  bytes
  pe
  identityValid := valid
  byteLengthExact := lengthExact
  parsedExactly := parsed
  peBytesExact := peBytes
}

example (compilation : ExactNativeCompilation)
    (compiledRoot : NativeWorldExecution)
    (launch : CheckedCompiledPE32ConsoleLaunch
      compilation.machineAuthority compiledRoot)
    (toolchainCorrect : CorrectPinnedNativeSourceStackHypothesis
      compilation) :
    exists sourceRoot,
      CheckedNativeCompilationLaunch compilation.project sourceRoot
          compilation.machineAuthority compiledRoot /\
        Nonempty (NativeCompilationSimulation compilation.project.kernel
          compilation.machineAuthority.program sourceRoot compiledRoot) := by
  exact toolchainCorrect.compiledLaunch compiledRoot launch

example {project : NativeSourceProject} {root : WorldExecution}
    {domain : CheckedExecutionDomain project.program.worldProgram root}
    (checked : CheckedNativeSourceProject project root domain) :
    ExactRawOriginalPESourceKernelObservationallyEquivalent
      project.program.worldProgram project.kernel root domain := by
  exact checked.sourceEquivalent

example (compilation : ExactNativeCompilation)
    (sourceRoot : SourceExecution) (compiledRoot : NativeWorldExecution)
    (launch : CheckedNativeCompilationLaunch compilation.project sourceRoot
      compilation.machineAuthority compiledRoot)
    {domain : CheckedExecutionDomain compilation.project.program.worldProgram
      sourceRoot.toWorldExecution}
    (checked : CheckedNativeSourceProject compilation.project
      sourceRoot.toWorldExecution domain)
    (simulation : NativeCompilationSimulation compilation.project.kernel
      compilation.machineAuthority.program sourceRoot compiledRoot) :
    ExactRawOriginalPECompiledArtifactObservationalEquivalence
      compilation.project.program.worldProgram
      sourceRoot.toWorldExecution domain compilation.profile
      compilation.project
      compilation.artifact compilation.machineAuthority
      compiledRoot := by
  exact compiledArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
    compilation sourceRoot compiledRoot launch checked simulation

#print axioms CheckedNativeSourceProject.sourceEquivalent
#print axioms compiledArtifactEquivalentUnderPinnedNativeSourceStackHypothesis

end StageA.NativeSourceKernelFixture
'''


_SWAP_REJECTION_FIXTURE = r'''import StageA.RelationalNativeSource

namespace StageA.NativeSourceSwapRejectionFixture

open StageA.Relational
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.SourceWorld
open StageA.Relational.NativeSource

example {project replacement : NativeSourceProject} {root : WorldExecution}
    {domain : CheckedExecutionDomain project.program.worldProgram root}
    {replacementDomain :
      CheckedExecutionDomain replacement.program.worldProgram root}
    (checked : CheckedNativeSourceProject project root domain) :
    CheckedNativeSourceProject replacement root replacementDomain := by
  exact checked

example {project : NativeSourceProject}
    {artifact : CompiledArtifact}
    {authority : ExactCompiledPE32Authority artifact}
    {sourceRoot replacementRoot : SourceExecution}
    {compiledRoot : NativeWorldExecution}
    (launch : CheckedNativeCompilationLaunch project sourceRoot authority
      compiledRoot) :
    CheckedNativeCompilationLaunch project replacementRoot authority
      compiledRoot := by
  exact launch

example (compilation : ExactNativeCompilation)
    (sourceRoot : SourceExecution) (compiledRoot : NativeWorldExecution)
    (launch : CheckedNativeCompilationLaunch compilation.project sourceRoot
      compilation.machineAuthority compiledRoot)
    {domain : CheckedExecutionDomain compilation.project.program.worldProgram
      sourceRoot.toWorldExecution}
    (checked : CheckedNativeSourceProject compilation.project
      sourceRoot.toWorldExecution domain)
    (simulation : NativeCompilationSimulation compilation.project.kernel
      compilation.machineAuthority.program sourceRoot compiledRoot)
    (replacementArtifact : CompiledArtifact)
    (replacementAuthority : ExactCompiledPE32Authority replacementArtifact) :
    ExactRawOriginalPECompiledArtifactObservationalEquivalence
      compilation.project.program.worldProgram
      sourceRoot.toWorldExecution domain compilation.profile
      compilation.project
      replacementArtifact replacementAuthority
      compiledRoot := by
  exact compiledArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
    compilation sourceRoot compiledRoot launch checked simulation

end StageA.NativeSourceSwapRejectionFixture
'''


if __name__ == "__main__":
    unittest.main()
