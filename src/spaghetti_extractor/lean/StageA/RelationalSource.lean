import StageA.RelationalC0
import StageA.RelationalInterpreterNormalization

namespace StageA.Relational.Source

open StageA.Formal
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization

structure ExactOriginalImage where
  bytes : ByteTree
  pe : PE32
  parsedExactly : parsePE32Tree bytes = some pe

structure CheckedOriginalRegion (pe : PE32) where
  path : ExactNormalizedTransferPath
  transfer : SemanticTransfer
  sourceRvaExact : path.record.sourceRva = path.sourceRva
  certificate : ExactProgramRecordNormalizationCertificate pe path transfer

def originalStep {pe : PE32} : List (CheckedOriginalRegion pe) -> Nat ->
    Interpreter.Environment -> MachineState -> Option MacroResult
  | [], _, _, _ => none
  | region :: tail, rva, environment, state =>
      if region.path.sourceRva == rva then
        runExactNormalizedPath pe region.path environment state
      else originalStep tail rva environment state

theorem originalStep_eq_sourceStep {pe : PE32}
    (regions : List (CheckedOriginalRegion pe))
    (rva : Nat) (environment : Interpreter.Environment) (state : MachineState) :
    originalStep regions rva environment state =
      sourceStep (regions.map fun region => region.path.record)
        rva environment state := by
  induction regions with
  | nil => rfl
  | cons region tail ih =>
      simp only [originalStep, List.map_cons, sourceStep]
      rw [region.sourceRvaExact]
      by_cases selected : region.path.sourceRva == rva
      · simp only [selected, if_true]
        exact (region.certificate.rawMacroStep environment state).symm
      · simp only [selected]
        exact ih

def OriginalSourceObservationallyEquivalent
    (image : ExactOriginalImage)
    (regions : List (CheckedOriginalRegion image.pe))
    (program : C0Program) : Prop :=
  forall fuel environment state,
    runWithStep (originalStep regions) environment fuel
        (WholeExecution.launch image.pe.entrypointRva state) =
      runWithStep (sourceStep program.records) environment fuel
        (WholeExecution.launch program.entryRva state)

structure OriginalSourceWholeProgramCertificate
    (image : ExactOriginalImage)
    (regions : List (CheckedOriginalRegion image.pe))
    (program : C0Program) (source : String) : Prop where
  recordsExact : program.records = regions.map fun region => region.path.record
  entryRvaExact : program.entryRva = image.pe.entrypointRva
  checkedSource : CheckedC0Source program source

theorem pe32EquivalentToC0Source
    (certificate : OriginalSourceWholeProgramCertificate image regions program source) :
    OriginalSourceObservationallyEquivalent image regions program := by
  intro fuel environment state
  rw [← certificate.entryRvaExact]
  have stepExact : originalStep regions = sourceStep program.records := by
    funext rva environment state
    rw [certificate.recordsExact]
    exact originalStep_eq_sourceStep regions rva environment state
  rw [stepExact]

def OriginalCompiledObservationallyEquivalent
    (image : ExactOriginalImage)
    (regions : List (CheckedOriginalRegion image.pe)) (program : C0Program)
    (compiledRun : Interpreter.Environment -> Nat -> WholeExecution -> WholeExecution) : Prop :=
  forall environment fuel state,
    runWithStep (originalStep regions) environment fuel
        (WholeExecution.launch image.pe.entrypointRva state) =
      compiledRun environment fuel
        (WholeExecution.launch program.entryRva state)

theorem compiledArtifactEquivalentAssumingCorrectToolchain
    (sourceCertificate :
      OriginalSourceWholeProgramCertificate image regions program source)
    (compilerCorrect :
      CorrectPinnedCompilation profile program artifact compiledRun) :
    OriginalCompiledObservationallyEquivalent image regions program compiledRun := by
  intro environment fuel state
  rw [pe32EquivalentToC0Source sourceCertificate fuel environment state]
  exact compilerCorrect.2.2.2.2.2.2.2 environment fuel
    (WholeExecution.launch program.entryRva state)

end StageA.Relational.Source
