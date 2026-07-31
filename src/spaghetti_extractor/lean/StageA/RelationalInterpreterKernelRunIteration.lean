import StageA.RelationalInterpreterKernelRunOperation

namespace StageA.Relational.InterpreterKernelRunIteration

open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked single-iteration Run execution

`RunFunctionNativeCheckedLocalSemantics.execute` closes a complete finite Run
derivation. Mixed whole-program composition also needs the smaller recurring
unit: one checked semantic Step, followed by either a continuation back to the
Run loop header or a terminal route to the Run epilogue.

The constructors below retain the exact checked Step derivation and the
computed native phases. They do not accept a submitted endpoint or path.
-/

/-- The checked semantic information needed for exactly one Run iteration.
Unlike `CheckedRunFunctionDerivation`, this does not retain or require a
finite proof for the future loop tail. -/
inductive CheckedRunFunctionHead
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine) : Prop where
  | unavailable
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical none)
  | terminal
      (result : MacroResult) (status : CallStatus)
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some result))
      (statusExact : completionCallStatus? result.completion = some status)
  | next
      (result : MacroResult) (continuation : Nat)
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some result))
      (continuationExact :
        completionContinuation? resolveCodeTarget result.completion =
          some continuation)

/-- Forget the recursively checked future tail while retaining the exact head
Step and its completion classification. -/
def CheckedRunFunctionDerivation.head
    (derivation : CheckedRunFunctionDerivation records environment
      resolveCodeTarget sourceRva logical runResult) :
    CheckedRunFunctionHead records environment resolveCodeTarget sourceRva
      logical := by
  cases derivation with
  | unavailable sourceRva logical step =>
      exact .unavailable step
  | terminal sourceRva logical result status step statusExact =>
      exact .terminal result status step statusExact
  | next sourceRva logical result continuation final step continuationExact
      rest =>
      exact .next result continuation step continuationExact

inductive RunFunctionNativeCheckedIteration
    (program : CompiledKernelProgram)
    (candidate : ExactNativeWorldProgram)
    (template : RunFunctionMachineTemplate)
    (records : List ProgramRecord)
    (stepEntryRva : Nat)
    (allowedResolverTargets : List Nat)
    (semantics : RunFunctionNativeCheckedLocalSemantics program candidate
      template records stepEntryRva allowedResolverTargets)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (loopState : StageA.Formal.MachineState)
    (runtime : RunFunctionNativeRuntime) : Type where
  | unavailable
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical none)
      (stepABI : KernelABIRelation)
      (prelude : RunFunctionNativeStepPrelude program stepABI candidate
        template records environment sourceRva logical stepEntryRva loopState
        runtime)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical none loopState runtime)
      (terminal : RunFunctionNativeTerminalPhase candidate template none
        .unimplemented stepPhase.after stepPhase.runtimeAfter) :
      RunFunctionNativeCheckedIteration program candidate template records
        stepEntryRva allowedResolverTargets semantics environment
        resolveCodeTarget sourceRva logical loopState runtime
  | terminal
      (result : MacroResult) (status : CallStatus)
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some result))
      (statusExact : completionCallStatus? result.completion = some status)
      (stepABI : KernelABIRelation)
      (prelude : RunFunctionNativeStepPrelude program stepABI candidate
        template records environment sourceRva logical stepEntryRva loopState
        runtime)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical (some result) loopState runtime)
      (terminal : RunFunctionNativeTerminalPhase candidate template
        (some result) status stepPhase.after stepPhase.runtimeAfter) :
      RunFunctionNativeCheckedIteration program candidate template records
        stepEntryRva allowedResolverTargets semantics environment
        resolveCodeTarget sourceRva logical loopState runtime
  | next
      (result : MacroResult) (continuation : Nat)
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some result))
      (continuationExact :
        completionContinuation? resolveCodeTarget result.completion =
          some continuation)
      (stepABI : KernelABIRelation)
      (prelude : RunFunctionNativeStepPrelude program stepABI candidate
        template records environment sourceRva logical stepEntryRva loopState
        runtime)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical (some result) loopState runtime)
      (continuationPhase : RunFunctionNativeContinuationPhase candidate template
        semantics.invariant allowedResolverTargets resolveCodeTarget result
        continuation stepPhase.after stepPhase.runtimeAfter) :
      RunFunctionNativeCheckedIteration program candidate template records
        stepEntryRva allowedResolverTargets semantics environment
        resolveCodeTarget sourceRva logical loopState runtime

def RunFunctionNativeCheckedIteration.after
    (iteration : RunFunctionNativeCheckedIteration program candidate template
      records stepEntryRva allowedResolverTargets semantics environment
      resolveCodeTarget sourceRva logical loopState runtime) :
    NativeWorldExecution := by
  cases iteration with
  | unavailable step stepABI prelude stepPhase terminal =>
      exact terminal.chunk.after
  | terminal result status step statusExact stepABI prelude stepPhase terminal =>
      exact terminal.chunk.after
  | next result continuation step continuationExact stepABI prelude stepPhase
      continuationPhase =>
      exact stepPhase.runtimeAfter.running template.loopHeaderRva
        continuationPhase.nextState

def RunFunctionNativeCheckedIteration.observations
    (iteration : RunFunctionNativeCheckedIteration program candidate template
      records stepEntryRva allowedResolverTargets semantics environment
      resolveCodeTarget sourceRva logical loopState runtime) :
    List WorldRelationalObservable := by
  cases iteration with
  | unavailable step stepABI prelude stepPhase terminal =>
      exact stepPhase.observations
  | terminal result status step statusExact stepABI prelude stepPhase terminal =>
      exact stepPhase.observations
  | next result continuation step continuationExact stepABI prelude stepPhase
      continuationPhase =>
      exact stepPhase.observations

theorem RunFunctionNativeCheckedIteration.path
    (iteration : RunFunctionNativeCheckedIteration program candidate template
      records stepEntryRva allowedResolverTargets semantics environment
      resolveCodeTarget sourceRva logical loopState runtime) :
    NonemptyRelatedPath candidate.transitionSystem
      (runtime.running template.loopHeaderRva loopState)
      iteration.observations iteration.after := by
  cases iteration with
  | unavailable step stepABI prelude stepPhase terminal =>
      have terminalPath := terminal.chunk.path
      rw [terminal.silent] at terminalPath
      simpa using stepPhase.path.trans terminalPath
  | terminal result status step statusExact stepABI prelude stepPhase terminal =>
      have terminalPath := terminal.chunk.path
      rw [terminal.silent] at terminalPath
      simpa using stepPhase.path.trans terminalPath
  | next result continuation step continuationExact stepABI prelude stepPhase
      continuationPhase =>
      have continuationPath := continuationPhase.localEvidence.path
      simpa using stepPhase.path.trans continuationPath

/-- Execute one checked semantic head from the Run loop cutpoint. The theorem
is independent of any recursively checked future execution. -/
theorem RunFunctionNativeCheckedLocalSemantics.executeHead
    (stepEntryExact :
      program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeCheckedLocalSemantics program candidate
      template records stepEntryRva allowedResolverTargets)
    (head : CheckedRunFunctionHead records environment resolveCodeTarget
      sourceRva logical)
    (invariantHolds : semantics.invariant sourceRva logical
      (runtime.running template.loopHeaderRva loopState)) :
    Nonempty (RunFunctionNativeCheckedIteration program candidate template
      records stepEntryRva allowedResolverTargets semantics environment
      resolveCodeTarget sourceRva logical loopState runtime) := by
  cases head with
  | unavailable step =>
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget sourceRva logical none
          loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        RunFunctionNativeStepPrelude.executeChecked stepEntryExact step
          stepRefines prelude
      obtain ⟨terminal⟩ :=
        semantics.unavailableExit environment resolveCodeTarget sourceRva
          logical loopState runtime stepABI step stepPhase
      exact ⟨.unavailable step stepABI prelude stepPhase terminal⟩
  | terminal result status step statusExact =>
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget sourceRva logical
          (some result) loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        RunFunctionNativeStepPrelude.executeChecked stepEntryExact step
          stepRefines prelude
      obtain ⟨terminal⟩ :=
        semantics.terminalExit environment resolveCodeTarget sourceRva logical
          loopState runtime result status stepABI step statusExact stepPhase
      exact
        ⟨.terminal result status step statusExact stepABI prelude stepPhase
          terminal⟩
  | next result continuation step continuationExact =>
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget sourceRva logical
          (some result) loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        RunFunctionNativeStepPrelude.executeChecked stepEntryExact step
          stepRefines prelude
      obtain ⟨continuationPhase⟩ :=
        semantics.continuation environment resolveCodeTarget sourceRva logical
          loopState runtime result continuation stepABI step continuationExact
          stepPhase
      exact
        ⟨.next result continuation step continuationExact stepABI prelude
          stepPhase continuationPhase⟩

/-- Compatibility wrapper for callers that already hold a finite checked Run
derivation. Only its head is executed. -/
theorem RunFunctionNativeCheckedLocalSemantics.executeIteration
    (stepEntryExact :
      program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeCheckedLocalSemantics program candidate
      template records stepEntryRva allowedResolverTargets)
    (derivation : CheckedRunFunctionDerivation records environment
      resolveCodeTarget sourceRva logical runResult)
    (invariantHolds : semantics.invariant sourceRva logical
      (runtime.running template.loopHeaderRva loopState)) :
    Nonempty (RunFunctionNativeCheckedIteration program candidate template
      records stepEntryRva allowedResolverTargets semantics environment
      resolveCodeTarget sourceRva logical loopState runtime) :=
  StageA.Relational.InterpreterKernelRunIteration.RunFunctionNativeCheckedLocalSemantics.executeHead
    stepEntryExact semantics
      (StageA.Relational.InterpreterKernelRunIteration.CheckedRunFunctionDerivation.head
        derivation)
      invariantHolds

#print axioms CheckedRunFunctionDerivation.head
#print axioms RunFunctionNativeCheckedIteration.path
#print axioms RunFunctionNativeCheckedLocalSemantics.executeHead
#print axioms RunFunctionNativeCheckedLocalSemantics.executeIteration

end StageA.Relational.InterpreterKernelRunIteration
