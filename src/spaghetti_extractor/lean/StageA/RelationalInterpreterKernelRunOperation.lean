import StageA.RelationalInterpreterKernelProgramLookupOperation
import StageA.RelationalInterpreterKernelOperationFrameParametric
import StageA.RelationalInterpreterKernelRun

namespace StageA.Relational.InterpreterKernelRunOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterNativeWorld

/-!
Composable authority for one exact native `runFunction` implementation.

The native Run theorem already constructs the whole execution by induction
over `AbstractRunFunction`.  This module exposes the exact proof objects that
must be supplied to that theorem, so generated code cannot replace them with a
status field or an asserted whole-operation path:

* exact static function, template, entry, and nested-Step identities;
* concrete cdecl record identity;
* nested `interpreterStep` refinement under arbitrary runtime frames;
* a loop invariant and exact Step-call prelude;
* terminal completion dispatch;
* continuation and finite resolver-callback behavior;
* entry-frame establishment; and
* the cdecl epilogue, response, and memory frame.

The authorities are generic over the candidate PE, ABI, records, external
environment, relational world, and callback resolver.
-/

/-- Exact static authority for the selected native Run function and its direct
Step call. -/
structure RunFunctionNativeStaticBinding
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram) where
  function : KernelFunction
  reflected : RunFunctionNativeTemplateCertificate program candidate.pe
    candidate.imports function
  entryRvaExact :
    program.functionEntry? .runFunction = some function.span.start
  templateEntryExact :
    reflected.reflected.template.entryRva = function.span.start
  stepEntryRva : Nat
  stepEntryExact :
    program.functionEntry? .interpreterStep = some stepEntryRva

/-- Concrete cdecl entry authority.  Record identity is split from the runtime
loop proof so program-table changes invalidate only this boundary. -/
structure RunFunctionNativeABIEntryAuthority
    (abi : KernelABIRelation) (semanticRecords : List ProgramRecord) : Prop where
  establishRecords : forall records environment resolveCodeTarget sourceRva
      logical before,
    abi.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      before ->
    records = semanticRecords

theorem concreteRunFunctionRecordsExact
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords)
    {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat}
    {sourceRva : Nat} {logical : InterpreterMachine} {before : MachineState}
    (related : abi.relation.requestRelated
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      before) :
    records = semanticRecords := by
  change ABIRequestFacts abi
    (.runFunction records environment resolveCodeTarget sourceRva logical)
    before at related
  have payload := related.payload
  simp only [RequestPayloadHolds] at payload
  exact payload.1

def concreteRunFunctionABIEntryAuthority
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords) :
    RunFunctionNativeABIEntryAuthority abi.relation semanticRecords := {
  establishRecords := by
    intro records environment resolveCodeTarget sourceRva logical before related
    exact concreteRunFunctionRecordsExact abi related
}

/-- The generic frame-parametric Step certificate instantiated at every Run
loop call context.  The contextual path is computed by the generic lifting
theorem; this adapter only changes the endpoint wrapper. -/
def runFunctionNativeStepOperationOfFrameParametric
    (certificate : KernelOperationFrameParametricCertificate program abi
      candidate .interpreterStep) :
    RunFunctionNativeStepOperation program abi candidate := {
  refines := by
    intro runtime continuationRva returnAddress
    let context : NativeWorldFrameContext := {
      frame := { continuationRva, returnAddress }
      tail := runtime.calls
      eventIndex := runtime.eventIndex
      eventPrefix := runtime.events
    }
    have contextual := certificate.refinesInContext context runtime.world
    intro request before operationMatches requestRelated response transition
    obtain ⟨entryRva, after, emitted, entryExact, dispatch, responseRelated,
        memoryFrame⟩ :=
      contextual request before operationMatches requestRelated response
        transition
    obtain ⟨result⟩ := dispatch
    refine ⟨entryRva, after, emitted, entryExact, ?_, responseRelated,
      memoryFrame⟩
    exact ⟨{
      afterWorld := result.afterWorld
      observations := result.observations
      path := by
        simpa [context, NativeWorldFrameContext.embed,
          RunFunctionNativeRuntime.running] using result.path
    }⟩
}

abbrev RunFunctionNativeFrameParametricStepCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) :=
  KernelOperationFrameParametricCertificate program abi candidate
    .interpreterStep

def RunFunctionNativeFrameParametricStepCertificate.stepOperation
    (certificate : RunFunctionNativeFrameParametricStepCertificate program abi
      candidate) :
    RunFunctionNativeStepOperation program abi candidate :=
  runFunctionNativeStepOperationOfFrameParametric certificate

/-- Loop invariant plus the exact nine-instruction nested-Step prelude.  The
Step operation itself is a separate index, preventing a prelude certificate
from silently selecting another dispatch relation. -/
structure RunFunctionNativeLoopPreludeAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate) where
  invariant : Nat -> InterpreterMachine -> NativeWorldExecution -> Prop
  stepPrelude : forall environment sourceRva logical loopState runtime,
    invariant sourceRva logical
      (runtime.running
        (static.reflected.reflected.template.entryRva + 58) loopState) ->
    Nonempty (RunFunctionNativeStepPrelude program abi candidate
      static.reflected.reflected.template semanticRecords environment sourceRva
      logical static.stepEntryRva loopState runtime)

/-- Exact completion-tag dispatch after a nested Step result. -/
structure RunFunctionNativeTerminalDispatchAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
      candidate static stepOperation) where
  unavailableExit : forall environment sourceRva logical loopState runtime
      (stepPhase : RunFunctionNativeStepPhase abi candidate
        static.reflected.reflected.template semanticRecords environment sourceRva
        logical loopState runtime),
    abstractInterpreterStep semanticRecords environment sourceRva logical =
      none ->
    Nonempty (RunFunctionNativeTerminalPhase candidate
      static.reflected.reflected.template none .unimplemented stepPhase.after
      stepPhase.runtimeAfter)
  terminalExit : forall environment sourceRva logical loopState runtime result
      status
      (stepPhase : RunFunctionNativeStepPhase abi candidate
        static.reflected.reflected.template semanticRecords environment sourceRva
        logical loopState runtime),
    abstractInterpreterStep semanticRecords environment sourceRva logical =
      some result ->
    completionCallStatus? result.completion = some status ->
    Nonempty (RunFunctionNativeTerminalPhase candidate
      static.reflected.reflected.template (some result) status stepPhase.after
      stepPhase.runtimeAfter)

/-- Exact direct continuation or finite resolver-callback behavior.  Unknown
or unbounded targets cannot inhabit this authority. -/
structure RunFunctionNativeContinuationAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
      candidate static stepOperation) where
  continuation : forall environment resolveCodeTarget sourceRva logical
      loopState runtime result continuationRva
      (stepPhase : RunFunctionNativeStepPhase abi candidate
        static.reflected.reflected.template semanticRecords environment sourceRva
        logical loopState runtime),
    abstractInterpreterStep semanticRecords environment sourceRva logical =
      some result ->
    completionContinuation? resolveCodeTarget result.completion =
      some continuationRva ->
    Nonempty (RunFunctionNativeContinuationPhase candidate
      static.reflected.reflected.template loop.invariant
      static.reflected.resolverTargets resolveCodeTarget result continuationRva
      stepPhase.after stepPhase.runtimeAfter)

/-- Terminal dispatch together with the exact machine encoding of the selected
semantic result.  The source RVA remains an index of the evidence, avoiding the
unsound widening that would require one terminal state to encode every possible
source RVA. -/
structure RunFunctionNativeResultIndexedTerminalDispatchAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi
      semanticRecords candidate static stepOperation)
    (resultEncoding : Nat -> CallResult -> MachineState -> Prop) where
  terminal : RunFunctionNativeTerminalDispatchAuthority program abi
    semanticRecords candidate static stepOperation loop
  unavailableEncoding : forall rootSourceRva environment sourceRva logical
      loopState runtime
      (stepPhase : RunFunctionNativeStepPhase abi candidate
        static.reflected.reflected.template semanticRecords environment sourceRva
        logical loopState runtime)
      (unavailable :
        abstractInterpreterStep semanticRecords environment sourceRva logical =
          none)
      (terminalPhase : RunFunctionNativeTerminalPhase candidate
        static.reflected.reflected.template none .unimplemented stepPhase.after
        stepPhase.runtimeAfter),
    resultEncoding rootSourceRva
      { status := .unimplemented, state := logical }
      terminalPhase.epilogueState
  terminalEncoding : forall rootSourceRva environment sourceRva logical
      loopState runtime
      macroResult status
      (stepPhase : RunFunctionNativeStepPhase abi candidate
        static.reflected.reflected.template semanticRecords environment sourceRva
        logical loopState runtime)
      (stepResult :
        abstractInterpreterStep semanticRecords environment sourceRva logical =
          some macroResult)
      (terminalStatus :
        completionCallStatus? macroResult.completion = some status)
      (terminalPhase : RunFunctionNativeTerminalPhase candidate
        static.reflected.reflected.template (some macroResult) status
        stepPhase.after stepPhase.runtimeAfter),
    resultEncoding rootSourceRva
      { status := status, state := macroResult.state }
      terminalPhase.epilogueState

/-- Source-indexed result semantics used by Run operation composition.  This is
the request-dependent counterpart of
`RunFunctionNativeResultIndexedLocalSemantics`: the terminal result predicate
may depend on the active source RVA while the base loop invariant remains
universal over recursive continuations. -/
structure RunFunctionNativeSourceResultIndexedLocalSemantics
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram) (template : RunFunctionMachineTemplate)
    (records : List ProgramRecord) (stepEntryRva : Nat)
    (allowedResolverTargets : List Nat)
    (resultEncoding : Nat -> CallResult -> MachineState -> Prop) where
  base : RunFunctionNativeLocalSemantics program abi candidate template records
    stepEntryRva allowedResolverTargets
  unavailableEncoding : forall rootSourceRva environment sourceRva logical
      loopState runtime
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime)
      (unavailable :
        abstractInterpreterStep records environment sourceRva logical = none)
      (terminal : RunFunctionNativeTerminalPhase candidate template none
        .unimplemented stepPhase.after stepPhase.runtimeAfter),
    resultEncoding rootSourceRva { status := .unimplemented, state := logical }
      terminal.epilogueState
  terminalEncoding : forall rootSourceRva environment sourceRva logical
      loopState runtime
      macroResult status
      (stepPhase : RunFunctionNativeStepPhase abi candidate template records
        environment sourceRva logical loopState runtime)
      (stepResult :
        abstractInterpreterStep records environment sourceRva logical =
          some macroResult)
      (terminalStatus :
        completionCallStatus? macroResult.completion = some status)
      (terminal : RunFunctionNativeTerminalPhase candidate template
        (some macroResult) status stepPhase.after stepPhase.runtimeAfter),
    resultEncoding rootSourceRva
      { status := status, state := macroResult.state } terminal.epilogueState

/-- Execute the source-indexed Run semantics while retaining the result
evidence produced at the exact terminal state. -/
theorem RunFunctionNativeSourceResultIndexedLocalSemantics.execute
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {records : List ProgramRecord} {stepEntryRva : Nat}
    {allowedResolverTargets : List Nat}
    {resultEncoding : Nat -> CallResult -> MachineState -> Prop}
    (stepEntryExact :
      program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeSourceResultIndexedLocalSemantics program abi
      candidate template records stepEntryRva allowedResolverTargets
      resultEncoding)
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    (rootSourceRva : Nat)
    (derivation : AbstractRunFunction records environment resolveCodeTarget
      sourceRva logical result)
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (invariantHolds : semantics.base.invariant sourceRva logical
      (runtime.running (template.entryRva + 58) loopState)) :
    Nonempty (RunFunctionNativeResultIndexedLoopResult candidate template
      (runtime.running (template.entryRva + 58) loopState)
      (resultEncoding rootSourceRva) result) := by
  induction derivation generalizing loopState runtime with
  | unavailable sourceRva logical unavailable =>
      obtain ⟨prelude⟩ := semantics.base.stepPrelude environment sourceRva
        logical loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ :=
        prelude.execute stepEntryExact semantics.base.stepOperation
      obtain ⟨terminal⟩ := semantics.base.unavailableExit environment sourceRva
        logical loopState runtime stepPhase unavailable
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        terminalRuntime := stepPhase.runtimeAfter
        terminalState := terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
        encoding := semantics.unavailableEncoding rootSourceRva environment
          sourceRva logical loopState runtime stepPhase unavailable terminal
      }⟩
  | terminal sourceRva logical macroResult status stepResult terminalStatus =>
      obtain ⟨prelude⟩ := semantics.base.stepPrelude environment sourceRva
        logical loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ :=
        prelude.execute stepEntryExact semantics.base.stepOperation
      obtain ⟨terminal⟩ := semantics.base.terminalExit environment sourceRva
        logical loopState runtime macroResult status stepPhase stepResult
        terminalStatus
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        terminalRuntime := stepPhase.runtimeAfter
        terminalState := terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
        encoding := semantics.terminalEncoding rootSourceRva environment
          sourceRva logical loopState runtime macroResult status stepPhase
          stepResult terminalStatus terminal
      }⟩
  | next sourceRva logical macroResult continuation final stepResult nextTarget
      tail induction =>
      obtain ⟨prelude⟩ := semantics.base.stepPrelude environment sourceRva
        logical loopState runtime invariantHolds
      obtain ⟨stepPhase⟩ :=
        prelude.execute stepEntryExact semantics.base.stepOperation
      obtain ⟨continuationPhase⟩ := semantics.base.continuation environment
        resolveCodeTarget sourceRva logical loopState runtime macroResult
        continuation stepPhase stepResult nextTarget
      have continuationPath := continuationPhase.localEvidence.path
      obtain ⟨tailResult⟩ := induction continuationPhase.invariantHolds
      exact ⟨{
        terminalRuntime := tailResult.terminalRuntime
        terminalState := tailResult.terminalState
        observations := stepPhase.observations ++ tailResult.observations
        path := by
          simpa only [List.append_assoc, List.append_nil] using
            stepPhase.path.trans (continuationPath.trans tailResult.path)
        encoding := tailResult.encoding
      }⟩

/-- Assemble the exact local loop semantics from separately cached authorities.
This definition contributes no new semantic premise. -/
def runFunctionNativeLocalSemanticsOf
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
      candidate static stepOperation)
    (terminal : RunFunctionNativeTerminalDispatchAuthority program abi
      semanticRecords candidate static stepOperation loop)
    (continuation : RunFunctionNativeContinuationAuthority program abi
      semanticRecords candidate static stepOperation loop) :
    RunFunctionNativeLocalSemantics program abi candidate
      static.reflected.reflected.template semanticRecords static.stepEntryRva
      static.reflected.resolverTargets := {
  invariant := loop.invariant
  stepOperation := stepOperation
  stepPrelude := loop.stepPrelude
  unavailableExit := terminal.unavailableExit
  terminalExit := terminal.terminalExit
  continuation := continuation.continuation
}

/-- Assemble the result-indexed Run semantics from the same exact local
authorities.  Unlike the legacy result-indexed wrapper, the encoding remains
indexed by the active source RVA and therefore composes through recursive Run
continuations without conflating distinct engine states. -/
def runFunctionNativeResultIndexedLocalSemanticsOf
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi
      semanticRecords candidate static stepOperation)
    (resultEncoding : Nat -> CallResult -> MachineState -> Prop)
    (terminal :
      RunFunctionNativeResultIndexedTerminalDispatchAuthority program abi
        semanticRecords candidate static stepOperation loop resultEncoding)
    (continuation : RunFunctionNativeContinuationAuthority program abi
      semanticRecords candidate static stepOperation loop) :
    RunFunctionNativeSourceResultIndexedLocalSemantics program abi
      candidate static.reflected.reflected.template semanticRecords
      static.stepEntryRva static.reflected.resolverTargets
      resultEncoding := {
  base := runFunctionNativeLocalSemanticsOf static stepOperation loop
    terminal.terminal continuation
  unavailableEncoding := terminal.unavailableEncoding
  terminalEncoding := terminal.terminalEncoding
}

/-- Exact prologue and outer-frame authority. -/
structure RunFunctionNativeEntryAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
      candidate static stepOperation) where
  entry : forall environment resolveCodeTarget sourceRva logical before,
    abi.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before ->
    RunFunctionNativeEntryPhase candidate
      static.reflected.reflected.template loop.invariant
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
      sourceRva logical before world

/-- Exact cdecl epilogue and ABI result authority. -/
structure RunFunctionNativeCDeclEpilogueAuthority
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation : RunFunctionNativeStepOperation program abi candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
      candidate static stepOperation) where
  epilogue : forall environment resolveCodeTarget sourceRva logical result
      before
      (requestRelated : abi.requestRelated
        (.runFunction semanticRecords environment resolveCodeTarget sourceRva
          logical) before)
      (derivation : AbstractRunFunction semanticRecords environment
        resolveCodeTarget sourceRva logical result)
      (entryPhase : RunFunctionNativeEntryPhase candidate
        static.reflected.reflected.template loop.invariant
        (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
        sourceRva logical before world)
      (afterLoop : NativeWorldExecution),
    RunFunctionNativeEpiloguePhase candidate
      static.reflected.reflected.template abi semanticRecords environment
      resolveCodeTarget sourceRva logical result before
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
      world afterLoop

/-- Compositional native Run operation certificate.  It contains no submitted
whole-function endpoint, path, or status. -/
structure RunFunctionNativeOperationCertificate
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word) where
  static : RunFunctionNativeStaticBinding program candidate
  abiEntry : RunFunctionNativeABIEntryAuthority abi semanticRecords
  stepFrameParametric :
    RunFunctionNativeFrameParametricStepCertificate program abi candidate
  loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
    candidate static stepFrameParametric.stepOperation
  terminal : RunFunctionNativeTerminalDispatchAuthority program abi
    semanticRecords candidate static stepFrameParametric.stepOperation loop
  continuation : RunFunctionNativeContinuationAuthority program abi
    semanticRecords candidate static stepFrameParametric.stepOperation loop
  entry : RunFunctionNativeEntryAuthority program abi semanticRecords candidate
    world outerContinuationRva outerReturnAddress static
    stepFrameParametric.stepOperation loop
  epilogue : RunFunctionNativeCDeclEpilogueAuthority program abi semanticRecords
    candidate world outerContinuationRva outerReturnAddress static
    stepFrameParametric.stepOperation loop

def RunFunctionNativeOperationCertificate.toMachineCertificate
    (certificate : RunFunctionNativeOperationCertificate program abi
      semanticRecords candidate world outerContinuationRva outerReturnAddress) :
    RunFunctionNativeMachineCertificate program abi semanticRecords candidate
      world outerContinuationRva outerReturnAddress := {
  function := certificate.static.function
  reflected := certificate.static.reflected
  entryRvaExact := certificate.static.entryRvaExact
  templateEntryExact := certificate.static.templateEntryExact
  stepEntryRva := certificate.static.stepEntryRva
  stepEntryExact := certificate.static.stepEntryExact
  establishRecords := certificate.abiEntry.establishRecords
  semantics := fun _ _ =>
    runFunctionNativeLocalSemanticsOf certificate.static
      certificate.stepFrameParametric.stepOperation certificate.loop
      certificate.terminal certificate.continuation
  entry := certificate.entry.entry
  epilogue := certificate.epilogue.epilogue
}

theorem RunFunctionNativeOperationCertificate.refines
    (certificate : RunFunctionNativeOperationCertificate program abi
      semanticRecords candidate world outerContinuationRva
      outerReturnAddress) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world outerContinuationRva
        outerReturnAddress) .runFunction :=
  certificate.toMachineCertificate.refines

#print axioms concreteRunFunctionRecordsExact
#print axioms runFunctionNativeStepOperationOfFrameParametric
#print axioms runFunctionNativeLocalSemanticsOf
#print axioms runFunctionNativeResultIndexedLocalSemanticsOf
#print axioms RunFunctionNativeSourceResultIndexedLocalSemantics.execute
#print axioms RunFunctionNativeOperationCertificate.toMachineCertificate
#print axioms RunFunctionNativeOperationCertificate.refines

end StageA.Relational.InterpreterKernelRunOperation
