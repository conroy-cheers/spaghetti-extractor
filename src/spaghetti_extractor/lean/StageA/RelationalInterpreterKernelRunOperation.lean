import StageA.RelationalInterpreterKernelProgramLookupOperation
import StageA.RelationalInterpreterKernelOperationABIFrame
import StageA.RelationalInterpreterKernelOperationFrameParametric
import StageA.RelationalInterpreterKernelClosedCallTree
import StageA.RelationalInterpreterKernelRun

namespace StageA.Relational.InterpreterKernelRunOperation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterKernelOperationABIFrame
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
      candidate .interpreterStep)
    (frameEntry : ∀ (runtime : RunFunctionNativeRuntime) continuationRva
        returnAddress,
      let context : NativeWorldFrameContext := {
        frame := { continuationRva, returnAddress }
        tail := runtime.calls
        eventIndex := runtime.eventIndex
        eventPrefix := runtime.events
      }
      KernelOperationFrameEntryAuthority abi .interpreterStep context) :
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
      (frameEntry runtime continuationRva returnAddress)
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
      candidate)
    (frameEntry : ∀ (runtime : RunFunctionNativeRuntime) continuationRva
        returnAddress,
      let context : NativeWorldFrameContext := {
        frame := { continuationRva, returnAddress }
        tail := runtime.calls
        eventIndex := runtime.eventIndex
        eventPrefix := runtime.events
      }
      KernelOperationFrameEntryAuthority abi .interpreterStep context) :
    RunFunctionNativeStepOperation program abi candidate :=
  runFunctionNativeStepOperationOfFrameParametric certificate frameEntry

/-! ## Request-local checked Step execution

The frame-parametric interface above remains as a compatibility path.  New Run
proofs use the finite checked call tree instead: every loop node retains the
exact Step derivation that the native nested call must implement.
-/

/-- Refinement of one exact Step request retained by a closed Run tree.  Unlike
`KernelOperationRefinesUsing`, neither the request nor the semantic response is
universally quantified. -/
def CheckedInterpreterStepRequestRefinesUsing
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) : Prop :=
  ∀ before,
    abi.requestRelated
      (.interpreterStep records environment sourceRva logical) before ->
    ∃ entryRva after nativeEvents,
      program.functionEntry? .interpreterStep = some entryRva ∧
      dispatches entryRva before after nativeEvents ∧
      abi.responseRelated
        (.interpreterStep records environment sourceRva logical)
        (.interpreterStep result) after nativeEvents ∧
      MemoryAgreesOutside
        (abi.scratchFootprint
          (.interpreterStep records environment sourceRva logical))
        after.memory before.memory

/-- Backwards-compatible projection from a whole Step theorem to the checked
request interface.  Checked Run certificates do not require this projection. -/
theorem checkedInterpreterStepRequestRefinesUsing_of_operationRefinement
    (operation :
      KernelOperationRefinesUsing program abi dispatches .interpreterStep)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) :
    CheckedInterpreterStepRequestRefinesUsing program abi dispatches
      derivation := by
  intro before requestRelated
  exact operation
    (.interpreterStep records environment sourceRva logical) before rfl
    requestRelated (.interpreterStep result)
    derivation.toAbstractKernelTransition

/-- Native Step evidence only for one exact Step derivation, reusable under the
runtime frame selected by the enclosing Run loop. -/
def RunFunctionNativeCheckedStepEvidence
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (candidate : ExactNativeWorldProgram)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) : Prop :=
  ∀ runtime continuationRva returnAddress,
    CheckedInterpreterStepRequestRefinesUsing program abi
      (RunFunctionNativeNestedDispatches candidate runtime continuationRva
        returnAddress) derivation

/-- Compose the exact Run-to-Step prelude with request-local native evidence.
The response is fixed by `derivation`; no independently asserted Step result is
accepted. -/
theorem RunFunctionNativeStepPrelude.executeChecked
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {candidate : ExactNativeWorldProgram}
    {template : RunFunctionMachineTemplate} {records : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat}
    {sourceRva : Nat} {logical : InterpreterMachine}
    {result : Option MacroResult} {stepEntryRva : Nat}
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (stepEntryExact :
      program.functionEntry? .interpreterStep = some stepEntryRva)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result)
    (operation : RunFunctionNativeCheckedStepEvidence program abi candidate
      derivation)
    (prelude : RunFunctionNativeStepPrelude program abi candidate template
      records environment sourceRva logical stepEntryRva loopState runtime) :
    Nonempty (RunFunctionNativeStepPhase abi candidate template records
      environment sourceRva logical result loopState runtime) := by
  obtain ⟨entryRva, after, emitted, entryExact, nested, responseRelated,
      memoryFrame⟩ :=
    operation runtime template.stepContinuationRva
      (runFunctionNativeReturnAddress candidate template) prelude.calleeState
      prelude.requestRelated
  have entryRvaExact : entryRva = stepEntryRva := by
    rw [stepEntryExact] at entryExact
    exact Option.some.inj entryExact.symm
  subst entryRva
  obtain ⟨nestedResult⟩ := nested
  have preludePath := prelude.chunk.path
  rw [prelude.atCallee, prelude.silent] at preludePath
  exact ⟨{
    calleeBefore := prelude.calleeState
    after := after
    emitted := emitted
    afterWorld := nestedResult.afterWorld
    observations := nestedResult.observations
    path := by simpa using preludePath.trans nestedResult.path
    responseRelated := responseRelated
    memoryFrame := memoryFrame
  }⟩

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
      (runtime.running static.reflected.reflected.template.loopHeaderRva
        loopState) ->
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
        logical none loopState runtime),
    abstractInterpreterStep semanticRecords environment sourceRva logical =
      none ->
    Nonempty (RunFunctionNativeTerminalPhase candidate
      static.reflected.reflected.template none .unimplemented stepPhase.after
      stepPhase.runtimeAfter)
  terminalExit : forall environment sourceRva logical loopState runtime result
      status
      (stepPhase : RunFunctionNativeStepPhase abi candidate
        static.reflected.reflected.template semanticRecords environment sourceRva
        logical (some result) loopState runtime),
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
        logical (some result) loopState runtime),
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
        logical none loopState runtime)
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
        logical (some macroResult) loopState runtime)
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
        environment sourceRva logical none loopState runtime)
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
        environment sourceRva logical (some macroResult) loopState runtime)
      (stepResult :
        abstractInterpreterStep records environment sourceRva logical =
          some macroResult)
      (terminalStatus :
        completionCallStatus? macroResult.completion = some status)
      (terminal : RunFunctionNativeTerminalPhase candidate template
        (some macroResult) status stepPhase.after stepPhase.runtimeAfter),
    resultEncoding rootSourceRva
      { status := status, state := macroResult.state } terminal.epilogueState

/- Legacy functional-Step source-indexed execution.
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
      (runtime.running template.loopHeaderRva loopState)) :
    Nonempty (RunFunctionNativeResultIndexedLoopResult candidate template
      (runtime.running template.loopHeaderRva loopState)
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
-/

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

/-! ## Closed-tree Run adapter

These authorities mirror the native Run phase boundary without importing a
universal Step theorem.  Structural induction over `CheckedRunFunctionDerivation`
selects every nested Step request and all semantic branch facts.
-/

/-- Exact native loop laws indexed by the Step derivations retained in a
finite checked Run tree. -/
structure RunFunctionNativeCheckedLocalSemantics
    (program : CompiledKernelProgram)
    (candidate : ExactNativeWorldProgram)
    (template : RunFunctionMachineTemplate) (records : List ProgramRecord)
    (stepEntryRva : Nat) (allowedResolverTargets : List Nat) where
  invariant : Nat -> InterpreterMachine -> NativeWorldExecution -> Prop
  stepCall : ∀ environment resolveCodeTarget sourceRva logical result
      loopState runtime
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical result),
    invariant sourceRva logical
      (runtime.running template.loopHeaderRva loopState) ->
    ∃ stepABI : KernelABIRelation,
      Nonempty (RunFunctionNativeStepPrelude program stepABI candidate template
        records environment sourceRva logical stepEntryRva loopState runtime) ∧
      RunFunctionNativeCheckedStepEvidence program stepABI candidate step
  unavailableExit : ∀ environment resolveCodeTarget sourceRva logical
      loopState runtime stepABI
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical none)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical none loopState runtime),
    Nonempty (RunFunctionNativeTerminalPhase candidate template none
      .unimplemented stepPhase.after stepPhase.runtimeAfter)
  terminalExit : ∀ environment resolveCodeTarget sourceRva logical loopState
      runtime result status stepABI
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some result))
      (statusExact : completionCallStatus? result.completion = some status)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical (some result) loopState runtime),
    Nonempty (RunFunctionNativeTerminalPhase candidate template (some result)
      status stepPhase.after stepPhase.runtimeAfter)
  continuation : ∀ environment resolveCodeTarget sourceRva logical loopState
      runtime result continuationRva stepABI
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some result))
      (continuationExact :
        completionContinuation? resolveCodeTarget result.completion =
          some continuationRva)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical (some result) loopState runtime),
    Nonempty (RunFunctionNativeContinuationPhase candidate template invariant
      allowedResolverTargets resolveCodeTarget result continuationRva
      stepPhase.after stepPhase.runtimeAfter)

/-- Execute only the Step requests contained in the supplied finite Run tree.
The terminal status and continuation are constructor fields of that tree, not
independent semantic assertions. -/
theorem RunFunctionNativeCheckedLocalSemantics.execute
    {program : CompiledKernelProgram}
    {candidate : ExactNativeWorldProgram}
    {template : RunFunctionMachineTemplate} {records : List ProgramRecord}
    {stepEntryRva : Nat} {allowedResolverTargets : List Nat}
    (stepEntryExact :
      program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeCheckedLocalSemantics program candidate
      template records stepEntryRva allowedResolverTargets)
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    (derivation : CheckedRunFunctionDerivation records environment
      resolveCodeTarget sourceRva logical result)
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (invariantHolds : semantics.invariant sourceRva logical
      (runtime.running template.loopHeaderRva loopState)) :
    Nonempty (RunFunctionNativeLoopResult candidate
      (runtime.running template.loopHeaderRva loopState)) :=
  match derivation with
  | .unavailable sourceRva logical step => by
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget
        sourceRva logical none loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        StageA.Relational.InterpreterKernelRunOperation.RunFunctionNativeStepPrelude.executeChecked
          stepEntryExact step stepRefines prelude
      obtain ⟨terminal⟩ := semantics.unavailableExit environment
        resolveCodeTarget sourceRva logical loopState runtime stepABI step
        stepPhase
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        afterLoop := stepPhase.runtimeAfter.running template.epilogueRva
          terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
      }⟩
  | .terminal sourceRva logical result status step statusExact => by
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget
        sourceRva logical (some result) loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        StageA.Relational.InterpreterKernelRunOperation.RunFunctionNativeStepPrelude.executeChecked
          stepEntryExact step stepRefines prelude
      obtain ⟨terminal⟩ := semantics.terminalExit environment resolveCodeTarget
        sourceRva logical loopState runtime result status stepABI step
        statusExact stepPhase
      have terminalPath := terminal.chunk.path
      rw [terminal.atEpilogue, terminal.silent] at terminalPath
      exact ⟨{
        afterLoop := stepPhase.runtimeAfter.running template.epilogueRva
          terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
      }⟩
  | .next sourceRva logical result continuation final step continuationExact
      rest => by
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget
        sourceRva logical (some result) loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        StageA.Relational.InterpreterKernelRunOperation.RunFunctionNativeStepPrelude.executeChecked
          stepEntryExact step stepRefines prelude
      obtain ⟨continuationPhase⟩ := semantics.continuation environment
        resolveCodeTarget sourceRva logical loopState runtime result continuation
        stepABI step continuationExact stepPhase
      have continuationPath := continuationPhase.localEvidence.path
      obtain ⟨tailResult⟩ :=
        RunFunctionNativeCheckedLocalSemantics.execute stepEntryExact semantics
          rest continuationPhase.invariantHolds
      exact ⟨{
        afterLoop := tailResult.afterLoop
        observations := stepPhase.observations ++ tailResult.observations
        path := by
          simpa only [List.append_assoc, List.append_nil] using
            stepPhase.path.trans (continuationPath.trans tailResult.path)
      }⟩

/-! ## Producer-indexed checked Run execution -/

/-- A terminal dispatch and the machine encoding that it establishes are one
proof object.  This prevents operation composition from selecting a terminal
path first and inventing unrelated result evidence later. -/
structure RunFunctionNativeCheckedEncodedTerminal
    (candidate : ExactNativeWorldProgram)
    (template : RunFunctionMachineTemplate)
    (resultEncoding : Nat -> CallResult -> MachineState -> Prop)
    (rootSourceRva : Nat) (result : CallResult)
    (semanticResult : Option MacroResult) (status : CallStatus)
    (beforeState : MachineState) (runtime : RunFunctionNativeRuntime) where
  terminal : RunFunctionNativeTerminalPhase candidate template semanticResult
    status beforeState runtime
  encoding : resultEncoding rootSourceRva result terminal.epilogueState

/-- Request-local native Run laws whose terminating branches retain the exact
result encoding required by the caller.  Recursive continuations keep the root
source RVA fixed while the loop invariant follows the current source RVA. -/
structure RunFunctionNativeCheckedResultIndexedLocalSemantics
    (program : CompiledKernelProgram)
    (candidate : ExactNativeWorldProgram)
    (template : RunFunctionMachineTemplate) (records : List ProgramRecord)
    (stepEntryRva : Nat) (allowedResolverTargets : List Nat)
    (resultEncoding : Nat -> CallResult -> MachineState -> Prop) where
  invariant : Nat -> InterpreterMachine -> NativeWorldExecution -> Prop
  stepCall : ∀ environment resolveCodeTarget sourceRva logical result
      loopState runtime
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical result),
    invariant sourceRva logical
      (runtime.running template.loopHeaderRva loopState) ->
    ∃ stepABI : KernelABIRelation,
      Nonempty (RunFunctionNativeStepPrelude program stepABI candidate template
        records environment sourceRva logical stepEntryRva loopState runtime) ∧
      RunFunctionNativeCheckedStepEvidence program stepABI candidate step
  unavailableExit : ∀ rootSourceRva environment resolveCodeTarget sourceRva
      logical loopState runtime stepABI
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical none)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical none loopState runtime),
    Nonempty (RunFunctionNativeCheckedEncodedTerminal candidate template
      resultEncoding rootSourceRva
      { status := .unimplemented, state := logical }
      none .unimplemented stepPhase.after stepPhase.runtimeAfter)
  terminalExit : ∀ rootSourceRva environment resolveCodeTarget sourceRva
      logical loopState runtime macroResult status stepABI
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some macroResult))
      (statusExact : completionCallStatus? macroResult.completion = some status)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical (some macroResult) loopState runtime),
    Nonempty (RunFunctionNativeCheckedEncodedTerminal candidate template
      resultEncoding rootSourceRva
      { status := status, state := macroResult.state }
      (some macroResult) status stepPhase.after stepPhase.runtimeAfter)
  continuation : ∀ environment resolveCodeTarget sourceRva logical loopState
      runtime macroResult continuationRva stepABI
      (step : CheckedInterpreterStepDerivation records environment
        resolveCodeTarget sourceRva logical (some macroResult))
      (continuationExact :
        completionContinuation? resolveCodeTarget macroResult.completion =
          some continuationRva)
      (stepPhase : RunFunctionNativeStepPhase stepABI candidate template records
        environment sourceRva logical (some macroResult) loopState runtime),
    Nonempty (RunFunctionNativeContinuationPhase candidate template invariant
      allowedResolverTargets resolveCodeTarget macroResult continuationRva
      stepPhase.after stepPhase.runtimeAfter)

/-- Forget only the terminal result encoding.  Exact paths and all checked
request-local Step evidence remain unchanged. -/
def RunFunctionNativeCheckedResultIndexedLocalSemantics.toLocalSemantics
    (semantics : RunFunctionNativeCheckedResultIndexedLocalSemantics program
      candidate template records stepEntryRva allowedResolverTargets
      resultEncoding) :
    RunFunctionNativeCheckedLocalSemantics program candidate template records
      stepEntryRva allowedResolverTargets := {
  invariant := semantics.invariant
  stepCall := semantics.stepCall
  unavailableExit := by
    intro environment resolveCodeTarget sourceRva logical loopState runtime
      stepABI step stepPhase
    obtain ⟨encoded⟩ := semantics.unavailableExit sourceRva environment
      resolveCodeTarget sourceRva logical loopState runtime stepABI step
      stepPhase
    exact ⟨encoded.terminal⟩
  terminalExit := by
    intro environment resolveCodeTarget sourceRva logical loopState runtime
      macroResult status stepABI step statusExact stepPhase
    obtain ⟨encoded⟩ := semantics.terminalExit sourceRva environment
      resolveCodeTarget sourceRva logical loopState runtime macroResult status
      stepABI step statusExact stepPhase
    exact ⟨encoded.terminal⟩
  continuation := semantics.continuation
}

/-- Execute a finite checked Run tree while retaining producer-side result
evidence at the decoder-computed epilogue entry. -/
theorem RunFunctionNativeCheckedResultIndexedLocalSemantics.execute
    {program : CompiledKernelProgram}
    {candidate : ExactNativeWorldProgram}
    {template : RunFunctionMachineTemplate} {records : List ProgramRecord}
    {stepEntryRva : Nat} {allowedResolverTargets : List Nat}
    {resultEncoding : Nat -> CallResult -> MachineState -> Prop}
    (stepEntryExact :
      program.functionEntry? .interpreterStep = some stepEntryRva)
    (semantics : RunFunctionNativeCheckedResultIndexedLocalSemantics program
      candidate template records stepEntryRva allowedResolverTargets
      resultEncoding)
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    (rootSourceRva : Nat)
    (derivation : CheckedRunFunctionDerivation records environment
      resolveCodeTarget sourceRva logical result)
    {loopState : MachineState} {runtime : RunFunctionNativeRuntime}
    (invariantHolds : semantics.invariant sourceRva logical
      (runtime.running template.loopHeaderRva loopState)) :
    Nonempty (RunFunctionNativeResultIndexedLoopResult candidate template
      (runtime.running template.loopHeaderRva loopState)
      (resultEncoding rootSourceRva) result) :=
  match derivation with
  | .unavailable sourceRva logical step => by
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget sourceRva logical none
          loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        RunFunctionNativeStepPrelude.executeChecked stepEntryExact step
          stepRefines prelude
      obtain ⟨encoded⟩ := semantics.unavailableExit rootSourceRva environment
        resolveCodeTarget sourceRva logical loopState runtime stepABI step
        stepPhase
      have terminalPath := encoded.terminal.chunk.path
      rw [encoded.terminal.atEpilogue, encoded.terminal.silent] at terminalPath
      exact ⟨{
        terminalRuntime := stepPhase.runtimeAfter
        terminalState := encoded.terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
        encoding := encoded.encoding
      }⟩
  | .terminal sourceRva logical macroResult status step statusExact => by
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget sourceRva logical
          (some macroResult) loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        RunFunctionNativeStepPrelude.executeChecked stepEntryExact step
          stepRefines prelude
      obtain ⟨encoded⟩ := semantics.terminalExit rootSourceRva environment
        resolveCodeTarget sourceRva logical loopState runtime macroResult status
        stepABI step statusExact stepPhase
      have terminalPath := encoded.terminal.chunk.path
      rw [encoded.terminal.atEpilogue, encoded.terminal.silent] at terminalPath
      exact ⟨{
        terminalRuntime := stepPhase.runtimeAfter
        terminalState := encoded.terminal.epilogueState
        observations := stepPhase.observations
        path := by simpa using stepPhase.path.trans terminalPath
        encoding := encoded.encoding
      }⟩
  | .next sourceRva logical macroResult continuation final step
      continuationExact rest => by
      obtain ⟨stepABI, ⟨prelude⟩, stepRefines⟩ :=
        semantics.stepCall environment resolveCodeTarget sourceRva logical
          (some macroResult) loopState runtime step invariantHolds
      obtain ⟨stepPhase⟩ :=
        RunFunctionNativeStepPrelude.executeChecked stepEntryExact step
          stepRefines prelude
      obtain ⟨continuationPhase⟩ := semantics.continuation environment
        resolveCodeTarget sourceRva logical loopState runtime macroResult
        continuation stepABI step continuationExact stepPhase
      have continuationPath := continuationPhase.localEvidence.path
      obtain ⟨tailResult⟩ :=
        RunFunctionNativeCheckedResultIndexedLocalSemantics.execute
          stepEntryExact semantics rootSourceRva rest
          continuationPhase.invariantHolds
      exact ⟨{
        terminalRuntime := tailResult.terminalRuntime
        terminalState := tailResult.terminalState
        observations := stepPhase.observations ++ tailResult.observations
        path := by
          simpa only [List.append_assoc, List.append_nil] using
            stepPhase.path.trans (continuationPath.trans tailResult.path)
        encoding := tailResult.encoding
      }⟩

/-- Completeness bridge from the authoritative Run relation to the finite
closed call tree consumed by the native adapter.  A generated checker must
construct this bridge; a status field cannot inhabit it. -/
structure RunFunctionClosedCallTreeAuthority
    (records : List ProgramRecord) : Prop where
  close : ∀ environment resolveCodeTarget sourceRva logical result,
    AbstractRunFunction records environment resolveCodeTarget sourceRva logical
      result ->
    CheckedRunFunctionDerivation records environment resolveCodeTarget sourceRva
      logical result

def RunFunctionClosedCallTreeAuthority.ofClosure
    (closure : CheckedSemanticCallTreeClosure records) :
    RunFunctionClosedCallTreeAuthority records := {
  close := closure.run
}

/-- Exact prologue authority for the checked-loop invariant. -/
structure RunFunctionNativeCheckedEntryAuthority
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (static : RunFunctionNativeStaticBinding program candidate)
    (semantics : RunFunctionNativeCheckedLocalSemantics program candidate
      static.reflected.reflected.template semanticRecords static.stepEntryRva
      static.reflected.resolverTargets) where
  entry : ∀ environment resolveCodeTarget sourceRva logical before,
    operationABI.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before ->
    RunFunctionNativeEntryPhase candidate
      static.reflected.reflected.template semantics.invariant
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
      sourceRva logical before world

/-- Exact cdecl epilogue authority indexed by the same checked Run tree used to
produce the native loop path. -/
structure RunFunctionNativeCheckedCDeclEpilogueAuthority
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (static : RunFunctionNativeStaticBinding program candidate)
    (semantics : RunFunctionNativeCheckedLocalSemantics program candidate
      static.reflected.reflected.template semanticRecords static.stepEntryRva
      static.reflected.resolverTargets) where
  epilogue : ∀ environment resolveCodeTarget sourceRva logical result before
      (requestRelated : operationABI.requestRelated
        (.runFunction semanticRecords environment resolveCodeTarget sourceRva
          logical) before)
      (derivation : CheckedRunFunctionDerivation semanticRecords environment
        resolveCodeTarget sourceRva logical result)
      (entryPhase : RunFunctionNativeEntryPhase candidate
        static.reflected.reflected.template semantics.invariant
        (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
        sourceRva logical before world)
      (loopResult : RunFunctionNativeLoopResult candidate
        (.running
          static.reflected.reflected.template.loopHeaderRva 0
          entryPhase.loopState
          [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
          0 [] world)),
    RunFunctionNativeEpiloguePhase candidate
      static.reflected.reflected.template operationABI semanticRecords environment
      resolveCodeTarget sourceRva logical result before
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
      world loopResult.afterLoop

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
  stepFrameEntry : ∀ (runtime : RunFunctionNativeRuntime) continuationRva
      returnAddress,
    let context : NativeWorldFrameContext := {
      frame := { continuationRva, returnAddress }
      tail := runtime.calls
      eventIndex := runtime.eventIndex
      eventPrefix := runtime.events
    }
    KernelOperationFrameEntryAuthority abi .interpreterStep context
  loop : RunFunctionNativeLoopPreludeAuthority program abi semanticRecords
    candidate static
      (stepFrameParametric.stepOperation stepFrameEntry)
  terminal : RunFunctionNativeTerminalDispatchAuthority program abi
    semanticRecords candidate static
      (stepFrameParametric.stepOperation stepFrameEntry) loop
  continuation : RunFunctionNativeContinuationAuthority program abi
    semanticRecords candidate static
      (stepFrameParametric.stepOperation stepFrameEntry) loop
  entry : RunFunctionNativeEntryAuthority program abi semanticRecords candidate
    world outerContinuationRva outerReturnAddress static
    (stepFrameParametric.stepOperation stepFrameEntry) loop
  epilogue : RunFunctionNativeCDeclEpilogueAuthority program abi semanticRecords
    candidate world outerContinuationRva outerReturnAddress static
    (stepFrameParametric.stepOperation stepFrameEntry) loop

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
      (certificate.stepFrameParametric.stepOperation
        certificate.stepFrameEntry) certificate.loop
      certificate.terminal certificate.continuation
  entry := certificate.entry.entry
  epilogue := certificate.epilogue.epilogue
}

/- Legacy whole-operation adapter.  The checked certificate below is the
authoritative call-aware path.
theorem RunFunctionNativeOperationCertificate.refines
    (certificate : RunFunctionNativeOperationCertificate program abi
      semanticRecords candidate world outerContinuationRva
      outerReturnAddress) :
    KernelOperationRefinesUsing program abi
      (NativeWorldSubroutineDispatches candidate world outerContinuationRva
        outerReturnAddress) .runFunction :=
  certificate.toMachineCertificate.refines
-/

/-- Request-local Run certificate.  It retains the exact checked semantic tree
for every accepted Run transition and uses no universal independent Step
refinement. -/
structure RunFunctionNativeCheckedOperationCertificate
    (program : CompiledKernelProgram) (operationABI : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word) where
  static : RunFunctionNativeStaticBinding program candidate
  abiEntry : RunFunctionNativeABIEntryAuthority operationABI semanticRecords
  closedTree : RunFunctionClosedCallTreeAuthority semanticRecords
  semantics : RunFunctionNativeCheckedLocalSemantics program candidate
    static.reflected.reflected.template semanticRecords static.stepEntryRva
    static.reflected.resolverTargets
  entry : RunFunctionNativeCheckedEntryAuthority program operationABI
    semanticRecords candidate world outerContinuationRva outerReturnAddress
    static semantics
  epilogue : RunFunctionNativeCheckedCDeclEpilogueAuthority program operationABI
    semanticRecords candidate world outerContinuationRva
    outerReturnAddress static semantics

/-- The exact finite cutpoint cluster retained by one checked Run execution.

The operation-level dispatch relation only exposes the final subroutine
endpoint.  Composition clients also need the checked entry, loop, and
epilogue segments in order to splice value-carry facts across a direct call.
This structure preserves those three path proofs without accepting a submitted
whole-operation path or endpoint. -/
structure RunFunctionNativeCheckedCutpointCluster
    {program : CompiledKernelProgram} {operationABI : KernelABIRelation}
    {semanticRecords : List ProgramRecord}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {outerContinuationRva : Nat} {outerReturnAddress : Word}
    (certificate : RunFunctionNativeCheckedOperationCertificate program
      operationABI semanticRecords candidate world outerContinuationRva
      outerReturnAddress)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState)
    (requestRelated : operationABI.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before)
    (derivation : AbstractRunFunction semanticRecords environment
      resolveCodeTarget sourceRva logical result) where
  checked : CheckedRunFunctionDerivation semanticRecords environment
    resolveCodeTarget sourceRva logical result
  entryPhase : RunFunctionNativeEntryPhase candidate
    certificate.static.reflected.reflected.template
    certificate.semantics.invariant
    (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
    sourceRva logical before world
  loopResult : RunFunctionNativeLoopResult candidate
    (.running
      certificate.static.reflected.reflected.template.loopHeaderRva 0
      entryPhase.loopState
      [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
      0 [] world)
  epilogue : RunFunctionNativeEpiloguePhase candidate
    certificate.static.reflected.reflected.template operationABI semanticRecords
    environment resolveCodeTarget sourceRva logical result before
    (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress)
    world loopResult.afterLoop

variable
  {program : CompiledKernelProgram} {operationABI : KernelABIRelation}
  {semanticRecords : List ProgramRecord}
  {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
  {outerContinuationRva : Nat} {outerReturnAddress : Word}
  {certificate : RunFunctionNativeCheckedOperationCertificate program
    operationABI semanticRecords candidate world outerContinuationRva
    outerReturnAddress}
  {environment : StageA.Relational.Interpreter.Environment}
  {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
  {logical : InterpreterMachine} {result : CallResult}
  {before : MachineState}
  {requestRelated : operationABI.requestRelated
    (.runFunction semanticRecords environment resolveCodeTarget sourceRva
      logical) before}
  {derivation : AbstractRunFunction semanticRecords environment
    resolveCodeTarget sourceRva logical result}

theorem RunFunctionNativeCheckedCutpointCluster.entryPath
    (cluster : RunFunctionNativeCheckedCutpointCluster certificate environment
      resolveCodeTarget sourceRva logical result before requestRelated
      derivation) :
    NonemptyRelatedPath candidate.transitionSystem
      (NativeWorldExecution.running certificate.static.function.span.start 0 before
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world)
      []
      (NativeWorldExecution.running
        certificate.static.reflected.reflected.template.loopHeaderRva 0
        cluster.entryPhase.loopState
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world) := by
  have path := cluster.entryPhase.chunk.path
  rw [cluster.entryPhase.atLoop, cluster.entryPhase.silent] at path
  rw [← certificate.static.templateEntryExact]
  exact path

theorem RunFunctionNativeCheckedCutpointCluster.loopPath
    (cluster : RunFunctionNativeCheckedCutpointCluster certificate environment
      resolveCodeTarget sourceRva logical result before requestRelated
      derivation) :
    NonemptyRelatedPath candidate.transitionSystem
      (NativeWorldExecution.running
        certificate.static.reflected.reflected.template.loopHeaderRva 0
        cluster.entryPhase.loopState
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world)
      cluster.loopResult.observations cluster.loopResult.afterLoop := by
  exact cluster.loopResult.path

theorem RunFunctionNativeCheckedCutpointCluster.epiloguePath
    (cluster : RunFunctionNativeCheckedCutpointCluster certificate environment
      resolveCodeTarget sourceRva logical result before requestRelated
      derivation) :
    NonemptyRelatedPath candidate.transitionSystem cluster.loopResult.afterLoop
      []
      (NativeWorldExecution.running outerContinuationRva 0 cluster.epilogue.after []
        cluster.epilogue.nativeEvents.length cluster.epilogue.nativeEvents
        cluster.epilogue.afterWorld) := by
  have path := cluster.epilogue.chunk.path
  rw [cluster.epilogue.atCaller, cluster.epilogue.silent] at path
  exact path

theorem RunFunctionNativeCheckedCutpointCluster.completePath
    (cluster : RunFunctionNativeCheckedCutpointCluster certificate environment
      resolveCodeTarget sourceRva logical result before requestRelated
      derivation) :
    NonemptyRelatedPath candidate.transitionSystem
      (NativeWorldExecution.running certificate.static.function.span.start 0 before
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world)
      cluster.loopResult.observations
      (NativeWorldExecution.running outerContinuationRva 0 cluster.epilogue.after []
        cluster.epilogue.nativeEvents.length cluster.epilogue.nativeEvents
        cluster.epilogue.afterWorld) := by
  simpa only [List.nil_append, List.append_nil] using
    (cluster.entryPath.trans cluster.loopPath).trans cluster.epiloguePath

def RunFunctionNativeCheckedCutpointCluster.subroutineResult
    (cluster : RunFunctionNativeCheckedCutpointCluster certificate environment
      resolveCodeTarget sourceRva logical result before requestRelated
      derivation) :
    NativeWorldSubroutineResult candidate world outerContinuationRva
      outerReturnAddress certificate.static.function.span.start before
      cluster.epilogue.after cluster.epilogue.nativeEvents := {
  afterWorld := cluster.epilogue.afterWorld
  observations := cluster.loopResult.observations
  path := cluster.completePath
}

/-- Construct the detailed Run proof before projecting it to the coarse
operation dispatch relation.  Every endpoint is produced by the existing
entry, checked-loop, and epilogue authorities. -/
noncomputable def RunFunctionNativeCheckedOperationCertificate.execute
    (certificate : RunFunctionNativeCheckedOperationCertificate program
      operationABI semanticRecords candidate world outerContinuationRva
      outerReturnAddress)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState)
    (requestRelated : operationABI.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before)
    (derivation : AbstractRunFunction semanticRecords environment
      resolveCodeTarget sourceRva logical result) :
    RunFunctionNativeCheckedCutpointCluster certificate environment
      resolveCodeTarget sourceRva logical result before requestRelated
      derivation := by
  let checked := certificate.closedTree.close environment resolveCodeTarget
    sourceRva logical result derivation
  let entryPhase := certificate.entry.entry environment resolveCodeTarget
    sourceRva logical before requestRelated
  let initialRuntime : RunFunctionNativeRuntime := {
    calls := [runFunctionNativeOuterFrame outerContinuationRva
      outerReturnAddress]
    eventIndex := 0
    events := []
    world := world
  }
  have entryInvariant : certificate.semantics.invariant sourceRva logical
      (initialRuntime.running
        certificate.static.reflected.reflected.template.loopHeaderRva
        entryPhase.loopState) := by
    have invariant := entryPhase.invariantHolds
    rw [entryPhase.atLoop] at invariant
    simpa [initialRuntime, RunFunctionNativeRuntime.running] using invariant
  let loopResult := Classical.choice
    (certificate.semantics.execute certificate.static.stepEntryExact checked
      entryInvariant)
  let epilogue := certificate.epilogue.epilogue environment resolveCodeTarget
    sourceRva logical result before requestRelated checked entryPhase loopResult
  exact {
    checked
    entryPhase
    loopResult
    epilogue
  }

/-- The checked Run adapter derives the existing operation-refinement target by
induction over the finite closed call tree.  Every nested Step result comes
from its retained derivation, while all native path, ABI response, and memory
frame facts remain explicit typed certificate fields. -/
theorem RunFunctionNativeCheckedOperationCertificate.refines
    (certificate : RunFunctionNativeCheckedOperationCertificate program
      operationABI
      semanticRecords candidate world outerContinuationRva
      outerReturnAddress) :
    KernelOperationRefinesUsing program operationABI
      (NativeWorldSubroutineDispatches candidate world outerContinuationRva
        outerReturnAddress) .runFunction := by
  intro request before operationMatches requestRelated response transition
  cases request with
  | programLookup records sourceRva =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | interpreterStep records environment sourceRva logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | invokeCall records environment resolveCodeTarget event logical =>
      simp [AbstractKernelRequest.operation] at operationMatches
  | runFunction records environment resolveCodeTarget sourceRva logical =>
      have recordsExact := certificate.abiEntry.establishRecords records
        environment resolveCodeTarget sourceRva logical before requestRelated
      subst records
      cases transition with
      | runFunction _ _ _ _ _ result derivation =>
          let cluster := certificate.execute environment resolveCodeTarget
            sourceRva logical result before requestRelated derivation
          refine ⟨certificate.static.function.span.start,
            cluster.epilogue.after, cluster.epilogue.nativeEvents,
            certificate.static.entryRvaExact, ?_,
            cluster.epilogue.responseRelated, cluster.epilogue.memoryFrame⟩
          exact ⟨cluster.subroutineResult⟩

/-- Transport an exact Run refinement into a wider dispatch relation.

The target relation receives the source's concrete dispatch witness unchanged;
only its proof-level packaging may differ.  In particular, this theorem cannot
construct execution from endpoint inventories, status fields, or counts.  It
is the stable adapter used when a fixed-frame Run proof is embedded in an
operation-indexed acceptance dispatch family. -/
theorem kernelOperationRefinesUsing_runFunction_mono
    {program : CompiledKernelProgram} {abi : KernelABIRelation}
    {sourceDispatch targetDispatch : KernelDispatchRelation}
    (refines :
      KernelOperationRefinesUsing program abi sourceDispatch .runFunction)
    (mapDispatch : ∀ entryRva before after events,
      sourceDispatch entryRva before after events ->
      targetDispatch entryRva before after events) :
    KernelOperationRefinesUsing program abi targetDispatch .runFunction := by
  intro request before operationExact requestRelated response transition
  obtain ⟨entryRva, after, events, entryExact, dispatched, responseRelated,
      memoryFrame⟩ :=
    refines request before operationExact requestRelated response transition
  exact ⟨entryRva, after, events, entryExact,
    mapDispatch entryRva before after events dispatched,
    responseRelated, memoryFrame⟩

#print axioms concreteRunFunctionRecordsExact
#print axioms runFunctionNativeStepOperationOfFrameParametric
#print axioms checkedInterpreterStepRequestRefinesUsing_of_operationRefinement
#print axioms RunFunctionNativeStepPrelude.executeChecked
#print axioms runFunctionNativeLocalSemanticsOf
#print axioms runFunctionNativeResultIndexedLocalSemanticsOf
#print axioms RunFunctionNativeCheckedLocalSemantics.execute
#print axioms RunFunctionNativeOperationCertificate.toMachineCertificate
#print axioms RunFunctionNativeCheckedCutpointCluster.entryPath
#print axioms RunFunctionNativeCheckedCutpointCluster.loopPath
#print axioms RunFunctionNativeCheckedCutpointCluster.epiloguePath
#print axioms RunFunctionNativeCheckedCutpointCluster.completePath
#print axioms RunFunctionNativeCheckedCutpointCluster.subroutineResult
#print axioms RunFunctionNativeCheckedOperationCertificate.execute
#print axioms RunFunctionNativeCheckedOperationCertificate.refines
#print axioms kernelOperationRefinesUsing_runFunction_mono

end StageA.Relational.InterpreterKernelRunOperation
