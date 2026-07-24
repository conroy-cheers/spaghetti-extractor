import StageA.RelationalInterpreterKernelRunOperation
import StageA.RelationalInterpreterKernelRunProducerResultClosure

namespace StageA.Relational.InterpreterKernelRunOperationResultBridge

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelOperationFrameParametric
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterKernelRunProducerResultClosure
open StageA.Relational.InterpreterNativeWorld

/-!
# Result-indexed Run operation to cdecl bridge

The exact native Run loop produces `CallResultEncodingResidual` at its computed
terminal state.  This module carries that evidence through the decoded cdecl
suffix and constructs the environment-closed response certificate.  The suffix
authority cannot choose or assert the semantic Run result.
-/

/-- Exact suffix evidence after a result-indexed Run loop.  Operation-result
evidence is intentionally absent and is derived by `environmentClosed`. -/
structure RunFunctionNativeResultIndexedCDeclSuffixEvidence
    (program : CompiledKernelProgram)
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords)
    (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) (outerContinuationRva : Nat)
    (outerReturnAddress : Word)
    (static : RunFunctionNativeStaticBinding program candidate)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState)
    (requestRelated : abi.relation.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before)
    (derivation : AbstractRunFunction semanticRecords environment
      resolveCodeTarget sourceRva logical result)
    (loopState : MachineState)
    (loopResult : RunFunctionNativeResultIndexedLoopResult candidate
      static.reflected.reflected.template
      (({
        calls := [runFunctionNativeOuterFrame outerContinuationRva
          outerReturnAddress]
        eventIndex := 0
        events := []
        world := world
      } : RunFunctionNativeRuntime).running
        (static.reflected.reflected.template.entryRva + 58)
        loopState)
      (CallResultEncodingResidual abi sourceRva) result) where
  cdecl : CheckedKernelCDeclEpilogue program candidate static.function
  epilogueRvaExact :
    cdecl.inventory.epilogueRva =
      static.reflected.reflected.template.entryRva + 326
  callsExact :
    loopResult.terminalRuntime.calls =
      [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
  eventIndexExact :
    loopResult.terminalRuntime.eventIndex =
      loopResult.terminalRuntime.events.length
  operationExact :
    (AbstractKernelRequest.runFunction semanticRecords environment
      resolveCodeTarget sourceRva logical).operation =
        cdecl.inventory.operation
  execution : ExactComputedCDeclEpilogue candidate cdecl
    (.caller
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress) [])
    loopResult.terminalState loopResult.terminalRuntime.eventIndex
    loopResult.terminalRuntime.events loopResult.terminalRuntime.world
  symbolic : ExactDecodedCDeclSymbolicExecution execution before
  frame : CDeclSymbolicFrameExpressions
  frameFacts : CDeclSymbolicABIFrameFacts abi
    (.caller
      (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress) [])
    (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
    before symbolic.behavior frame
  preservation : ExactRunFunctionCDeclSuffixResultPreservation
    loopResult.terminalState execution
  externalTrace : CheckedResponseExternalTrace
    (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
    (.call result) loopResult.terminalRuntime.events

/-- Construct the environment-closed epilogue certificate from exact suffix
facts and producer-side result evidence. -/
def RunFunctionNativeResultIndexedCDeclSuffixEvidence.environmentClosed
    {program : CompiledKernelProgram} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {semanticRecords : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {outerContinuationRva : Nat} {outerReturnAddress : Word}
    {static : RunFunctionNativeStaticBinding program candidate}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    {before loopState : MachineState}
    {requestRelated : abi.relation.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before}
    {derivation : AbstractRunFunction semanticRecords environment
      resolveCodeTarget sourceRva logical result}
    {loopResult : RunFunctionNativeResultIndexedLoopResult candidate
      static.reflected.reflected.template
      ((({
        calls := [runFunctionNativeOuterFrame outerContinuationRva
          outerReturnAddress]
        eventIndex := 0
        events := []
        world := world
      } : RunFunctionNativeRuntime).running
        (static.reflected.reflected.template.entryRva + 58) loopState))
      (CallResultEncodingResidual abi sourceRva) result}
    (evidence : RunFunctionNativeResultIndexedCDeclSuffixEvidence program abi
      candidate world outerContinuationRva outerReturnAddress static environment
      resolveCodeTarget sourceRva logical result before requestRelated derivation
      loopState loopResult) :
    EnvironmentClosedCDeclEpilogueCertificate abi candidate evidence.cdecl
      (.caller
        (runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress) [])
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva logical)
      (.call result) before loopResult.terminalState
      loopResult.terminalRuntime.eventIndex loopResult.terminalRuntime.events
      loopResult.terminalRuntime.world := {
  operationExact := evidence.operationExact
  transition := .runFunction semanticRecords environment resolveCodeTarget
    sourceRva logical result derivation
  entry := requestRelated
  execution := evidence.execution
  symbolic := evidence.symbolic
  frame := evidence.frame
  frameFacts := evidence.frameFacts
  operationResult :=
    RunFunctionNativeResultIndexedLoopResult.operationResultEvidence loopResult
      evidence.preservation semanticRecords environment resolveCodeTarget logical
  externalTrace := evidence.externalTrace
}

/-- The residual suffix premise contains only exact execution, symbolic frame,
preservation, and trace evidence. -/
structure RunFunctionNativeResultIndexedCDeclSuffixAuthority
    (program : CompiledKernelProgram)
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word)
    (static : RunFunctionNativeStaticBinding program candidate)
    (stepOperation :
      RunFunctionNativeStepOperation program abi.relation candidate)
    (loop : RunFunctionNativeLoopPreludeAuthority program abi.relation
      semanticRecords candidate static stepOperation) where
  suffix : forall environment resolveCodeTarget sourceRva logical result before
      (requestRelated : abi.relation.requestRelated
        (.runFunction semanticRecords environment resolveCodeTarget sourceRva
          logical) before)
      (derivation : AbstractRunFunction semanticRecords environment
        resolveCodeTarget sourceRva logical result)
      (loopState : MachineState)
      (loopResult : RunFunctionNativeResultIndexedLoopResult candidate
        static.reflected.reflected.template
        (({
          calls := [runFunctionNativeOuterFrame outerContinuationRva
            outerReturnAddress]
          eventIndex := 0
          events := []
          world := world
        } : RunFunctionNativeRuntime).running
          (static.reflected.reflected.template.entryRva + 58) loopState)
        (CallResultEncodingResidual abi sourceRva) result),
    Nonempty (RunFunctionNativeResultIndexedCDeclSuffixEvidence program abi
      candidate world outerContinuationRva outerReturnAddress static environment
      resolveCodeTarget sourceRva logical result before requestRelated derivation
      loopState loopResult)

/-- Result-indexed Run certificate.  The loop produces the semantic result
encoding; the suffix authority supplies only exact decoded execution and frame
facts. -/
structure RunFunctionNativeResultIndexedOperationCertificate
    (program : CompiledKernelProgram)
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word) where
  static : RunFunctionNativeStaticBinding program candidate
  abiEntry : RunFunctionNativeABIEntryAuthority abi.relation semanticRecords
  stepFrameParametric :
    RunFunctionNativeFrameParametricStepCertificate program abi.relation
      candidate
  loop : RunFunctionNativeLoopPreludeAuthority program abi.relation
    semanticRecords candidate static stepFrameParametric.stepOperation
  terminal : RunFunctionNativeResultIndexedTerminalDispatchAuthority program
    abi.relation semanticRecords candidate static
    stepFrameParametric.stepOperation loop (CallResultEncodingResidual abi)
  continuation : RunFunctionNativeContinuationAuthority program abi.relation
    semanticRecords candidate static stepFrameParametric.stepOperation loop
  entry : RunFunctionNativeEntryAuthority program abi.relation semanticRecords
    candidate world outerContinuationRva outerReturnAddress static
    stepFrameParametric.stepOperation loop
  suffix : RunFunctionNativeResultIndexedCDeclSuffixAuthority program abi
    candidate world outerContinuationRva outerReturnAddress static
    stepFrameParametric.stepOperation loop

def RunFunctionNativeResultIndexedOperationCertificate.semantics
    {program : CompiledKernelProgram} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {semanticRecords : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {outerContinuationRva : Nat} {outerReturnAddress : Word}
    (certificate : RunFunctionNativeResultIndexedOperationCertificate program abi
      candidate world outerContinuationRva outerReturnAddress) :
    RunFunctionNativeSourceResultIndexedLocalSemantics program abi.relation
      candidate certificate.static.reflected.reflected.template semanticRecords
      certificate.static.stepEntryRva certificate.static.reflected.resolverTargets
      (CallResultEncodingResidual abi) :=
  runFunctionNativeResultIndexedLocalSemanticsOf certificate.static
    certificate.stepFrameParametric.stepOperation certificate.loop
    (CallResultEncodingResidual abi) certificate.terminal
    certificate.continuation

theorem RunFunctionNativeResultIndexedOperationCertificate.refines
    {program : CompiledKernelProgram} {pe : PE32}
    {imports : List PEImport} {relocations : List BaseRelocation}
    {tableRva countRva : Nat} {semanticRecords : List ProgramRecord}
    {abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {outerContinuationRva : Nat} {outerReturnAddress : Word}
    (certificate : RunFunctionNativeResultIndexedOperationCertificate program abi
      candidate world outerContinuationRva outerReturnAddress) :
    KernelOperationRefinesUsing program abi.relation
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
          let semantics := certificate.semantics
          let entryPhase := certificate.entry.entry environment resolveCodeTarget
            sourceRva logical before requestRelated
          let initialRuntime : RunFunctionNativeRuntime := {
            calls := [runFunctionNativeOuterFrame outerContinuationRva
              outerReturnAddress]
            eventIndex := 0
            events := []
            world := world
          }
          have entryInvariant : semantics.base.invariant sourceRva logical
              (initialRuntime.running
                (certificate.static.reflected.reflected.template.entryRva + 58)
                entryPhase.loopState) := by
            have invariant := entryPhase.invariantHolds
            rw [entryPhase.atLoop] at invariant
            simpa [semantics, initialRuntime,
              RunFunctionNativeRuntime.running] using invariant
          obtain ⟨loopResult⟩ := semantics.execute
            certificate.static.stepEntryExact sourceRva derivation entryInvariant
          obtain ⟨suffixEvidence⟩ := certificate.suffix.suffix environment
            resolveCodeTarget sourceRva logical result before requestRelated
            derivation entryPhase.loopState loopResult
          let closed := suffixEvidence.environmentClosed
          have entryPath := entryPhase.chunk.path
          rw [entryPhase.atLoop, entryPhase.silent] at entryPath
          have loopPath := loopResult.path
          change NonemptyRelatedPath candidate.transitionSystem
            (.running
              (certificate.static.reflected.reflected.template.entryRva + 58) 0
              entryPhase.loopState
              [runFunctionNativeOuterFrame outerContinuationRva
                outerReturnAddress]
              0 [] world) loopResult.observations
            (loopResult.terminalRuntime.running
              (certificate.static.reflected.reflected.template.entryRva + 326)
              loopResult.terminalState) at loopPath
          have suffixPath := closed.path
          have suffixPath' : NonemptyRelatedPath candidate.transitionSystem
              (loopResult.terminalRuntime.running
                (certificate.static.reflected.reflected.template.entryRva + 326)
                loopResult.terminalState)
              []
              (.running outerContinuationRva 0 closed.execution.returnedState []
                loopResult.terminalRuntime.events.length
                loopResult.terminalRuntime.events
                loopResult.terminalRuntime.world) := by
            simpa [closed, ExactComputedCDeclEpilogue.start,
              ExactComputedCDeclEpilogue.after,
              ExactComputedCDeclEpilogue.observations,
              CDeclReturnDisposition.calls, CDeclReturnDisposition.endpoint,
              CDeclReturnDisposition.observations,
              RunFunctionNativeRuntime.running, runFunctionNativeOuterFrame,
              suffixEvidence.epilogueRvaExact, suffixEvidence.callsExact,
              suffixEvidence.eventIndexExact] using suffixPath
          have completePath :=
            (entryPath.trans loopPath).trans suffixPath'
          refine ⟨certificate.static.function.span.start,
            closed.execution.returnedState, loopResult.terminalRuntime.events,
            certificate.static.entryRvaExact, ?_, closed.responseRelated,
            closed.memoryFrame⟩
          refine ⟨{
            afterWorld := loopResult.terminalRuntime.world
            observations := loopResult.observations
            path := ?_
          }⟩
          rw [← certificate.static.templateEntryExact]
          simpa only [List.nil_append, List.append_nil] using completePath

#print axioms
  RunFunctionNativeResultIndexedCDeclSuffixEvidence.environmentClosed
#print axioms RunFunctionNativeResultIndexedOperationCertificate.semantics
#print axioms RunFunctionNativeResultIndexedOperationCertificate.refines

end StageA.Relational.InterpreterKernelRunOperationResultBridge
