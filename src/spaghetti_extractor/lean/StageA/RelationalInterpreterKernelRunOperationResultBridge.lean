import StageA.RelationalInterpreterKernelRunOperation
import StageA.RelationalInterpreterKernelRunProducerResultClosure

namespace StageA.Relational.InterpreterKernelRunOperationResultBridge

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelClosedCallTree
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
# Result-indexed Run cdecl bridge

The exact native Run loop produces `CallResultEncodingResidual` at its computed
terminal state.  This module carries that evidence through the decoded cdecl
suffix and constructs the environment-closed response certificate.  Operation
composition is owned by `RunFunctionNativeCheckedOperationCertificate`; this
module deliberately exports no parallel whole-operation refinement path.
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
        static.reflected.reflected.template.loopHeaderRva
        loopState)
      (CallResultEncodingResidual abi sourceRva) result) where
  cdecl : CheckedKernelCDeclEpilogue program candidate static.function
  epilogueRvaExact :
    cdecl.inventory.epilogueRva =
      static.reflected.reflected.template.epilogueRva
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
        static.reflected.reflected.template.loopHeaderRva loopState))
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
    (static : RunFunctionNativeStaticBinding program candidate) where
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
          static.reflected.reflected.template.loopHeaderRva loopState)
        (CallResultEncodingResidual abi sourceRva) result),
    Nonempty (RunFunctionNativeResultIndexedCDeclSuffixEvidence program abi
      candidate world outerContinuationRva outerReturnAddress static environment
      resolveCodeTarget sourceRva logical result before requestRelated derivation
      loopState loopResult)

/-- Result-indexed checked Run operation certificate.

The terminal encoding is produced by the exact checked loop and consumed by the
exact cdecl suffix.  Consequently the response proof cannot select a status or
output state independently of the execution that reached the epilogue. -/
structure RunFunctionNativeCheckedResultIndexedOperationCertificate
    (program : CompiledKernelProgram)
    (abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (outerContinuationRva : Nat) (outerReturnAddress : Word) where
  static : RunFunctionNativeStaticBinding program candidate
  abiEntry : RunFunctionNativeABIEntryAuthority abi.relation semanticRecords
  closedTree : RunFunctionClosedCallTreeAuthority semanticRecords
  semantics : RunFunctionNativeCheckedResultIndexedLocalSemantics program
    candidate static.reflected.reflected.template semanticRecords
    static.stepEntryRva static.reflected.resolverTargets
    (CallResultEncodingResidual abi)
  entry : RunFunctionNativeCheckedEntryAuthority program abi.relation
    semanticRecords candidate world outerContinuationRva outerReturnAddress
    static semantics.toLocalSemantics
  suffix : RunFunctionNativeResultIndexedCDeclSuffixAuthority program abi
    candidate world outerContinuationRva outerReturnAddress static

/-- Exact entry, checked loop, and cdecl suffix retained for one Run request. -/
structure RunFunctionNativeCheckedResultIndexedCutpointCluster
    {program : CompiledKernelProgram}
    {abi : ConcreteKernelABI pe imports relocations tableRva countRva
      semanticRecords}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {outerContinuationRva : Nat} {outerReturnAddress : Word}
    (certificate : RunFunctionNativeCheckedResultIndexedOperationCertificate
      program abi candidate world outerContinuationRva outerReturnAddress)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState)
    (requestRelated : abi.relation.requestRelated
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
  loopResult : RunFunctionNativeResultIndexedLoopResult candidate
    certificate.static.reflected.reflected.template
    (({
      calls := [runFunctionNativeOuterFrame outerContinuationRva
        outerReturnAddress]
      eventIndex := 0
      events := []
      world := world
    } : RunFunctionNativeRuntime).running
      certificate.static.reflected.reflected.template.loopHeaderRva
      entryPhase.loopState)
    (CallResultEncodingResidual abi sourceRva) result
  suffixEvidence : RunFunctionNativeResultIndexedCDeclSuffixEvidence program abi
    candidate world outerContinuationRva outerReturnAddress certificate.static
    environment resolveCodeTarget sourceRva logical result before requestRelated
    derivation entryPhase.loopState loopResult

variable
  {program : CompiledKernelProgram}
  {abi : ConcreteKernelABI pe imports relocations tableRva countRva
    semanticRecords}
  {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
  {outerContinuationRva : Nat} {outerReturnAddress : Word}
  {certificate : RunFunctionNativeCheckedResultIndexedOperationCertificate
    program abi candidate world outerContinuationRva outerReturnAddress}
  {environment : StageA.Relational.Interpreter.Environment}
  {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
  {logical : InterpreterMachine} {result : CallResult}
  {before : MachineState}
  {requestRelated : abi.relation.requestRelated
    (.runFunction semanticRecords environment resolveCodeTarget sourceRva
      logical) before}
  {derivation : AbstractRunFunction semanticRecords environment
    resolveCodeTarget sourceRva logical result}

theorem RunFunctionNativeCheckedResultIndexedCutpointCluster.entryPath
    (cluster : RunFunctionNativeCheckedResultIndexedCutpointCluster certificate
      environment resolveCodeTarget sourceRva logical result before
      requestRelated derivation) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running certificate.static.function.span.start 0 before
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world)
      []
      (({
        calls := [runFunctionNativeOuterFrame outerContinuationRva
          outerReturnAddress]
        eventIndex := 0
        events := []
        world := world
      } : RunFunctionNativeRuntime).running
        certificate.static.reflected.reflected.template.loopHeaderRva
        cluster.entryPhase.loopState) := by
  have path := cluster.entryPhase.chunk.path
  rw [cluster.entryPhase.atLoop, cluster.entryPhase.silent] at path
  rw [← certificate.static.templateEntryExact]
  exact path

theorem RunFunctionNativeCheckedResultIndexedCutpointCluster.suffixPath
    (cluster : RunFunctionNativeCheckedResultIndexedCutpointCluster certificate
      environment resolveCodeTarget sourceRva logical result before
      requestRelated derivation) :
    NonemptyRelatedPath candidate.transitionSystem
      (cluster.loopResult.terminalRuntime.running
        certificate.static.reflected.reflected.template.epilogueRva
        cluster.loopResult.terminalState)
      []
      (.running outerContinuationRva 0
        cluster.suffixEvidence.execution.returnedState []
        cluster.loopResult.terminalRuntime.events.length
        cluster.loopResult.terminalRuntime.events
        cluster.loopResult.terminalRuntime.world) := by
  let closed := cluster.suffixEvidence.environmentClosed
  have path := closed.path
  simpa [ExactComputedCDeclEpilogue.start,
    ExactComputedCDeclEpilogue.after, CDeclReturnDisposition.endpoint,
    CDeclReturnDisposition.observations,
    cluster.suffixEvidence.epilogueRvaExact,
    cluster.suffixEvidence.callsExact,
    cluster.suffixEvidence.eventIndexExact,
    RunFunctionNativeRuntime.running] using path

theorem RunFunctionNativeCheckedResultIndexedCutpointCluster.completePath
    (cluster : RunFunctionNativeCheckedResultIndexedCutpointCluster certificate
      environment resolveCodeTarget sourceRva logical result before
      requestRelated derivation) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running certificate.static.function.span.start 0 before
        [runFunctionNativeOuterFrame outerContinuationRva outerReturnAddress]
        0 [] world)
      cluster.loopResult.observations
      (.running outerContinuationRva 0
        cluster.suffixEvidence.execution.returnedState []
        cluster.loopResult.terminalRuntime.events.length
        cluster.loopResult.terminalRuntime.events
        cluster.loopResult.terminalRuntime.world) := by
  simpa only [List.nil_append, List.append_nil] using
    (cluster.entryPath.trans cluster.loopResult.path).trans cluster.suffixPath

def RunFunctionNativeCheckedResultIndexedCutpointCluster.subroutineResult
    (cluster : RunFunctionNativeCheckedResultIndexedCutpointCluster certificate
      environment resolveCodeTarget sourceRva logical result before
      requestRelated derivation) :
    NativeWorldSubroutineResult candidate world outerContinuationRva
      outerReturnAddress certificate.static.function.span.start before
      cluster.suffixEvidence.execution.returnedState
      cluster.loopResult.terminalRuntime.events := {
  afterWorld := cluster.loopResult.terminalRuntime.world
  observations := cluster.loopResult.observations
  path := cluster.completePath
}

/-- Execute the exact finite checked Run tree and retain its producer-side
result evidence through the cdecl return. -/
noncomputable def
    RunFunctionNativeCheckedResultIndexedOperationCertificate.execute
    (certificate : RunFunctionNativeCheckedResultIndexedOperationCertificate
      program abi candidate world outerContinuationRva outerReturnAddress)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (sourceRva : Nat)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState)
    (requestRelated : abi.relation.requestRelated
      (.runFunction semanticRecords environment resolveCodeTarget sourceRva
        logical) before)
    (derivation : AbstractRunFunction semanticRecords environment
      resolveCodeTarget sourceRva logical result) :
    RunFunctionNativeCheckedResultIndexedCutpointCluster certificate environment
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
    (certificate.semantics.execute certificate.static.stepEntryExact sourceRva
      checked entryInvariant)
  let suffixEvidence := Classical.choice
    (certificate.suffix.suffix environment resolveCodeTarget sourceRva logical
      result before requestRelated derivation entryPhase.loopState loopResult)
  exact {
    checked
    entryPhase
    loopResult
    suffixEvidence
  }

/-- The result-indexed Run certificate closes the operation refinement without
consumer-supplied status or output-state evidence. -/
theorem RunFunctionNativeCheckedResultIndexedOperationCertificate.refines
    (certificate : RunFunctionNativeCheckedResultIndexedOperationCertificate
      program abi candidate world outerContinuationRva outerReturnAddress) :
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
          let cluster := certificate.execute environment resolveCodeTarget
            sourceRva logical result before requestRelated derivation
          let closed := cluster.suffixEvidence.environmentClosed
          refine ⟨certificate.static.function.span.start,
            cluster.suffixEvidence.execution.returnedState,
            cluster.loopResult.terminalRuntime.events,
            certificate.static.entryRvaExact, ⟨cluster.subroutineResult⟩,
            closed.responseRelated, closed.memoryFrame⟩

#print axioms
  RunFunctionNativeResultIndexedCDeclSuffixEvidence.environmentClosed
#print axioms
  RunFunctionNativeCheckedResultIndexedCutpointCluster.entryPath
#print axioms
  RunFunctionNativeCheckedResultIndexedCutpointCluster.suffixPath
#print axioms
  RunFunctionNativeCheckedResultIndexedCutpointCluster.completePath
#print axioms
  RunFunctionNativeCheckedResultIndexedOperationCertificate.execute
#print axioms
  RunFunctionNativeCheckedResultIndexedOperationCertificate.refines

end StageA.Relational.InterpreterKernelRunOperationResultBridge
