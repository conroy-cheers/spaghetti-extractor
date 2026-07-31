import StageA.RelationalInterpreterKernelCdeclEpilogue
import StageA.RelationalInterpreterKernelStepProgramLookupExactComputation
import StageA.RelationalInterpreterNativeWorldProjection

namespace StageA.Relational.InterpreterKernelStepOperationClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepProgramLookupCall
open StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
open StageA.Relational.InterpreterKernelStepProgramLookupExactComputation
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact `interpreterStep` operation closure

The generated Step operation deliberately exposes six native proof fields.
This module gives each field one proof-bearing construction from exact
candidate execution:

* the nested `programLookup` frame is assembled from exact prefix, call, and
  return replays;
* ordinary helpers and the x87 callback are exact computed subroutines;
* Invoke sites reuse a checked nested Invoke operation at their concrete frame;
* action paths contain only checked Step chunks and exact subroutines; and
* the epilogue is the generic exact cdecl certificate.

None of these adapters accepts a submitted path endpoint, response, memory
frame, or operation status.
-/

/-! ## Nested `programLookup` -/

structure InterpreterStepExactProgramLookupClosure
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (site : InterpreterStepProgramLookupCallSiteCertificate program candidate
      static) where
  caller : forall environment sourceRva logical before,
    abi.relation.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      ExecutorClosedInterpreterStepProgramLookupCallerFrame program
        semanticRecords abi candidate world static site sourceRva before

def InterpreterStepExactProgramLookupClosure.toAuthority
    (closure : InterpreterStepExactProgramLookupClosure semanticRecords abi
      program candidate world static site)
    (operation :
      InterpreterStepProgramLookupOperation program abi.relation candidate) :
    InterpreterStepNativeCheckedProgramLookupCallAuthority program abi.relation
      semanticRecords candidate world static := {
  prepare := by
    intro environment sourceRva logical before related
    let exactFrame :=
      closure.caller environment sourceRva logical before related
    exact {
      abi := abi.relation
      operation
      prepared := exactFrame.toClosed.toCallerFrame.prepared
    }
}

/-! ## Exact helper replays -/

structure InterpreterStepExactHelperClosure
    (candidate : ExactNativeWorldProgram)
    (template : InterpreterStepNativeTemplate) where
  replay : forall targetRva continuationRva before,
    targetRva ∈ template.helperTargetRvas ->
      template.subroutineBoundaryAllowed targetRva continuationRva ->
      before.rva? = some targetRva ->
      Nonempty (ExactInterpreterStepHelperReplay template candidate targetRva
        continuationRva before)

def InterpreterStepExactHelperClosure.toAuthority
    (closure : InterpreterStepExactHelperClosure candidate template) :
    InterpreterStepNativeHelperSubroutineAuthority candidate template := {
  targetRvas := template.helperTargetRvas
  targetsExact := rfl
  execute := by
    intro targetRva continuationRva before targetMember boundary startsAt
    obtain ⟨replay⟩ :=
      closure.replay targetRva continuationRva before targetMember boundary
        startsAt
    exact ⟨replay.replay.after, replay.replay.observations,
      ⟨replay.toSubroutine.toLocal⟩⟩
}

/-! ## Request-local Invoke sites -/

structure InterpreterStepCheckedInvokeOperationClosure
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld) where
  refines : forall continuationRva returnAddress,
    exists invokeABI : KernelABIRelation,
      KernelOperationRefinesUsing program invokeABI
        (NativeWorldSubroutineDispatches candidate world continuationRva
          returnAddress) .invokeCall

def InterpreterStepCheckedInvokeOperationClosure.requestLocal
    (closure : InterpreterStepCheckedInvokeOperationClosure program candidate
      world)
    (derivation : CheckedInterpreterStepDerivation records environment
      resolveCodeTarget sourceRva logical result) :
    InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
      world derivation := by
  intro site _contains continuationRva returnAddress
  obtain ⟨invokeABI, refinement⟩ :=
    closure.refines continuationRva returnAddress
  exact ⟨invokeABI,
    checkedInvokeCallRequestRefinesUsing_of_operationRefinement refinement site⟩

/-! ## Exact action paths -/

structure InterpreterStepExactActionExecution
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    {records : List ProgramRecord} {sourceRva : Nat} {before : MachineState}
    {world : RelationalWorld}
    (lookupPhase : InterpreterStepNativeLookupPhase template candidate records
      sourceRva before world) where
  after : NativeWorldExecution
  observations : List WorldRelationalObservable
  path : ExactComputedInterpreterStepPath template candidate
    lookupPhase.afterLookup observations after

structure InterpreterStepExactActionClosure
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (semanticRecords : List ProgramRecord)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (invokeCall : InterpreterStepNativeInvokeCallStaticBinding program candidate
      static.reflected.template)
    (x87Replay : InterpreterStepNativeX87ReplayAuthority candidate
      static.reflected.template) where
  path : forall environment (resolveCodeTarget : Word -> Option Nat) sourceRva
      logical result before
      (derivation : CheckedInterpreterStepDerivation semanticRecords environment
        resolveCodeTarget sourceRva logical result)
      (requestRelated : abi.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before)
      (lookupPhase : InterpreterStepNativeLookupPhase
        static.reflected.template candidate semanticRecords sourceRva before
        world)
      (invokeCallRefines :
        InterpreterStepNativeFramedRequestLocalInvokeEvidence program candidate
          world derivation),
    InterpreterStepExactActionExecution static.reflected.template candidate
      lookupPhase

def InterpreterStepExactActionClosure.toAuthority
    (closure : InterpreterStepExactActionClosure program abi semanticRecords
      candidate world static invokeCall x87Replay) :
    InterpreterStepNativeCheckedActionLoopAuthority program abi semanticRecords
      candidate world static invokeCall x87Replay := {
  actions := by
    intro environment resolveCodeTarget sourceRva logical result before
      derivation requestRelated lookupPhase invokeCallRefines
    let execution :=
      closure.path environment resolveCodeTarget sourceRva logical result before
        derivation requestRelated lookupPhase invokeCallRefines
    exact {
      afterActions := execution.after
      observations := execution.observations
      path := execution.path.toNativePath
    }
}

/-! ## Exact cdecl epilogue -/

structure InterpreterStepExactEpilogueExecution
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function)
    (adapter : InterpreterStepCDeclEpilogueAdapter abi program candidate static
      checked)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (lookup : InterpreterStepNativeLookupPhase static.reflected.template
      candidate semanticRecords sourceRva before initialWorld)
    (actions : InterpreterStepNativeActionPhase static.reflected.template
      candidate environment logical lookup) where
  eventIndex : Nat
  events : List NativeExternalEvent
  epilogueBefore : MachineState
  startExact : actions.afterActions =
    .running checked.inventory.epilogueRva 0 epilogueBefore
      CDeclReturnDisposition.topLevel.calls eventIndex events initialWorld
  certificate : CheckedCDeclEpilogueCertificate abi candidate checked
    .topLevel
    (.interpreterStep semanticRecords environment sourceRva logical)
    (.interpreterStep actions.result) before epilogueBefore eventIndex events
    initialWorld
  fuelExact : adapter.cutpoint.instructionCount =
    certificate.execution.prefixFuel + 1

def InterpreterStepExactEpilogueExecution.phase
    (execution : InterpreterStepExactEpilogueExecution semanticRecords abi
      program candidate static checked adapter environment sourceRva logical
      before lookup actions) :
    InterpreterStepNativeEpiloguePhase static.reflected.template candidate
      abi.relation semanticRecords environment sourceRva logical before
      actions :=
  adapter.phase actions execution.eventIndex execution.events
    execution.epilogueBefore execution.startExact execution.certificate
    execution.fuelExact

structure InterpreterStepExactEpilogueClosure
    (semanticRecords : List ProgramRecord)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (initialWorld : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function)
    (adapter : InterpreterStepCDeclEpilogueAdapter abi program candidate static
      checked) where
  finish : forall environment sourceRva logical before,
    abi.relation.requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      forall
        (lookup : InterpreterStepNativeLookupPhase static.reflected.template
          candidate semanticRecords sourceRva before initialWorld)
        (actions : InterpreterStepNativeActionPhase static.reflected.template
          candidate environment logical lookup),
        InterpreterStepExactEpilogueExecution semanticRecords abi program
          candidate static checked adapter environment sourceRva logical before
          lookup actions

def InterpreterStepExactEpilogueClosure.toAuthority
    (closure : InterpreterStepExactEpilogueClosure semanticRecords abi program
      candidate initialWorld static checked adapter) :
    InterpreterStepNativeCDeclEpilogueAuthority program abi.relation
      semanticRecords candidate initialWorld static := {
  epilogue := by
    intro environment sourceRva logical before requestRelated lookup actions
    let execution :=
      closure.finish environment sourceRva logical before requestRelated lookup
        actions
    exact execution.phase
}

/-! ## Exact frame-relative cdecl epilogue -/

structure InterpreterStepExactFramedEpilogueExecution
    (semanticRecords : List ProgramRecord)
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function)
    (adapter : InterpreterStepCDeclEpilogueAdapter abi program candidate static
      checked)
    (environment : StageA.Relational.Interpreter.Environment)
    (sourceRva : Nat) (logical : InterpreterMachine) (before : MachineState)
    (lookup : InterpreterStepNativeLookupPhase static.reflected.template
      candidate semanticRecords sourceRva before initialWorld)
    (actions : InterpreterStepNativeActionPhase static.reflected.template
      candidate environment logical lookup) where
  eventIndex : Nat
  events : List NativeExternalEvent
  epilogueBefore : MachineState
  startExact : actions.afterActions =
    .running checked.inventory.epilogueRva 0 epilogueBefore
      CDeclReturnDisposition.topLevel.calls eventIndex events initialWorld
  certificate : CheckedFramedCDeclEpilogueCertificate frame abi candidate checked
    .topLevel
    (.interpreterStep semanticRecords environment sourceRva logical)
    (.interpreterStep actions.result) before epilogueBefore eventIndex events
    initialWorld
  fuelExact : adapter.cutpoint.instructionCount =
    certificate.execution.prefixFuel + 1

def InterpreterStepExactFramedEpilogueExecution.phase
    (execution : InterpreterStepExactFramedEpilogueExecution semanticRecords
      frame abi program candidate static checked adapter environment sourceRva
      logical before lookup actions) :
    InterpreterStepNativeEpiloguePhase static.reflected.template candidate
      (frame.relation abi) semanticRecords environment sourceRva logical before
      actions :=
  adapter.phaseFrame frame actions execution.eventIndex execution.events
    execution.epilogueBefore execution.startExact execution.certificate
    execution.fuelExact

structure InterpreterStepExactFramedEpilogueClosure
    (semanticRecords : List ProgramRecord)
    (frame : KernelOperationABIFrame)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      semanticRecords)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (initialWorld : RelationalWorld)
    (static : InterpreterStepNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function)
    (adapter : InterpreterStepCDeclEpilogueAdapter abi program candidate static
      checked) where
  finish : forall environment sourceRva logical before,
    (frame.relation abi).requestRelated
        (.interpreterStep semanticRecords environment sourceRva logical) before ->
      forall
        (lookup : InterpreterStepNativeLookupPhase static.reflected.template
          candidate semanticRecords sourceRva before initialWorld)
        (actions : InterpreterStepNativeActionPhase static.reflected.template
          candidate environment logical lookup),
        InterpreterStepExactFramedEpilogueExecution semanticRecords frame abi
          program candidate static checked adapter environment sourceRva logical
          before lookup actions

def InterpreterStepExactFramedEpilogueClosure.toAuthority
    (closure : InterpreterStepExactFramedEpilogueClosure semanticRecords frame
      abi program candidate initialWorld static checked adapter) :
    InterpreterStepNativeCDeclEpilogueAuthority program (frame.relation abi)
      semanticRecords candidate initialWorld static := {
  epilogue := by
    intro environment sourceRva logical before requestRelated lookup actions
    exact (closure.finish environment sourceRva logical before requestRelated
      lookup actions).phase
}

#print axioms InterpreterStepExactProgramLookupClosure.toAuthority
#print axioms InterpreterStepExactHelperClosure.toAuthority
#print axioms InterpreterStepCheckedInvokeOperationClosure.requestLocal
#print axioms InterpreterStepExactActionClosure.toAuthority
#print axioms InterpreterStepExactEpilogueExecution.phase
#print axioms InterpreterStepExactEpilogueClosure.toAuthority
#print axioms InterpreterStepExactFramedEpilogueExecution.phase
#print axioms InterpreterStepExactFramedEpilogueClosure.toAuthority

end StageA.Relational.InterpreterKernelStepOperationClosure
