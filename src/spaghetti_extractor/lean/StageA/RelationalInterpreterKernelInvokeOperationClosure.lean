import StageA.RelationalInterpreterKernelInvokeResultProducer

namespace StageA.Relational.InterpreterKernelInvokeOperationClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelHelperPath
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelInvokeResultProducer
open StageA.Relational.InterpreterKernelRunOperation
open StageA.Relational.InterpreterNativeWorld

variable {pe : PE32} {imports : List PEImport}
variable {relocations : List BaseRelocation}
variable {tableOffset countOffset : Nat}
variable {records : List ProgramRecord}
variable {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
  records}

/-!
# Proof-bearing Invoke arm closure

The public Invoke operation interface needs four broad authorities: exact
external execution, external-environment refinement, internal-arm assembly,
and indirect-arm assembly.  Those authorities are convenient consumers but
poor generated-proof boundaries because their response and frame fields can
hide which exact endpoint established them.

This module exposes producer-side closure certificates.  Every response and
memory-frame fact is derived from an environment-closed cdecl certificate
whose start, fuel, events, world, and returned state are tied to the exact
computed Invoke epilogue.  Internal and indirect closures additionally retain
the exact checked Run certificate selected for the request-local derivation.
-/

/-! ## External helper and environment -/

structure InvokeCallNativeExternalResultClosure
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function)
    (graph : HelperPathGraph) (before : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine)
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before) where
  epilogueBefore : MachineState
  certificate : EnvironmentClosedCDeclEpilogueCertificate (records := records)
    abi candidate checked
    .topLevel
    (.invokeCall records environment resolveCodeTarget event logical)
    (.call (environment.invokeCall event logical)) before epilogueBefore 1
    [execution.nativeEvent] execution.result.world
  epilogueStartExact :
    (NativeWorldExecution.running
      execution.helperExecution.boundary.continuationRva 0 execution.result.state
      execution.helperExecution.boundary.calls 1 [execution.nativeEvent]
      execution.result.world) = certificate.execution.start
  epilogueFuelExact :
    execution.epilogue.fuel = certificate.execution.prefixFuel + 1

theorem InvokeCallNativeExternalResultClosure.endpointExact
    (closure : InvokeCallNativeExternalResultClosure (records := records) abi
      program candidate world static helper checked graph before environment
      resolveCodeTarget event logical execution) :
    execution.after = closure.certificate.execution.returnedState :=
  exactSegmentTopLevelCdeclReturnedState execution.epilogue closure.certificate
    closure.epilogueStartExact closure.epilogueFuelExact
    execution.epilogueReturned

theorem InvokeCallNativeExternalResultClosure.nativeEventShape
    (closure : InvokeCallNativeExternalResultClosure (records := records) abi
      program candidate world static helper checked graph before environment
      resolveCodeTarget event logical execution)
    (kind : event.kind = .external) :
    NativeExternalEventShape event execution.nativeEvent := by
  have trace := closure.certificate.externalTrace.holds
  simp only [ResponseExternalTraceHolds, kind, beq_self_eq_true, ↓reduceIte]
    at trace
  obtain ⟨native, eventsExact, shape⟩ := trace
  injection eventsExact with eventExact
  simpa [eventExact] using shape

theorem InvokeCallNativeExternalResultClosure.responseRelated
    (closure : InvokeCallNativeExternalResultClosure (records := records) abi
      program candidate world static helper checked graph before environment
      resolveCodeTarget event logical execution) :
    abi.relation.responseRelated
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call (environment.invokeCall event logical)) execution.after
      [execution.nativeEvent] := by
  rw [closure.endpointExact]
  exact closure.certificate.responseRelated

theorem InvokeCallNativeExternalResultClosure.memoryFrame
    (closure : InvokeCallNativeExternalResultClosure (records := records) abi
      program candidate world static helper checked graph before environment
      resolveCodeTarget event logical execution) :
    MemoryAgreesOutside
      (abi.relation.scratchFootprint
        (.invokeCall records environment resolveCodeTarget event logical))
      execution.after.memory before.memory := by
  rw [closure.endpointExact]
  exact closure.certificate.memoryFrame

structure InvokeCallNativeExternalArmClosure
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function) where
  execution : InvokeCallNativeExternalHelperExecutionAuthority program
    abi.relation records candidate world static helper
  close : forall environment resolveCodeTarget event logical before,
    abi.relation.requestRelated
        (.invokeCall records environment resolveCodeTarget event logical) before ->
    event.kind = .external ->
    (exactExecution : InvokeCallNativeExternalHelperArmExecution program
      candidate world static helper execution.graph before) ->
    Nonempty (InvokeCallNativeExternalResultClosure (records := records) abi
      program candidate world static helper checked execution.graph before
      environment resolveCodeTarget event logical exactExecution)

def InvokeCallNativeExternalArmClosure.environmentRefinement
    (closure : InvokeCallNativeExternalArmClosure (records := records) abi
      program candidate world static helper checked) :
    InvokeCallNativeExternalEnvironmentRefinement program abi.relation records
      candidate world static helper closure.execution.graph := {
  complete := by
    intro environment resolveCodeTarget event logical before related kind
      exactExecution
    obtain ⟨result⟩ := closure.close environment resolveCodeTarget event logical
      before related kind exactExecution
    exact ⟨result.nativeEventShape kind, result.responseRelated,
      result.memoryFrame⟩
}

def InvokeCallNativeExternalArmClosure.branchAuthority
    (closure : InvokeCallNativeExternalArmClosure (records := records) abi
      program candidate world static helper checked) :
    InvokeCallNativeExternalBranchAuthority program abi.relation records
      candidate world static := {
  helper
  execution := closure.execution
  environment := closure.environmentRefinement
}

/-! ## Internal arm -/

structure InvokeCallNativeInternalExactAssembly
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (checked : CheckedKernelCDeclEpilogue program candidate function)
    (world : RelationalWorld)
    (invokeEntryRva subroutineEntryRva continuationRva : Nat)
    (returnAddress : Word)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (before subroutineBefore subroutineAfter : MachineState)
    (events : List NativeExternalEvent)
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      returnAddress subroutineEntryRva subroutineBefore subroutineAfter events)
    where
  after : MachineState
  execution : InvokeCallNativeArmExecution candidate world invokeEntryRva
    subroutineEntryRva continuationRva returnAddress before subroutineBefore
    subroutineAfter after events
  subroutineExact : execution.subroutine = subroutine
  epilogueBefore : MachineState
  certificate : EnvironmentClosedCDeclEpilogueCertificate (records := records)
    abi candidate checked
    .topLevel
    (.invokeCall records environment resolveCodeTarget event logical)
    (.call result) before epilogueBefore events.length events
    execution.subroutine.afterWorld
  epilogueStartExact :
    (NativeWorldExecution.running continuationRva 0 subroutineAfter []
      events.length events execution.subroutine.afterWorld) =
      certificate.execution.start
  epilogueFuelExact :
    execution.epilogue.fuel = certificate.execution.prefixFuel + 1

theorem InvokeCallNativeInternalExactAssembly.endpointExact
    (assembly : InvokeCallNativeInternalExactAssembly (records := records) abi
      program candidate checked world invokeEntryRva subroutineEntryRva continuationRva
      returnAddress environment resolveCodeTarget event logical result before
      subroutineBefore subroutineAfter events subroutine) :
    assembly.after = assembly.certificate.execution.returnedState :=
  exactSegmentTopLevelCdeclReturnedState assembly.execution.epilogue
    assembly.certificate assembly.epilogueStartExact assembly.epilogueFuelExact
    assembly.execution.epilogueReturned

def InvokeCallNativeInternalExactAssembly.completion
    (assembly : InvokeCallNativeInternalExactAssembly (records := records) abi
      program candidate checked world invokeEntryRva subroutineEntryRva continuationRva
      returnAddress environment resolveCodeTarget event logical result before
      subroutineBefore subroutineAfter events subroutine) :
    InvokeCallNativeInternalCompletion abi.relation candidate world
      invokeEntryRva subroutineEntryRva continuationRva returnAddress
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before subroutineBefore subroutineAfter events subroutine := {
  after := assembly.after
  execution := assembly.execution
  subroutineExact := assembly.subroutineExact
  responseRelated := by
    rw [assembly.endpointExact]
    exact assembly.certificate.responseRelated
  memoryFrame := by
    rw [assembly.endpointExact]
    exact assembly.certificate.memoryFrame
}

structure InvokeCallNativeCheckedInternalExactFrame
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (checked : CheckedKernelCDeclEpilogue program candidate function)
    (world : RelationalWorld) (invokeEntryRva continuationRva : Nat)
    (returnAddress : Word)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState) where
  runFunctionBefore : MachineState
  runRequestRelated : abi.relation.requestRelated
    (.runFunction records environment resolveCodeTarget event.targetRva.toNat
      logical) runFunctionBefore
  runCertificate : RunFunctionNativeCheckedOperationCertificate program
    abi.relation records candidate world continuationRva returnAddress
  assemble : forall entryRva runFunctionAfter events,
    program.functionEntry? .runFunction = some entryRva ->
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      returnAddress entryRva runFunctionBefore runFunctionAfter events) ->
    Nonempty (InvokeCallNativeInternalExactAssembly (records := records) abi
      program candidate checked world invokeEntryRva entryRva continuationRva
      returnAddress environment resolveCodeTarget event logical result before
      runFunctionBefore runFunctionAfter events subroutine)

structure InvokeCallNativeCheckedInternalArmClosure
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function) where
  continuationRva : Nat
  continuationExact :
    continuationRva = static.reflected.template.entryRva + 67
  returnAddress : Word
  returnAddressExact :
    returnAddress =
      BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)
  prepare : forall environment resolveCodeTarget event logical before result
      (run : CheckedRunFunctionDerivation records environment resolveCodeTarget
        event.targetRva.toNat logical result),
    abi.relation.requestRelated
        (.invokeCall records environment resolveCodeTarget event logical) before ->
    event.kind = .internal ->
    Nonempty (InvokeCallNativeCheckedInternalExactFrame (records := records) abi
      program candidate checked world static.function.span.start continuationRva
      returnAddress environment resolveCodeTarget event logical result before)

def InvokeCallNativeCheckedInternalArmClosure.branchAuthority
    (closure : InvokeCallNativeCheckedInternalArmClosure (records := records) abi
      program candidate world static checked) :
    InvokeCallNativeCheckedInternalBranchAuthority program abi.relation records
      candidate world static := {
  continuationRva := closure.continuationRva
  continuationExact := closure.continuationExact
  returnAddress := closure.returnAddress
  returnAddressExact := closure.returnAddressExact
  prepare := by
    intro environment resolveCodeTarget event logical before result run related
      kind
    obtain ⟨exactFrame⟩ := closure.prepare environment resolveCodeTarget event
      logical before result run related kind
    exact ⟨{
      runABI := abi.relation
      prepared := {
        runFunctionBefore := exactFrame.runFunctionBefore
        requestRelated := exactFrame.runRequestRelated
        assemble := by
          intro entryRva runFunctionAfter events entryExact subroutine
          obtain ⟨assembly⟩ := exactFrame.assemble entryRva runFunctionAfter
            events entryExact subroutine
          exact ⟨assembly.completion⟩
      }
      runCertificate := exactFrame.runCertificate
    }⟩
}

/-! ## Indirect arm -/

structure InvokeCallNativeIndirectExactAssembly
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (checked : CheckedKernelCDeclEpilogue program candidate function)
    (inventory : KernelCallbackInventory) (world : RelationalWorld)
    (invokeEntryRva runFunctionEntryRva continuationRva : Nat)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (before runFunctionBefore runFunctionAfter : MachineState)
    (events : List NativeExternalEvent)
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))
      runFunctionEntryRva runFunctionBefore runFunctionAfter events) where
  resolverBefore : MachineState
  callbackBefore : MachineState
  callbackAfter : MachineState
  after : MachineState
  site : KernelIndirectCallbackSite
  target : CallbackTargetEntry
  execution : InvokeCallNativeIndirectArmExecution candidate world program
    inventory invokeEntryRva runFunctionEntryRva continuationRva before
    resolverBefore callbackBefore callbackAfter runFunctionBefore
    runFunctionAfter after site target events
  subroutineExact : execution.runFunction = subroutine
  epilogueBefore : MachineState
  certificate : EnvironmentClosedCDeclEpilogueCertificate (records := records)
    abi candidate checked
    .topLevel
    (.invokeCall records environment resolveCodeTarget event logical)
    (.call result) before epilogueBefore events.length events
    execution.runFunction.afterWorld
  epilogueStartExact :
    (NativeWorldExecution.running continuationRva 0 runFunctionAfter []
      events.length events execution.runFunction.afterWorld) =
      certificate.execution.start
  epilogueFuelExact :
    execution.epilogue.fuel = certificate.execution.prefixFuel + 1

theorem InvokeCallNativeIndirectExactAssembly.endpointExact
    (assembly : InvokeCallNativeIndirectExactAssembly (records := records) abi
      program candidate checked inventory world invokeEntryRva
      runFunctionEntryRva continuationRva
      environment resolveCodeTarget event logical result before
      runFunctionBefore runFunctionAfter events subroutine) :
    assembly.after = assembly.certificate.execution.returnedState :=
  exactSegmentTopLevelCdeclReturnedState assembly.execution.epilogue
    assembly.certificate assembly.epilogueStartExact assembly.epilogueFuelExact
    assembly.execution.epilogueReturned

def InvokeCallNativeIndirectExactAssembly.completion
    (assembly : InvokeCallNativeIndirectExactAssembly (records := records) abi
      program candidate checked inventory world invokeEntryRva
      runFunctionEntryRva continuationRva
      environment resolveCodeTarget event logical result before
      runFunctionBefore runFunctionAfter events subroutine) :
    InvokeCallNativeIndirectCompletion program inventory abi.relation candidate
      world invokeEntryRva runFunctionEntryRva continuationRva
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before runFunctionBefore runFunctionAfter events
      subroutine := {
  resolverBefore := assembly.resolverBefore
  callbackBefore := assembly.callbackBefore
  callbackAfter := assembly.callbackAfter
  after := assembly.after
  site := assembly.site
  target := assembly.target
  execution := assembly.execution
  subroutineExact := assembly.subroutineExact
  responseRelated := by
    rw [assembly.endpointExact]
    exact assembly.certificate.responseRelated
  memoryFrame := by
    rw [assembly.endpointExact]
    exact assembly.certificate.memoryFrame
}

structure InvokeCallNativeCheckedIndirectExactFrame
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function)
    (continuationRva targetRva : Nat)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (before : MachineState) where
  runFunctionBefore : MachineState
  runRequestRelated : abi.relation.requestRelated
    (.runFunction records environment resolveCodeTarget targetRva logical)
    runFunctionBefore
  runCertificate : RunFunctionNativeCheckedOperationCertificate program
    abi.relation records candidate world continuationRva
    (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))
  assemble : forall entryRva runFunctionAfter events,
    program.functionEntry? .runFunction = some entryRva ->
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva)) entryRva
      runFunctionBefore runFunctionAfter events) ->
    Nonempty (InvokeCallNativeIndirectExactAssembly (records := records) abi
      program candidate checked static.reflected.callbacks world
      static.function.span.start entryRva continuationRva environment
      resolveCodeTarget event logical result before runFunctionBefore
      runFunctionAfter events subroutine)

structure InvokeCallNativeCheckedIndirectArmClosure
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function) where
  continuationRva : Nat
  continuationExact :
    continuationRva = static.reflected.template.entryRva + 162
  prepare : forall environment resolveCodeTarget event logical before target
      result
      (run : CheckedRunFunctionDerivation records environment resolveCodeTarget
        target logical result),
    abi.relation.requestRelated
        (.invokeCall records environment resolveCodeTarget event logical) before ->
    event.kind = .indirect ->
    resolveCodeTarget event.targetRva = some target ->
    Nonempty (InvokeCallNativeCheckedIndirectExactFrame (records := records) abi
      program candidate world static checked continuationRva target environment
      resolveCodeTarget event logical result before)

def InvokeCallNativeCheckedIndirectArmClosure.branchAuthority
    (closure : InvokeCallNativeCheckedIndirectArmClosure (records := records) abi
      program candidate world static checked) :
    InvokeCallNativeCheckedIndirectBranchAuthority program abi.relation records
      candidate world static := {
  continuationRva := closure.continuationRva
  continuationExact := closure.continuationExact
  prepare := by
    intro environment resolveCodeTarget event logical before target result run
      related kind targetExact
    obtain ⟨exactFrame⟩ := closure.prepare environment resolveCodeTarget event
      logical before target result run related kind targetExact
    exact ⟨{
      runABI := abi.relation
      prepared := {
        runFunctionBefore := exactFrame.runFunctionBefore
        requestRelated := exactFrame.runRequestRelated
        assemble := by
          intro entryRva runFunctionAfter events entryExact subroutine
          obtain ⟨assembly⟩ := exactFrame.assemble entryRva runFunctionAfter
            events entryExact subroutine
          exact ⟨assembly.completion⟩
      }
      runCertificate := exactFrame.runCertificate
    }⟩
}

/-! ## Unified generated boundary -/

structure InvokeCallNativeCheckedArmClosures
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (checked : CheckedKernelCDeclEpilogue program candidate static.function) where
  external : InvokeCallNativeExternalArmClosure (records := records) abi program
    candidate world static helper checked
  internal : InvokeCallNativeCheckedInternalArmClosure (records := records) abi
    program candidate world static checked
  indirect : InvokeCallNativeCheckedIndirectArmClosure (records := records) abi
    program candidate world static checked

def InvokeCallNativeCheckedArmClosures.externalAuthority
    (closures : InvokeCallNativeCheckedArmClosures (records := records) abi
      program candidate world static helper checked) :
    InvokeCallNativeExternalBranchAuthority program abi.relation records
      candidate world static :=
  closures.external.branchAuthority

def InvokeCallNativeCheckedArmClosures.internalAuthority
    (closures : InvokeCallNativeCheckedArmClosures (records := records) abi
      program candidate world static helper checked) :
    InvokeCallNativeCheckedInternalBranchAuthority program abi.relation records
      candidate world static :=
  closures.internal.branchAuthority

def InvokeCallNativeCheckedArmClosures.indirectAuthority
    (closures : InvokeCallNativeCheckedArmClosures (records := records) abi
      program candidate world static helper checked) :
    InvokeCallNativeCheckedIndirectBranchAuthority program abi.relation records
      candidate world static :=
  closures.indirect.branchAuthority

#print axioms InvokeCallNativeExternalResultClosure.endpointExact
#print axioms InvokeCallNativeExternalResultClosure.nativeEventShape
#print axioms InvokeCallNativeExternalResultClosure.responseRelated
#print axioms InvokeCallNativeExternalResultClosure.memoryFrame
#print axioms InvokeCallNativeExternalArmClosure.environmentRefinement
#print axioms InvokeCallNativeExternalArmClosure.branchAuthority
#print axioms InvokeCallNativeInternalExactAssembly.endpointExact
#print axioms InvokeCallNativeInternalExactAssembly.completion
#print axioms InvokeCallNativeCheckedInternalArmClosure.branchAuthority
#print axioms InvokeCallNativeIndirectExactAssembly.endpointExact
#print axioms InvokeCallNativeIndirectExactAssembly.completion
#print axioms InvokeCallNativeCheckedIndirectArmClosure.branchAuthority
#print axioms InvokeCallNativeCheckedArmClosures.externalAuthority
#print axioms InvokeCallNativeCheckedArmClosures.internalAuthority
#print axioms InvokeCallNativeCheckedArmClosures.indirectAuthority

end StageA.Relational.InterpreterKernelInvokeOperationClosure
