import StageA.RelationalInterpreterKernelCdeclEpilogueExternalPayload

namespace StageA.Relational.InterpreterKernelOperationEnvironment

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterNativeWorld

/-!
# Environment-indexed kernel operations

`KernelOperationRefinesUsing` deliberately quantifies over every abstract
request accepted by its ABI relation.  A concrete native program, however,
contains one fixed `NativeWorldEnvironment`; it cannot implement two unrelated
semantic `Environment.invokeCall` functions for the same external event.

The environment index below records this necessary dependency in the request
relation.  It does not define or assume external API behavior.  Actual
external calls remain governed by checked one-to-one response evidence from
the whole-program paired-environment theorem.
-/

def requestUsesEnvironment
    (expected : StageA.Relational.Interpreter.Environment) :
    AbstractKernelRequest -> Prop
  | .programLookup .. => True
  | .interpreterStep _ environment .. => environment = expected
  | .runFunction _ environment .. => environment = expected
  | .invokeCall _ environment .. => environment = expected

def kernelABIAtEnvironment
    (abi : KernelABIRelation)
    (environment : StageA.Relational.Interpreter.Environment) :
    KernelABIRelation := {
  requestRelated := fun request state =>
    abi.requestRelated request state /\
      requestUsesEnvironment environment request
  responseRelated := abi.responseRelated
  scratchFootprint := abi.scratchFootprint
}

def KernelOperationRefinesUsingAtEnvironment
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (environment : StageA.Relational.Interpreter.Environment)
    (dispatches : KernelDispatchRelation)
    (operation : KernelOperation) : Prop :=
  forall request before,
    request.operation = operation ->
    requestUsesEnvironment environment request ->
    abi.requestRelated request before ->
    forall response, AbstractKernelTransition request response ->
      exists entryRva after nativeEvents,
        program.functionEntry? operation.role = some entryRva /\
        dispatches entryRva before after nativeEvents /\
        abi.responseRelated request response after nativeEvents /\
        MemoryAgreesOutside (abi.scratchFootprint request)
          after.memory before.memory

theorem kernelOperationRefinesUsingAtEnvironment_iff
    (program : CompiledKernelProgram) (abi : KernelABIRelation)
    (environment : StageA.Relational.Interpreter.Environment)
    (dispatches : KernelDispatchRelation)
    (operation : KernelOperation) :
    KernelOperationRefinesUsingAtEnvironment program abi environment
        dispatches operation <->
      KernelOperationRefinesUsing program (kernelABIAtEnvironment abi environment)
        dispatches operation := by
  constructor
  · intro refines request before operationExact related response transition
    exact refines request before operationExact related.2 related.1 response
      transition
  · intro refines request before operationExact environmentExact related response
      transition
    exact refines request before operationExact ⟨related, environmentExact⟩
      response transition

theorem kernelABIAtEnvironment_request
    (abi : KernelABIRelation)
    (environment : StageA.Relational.Interpreter.Environment)
    (request : AbstractKernelRequest) (state : MachineState)
    (related :
      (kernelABIAtEnvironment abi environment).requestRelated request state) :
    abi.requestRelated request state /\
      requestUsesEnvironment environment request :=
  related

theorem kernelABIAtEnvironment_response
    (abi : KernelABIRelation)
    (environment : StageA.Relational.Interpreter.Environment)
    (request : AbstractKernelRequest) (response : AbstractKernelResponse)
    (state : MachineState) (events : List NativeExternalEvent) :
    (kernelABIAtEnvironment abi environment).responseRelated request response
        state events =
      abi.responseRelated request response state events :=
  rfl

theorem kernelABIAtEnvironment_scratch
    (abi : KernelABIRelation)
    (environment : StageA.Relational.Interpreter.Environment)
    (request : AbstractKernelRequest) :
    (kernelABIAtEnvironment abi environment).scratchFootprint request =
      abi.scratchFootprint request :=
  rfl

/-!
The external environment law is request local.  It carries the actual checked
lockstep response for the native event reached by exact replay.  In
particular, it accepts neither a replacement native endpoint nor an asserted
machine-state equality.
-/

structure CheckedKernelOperationExternalEnvironment
    (abi : KernelABIRelation) (records : List ProgramRecord)
    (semanticEnvironment : StageA.Relational.Interpreter.Environment)
    (nativeEnvironment : NativeWorldEnvironment) : Prop where
  response : forall resolveCodeTarget event logical before native eventIndex
      world,
    abi.requestRelated
        (.invokeCall records semanticEnvironment resolveCodeTarget event logical)
        before ->
    event.kind = .external ->
    NativeExternalEventShape event native ->
    exists checked : CheckedOneToOneKernelExternalResponse event native,
      checked.nativeEnvironment = nativeEnvironment /\
      checked.world = world /\
      checked.eventIndex = eventIndex

theorem CheckedKernelOperationExternalEnvironment.semanticResult
    (checked : CheckedKernelOperationExternalEnvironment abi records
      semanticEnvironment nativeEnvironment)
    (resolveCodeTarget : Word -> Option Nat)
    (event : CallEvent) (logical : InterpreterMachine)
    (before : MachineState) (native : NativeExternalEvent)
    (eventIndex : Nat) (world : RelationalWorld)
    (related : abi.requestRelated
      (.invokeCall records semanticEnvironment resolveCodeTarget event logical)
      before)
    (kind : event.kind = .external)
    (shape : NativeExternalEventShape event native) :
    exists response : CheckedOneToOneKernelExternalResponse event native,
      response.nativeEnvironment = nativeEnvironment /\
      response.world = world /\
      response.eventIndex = eventIndex :=
  checked.response resolveCodeTarget event logical before native eventIndex
    world related kind shape

#print axioms kernelOperationRefinesUsingAtEnvironment_iff
#print axioms kernelABIAtEnvironment_request
#print axioms CheckedKernelOperationExternalEnvironment.semanticResult

end StageA.Relational.InterpreterKernelOperationEnvironment
