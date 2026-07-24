import StageA.RelationalInterpreterKernelOperationResultEncoding

namespace StageA.Relational.InterpreterKernelInvokeResultClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact Invoke endpoint-result closure

For a concrete kernel ABI, an established Invoke response contains exactly the
status-register and output-engine facts represented by
`CallResultEncodingResidual`.  The three arm-specific projections below retain
the exact endpoint selected by their native execution objects:

* the internal arm uses `InvokeCallNativeInternalCompletion.after`;
* the external arm uses the helper execution's computed `after`;
* the indirect arm uses `InvokeCallNativeIndirectCompletion.after`.

This is deliberately a consumer-side closure.  Constructing these completion
objects through an environment-closed cdecl epilogue already requires exact
operation-result evidence, so using the projections below to construct those
same objects would be circular.  The producer-side repair is to strengthen the
Invoke arm assemblers so their exact epilogue executions retain EAX and output
engine-state encoding independently of `responseRelated`.
-/

/-- The machine part of a concrete Invoke response is definitionally the
existing endpoint-indexed residual.  External trace evidence is independent
and intentionally absent. -/
theorem callResultEncodingResidual_iff_invokeResponseMachinePayloadHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (event : CallEvent) (logical : InterpreterMachine)
    (result : CallResult) (state : MachineState) :
    CallResultEncodingResidual abi event.targetRva.toNat result state ↔
      ResponseMachinePayloadHolds abi
        (.invokeCall requestRecords environment resolveCodeTarget event logical)
        (.call result) state := by
  constructor
  · intro residual
    exact ⟨residual.eaxExact, residual.engineState⟩
  · intro payload
    exact {
      eaxExact := payload.1
      engineState := payload.2
    }

/-- Project exact Invoke result encoding from an already-established concrete
ABI response at the same endpoint. -/
def callResultEncodingResidualOfInvokeResponseRelated
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (event : CallEvent) (logical : InterpreterMachine)
    (result : CallResult) (state : MachineState)
    (nativeEvents : List NativeExternalEvent)
    (related : abi.relation.responseRelated
      (.invokeCall requestRecords environment resolveCodeTarget event logical)
      (.call result) state nativeEvents) :
    CallResultEncodingResidual abi event.targetRva.toNat result state := by
  change ABIResponseFacts abi
    (.invokeCall requestRecords environment resolveCodeTarget event logical)
    (.call result) state nativeEvents at related
  have payload := related.payload
  change state.registers.eax = callStatusWord result.status ∧
    EngineStateHolds abi.engineLayout
      (abi.parameters.outputAddress abi.engineLayout)
      result.state event.targetRva.toNat state ∧
    (if event.kind == .external then
      ∃ native, nativeEvents = [native] ∧
        NativeExternalEventShape event native
    else nativeEvents = []) at payload
  exact {
    eaxExact := payload.1
    engineState := payload.2.1
  }

/-- Internal-arm projection.  No endpoint is accepted separately:
`completion.after` is the endpoint indexed by the exact wrapper/subroutine/
epilogue execution retained by the completion. -/
def internalCompletionCallResultEncodingResidual
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva subroutineEntryRva continuationRva : Nat}
    {returnAddress : Word}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine} {result : CallResult}
    {before subroutineBefore subroutineAfter : MachineState}
    {events : List NativeExternalEvent}
    {subroutine : NativeWorldSubroutineResult candidate world continuationRva
      returnAddress subroutineEntryRva subroutineBefore subroutineAfter events}
    (completion : InvokeCallNativeInternalCompletion abi.relation candidate world
      invokeEntryRva subroutineEntryRva continuationRva returnAddress
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before subroutineBefore subroutineAfter events subroutine) :
    CallResultEncodingResidual abi event.targetRva.toNat result
      completion.after :=
  callResultEncodingResidualOfInvokeResponseRelated abi records environment
    resolveCodeTarget event logical result completion.after events
    completion.responseRelated

/-- Internal-arm adapter to the operation-result evidence consumed by the
cdecl payload layer. -/
def internalCompletionOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva subroutineEntryRva continuationRva : Nat}
    {returnAddress : Word}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine} {result : CallResult}
    {before subroutineBefore subroutineAfter : MachineState}
    {events : List NativeExternalEvent}
    {subroutine : NativeWorldSubroutineResult candidate world continuationRva
      returnAddress subroutineEntryRva subroutineBefore subroutineAfter events}
    (completion : InvokeCallNativeInternalCompletion abi.relation candidate world
      invokeEntryRva subroutineEntryRva continuationRva returnAddress
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before subroutineBefore subroutineAfter events subroutine) :
    CheckedOperationResultEvidence abi
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) completion.after :=
  CallResultEncodingResidual.toInvokeCallEvidence
    (internalCompletionCallResultEncodingResidual completion)
    records environment resolveCodeTarget logical

/-- The external-helper arm obtains its concrete response at the exact helper
execution endpoint from the checked environment refinement. -/
def externalHelperExecutionCallResultEncodingResidual
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {world : RelationalWorld}
    {static : InvokeCallNativeStaticBinding program candidate}
    {helper : InvokeCallNativeExternalHelperBinding program candidate static}
    {graph :
      StageA.Relational.InterpreterKernelHelperPath.HelperPathGraph}
    {before : MachineState}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine}
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before)
    (refinement : InvokeCallNativeExternalEnvironmentRefinement program
      abi.relation records candidate world static helper graph)
    (related : abi.relation.requestRelated
      (.invokeCall records environment resolveCodeTarget event logical) before)
    (kind : event.kind = .external) :
    CallResultEncodingResidual abi event.targetRva.toNat
      (environment.invokeCall event logical) execution.after := by
  have response :=
    (refinement.complete environment resolveCodeTarget event logical before
      related kind execution).2.1
  exact callResultEncodingResidualOfInvokeResponseRelated abi records
    environment resolveCodeTarget event logical
    (environment.invokeCall event logical) execution.after
    [execution.nativeEvent] response

/-- External-helper adapter to exact operation-result evidence. -/
def externalHelperExecutionOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {program : CompiledKernelProgram} {candidate : ExactNativeWorldProgram}
    {world : RelationalWorld}
    {static : InvokeCallNativeStaticBinding program candidate}
    {helper : InvokeCallNativeExternalHelperBinding program candidate static}
    {graph :
      StageA.Relational.InterpreterKernelHelperPath.HelperPathGraph}
    {before : MachineState}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine}
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before)
    (refinement : InvokeCallNativeExternalEnvironmentRefinement program
      abi.relation records candidate world static helper graph)
    (related : abi.relation.requestRelated
      (.invokeCall records environment resolveCodeTarget event logical) before)
    (kind : event.kind = .external) :
    CheckedOperationResultEvidence abi
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call (environment.invokeCall event logical)) execution.after :=
  CallResultEncodingResidual.toInvokeCallEvidence
    (externalHelperExecutionCallResultEncodingResidual execution refinement
      related kind)
    records environment resolveCodeTarget logical

/-- Indirect-arm projection at the exact resolver/callback/Run/epilogue
endpoint retained by `completion.execution`. -/
def indirectCompletionCallResultEncodingResidual
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {program : CompiledKernelProgram}
    {inventory :
      StageA.Relational.InterpreterKernelCallback.KernelCallbackInventory}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva runFunctionEntryRva continuationRva : Nat}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine} {result : CallResult}
    {before runFunctionBefore runFunctionAfter : MachineState}
    {events : List NativeExternalEvent}
    {subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))
      runFunctionEntryRva runFunctionBefore runFunctionAfter events}
    (completion : InvokeCallNativeIndirectCompletion program inventory
      abi.relation candidate world invokeEntryRva runFunctionEntryRva
      continuationRva
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before runFunctionBefore runFunctionAfter events
      subroutine) :
    CallResultEncodingResidual abi event.targetRva.toNat result
      completion.after :=
  callResultEncodingResidualOfInvokeResponseRelated abi records environment
    resolveCodeTarget event logical result completion.after events
    completion.responseRelated

/-- Indirect-arm adapter to exact operation-result evidence. -/
def indirectCompletionOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {program : CompiledKernelProgram}
    {inventory :
      StageA.Relational.InterpreterKernelCallback.KernelCallbackInventory}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva runFunctionEntryRva continuationRva : Nat}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine} {result : CallResult}
    {before runFunctionBefore runFunctionAfter : MachineState}
    {events : List NativeExternalEvent}
    {subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))
      runFunctionEntryRva runFunctionBefore runFunctionAfter events}
    (completion : InvokeCallNativeIndirectCompletion program inventory
      abi.relation candidate world invokeEntryRva runFunctionEntryRva
      continuationRva
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before runFunctionBefore runFunctionAfter events
      subroutine) :
    CheckedOperationResultEvidence abi
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) completion.after :=
  CallResultEncodingResidual.toInvokeCallEvidence
    (indirectCompletionCallResultEncodingResidual completion)
    records environment resolveCodeTarget logical

#print axioms
  callResultEncodingResidual_iff_invokeResponseMachinePayloadHolds
#print axioms callResultEncodingResidualOfInvokeResponseRelated
#print axioms internalCompletionCallResultEncodingResidual
#print axioms internalCompletionOperationResultEvidence
#print axioms externalHelperExecutionCallResultEncodingResidual
#print axioms externalHelperExecutionOperationResultEvidence
#print axioms indirectCompletionCallResultEncodingResidual
#print axioms indirectCompletionOperationResultEvidence

end StageA.Relational.InterpreterKernelInvokeResultClosure
