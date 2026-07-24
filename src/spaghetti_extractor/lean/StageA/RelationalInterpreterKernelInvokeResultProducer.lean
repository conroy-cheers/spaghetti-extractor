import StageA.RelationalInterpreterKernelOperationResultEncoding

namespace StageA.Relational.InterpreterKernelInvokeResultProducer

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCallback
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelHelperPath
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterNativeWorld

/-!
# Producer-side Invoke result encoding

The broad Invoke operation objects retain a response relation because that is
their public `KernelOperationRefinesUsing` interface.  That relation must not be
used to manufacture the machine-result evidence needed to construct the same
response.

This module records the independent producer evidence.  Each arm supplies an
environment-closed cdecl certificate whose operation-result field is indexed by
the exact cdecl return state.  Exact start and fuel equalities identify that
execution with the arm's computed epilogue.  Consequently the final endpoint
and its result encoding are derived from execution; no endpoint or response
relation is accepted.
-/

/-- Extract the Invoke-specific residual directly from operation-result
evidence.  The impossible operation constructors are eliminated by the
indices. -/
def callResultEncodingResidualOfInvokeOperationResult
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {requestRecords : List ProgramRecord}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {event : CallEvent}
    {logical : InterpreterMachine} {result : CallResult}
    {state : MachineState}
    (evidence : CheckedOperationResultEvidence abi
      (.invokeCall requestRecords environment resolveCodeTarget event logical)
      (.call result) state) :
    CallResultEncodingResidual abi event.targetRva.toNat result state := by
  cases evidence with
  | invokeCall eaxExact engineState =>
      exact {
        eaxExact
        engineState
      }

/-- A generic exact segment and an exact top-level cdecl execution with the
same start and fuel have the same returned machine state. -/
theorem exactSegmentTopLevelCdeclReturnedState
    {candidate : ExactNativeWorldProgram}
    {segmentStart : NativeWorldExecution}
    (segment : ExactComputedNativeWorldSegment candidate segmentStart)
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {program : CompiledKernelProgram} {function : KernelFunction}
    {static : CheckedKernelCDeclEpilogue program candidate function}
    {request : AbstractKernelRequest} {response : AbstractKernelResponse}
    {entryBefore epilogueBefore : MachineState} {eventIndex : Nat}
    {events : List NativeExternalEvent} {world : RelationalWorld}
    (certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate
      static .topLevel request response entryBefore epilogueBefore eventIndex
      events world)
    (startExact : segmentStart = certificate.execution.start)
    (fuelExact :
      segment.fuel = certificate.execution.prefixFuel + 1)
    {after : MachineState}
    (segmentReturned : segment.after = .returned after events world) :
    after = certificate.execution.returnedState := by
  have resultExact :
      segment.result =
        (certificate.execution.after, certificate.execution.observations) := by
    unfold ExactComputedNativeWorldSegment.result
    rw [fuelExact, startExact]
    exact certificate.execution.runExact certificate.toChecked.stackReturnWord
      certificate.toChecked.returnAccepted
  have afterExact : segment.after = certificate.execution.after := by
    exact congrArg Prod.fst resultExact
  rw [segmentReturned] at afterExact
  simpa [ExactComputedCDeclEpilogue.after,
    CDeclReturnDisposition.endpoint] using afterExact

/-- Internal-arm producer evidence.  The cdecl execution is tied to the exact
wrapper epilogue by its computed start and fuel. -/
structure InvokeCallNativeInternalResultProducer
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (function : KernelFunction)
    (candidate : ExactNativeWorldProgram)
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
    (completion : InvokeCallNativeInternalCompletion abi.relation candidate world
      invokeEntryRva subroutineEntryRva continuationRva returnAddress
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before subroutineBefore subroutineAfter events subroutine)
    (epilogueBefore : MachineState) where
  certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate checked
    .topLevel
    (.invokeCall records environment resolveCodeTarget event logical)
    (.call result) before epilogueBefore events.length events
    completion.execution.subroutine.afterWorld
  epilogueStartExact :
    (NativeWorldExecution.running continuationRva 0 subroutineAfter []
      events.length events completion.execution.subroutine.afterWorld) =
      certificate.execution.start
  epilogueFuelExact :
    completion.execution.epilogue.fuel =
      certificate.execution.prefixFuel + 1

def InvokeCallNativeInternalResultProducer.resultEncoding
    (producer : InvokeCallNativeInternalResultProducer abi program function
      candidate checked world invokeEntryRva subroutineEntryRva continuationRva
      returnAddress environment resolveCodeTarget event logical result before
      subroutineBefore subroutineAfter events subroutine completion
      epilogueBefore) :
    CallResultEncodingResidual abi event.targetRva.toNat result
      completion.after := by
  have endpointExact : completion.after =
      producer.certificate.execution.returnedState :=
    exactSegmentTopLevelCdeclReturnedState
      completion.execution.epilogue producer.certificate
      producer.epilogueStartExact producer.epilogueFuelExact
      completion.execution.epilogueReturned
  rw [endpointExact]
  exact callResultEncodingResidualOfInvokeOperationResult
    producer.certificate.operationResult

/-- External-helper producer evidence.  The machine result comes from the
checked epilogue, while the one-to-one external trace remains a separate field
of the environment-closed certificate. -/
structure InvokeCallNativeExternalHelperResultProducer
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (function : KernelFunction)
    (candidate : ExactNativeWorldProgram)
    (checked : CheckedKernelCDeclEpilogue program candidate function)
    (world : RelationalWorld)
    (static : InvokeCallNativeStaticBinding program candidate)
    (helper : InvokeCallNativeExternalHelperBinding program candidate static)
    (graph : HelperPathGraph) (before : MachineState)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine)
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before)
    (epilogueBefore : MachineState) where
  certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate checked
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

def InvokeCallNativeExternalHelperResultProducer.resultEncoding
    (producer : InvokeCallNativeExternalHelperResultProducer abi program function
      candidate checked world static helper graph before environment
      resolveCodeTarget event logical execution epilogueBefore) :
    CallResultEncodingResidual abi event.targetRva.toNat
      (environment.invokeCall event logical) execution.after := by
  have endpointExact : execution.after =
      producer.certificate.execution.returnedState :=
    exactSegmentTopLevelCdeclReturnedState execution.epilogue
      producer.certificate producer.epilogueStartExact producer.epilogueFuelExact
      execution.epilogueReturned
  rw [endpointExact]
  exact callResultEncodingResidualOfInvokeOperationResult
    producer.certificate.operationResult

/-- Indirect-arm producer evidence.  Resolver and nested Run execution remain
in the existing completion; only its exact final epilogue is synchronized with
the result-bearing cdecl certificate. -/
structure InvokeCallNativeIndirectResultProducer
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (program : CompiledKernelProgram) (function : KernelFunction)
    (candidate : ExactNativeWorldProgram)
    (checked : CheckedKernelCDeclEpilogue program candidate function)
    (inventory : KernelCallbackInventory)
    (world : RelationalWorld)
    (invokeEntryRva runFunctionEntryRva continuationRva : Nat)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (before runFunctionBefore runFunctionAfter : MachineState)
    (events : List NativeExternalEvent)
    (subroutine : NativeWorldSubroutineResult candidate world continuationRva
      (BitVec.ofNat 32 (candidate.pe.imageBase + continuationRva))
      runFunctionEntryRva runFunctionBefore runFunctionAfter events)
    (completion : InvokeCallNativeIndirectCompletion program inventory
      abi.relation candidate world invokeEntryRva runFunctionEntryRva
      continuationRva
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) before runFunctionBefore runFunctionAfter events subroutine)
    (epilogueBefore : MachineState) where
  certificate : EnvironmentClosedCDeclEpilogueCertificate abi candidate checked
    .topLevel
    (.invokeCall records environment resolveCodeTarget event logical)
    (.call result) before epilogueBefore events.length events
    completion.execution.runFunction.afterWorld
  epilogueStartExact :
    (NativeWorldExecution.running continuationRva 0 runFunctionAfter []
      events.length events completion.execution.runFunction.afterWorld) =
      certificate.execution.start
  epilogueFuelExact :
    completion.execution.epilogue.fuel =
      certificate.execution.prefixFuel + 1

def InvokeCallNativeIndirectResultProducer.resultEncoding
    (producer : InvokeCallNativeIndirectResultProducer abi program function
      candidate checked inventory world invokeEntryRva runFunctionEntryRva
      continuationRva environment resolveCodeTarget event logical result before
      runFunctionBefore runFunctionAfter events subroutine completion
      epilogueBefore) :
    CallResultEncodingResidual abi event.targetRva.toNat result
      completion.after := by
  have endpointExact : completion.after =
      producer.certificate.execution.returnedState :=
    exactSegmentTopLevelCdeclReturnedState completion.execution.epilogue
      producer.certificate producer.epilogueStartExact producer.epilogueFuelExact
      completion.execution.epilogueReturned
  rw [endpointExact]
  exact callResultEncodingResidualOfInvokeOperationResult
    producer.certificate.operationResult

#print axioms callResultEncodingResidualOfInvokeOperationResult
#print axioms exactSegmentTopLevelCdeclReturnedState
#print axioms InvokeCallNativeInternalResultProducer.resultEncoding
#print axioms InvokeCallNativeExternalHelperResultProducer.resultEncoding
#print axioms InvokeCallNativeIndirectResultProducer.resultEncoding

end StageA.Relational.InterpreterKernelInvokeResultProducer
