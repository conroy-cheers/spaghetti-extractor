import StageA.RelationalInterpreterKernelCdeclEpilogueExternalPayload
import StageA.RelationalInterpreterKernelProgramLookupOperation
import StageA.RelationalInterpreterKernelStepOperation
import StageA.RelationalInterpreterKernelRunOperation
import StageA.RelationalInterpreterKernelInvokeOperation

namespace StageA.Relational.InterpreterKernelOperationResultEncoding

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelInvokeNative
open StageA.Relational.InterpreterKernelInvokeOperation
open StageA.Relational.InterpreterKernelLookupNative
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterKernelSummary
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact operation-result encoding

This layer connects the exact operation executors to
`CheckedOperationResultEvidence`.  A `programLookup` return certificate already
contains its exact result word, so that operation needs no additional machine
premise.  The other executors determine their endpoints but do not, independently
of their broad ABI response fields, relate those endpoint bytes to the selected
semantic result.  The two residual types below contain only those missing
endpoint-indexed facts.
-/

/-- The exact result words missing from an `interpreterStep` executor endpoint.
The `none` case has no engine-state premise. -/
inductive InterpreterStepResultEncodingResidual
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) : Option MacroResult -> MachineState -> Prop
  | none
      (eaxExact :
        state.registers.eax =
          abi.parameters.resultAddress abi.engineLayout)
      (resultWords :
        WordsAt state.memory
          (abi.parameters.resultAddress abi.engineLayout)
          (stepResultWords none)) :
      InterpreterStepResultEncodingResidual abi sourceRva none state
  | some
      (eaxExact :
        state.registers.eax =
          abi.parameters.resultAddress abi.engineLayout)
      (resultWords :
        WordsAt state.memory
          (abi.parameters.resultAddress abi.engineLayout)
          (stepResultWords (some result)))
      (engineState :
        EngineStateHolds abi.engineLayout abi.parameters.inputAddress
          result.state sourceRva state) :
      InterpreterStepResultEncodingResidual abi sourceRva (some result) state

def InterpreterStepResultEncodingResidual.toCheckedOperationResultEvidence
    (residual : InterpreterStepResultEncodingResidual abi sourceRva result state)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (logical : InterpreterMachine) :
    CheckedOperationResultEvidence abi
      (.interpreterStep requestRecords environment sourceRva logical)
      (.interpreterStep result) state := by
  cases residual with
  | none eaxExact resultWords =>
      exact .interpreterStepNone eaxExact resultWords
  | some eaxExact resultWords engineState =>
      exact .interpreterStepSome eaxExact resultWords engineState

/-- The exact status word and output engine state missing from a computed
`runFunction` or `invokeCall` endpoint. -/
structure CallResultEncodingResidual
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (sourceRva : Nat) (result : CallResult) (state : MachineState) : Prop where
  eaxExact : state.registers.eax = callStatusWord result.status
  engineState :
    EngineStateHolds abi.engineLayout
      (abi.parameters.outputAddress abi.engineLayout)
      result.state sourceRva state

def CallResultEncodingResidual.toRunFunctionEvidence
    (residual : CallResultEncodingResidual abi sourceRva result state)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine) :
    CheckedOperationResultEvidence abi
      (.runFunction requestRecords environment resolveCodeTarget sourceRva logical)
      (.call result) state :=
  .runFunction residual.eaxExact residual.engineState

def CallResultEncodingResidual.toInvokeCallEvidence
    (residual : CallResultEncodingResidual abi event.targetRva.toNat result state)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine) :
    CheckedOperationResultEvidence abi
      (.invokeCall requestRecords environment resolveCodeTarget event logical)
      (.call result) state :=
  .invokeCall residual.eaxExact residual.engineState

/-- The exact ProgramLookup executor already computes every machine fact needed
by `CheckedOperationResultEvidence`. -/
def ProgramLookupNativeReturnState.toCheckedOperationResultEvidence
    (returned : ProgramLookupNativeReturnState pe parameters records sourceRva
      before after)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (tableExact : parameters.tableRva = tableOffset)
    (requestRecords : List ProgramRecord) (record : Option ProgramRecord) :
    CheckedOperationResultEvidence abi
      (.programLookup requestRecords sourceRva) (.programLookup record) after :=
  .programLookup (by
    simpa [programLookupReturnWord, tableExact] using returned.eaxExact)

/-- ProgramLookup closure from the local exact executor.  The endpoint is
obtained from `constructsNativeDispatch`; it is not accepted as an argument. -/
theorem ProgramLookupNativeLocalSemantics.constructsOperationResultEvidence
    {program : CompiledKernelProgram} {pe : PE32} {imports : List PEImport}
    {function : KernelFunction} {environment : NativeEnvironment}
    {records requestRecords : List ProgramRecord}
    {transferCount sourceRva resultIndex : Nat}
    {before : MachineState}
    {certificate : ProgramLookupNativeTemplateCertificate program pe imports
      function}
    (semantics : ProgramLookupNativeLocalSemantics pe imports environment records
      transferCount certificate)
    (entry : ProgramLookupNativeLoadedEntry pe certificate.template.parameters
      records transferCount sourceRva before)
    (trace : ReflectedProgramLookupTrace records sourceRva 0 transferCount
      resultIndex)
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (tableExact : certificate.template.parameters.tableRva = tableOffset)
    (record : Option ProgramRecord) :
    exists after,
      NativeDispatches pe imports environment
        certificate.template.parameters.entryRva before after [] /\
      CheckedOperationResultEvidence abi
        (.programLookup requestRecords sourceRva) (.programLookup record) after := by
  obtain ⟨after, dispatch, returned⟩ :=
    semantics.constructsNativeDispatch entry trace
  exact ⟨after, dispatch,
    ProgramLookupNativeReturnState.toCheckedOperationResultEvidence returned abi
      tableExact requestRecords record⟩

/-- Adapter at the exact endpoint selected by the Step operation epilogue. -/
def InterpreterStepNativeEpiloguePhase.toCheckedOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {template : InterpreterStepNativeTemplate}
    {candidate : ExactNativeWorldProgram}
    {environment : StageA.Relational.Interpreter.Environment}
    {sourceRva : Nat} {logical : InterpreterMachine} {before : MachineState}
    {world : RelationalWorld}
    {lookup : InterpreterStepNativeLookupPhase template candidate records
      sourceRva before world}
    {actions : InterpreterStepNativeActionPhase template candidate environment
      logical lookup}
    (phase : InterpreterStepNativeEpiloguePhase template candidate abi.relation
      records environment sourceRva logical before actions)
    (residual : InterpreterStepResultEncodingResidual abi sourceRva
      actions.result phase.after) :
    CheckedOperationResultEvidence abi
      (.interpreterStep records environment sourceRva logical)
      (.interpreterStep actions.result) phase.after :=
  residual.toCheckedOperationResultEvidence records environment logical

/-- Adapter at the fixed-fuel exact Run epilogue endpoint. -/
def RunFunctionNativeEpiloguePhase.toCheckedOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {candidate : ExactNativeWorldProgram} {template : RunFunctionMachineTemplate}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    {before : MachineState} {outerFrame : NativeCallFrame}
    {world : RelationalWorld} {afterLoop : NativeWorldExecution}
    (phase : RunFunctionNativeEpiloguePhase candidate template abi.relation records
      environment resolveCodeTarget sourceRva logical result before outerFrame
      world afterLoop)
    (residual : CallResultEncodingResidual abi sourceRva result phase.after) :
    CheckedOperationResultEvidence abi
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      (.call result) phase.after :=
  residual.toRunFunctionEvidence records environment resolveCodeTarget logical

/-- Adapter for the exact prefix/subroutine/epilogue endpoint used by the
internal Invoke arm. -/
def InvokeCallNativeArmExecution.toCheckedOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {candidate : ExactNativeWorldProgram} {world : RelationalWorld}
    {invokeEntryRva subroutineEntryRva continuationRva : Nat}
    {returnAddress : Word}
    {before subroutineBefore subroutineAfter after : MachineState}
    {events : List NativeExternalEvent}
    (execution : InvokeCallNativeArmExecution candidate world invokeEntryRva
      subroutineEntryRva continuationRva returnAddress before subroutineBefore
      subroutineAfter after events)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (residual : CallResultEncodingResidual abi event.targetRva.toNat result
      after) :
    CheckedOperationResultEvidence abi
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) after :=
  residual.toInvokeCallEvidence records environment resolveCodeTarget logical

/-- Adapter for the helper-graph external Invoke arm.  Its endpoint is the
state selected by the exact wrapper/helper/epilogue execution. -/
def InvokeCallNativeExternalHelperArmExecution.toCheckedOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    (execution : InvokeCallNativeExternalHelperArmExecution program candidate
      world static helper graph before)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (residual : CallResultEncodingResidual abi event.targetRva.toNat result
      execution.after) :
    CheckedOperationResultEvidence abi
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) execution.after :=
  residual.toInvokeCallEvidence records environment resolveCodeTarget logical

/-- Adapter for the exact resolver/callback/RunFunction/epilogue endpoint used
by the indirect Invoke arm. -/
def InvokeCallNativeIndirectArmExecution.toCheckedOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    (execution : InvokeCallNativeIndirectArmExecution candidate world program
      inventory invokeEntryRva runFunctionEntryRva runFunctionContinuationRva
      before resolverBefore callbackBefore callbackAfter runFunctionBefore
      runFunctionAfter after site target runFunctionEvents)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (event : CallEvent)
    (logical : InterpreterMachine) (result : CallResult)
    (residual : CallResultEncodingResidual abi event.targetRva.toNat result
      after) :
    CheckedOperationResultEvidence abi
      (.invokeCall records environment resolveCodeTarget event logical)
      (.call result) after :=
  residual.toInvokeCallEvidence records environment resolveCodeTarget logical

#print axioms
  InterpreterStepResultEncodingResidual.toCheckedOperationResultEvidence
#print axioms CallResultEncodingResidual.toRunFunctionEvidence
#print axioms CallResultEncodingResidual.toInvokeCallEvidence
#print axioms
  ProgramLookupNativeReturnState.toCheckedOperationResultEvidence
#print axioms
  ProgramLookupNativeLocalSemantics.constructsOperationResultEvidence
#print axioms
  InterpreterStepNativeEpiloguePhase.toCheckedOperationResultEvidence
#print axioms
  RunFunctionNativeEpiloguePhase.toCheckedOperationResultEvidence
#print axioms
  InvokeCallNativeArmExecution.toCheckedOperationResultEvidence
#print axioms
  InvokeCallNativeExternalHelperArmExecution.toCheckedOperationResultEvidence
#print axioms
  InvokeCallNativeIndirectArmExecution.toCheckedOperationResultEvidence

end StageA.Relational.InterpreterKernelOperationResultEncoding
