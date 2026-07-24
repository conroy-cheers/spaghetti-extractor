import StageA.RelationalInterpreterKernelOperationResultEncoding

namespace StageA.Relational.InterpreterKernelRunResultClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact Run endpoint-result closure

For a concrete kernel ABI, the response relation at an established
`RunFunctionNativeEpiloguePhase` contains exactly the status-register and
output-engine facts represented by `CallResultEncodingResidual`.  This module
projects those facts without accepting a second endpoint or any report status.

This is deliberately a consumer-side closure.  Constructing the epilogue phase
through `EnvironmentClosedCDeclEpilogueCertificate` already requires
`CheckedOperationResultEvidence`, so using this projection to construct that
certificate would be circular.  The producer-side repair is to strengthen
`RunFunctionNativeLocalSemantics.execute`: its `RunFunctionNativeLoopResult`
must retain the terminal branch's status word and output engine-state encoding
through the exact cdecl epilogue.  Until then, `CallResultEncodingResidual` is
the smallest endpoint-indexed semantic premise at that construction boundary.
-/

/-- The machine part of a concrete Run response is definitionally the existing
endpoint-indexed residual.  The response trace is intentionally absent. -/
theorem callResultEncodingResidual_iff_responseMachinePayloadHolds
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (result : CallResult) (state : MachineState) :
    CallResultEncodingResidual abi sourceRva result state ↔
      ResponseMachinePayloadHolds abi
        (.runFunction requestRecords environment resolveCodeTarget sourceRva
          logical)
        (.call result) state := by
  constructor
  · intro residual
    exact ⟨residual.eaxExact, residual.engineState⟩
  · intro payload
    exact {
      eaxExact := payload.1
      engineState := payload.2
    }

/-- Project the exact Run result encoding from an already-established concrete
ABI response. -/
def callResultEncodingResidualOfResponseRelated
    (abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat)
    (sourceRva : Nat) (logical : InterpreterMachine)
    (result : CallResult) (state : MachineState)
    (nativeEvents : List NativeExternalEvent)
    (related : abi.relation.responseRelated
      (.runFunction requestRecords environment resolveCodeTarget sourceRva
        logical)
      (.call result) state nativeEvents) :
    CallResultEncodingResidual abi sourceRva result state := by
  change ABIResponseFacts abi
    (.runFunction requestRecords environment resolveCodeTarget sourceRva
      logical)
    (.call result) state nativeEvents at related
  have payload := related.payload
  change state.registers.eax = callStatusWord result.status ∧
    EngineStateHolds abi.engineLayout
      (abi.parameters.outputAddress abi.engineLayout)
      result.state sourceRva state ∧ nativeEvents = [] at payload
  exact {
    eaxExact := payload.1
    engineState := payload.2.1
  }

/-- An established exact Run epilogue phase therefore needs no additional
result-encoding argument at a consumer. -/
def RunFunctionNativeEpiloguePhase.establishedCallResultEncodingResidual
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {candidate : ExactNativeWorldProgram}
    {template : RunFunctionMachineTemplate}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    {before : MachineState} {outerFrame : NativeCallFrame}
    {world : RelationalWorld} {afterLoop : NativeWorldExecution}
    (phase : RunFunctionNativeEpiloguePhase candidate template abi.relation
      records environment resolveCodeTarget sourceRva logical result before
      outerFrame world afterLoop) :
    CallResultEncodingResidual abi sourceRva result phase.after :=
  callResultEncodingResidualOfResponseRelated abi records environment
    resolveCodeTarget sourceRva logical result phase.after phase.nativeEvents
    phase.responseRelated

/-- Consumer adapter from the established exact endpoint directly to the
operation-result evidence used by the cdecl payload layer. -/
def RunFunctionNativeEpiloguePhase.establishedOperationResultEvidence
    {abi : ConcreteKernelABI pe imports relocations tableOffset countOffset
      records}
    {candidate : ExactNativeWorldProgram}
    {template : RunFunctionMachineTemplate}
    {environment : StageA.Relational.Interpreter.Environment}
    {resolveCodeTarget : Word -> Option Nat} {sourceRva : Nat}
    {logical : InterpreterMachine} {result : CallResult}
    {before : MachineState} {outerFrame : NativeCallFrame}
    {world : RelationalWorld} {afterLoop : NativeWorldExecution}
    (phase : RunFunctionNativeEpiloguePhase candidate template abi.relation
      records environment resolveCodeTarget sourceRva logical result before
      outerFrame world afterLoop) :
    CheckedOperationResultEvidence abi
      (.runFunction records environment resolveCodeTarget sourceRva logical)
      (.call result) phase.after :=
  (RunFunctionNativeEpiloguePhase.establishedCallResultEncodingResidual
    phase).toRunFunctionEvidence records environment resolveCodeTarget logical

#print axioms callResultEncodingResidual_iff_responseMachinePayloadHolds
#print axioms callResultEncodingResidualOfResponseRelated
#print axioms
  RunFunctionNativeEpiloguePhase.establishedCallResultEncodingResidual
#print axioms RunFunctionNativeEpiloguePhase.establishedOperationResultEvidence

end StageA.Relational.InterpreterKernelRunResultClosure
