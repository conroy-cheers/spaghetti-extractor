import StageA.RelationalInterpreterKernelRunResultClosure
import StageA.RelationalInterpreterKernelCdeclEpilogueSymbolicClosure

namespace StageA.Relational.InterpreterKernelRunProducerResultClosure

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.Relational.InterpreterKernelRun
open StageA.Relational.InterpreterNativeWorld

/-!
# Producer-side Run result closure

The native Run loop now retains exact result-indexed evidence at its computed
epilogue entry.  This module carries that evidence through an exact symbolic
execution of the fixed cdecl suffix.  The suffix checker accepts only a behavior
that preserves EAX and performs no memory writes, which is sufficient to
preserve the concrete engine representation.

This layer is intentionally below the environment/response certificate:
`CallResultEncodingResidual` is produced before
`EnvironmentClosedCDeclEpilogueCertificate` is constructed, avoiding the
consumer-side circularity.
-/

def runFunctionCDeclSuffixPreservesResult
    (behavior : SymbolicBehavior) : Bool :=
  behavior.registers.eax == .inputReg .eax && behavior.writes.isEmpty

/-- Exact symbolic suffix evidence tied to the decoder-computed return state.
The Boolean check prevents a certificate author from asserting preservation for
an arbitrary symbolic behavior. -/
structure ExactRunFunctionCDeclSuffixResultPreservation
    (epilogueBefore : MachineState)
    (execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world) where
  symbolic : ExactDecodedCDeclSymbolicExecution execution epilogueBefore
  checked : runFunctionCDeclSuffixPreservesResult symbolic.behavior = true

theorem ExactRunFunctionCDeclSuffixResultPreservation.eaxPreserved
    {program : CompiledKernelProgram} {function : KernelFunction}
    {candidate : ExactNativeWorldProgram}
    {static : CheckedKernelCDeclEpilogue program candidate function}
    {disposition : CDeclReturnDisposition}
    {epilogueBefore : MachineState}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world}
    (preservation :
      ExactRunFunctionCDeclSuffixResultPreservation epilogueBefore execution) :
    execution.returnedState.registers.eax =
      epilogueBefore.registers.eax := by
  have checked := preservation.checked
  simp only [runFunctionCDeclSuffixPreservesResult, Bool.and_eq_true,
    beq_iff_eq] at checked
  rw [preservation.symbolic.returnedStateExact]
  change preservation.symbolic.behavior.registers.eax.eval epilogueBefore =
    epilogueBefore.registers.eax
  rw [checked.1]
  rfl

theorem ExactRunFunctionCDeclSuffixResultPreservation.memoryPreserved
    {program : CompiledKernelProgram} {function : KernelFunction}
    {candidate : ExactNativeWorldProgram}
    {static : CheckedKernelCDeclEpilogue program candidate function}
    {disposition : CDeclReturnDisposition}
    {epilogueBefore : MachineState}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world}
    (preservation :
      ExactRunFunctionCDeclSuffixResultPreservation epilogueBefore execution) :
    execution.returnedState.memory = epilogueBefore.memory := by
  have checked := preservation.checked
  simp only [runFunctionCDeclSuffixPreservesResult, Bool.and_eq_true] at checked
  rw [preservation.symbolic.returnedStateExact]
  change applyWrites epilogueBefore preservation.symbolic.behavior.writes =
    epilogueBefore.memory
  have noWrites : preservation.symbolic.behavior.writes = [] := by
    simpa using checked.2
  rw [noWrites]
  rfl

theorem ExactRunFunctionCDeclSuffixResultPreservation.x87SemanticsPreserved
    {program : CompiledKernelProgram} {function : KernelFunction}
    {candidate : ExactNativeWorldProgram}
    {static : CheckedKernelCDeclEpilogue program candidate function}
    {disposition : CDeclReturnDisposition}
    {epilogueBefore : MachineState}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world}
    (preservation :
      ExactRunFunctionCDeclSuffixResultPreservation epilogueBefore execution) :
    execution.returnedState.x87Semantics =
      epilogueBefore.x87Semantics := by
  rw [preservation.symbolic.returnedStateExact]
  rfl

theorem EngineStateHolds.preserveMachineBacking
    (holds : EngineStateHolds layout base logical sourceRva before)
    (memory : after.memory = before.memory)
    (x87Semantics : after.x87Semantics = before.x87Semantics) :
    EngineStateHolds layout base logical sourceRva after := by
  rcases holds with ⟨original, machineMatches, related⟩
  refine ⟨original, machineMatches, {
    repValid := related.repValid
    fields := ?_
    memory := ?_
    control := related.control
    originalSemantics := related.originalSemantics
    candidateSemantics := x87Semantics.trans related.candidateSemantics
  }⟩
  · intro entry member
    rw [memory]
    exact related.fields entry member
  · intro originalAddress candidateAddress mapped
    rw [memory]
    exact related.memory originalAddress candidateAddress mapped

/-- Preserve the loop-produced machine result through the checked exact cdecl
suffix.  The returned endpoint is computed by `ExactComputedCDeclEpilogue`; it
is not supplied by this theorem. -/
def CallResultEncodingResidual.preserveThroughExactCDeclSuffix
    {program : CompiledKernelProgram} {function : KernelFunction}
    {candidate : ExactNativeWorldProgram}
    {static : CheckedKernelCDeclEpilogue program candidate function}
    {disposition : CDeclReturnDisposition}
    {epilogueBefore : MachineState}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    {execution : ExactComputedCDeclEpilogue candidate static disposition
      epilogueBefore eventIndex events world}
    (residual : CallResultEncodingResidual abi sourceRva result epilogueBefore)
    (preservation :
      ExactRunFunctionCDeclSuffixResultPreservation epilogueBefore execution) :
    CallResultEncodingResidual abi sourceRva result execution.returnedState := {
  eaxExact := preservation.eaxPreserved.trans residual.eaxExact
  engineState := EngineStateHolds.preserveMachineBacking residual.engineState
    preservation.memoryPreserved preservation.x87SemanticsPreserved
}

/-- Specialize the generic result-indexed loop theorem to the concrete result
encoding required by the Run ABI. -/
def RunFunctionNativeResultIndexedLoopResult.callResultEncodingResidual
    (loopResult :
      RunFunctionNativeResultIndexedLoopResult candidate template before
        (CallResultEncodingResidual abi sourceRva) result) :
    CallResultEncodingResidual abi sourceRva result loopResult.terminalState :=
  loopResult.encoding

/-- End-to-end producer adapter: exact loop evidence plus an exact checked cdecl
suffix constructs the operation-result evidence consumed by the environment
closure. -/
def RunFunctionNativeResultIndexedLoopResult.operationResultEvidence
    {program : CompiledKernelProgram} {function : KernelFunction}
    {static : CheckedKernelCDeclEpilogue program candidate function}
    {disposition : CDeclReturnDisposition}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (loopResult :
      RunFunctionNativeResultIndexedLoopResult candidate template before
        (CallResultEncodingResidual abi sourceRva) result)
    {execution : ExactComputedCDeclEpilogue candidate static disposition
      loopResult.terminalState eventIndex events world}
    (preservation :
      ExactRunFunctionCDeclSuffixResultPreservation loopResult.terminalState
        execution)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine) :
    CheckedOperationResultEvidence abi
      (.runFunction requestRecords environment resolveCodeTarget sourceRva
        logical)
      (.call result) execution.returnedState :=
  (CallResultEncodingResidual.preserveThroughExactCDeclSuffix
    (RunFunctionNativeResultIndexedLoopResult.callResultEncodingResidual
      loopResult) preservation).toRunFunctionEvidence requestRecords environment
        resolveCodeTarget logical

#print axioms
  ExactRunFunctionCDeclSuffixResultPreservation.eaxPreserved
#print axioms
  ExactRunFunctionCDeclSuffixResultPreservation.memoryPreserved
#print axioms
  ExactRunFunctionCDeclSuffixResultPreservation.x87SemanticsPreserved
#print axioms EngineStateHolds.preserveMachineBacking
#print axioms CallResultEncodingResidual.preserveThroughExactCDeclSuffix
#print axioms
  RunFunctionNativeResultIndexedLoopResult.callResultEncodingResidual
#print axioms
  RunFunctionNativeResultIndexedLoopResult.operationResultEvidence

end StageA.Relational.InterpreterKernelRunProducerResultClosure
