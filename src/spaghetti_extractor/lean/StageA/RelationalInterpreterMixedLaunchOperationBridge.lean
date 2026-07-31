import StageA.RelationalInterpreterKernelOperationABIFrame
import StageA.RelationalInterpreterMixedBoundaryOperation

namespace StageA.Relational.InterpreterMixedLaunchOperationBridge

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelOperationABIFrame
open StageA.Relational.InterpreterMixedBoundaryOperation
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

/-!
# Exact native launch-to-operation prefixes

The launch graph may stop at a C callback wrapper while operation checking
starts at a nested interpreter entry.  This module retains the machine facts
that must survive that gap:

* the exact callback-wrapper CDecl stack words;
* the native return frame pushed by the decoded launch call;
* the complete nested native call-frame prefix at the operation entry; and
* one nonempty, observation-free path in the exact PE transition system.

The structures are proof objects over concrete flat memory.  They are not
submitted status records, source-level calling-convention claims, or alternate
execution semantics.
-/

/-- Static callback-wrapper ABI values that are fixed by exact PE code. -/
structure NativeCallbackWrapperDescriptor where
  boundaryRva : Nat
  operationEntryRva : Nat
  launchContinuationRva : Nat
  callbackRva : Nat
  stackCleanupBytes : Nat
deriving Repr, DecidableEq

def NativeCallbackWrapperDescriptor.launchReturnAddress
    (descriptor : NativeCallbackWrapperDescriptor)
    (candidate : ExactNativeWorldProgram) : Word :=
  BitVec.ofNat 32 (candidate.pe.imageBase + descriptor.launchContinuationRva)

/-- The six arguments accepted by the native callback wrapper. -/
structure NativeCallbackWrapperArguments where
  inputAddress : Word
  outputAddress : Word
  inputX87Address : Word
  outputX87Address : Word
deriving Repr, DecidableEq

def NativeCallbackWrapperArguments.stackWords
    (descriptor : NativeCallbackWrapperDescriptor)
    (candidate : ExactNativeWorldProgram)
    (arguments : NativeCallbackWrapperArguments) : List Word :=
  [
    descriptor.launchReturnAddress candidate,
    BitVec.ofNat 32 descriptor.callbackRva,
    BitVec.ofNat 32 descriptor.stackCleanupBytes,
    arguments.inputAddress,
    arguments.outputAddress,
    arguments.inputX87Address,
    arguments.outputX87Address
  ]

def nativeCallbackWrapperArgumentsAt
    (state : MachineState) : NativeCallbackWrapperArguments := {
  inputAddress :=
    Memory.read32 state.memory (state.registers.esp + BitVec.ofNat 32 12)
  outputAddress :=
    Memory.read32 state.memory (state.registers.esp + BitVec.ofNat 32 16)
  inputX87Address :=
    Memory.read32 state.memory (state.registers.esp + BitVec.ofNat 32 20)
  outputX87Address :=
    Memory.read32 state.memory (state.registers.esp + BitVec.ofNat 32 24)
}

def nativeWorldExecutionCalls? : NativeWorldExecution ->
    Option (List NativeCallFrame)
  | .running _ _ _ calls .. => some calls
  | _ => none

theorem nativeCallbackWrapperArgumentsAt_stackWords
    (candidate : ExactNativeWorldProgram)
    (descriptor : NativeCallbackWrapperDescriptor)
    (state : MachineState)
    (returnAddress :
      Memory.read32 state.memory state.registers.esp =
        descriptor.launchReturnAddress candidate)
    (callback :
      Memory.read32 state.memory
          (state.registers.esp + BitVec.ofNat 32 4) =
        BitVec.ofNat 32 descriptor.callbackRva)
    (cleanup :
      Memory.read32 state.memory
          (state.registers.esp + BitVec.ofNat 32 8) =
        BitVec.ofNat 32 descriptor.stackCleanupBytes) :
    WordsAt state.memory state.registers.esp
      ((nativeCallbackWrapperArgumentsAt state).stackWords descriptor
        candidate) := by
  simp [NativeCallbackWrapperArguments.stackWords,
    nativeCallbackWrapperArgumentsAt, WordsAt, returnAddress, callback, cleanup,
    word32, BitVec.add_assoc]

/-- Exact callback-wrapper state produced by a decoded native launch call.

`executionExact` retains the logical native call frame, while `stackWords`
retains the corresponding physical CDecl return word and arguments.  Neither
side can be reconstructed from the recurring mixed invariant, so both are
carried by the one-time launch proof. -/
structure ExactNativeCallbackWrapperBoundaryFrame
    (candidate : ExactNativeWorldProgram)
    (descriptor : NativeCallbackWrapperDescriptor)
    (before : NativeWorldExecution) where
  state : MachineState
  arguments : NativeCallbackWrapperArguments
  callerFrames : List NativeCallFrame
  eventIndex : Nat
  events : List NativeExternalEvent
  world : RelationalWorld
  executionExact :
    before =
      .running descriptor.boundaryRva 0 state
        ({
          continuationRva := descriptor.launchContinuationRva
          returnAddress := descriptor.launchReturnAddress candidate
        } :: callerFrames)
        eventIndex events world
  stackWords :
    WordsAt state.memory state.registers.esp
      (arguments.stackWords descriptor candidate)

theorem ExactNativeCallbackWrapperBoundaryFrame.atBoundary
    (frame : ExactNativeCallbackWrapperBoundaryFrame candidate descriptor
      before) :
    nativeExecutionAtRva descriptor.boundaryRva before := by
  rw [frame.executionExact]
  rfl

theorem ExactNativeCallbackWrapperBoundaryFrame.logicalReturnFrame
    (frame : ExactNativeCallbackWrapperBoundaryFrame candidate descriptor
      before) :
  exists tail,
      nativeWorldExecutionCalls? before =
        some ({
          continuationRva := descriptor.launchContinuationRva
          returnAddress := descriptor.launchReturnAddress candidate
        } :: tail) := by
  obtain ⟨state, arguments, callerFrames, eventIndex, events, world,
      executionExact, stackWords⟩ := frame
  subst before
  exact ⟨callerFrames, rfl⟩

/-- Exact nested native state at the first checked operation entry.

The operation-frame prefix is ordered from the innermost return frame to the
outer callback-wrapper frame.  The launch caller tail is retained unchanged.
This exposes the stack discipline required by nested operation replay without
requiring the recurring invariant to infer it. -/
structure ExactNativeLaunchOperationPrefix
    (candidate : ExactNativeWorldProgram)
    (descriptor : NativeCallbackWrapperDescriptor)
    (boundaryBefore : NativeWorldExecution) where
  boundary :
    ExactNativeCallbackWrapperBoundaryFrame candidate descriptor boundaryBefore
  operationState : MachineState
  operationFrames : List NativeCallFrame
  candidatePrefix :
    NonemptyRelatedPath candidate.transitionSystem boundaryBefore []
      (.running descriptor.operationEntryRva 0 operationState
        (operationFrames ++ boundary.callerFrames)
        boundary.eventIndex boundary.events boundary.world)

def ExactNativeLaunchOperationPrefix.operationExecution
    (launchPrefix : ExactNativeLaunchOperationPrefix candidate descriptor
      boundaryBefore) : NativeWorldExecution :=
    .running descriptor.operationEntryRva 0 launchPrefix.operationState
      (launchPrefix.operationFrames ++ launchPrefix.boundary.callerFrames)
      launchPrefix.boundary.eventIndex launchPrefix.boundary.events
      launchPrefix.boundary.world

theorem ExactNativeLaunchOperationPrefix.atOperationEntry
    (launchPrefix : ExactNativeLaunchOperationPrefix candidate descriptor
      boundaryBefore) :
    nativeExecutionAtRva descriptor.operationEntryRva
      launchPrefix.operationExecution := by
  simp [ExactNativeLaunchOperationPrefix.operationExecution,
    nativeExecutionAtRva]

theorem ExactNativeLaunchOperationPrefix.callerTailPreserved
    (launchPrefix : ExactNativeLaunchOperationPrefix candidate descriptor
      boundaryBefore) :
    nativeWorldExecutionCalls? launchPrefix.operationExecution =
      some (launchPrefix.operationFrames ++
        launchPrefix.boundary.callerFrames) := by
  simp [ExactNativeLaunchOperationPrefix.operationExecution,
    nativeWorldExecutionCalls?]

/-- Instantiate the generic mixed boundary bridge from the retained exact
launch prefix and an operation certificate at its computed endpoint. -/
def ExactNativeLaunchOperationPrefix.toBoundaryBridge
    (launchPrefix : ExactNativeLaunchOperationPrefix candidate descriptor
      boundaryBefore)
    (certificate : MixedKernelOperationComponentCertificate original candidate
      contract invariant program abi dispatches candidateAuthority sourceRva
      owner.operation owner.entryRva originalBefore
        launchPrefix.operationExecution) :
    ExactMixedKernelBoundaryToOperationBridge original candidate contract
      invariant program abi dispatches candidateAuthority sourceRva owner
      originalBefore boundaryBefore := by
  exact {
    operationBefore := launchPrefix.operationExecution
    candidatePrefix := by
      simpa [ExactNativeLaunchOperationPrefix.operationExecution] using
        launchPrefix.candidatePrefix
    certificate
  }

#print axioms ExactNativeCallbackWrapperBoundaryFrame.atBoundary
#print axioms ExactNativeCallbackWrapperBoundaryFrame.logicalReturnFrame
#print axioms nativeCallbackWrapperArgumentsAt_stackWords
#print axioms ExactNativeLaunchOperationPrefix.atOperationEntry
#print axioms ExactNativeLaunchOperationPrefix.callerTailPreserved
#print axioms ExactNativeLaunchOperationPrefix.toBoundaryBridge

end StageA.Relational.InterpreterMixedLaunchOperationBridge
