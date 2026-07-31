import StageA.RelationalInterpreterMixedEnvironment

namespace StageA.Relational.InterpreterMixedRuntimeFoundation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Checked mixed runtime foundations

This module supplies one structural relation for ordinary machine call frames.
The relation is deliberately recursive and checks both the mapped continuation
RVA and the concrete native return address in every frame.

The callback-capable relation remains separate because callback frames are
runtime state in `NestedNativeWorldExecution`; they are not present in the
ordinary `NativeWorldExecution` consumed by `MixedExternalFrameContract`.
-/

/-- The concrete return word pushed by a native direct call. -/
def ExactNativeReturnAddress
    (candidateImageBase : Nat)
    (frame : NativeCallFrame) : Prop :=
  frame.returnAddress =
    BitVec.ofNat 32 (candidateImageBase + frame.continuationRva)

/-- Exact recursive relation between decoded continuation IDs and candidate
machine call frames.  Length mismatches cannot be hidden. -/
inductive ExactMixedCallFramesRelated
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop) :
    List Nat -> List NativeCallFrame -> Prop where
  | nil :
      ExactMixedCallFramesRelated candidateImageBase
        continuationTargetsRelated [] []
  | cons
      (originalTargetId : Nat)
      (candidateFrame : NativeCallFrame)
      (originalTail : List Nat)
      (candidateTail : List NativeCallFrame)
      (continuation :
        continuationTargetsRelated originalTargetId
          candidateFrame.continuationRva)
      (returnAddress :
        ExactNativeReturnAddress candidateImageBase candidateFrame)
      (tail : ExactMixedCallFramesRelated candidateImageBase
        continuationTargetsRelated originalTail candidateTail) :
      ExactMixedCallFramesRelated candidateImageBase continuationTargetsRelated
        (originalTargetId :: originalTail) (candidateFrame :: candidateTail)

/-- Callback-free parent relation used by the synchronous external component.
The empty callback requirement is explicit; callback state is never discarded
or treated as an ordinary machine frame. -/
def ExactMixedExternalCallFramesRelated
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop)
    (originalCalls : List Nat)
    (originalCallbacks : List WorldExternalCallbackRuntime)
    (candidateCalls : List NativeCallFrame) : Prop :=
  originalCallbacks = [] /\
    ExactMixedCallFramesRelated candidateImageBase continuationTargetsRelated
      originalCalls candidateCalls

/-- Ordinary call frames inside the nested carrier.  Callback frames are not
discarded here: the enclosing `MixedNestedExternalCallbackFramesRelated`
relates the original and candidate callback stacks recursively. -/
def ExactMixedNestedCallFramesRelated
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop)
    (originalCalls : List Nat)
    (_originalCallbacks : List WorldExternalCallbackRuntime)
    (candidateCalls : List NativeCallFrame) : Prop :=
  ExactMixedCallFramesRelated candidateImageBase continuationTargetsRelated
    originalCalls candidateCalls

/-- Exact callback-free frame contract for one canonical relation core. -/
def exactMixedExternalFrameContract
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop) :
    MixedExternalFrameContract := {
  continuationTargetsRelated
  callFramesRelated :=
    ExactMixedExternalCallFramesRelated candidateImageBase
      continuationTargetsRelated
}

/-- Callback-capable extension.  Its parent remains suitable for callback-free
boundaries, while `MixedNestedExternalCallbackFramesRelated` relates the actual
candidate external-frame stack recursively. -/
def exactMixedNestedExternalFrameContract
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop)
    (callbackReturnAddressesRelated : Word -> Word -> Prop) :
    MixedNestedExternalFrameContract := {
  continuationTargetsRelated
  callFramesRelated :=
    ExactMixedNestedCallFramesRelated candidateImageBase
      continuationTargetsRelated
  callbackReturnAddressesRelated
}

@[simp] theorem exactMixedExternalFrameContract_continuation
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop)
    (originalTargetId candidateRva : Nat) :
    (exactMixedExternalFrameContract candidateImageBase
      continuationTargetsRelated).continuationTargetsRelated
        originalTargetId candidateRva =
      continuationTargetsRelated originalTargetId candidateRva := rfl

@[simp] theorem exactMixedExternalFrameContract_calls
    (candidateImageBase : Nat)
    (continuationTargetsRelated : Nat -> Nat -> Prop)
    (originalCalls : List Nat)
    (callbacks : List WorldExternalCallbackRuntime)
    (candidateCalls : List NativeCallFrame) :
    (exactMixedExternalFrameContract candidateImageBase
      continuationTargetsRelated).callFramesRelated
        originalCalls callbacks candidateCalls =
      ExactMixedExternalCallFramesRelated candidateImageBase
        continuationTargetsRelated originalCalls callbacks candidateCalls := rfl

theorem ExactMixedCallFramesRelated.length_eq
    (related : ExactMixedCallFramesRelated candidateImageBase
      continuationTargetsRelated
      originalCalls candidateCalls) :
    originalCalls.length = candidateCalls.length := by
  induction related with
  | nil => rfl
  | cons _ _ _ _ _ _ _ induction => simp [induction]

theorem ExactMixedCallFramesRelated.head_return_address
    (related : ExactMixedCallFramesRelated candidateImageBase
      continuationTargetsRelated
      (originalTargetId :: originalTail) (candidateFrame :: candidateTail)) :
    ExactNativeReturnAddress candidateImageBase candidateFrame := by
  cases related
  assumption

/-- Every parsed launch continuation belongs to the checked original
reachability closure.  This is a structural root fact, independent of the
candidate runtime representation. -/
theorem exactOriginalLaunchExecutionReachable
    (root : DirectExactOriginalDecodedLaunchRoot original launch)
    (reachability :
      ExactOriginalDecodedReachability original authority launch root)
    (originalState : MachineState)
    (originalWorld : RelationalWorld) :
    OriginalExecutionReachable reachability.targetIds
      (.running launch.rootTargetId originalState
        launch.continuationTargetIds 0 originalWorld) := by
  constructor
  · rw [root.initialExact]
    unfold PE32ConsoleLaunchV2.initialTargetId
    cases targetsExact : launch.tlsCallbackTargetIds with
    | nil =>
        simpa [targetsExact] using reachability.entryReachable
    | cons target targets =>
        apply reachability.tlsReachable target
        simp [targetsExact]
  · intro continuation continuationMember
    unfold PE32ConsoleLaunchV2.continuationTargetIds at continuationMember
    cases targetsExact : launch.tlsCallbackTargetIds with
    | nil =>
        simp [targetsExact] at continuationMember
    | cons target targets =>
        simp only [targetsExact] at continuationMember
        rcases List.mem_append.mp continuationMember with tailMember |
          entryMember
        · apply reachability.tlsReachable continuation
          simp [targetsExact, tailMember]
        · have continuationExact : continuation = launch.entryTargetId := by
            simpa using entryMember
          simpa [continuationExact] using reachability.entryReachable

/-- Project the world relation from the complete mixed launch premise. -/
theorem mixedLaunchWorldsRelated
    (related : MixedLaunchStatesRelated original candidate contract
      originalWorld candidateWorld originalState candidateState) :
    contract.worldsRelated originalWorld candidateWorld :=
  related.2.2.1

/-- One concrete related launch-state tuple directly inhabits launch
realizability.  No additional relation or status field is accepted. -/
theorem mixedLaunchRealizable_of_related
    (related : MixedLaunchStatesRelated original candidate contract
      originalWorld candidateWorld originalState candidateState) :
    MixedLaunchRealizable original candidate contract :=
  ⟨originalWorld, candidateWorld, originalState, candidateState, related⟩

/-- Exact pre-wrapper bootstrap evidence.  It is indexed by both parsed roots
and by the loader-derived candidate call frames, so it cannot be reused at an
arbitrary state that happens to revisit the same RVA.  This evidence belongs
at the input of wrapper replay, outside the runtime invariant. -/
structure ExactMixedLaunchRootRelated
    (original : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority original)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot original launch)
    (reachability :
      ExactOriginalDecodedReachability original authority launch originalRoot)
    (candidateRootRva : Nat)
    (candidateRoot :
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva)
    (candidateLaunchCalls : MachineState -> List NativeCallFrame)
    (candidateLaunchCallsExact : forall candidateState,
      candidateNativeLaunchCallFrames? candidate launch candidateState =
        some (candidateLaunchCalls candidateState))
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) : Prop where
  launchRelated :
    MixedLaunchStatesRelated original candidate contract originalWorld
      candidateWorld originalState candidateState

def ExactMixedLaunchRootRelated.originalExecution
    (evidence : ExactMixedLaunchRootRelated original authority candidate
      contract launch originalRoot reachability candidateRootRva candidateRoot
      candidateLaunchCalls candidateLaunchCallsExact originalWorld
      candidateWorld originalState candidateState) : WorldExecution :=
  .running launch.rootTargetId originalState launch.continuationTargetIds 0
    originalWorld

def ExactMixedLaunchRootRelated.candidateExecution
    (evidence : ExactMixedLaunchRootRelated original authority candidate
      contract launch originalRoot reachability candidateRootRva candidateRoot
      candidateLaunchCalls candidateLaunchCallsExact originalWorld
      candidateWorld originalState candidateState) : NativeWorldExecution :=
  .running candidateRootRva 0 candidateState
    (candidateLaunchCalls candidateState) 0 [] candidateWorld

theorem ExactMixedLaunchRootRelated.originalReachable
    (evidence : ExactMixedLaunchRootRelated original authority candidate
      contract launch originalRoot reachability candidateRootRva candidateRoot
      candidateLaunchCalls candidateLaunchCallsExact originalWorld
      candidateWorld originalState candidateState) :
    OriginalExecutionReachable reachability.targetIds
      evidence.originalExecution :=
  exactOriginalLaunchExecutionReachable originalRoot reachability
    originalState originalWorld

theorem ExactMixedLaunchRootRelated.candidateProofOpen
    (evidence : ExactMixedLaunchRootRelated original authority candidate
      contract launch originalRoot reachability candidateRootRva candidateRoot
      candidateLaunchCalls candidateLaunchCallsExact originalWorld
      candidateWorld originalState candidateState) :
    NativeExecutionProofOpen evidence.candidateExecution := by
  simp [ExactMixedLaunchRootRelated.candidateExecution,
    NativeExecutionProofOpen]

#print axioms ExactMixedCallFramesRelated.length_eq
#print axioms ExactMixedCallFramesRelated.head_return_address
#print axioms exactOriginalLaunchExecutionReachable
#print axioms mixedLaunchWorldsRelated
#print axioms mixedLaunchRealizable_of_related
#print axioms ExactMixedLaunchRootRelated.originalReachable
#print axioms ExactMixedLaunchRootRelated.candidateProofOpen

end StageA.Relational.InterpreterMixedRuntimeFoundation
