import StageA.RelationalOriginalTargetPreservation

namespace StageA.Relational.OriginalTargetControlPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel

/-!
# Generic control-side target preservation

This module turns one exact `CheckedOriginalTargetEffect` into the control
portion of a target-preservation case.  Lean performs the semantic split
between an ordinary outcome and an x87 fault.  A generated adapter supplies
only routed static evidence for the concrete decoded outcome under the complete
pre-invariant.

The routed evidence names an exact non-blocked successor and constructs the
reachability and call-frame postconditions together.  The constructors below
cover normal execution, nested callbacks, external suspension, return,
termination, and faults.  There is deliberately no authority path for
`callUnmappedReturn`; indirect control requires the existing canonical target
resolution witness, and external control requires an exact import-site and
machine-contract lookup.
-/

/-- Exact finite membership for one statically named target. -/
structure CheckedOriginalStaticTargetEvidence
    (targetIds : List Nat) (targetId : Nat) : Prop where
  reachable : targetId ∈ targetIds

/-- Both destinations of a conditional branch belong to the exact reachable
inventory. -/
structure CheckedOriginalBranchTargetEvidence
    (targetIds : List Nat) (taken fallthrough : Nat) : Prop where
  takenReachable : taken ∈ targetIds
  fallthroughReachable : fallthrough ∈ targetIds

/-- A direct internal call has both a checked callee and a checked concrete
continuation. -/
structure CheckedOriginalDirectCallEvidence
    (targetIds : List Nat) (target continuation : Nat) : Prop where
  targetReachable : target ∈ targetIds
  continuationReachable : continuation ∈ targetIds

/-- Exact static resolution of one imported call boundary.  The two lookup
equalities rule out missing sites, missing contracts, and a contract selected
from a different site. -/
structure CheckedOriginalImportEvidence
    (program : DecodedWorldProgram) (sourceTargetId continuation : Nat)
    (imported : ExternalTarget) where
  siteId : Nat
  siteResolved :
    resolveExternalCallSite program.context program.externalCallSites
      sourceTargetId continuation imported = some siteId
  contract : MachineImportCallContract
  contractResolved :
    resolvedExternalCallContract? program.context program.externalCallSites
      siteId = some contract

/-- Exact return routing.  Top-level returns, callback returns, and internal
returns are distinct because they have different world successors. -/
inductive CheckedOriginalReturnEvidence
    (program : DecodedWorldProgram) (state : MachineState)
    (calls : List Nat) (callbacks : List WorldExternalCallbackRuntime)
    (target : Word) : Prop where
  | top
      (callsExact : calls = [])
      (callbacksExact : callbacks = []) :
      CheckedOriginalReturnEvidence program state calls callbacks target
  | callback
      (callback : WorldExternalCallbackRuntime)
      (outerCallbacks : List WorldExternalCallbackRuntime)
      (callsExact : calls = [])
      (callbacksExact : callbacks = callback :: outerCallbacks)
      (targetExact : target = callback.entry.returnAddress) :
      CheckedOriginalReturnEvidence program state calls callbacks target
  | internal
      (continuation : Nat) (tail : List Nat)
      (callsExact : calls = continuation :: tail)
      (resolvedExact :
        resolveMappedCodeTarget program.candidate
          (if program.candidate then program.context.candidatePe.imageBase
           else program.context.originalPe.imageBase)
          program.context.codeMap.entries.toList target = some continuation) :
      CheckedOriginalReturnEvidence program state calls callbacks target

/-- Reachability and call-frame postconditions for one exact normalized
successor.  These are kept together so no control route can close only one of
the two whole-program families. -/
structure CheckedOriginalControlPost
    (context : StaticProofContext) (targetIds : List Nat)
    (successor : OriginalNormalizedSuccessor) : Prop where
  reachability : OriginalReachabilityPostEvidence targetIds successor
  callFrames : OriginalCallFramePostEvidence context successor

def CheckedOriginalControlPost.running
    (context : StaticProofContext) (targetIds : List Nat)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (targetReachable : targetId ∈ targetIds)
    (callsReachable : forall continuation,
      continuation ∈ calls -> continuation ∈ targetIds)
    (frames : List DormantOriginalCallFrame)
    (framesHold : OriginalCallFramesHold context world state frames calls) :
    CheckedOriginalControlPost context targetIds
      (.running targetId state calls eventIndex world) := {
  reachability := .running targetId state calls eventIndex world
    targetReachable callsReachable
  callFrames := .running targetId state calls eventIndex world frames framesHold
}

def CheckedOriginalControlPost.callbackRunning
    (context : StaticProofContext) (targetIds : List Nat)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (targetReachable : targetId ∈ targetIds)
    (callsReachable : forall continuation,
      continuation ∈ calls -> continuation ∈ targetIds)
    (callbacksReachable : originalCallbackTargetsReachable targetIds callbacks)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (framesHold : OriginalCallFramesHold context world state frames calls)
    (suspendedHold :
      SuspendedOriginalCallFramesHold context callbacks suspended) :
    CheckedOriginalControlPost context targetIds
      (.callbackRunning targetId state calls eventIndex world callbacks) := {
  reachability := .callbackRunning targetId state calls eventIndex world
    callbacks targetReachable callsReachable callbacksReachable
  callFrames := .callbackRunning targetId state calls eventIndex world callbacks
    frames suspended framesHold suspendedHold
}

def CheckedOriginalControlPost.awaitingExternal
    (context : StaticProofContext) (targetIds : List Nat)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (sourceReachable : suspension.sourceTargetId ∈ targetIds)
    (continuationReachable : suspension.continuationTargetId ∈ targetIds)
    (callsReachable : forall continuation,
      continuation ∈ suspension.calls -> continuation ∈ targetIds)
    (callbacksReachable : originalCallbackTargetsReachable targetIds callbacks)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (framesHold : OriginalCallFramesHold context suspension.world
      suspension.state frames suspension.calls)
    (suspendedHold :
      SuspendedOriginalCallFramesHold context callbacks suspended) :
    CheckedOriginalControlPost context targetIds
      (.awaitingExternal suspension callbacks) := {
  reachability := .awaitingExternal suspension callbacks sourceReachable
    continuationReachable callsReachable callbacksReachable
  callFrames := .awaitingExternal suspension callbacks frames suspended
    framesHold suspendedHold
}

def CheckedOriginalControlPost.returned
    (context : StaticProofContext) (targetIds : List Nat)
    (state : MachineState) (world : RelationalWorld) :
    CheckedOriginalControlPost context targetIds (.returned state world) := {
  reachability := .returned state world
  callFrames := .returned state world
}

def CheckedOriginalControlPost.terminated
    (context : StaticProofContext) (targetIds : List Nat)
    (world : RelationalWorld) :
    CheckedOriginalControlPost context targetIds (.terminated world) := {
  reachability := .terminated world
  callFrames := .terminated world
}

def CheckedOriginalControlPost.fault
    (context : StaticProofContext) (targetIds : List Nat)
    (cause : ModeledFault) :
    CheckedOriginalControlPost context targetIds (.fault cause) := {
  reachability := .fault cause
  callFrames := .fault cause
}

/-- Normalized counterpart of the authoritative callback-sensitive resume
helper. -/
def originalNormalizedResume
    (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld) :
    OriginalNormalizedSuccessor :=
  match callbacks with
  | [] => .running targetId state calls eventIndex world
  | _ => .callbackRunning targetId state calls eventIndex world callbacks

@[simp]
theorem originalNormalizedResume_execution
    (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld) :
    (originalNormalizedResume callbacks targetId state calls eventIndex world).execution =
      resumeWorldExecution callbacks targetId state calls eventIndex world := by
  cases callbacks <;> rfl

def CheckedOriginalControlPost.resumed
    (context : StaticProofContext) (targetIds : List Nat)
    (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (targetReachable : targetId ∈ targetIds)
    (callsReachable : forall continuation,
      continuation ∈ calls -> continuation ∈ targetIds)
    (callbacksReachable : originalCallbackTargetsReachable targetIds callbacks)
    (frames : List DormantOriginalCallFrame)
    (suspended : List (List DormantOriginalCallFrame))
    (framesHold : OriginalCallFramesHold context world state frames calls)
    (suspendedHold :
      SuspendedOriginalCallFramesHold context callbacks suspended) :
    CheckedOriginalControlPost context targetIds
      (originalNormalizedResume callbacks targetId state calls eventIndex
        world) := by
  cases callbacks with
  | nil =>
      exact .running context targetIds targetId state calls eventIndex world
        targetReachable callsReachable frames framesHold
  | cons callback callbacks =>
      exact .callbackRunning context targetIds targetId state calls eventIndex
        world (callback :: callbacks) targetReachable callsReachable
        callbacksReachable frames suspended framesHold suspendedHold

/-- Preserve an unchanged concrete call stack across a local control step.
The complete pre-invariant supplies target/call reachability and the exact
active/suspended frame inventory.  The only additional premise is the genuine
per-frame state/world preservation fact required after memory mutation. -/
theorem controlPostOfPreservedFrames
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {sourceTargetId : Nat}
    (invocation : OriginalTargetInvocation sourceTargetId)
    (holds : inventory.Holds invocation.execution)
    (nextTargetId : Nat) (afterState : MachineState)
    (afterEventIndex : Nat) (afterWorld : RelationalWorld)
    (nextTargetReachable :
      nextTargetId ∈ inventory.reachableTargets.targetIds)
    (framesPreserved : forall frame : DormantOriginalCallFrame,
      frame.Holds program.context invocation.world invocation.state ->
        frame.Holds program.context afterWorld afterState) :
    CheckedOriginalControlPost program.context
      inventory.reachableTargets.targetIds
      (originalNormalizedResume invocation.routingCallbacks nextTargetId
        afterState invocation.calls afterEventIndex afterWorld) := by
  have reachable := inventory.reachable holds
  have callFrames := inventory.callFramesHold holds
  rcases callFrames with ⟨frameInventory, frameInventoryHolds⟩
  cases callbackCase : invocation.callbacks with
  | none =>
      have sourceReachability :
          sourceTargetId ∈ inventory.reachableTargets.targetIds /\
            (forall continuation, continuation ∈ invocation.calls ->
              continuation ∈ inventory.reachableTargets.targetIds) := by
        simpa [OriginalTargetInvocation.execution, callbackCase] using reachable
      have sourceFrames :
          frameInventory.suspended = [] /\
            OriginalCallFramesHold program.context invocation.world
              invocation.state frameInventory.active invocation.calls := by
        simpa [OriginalTargetInvocation.execution, callbackCase] using
          frameInventoryHolds
      have afterFrames := sourceFrames.2.after program.context invocation.world
        afterWorld invocation.state afterState frameInventory.active
        invocation.calls framesPreserved
      simpa [OriginalTargetInvocation.routingCallbacks, callbackCase] using
        (CheckedOriginalControlPost.resumed program.context
          inventory.reachableTargets.targetIds [] nextTargetId afterState
          invocation.calls afterEventIndex afterWorld nextTargetReachable
          sourceReachability.2 trivial frameInventory.active [] afterFrames
          trivial)
  | some callbacks =>
      have sourceReachability :
          sourceTargetId ∈ inventory.reachableTargets.targetIds /\
            (forall continuation, continuation ∈ invocation.calls ->
              continuation ∈ inventory.reachableTargets.targetIds) /\
            originalCallbackTargetsReachable
              inventory.reachableTargets.targetIds callbacks := by
        simpa [OriginalTargetInvocation.execution, callbackCase] using reachable
      have sourceFrames :
          OriginalCallFramesHold program.context invocation.world
              invocation.state frameInventory.active invocation.calls /\
            SuspendedOriginalCallFramesHold program.context callbacks
              frameInventory.suspended := by
        simpa [OriginalTargetInvocation.execution, callbackCase] using
          frameInventoryHolds
      have afterFrames := sourceFrames.1.after program.context invocation.world
        afterWorld invocation.state afterState frameInventory.active
        invocation.calls framesPreserved
      simpa [OriginalTargetInvocation.routingCallbacks, callbackCase] using
        (CheckedOriginalControlPost.resumed program.context
          inventory.reachableTargets.targetIds callbacks nextTargetId afterState
          invocation.calls afterEventIndex afterWorld nextTargetReachable
          sourceReachability.2.1 sourceReachability.2.2 frameInventory.active
          frameInventory.suspended afterFrames sourceFrames.2)

/-- One statically classified decoded outcome, its exact world routing, and
both control-side postcondition families. -/
structure CheckedOriginalRoutedOutcome
    {program : Program} {targetId : Nat}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (invocation : OriginalTargetInvocation targetId)
    (afterState : MachineState) (outcome : PureOutcome) where
  control : CheckedOriginalOutcomeEvidence originalContext
    inventory.reachableTargets.targetIds targetId afterState outcome
  successor : OriginalNormalizedSuccessor
  successorExact :
    (transitionFromWorldOutcome program.worldProgram targetId afterState
      invocation.calls invocation.eventIndex invocation.world
      invocation.routingCallbacks outcome).next = successor.execution
  post : CheckedOriginalControlPost program.worldProgram.context
    inventory.reachableTargets.targetIds successor

/-- The control-only result assembled for one target invocation.  Memory,
value-flow, and indirect-storage postconditions remain separate layers. -/
structure CheckedOriginalTargetControlPreservationCase
    {program : Program} {targetId : Nat}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (checked : CheckedOriginalTargetEffect program targetId)
    (invocation : OriginalTargetInvocation targetId) where
  transition : CheckedOriginalTargetTransition checked originalContext
    inventory.reachableTargets.targetIds invocation
  reachability : OriginalReachabilityPostEvidence
    inventory.reachableTargets.targetIds transition.successor
  callFrames : OriginalCallFramePostEvidence program.worldProgram.context
    transition.successor

/-- Universal static/routing provider for one checked target.  It receives the
complete pre-invariant, so target resolution and frame restoration may consume
any already checked family without introducing a second state relation. -/
structure CheckedOriginalTargetControlEvidence
    {program : Program} {targetId : Nat}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (checked : CheckedOriginalTargetEffect program targetId) where
  outcome : forall (invocation : OriginalTargetInvocation targetId),
    inventory.Holds invocation.execution ->
      let behavior := checked.components.decodedBehavior invocation.state
        invocation.calls
      behavior.x87Fault = none ->
        CheckedOriginalRoutedOutcome originalContext inventory invocation
          (behavior.nextMachineState invocation.state) behavior.outcome

/-- Lean, rather than generated analysis, performs the exact semantic split.
The x87-fault branch is closed generically; the outcome branch consumes the
checked routed evidence for the actual decoded behavior. -/
def CheckedOriginalTargetControlEvidence.toPreservationCase
    {program : Program} {targetId : Nat}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {checked : CheckedOriginalTargetEffect program targetId}
    (evidence : CheckedOriginalTargetControlEvidence originalContext inventory
      checked)
    (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    CheckedOriginalTargetControlPreservationCase originalContext inventory
      checked invocation := by
  let behavior := checked.components.decodedBehavior invocation.state
    invocation.calls
  cases faultExact : behavior.x87Fault with
  | none =>
      let routed := evidence.outcome invocation holds faultExact
      have effectExact :
          (checked.components.sourceStep invocation.state
            invocation.calls).effect =
            EvaluatedEffect.outcome
              (behavior.nextMachineState invocation.state) behavior.outcome := by
        rw [checked.components.effectsExact]
        simp [evaluatedEffectOfBehavior, behavior, faultExact]
      let effectCase : CheckedOriginalTargetEffectCase checked originalContext
          inventory.reachableTargets.targetIds invocation :=
        .outcome (behavior.nextMachineState invocation.state) behavior.outcome
          effectExact faultExact rfl routed.control
      let transition : CheckedOriginalTargetTransition checked originalContext
          inventory.reachableTargets.targetIds invocation := {
        effect := effectCase
        successor := routed.successor
        successorExact := by
          rw [effectExact]
          exact routed.successorExact
      }
      exact {
        transition
        reachability := routed.post.reachability
        callFrames := routed.post.callFrames
      }
  | some fault =>
      cases fault
      have effectExact :
          (checked.components.sourceStep invocation.state
            invocation.calls).effect =
            EvaluatedEffect.fault .x87FloatingPoint := by
        rw [checked.components.effectsExact]
        simp [evaluatedEffectOfBehavior, behavior, faultExact]
      let effectCase : CheckedOriginalTargetEffectCase checked originalContext
          inventory.reachableTargets.targetIds invocation :=
        .fault .x87FloatingPoint effectExact
      let transition : CheckedOriginalTargetTransition checked originalContext
          inventory.reachableTargets.targetIds invocation := {
        effect := effectCase
        successor := .fault .x87FloatingPoint
        successorExact := by
          simp [effectExact, transitionFromEvaluatedEffect,
            OriginalNormalizedSuccessor.execution]
      }
      exact {
        transition
        reachability := .fault .x87FloatingPoint
        callFrames := .fault .x87FloatingPoint
      }

def CheckedOriginalStaticTargetEvidence.jumpControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId : Nat} {state : MachineState} {target : Nat}
    (evidence : CheckedOriginalStaticTargetEvidence targetIds target) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.jump target) :=
  .jump target evidence.reachable

def CheckedOriginalBranchTargetEvidence.branchControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId : Nat} {state : MachineState} {condition : Bool}
    {taken fallthrough : Nat}
    (evidence : CheckedOriginalBranchTargetEvidence targetIds taken fallthrough) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.branch condition taken fallthrough) :=
  .branch condition taken fallthrough evidence.takenReachable
    evidence.fallthroughReachable

def CheckedOriginalDirectCallEvidence.callControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId : Nat} {state : MachineState} {target continuation : Nat}
    (evidence : CheckedOriginalDirectCallEvidence targetIds target continuation) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.call target continuation) :=
  .call target continuation evidence.targetReachable
    evidence.continuationReachable

def CheckedOriginalReturnEvidence.returnedControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {program : DecodedWorldProgram} {sourceTargetId : Nat}
    {state : MachineState} {calls : List Nat}
    {callbacks : List WorldExternalCallbackRuntime} {target : Word}
    (evidence : CheckedOriginalReturnEvidence program state calls callbacks
      target) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.returned target) := by
  cases evidence <;> exact .returned target

def CheckedOriginalImportEvidence.externalCallControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {program : DecodedWorldProgram} {sourceTargetId continuation : Nat}
    {state : MachineState} {imported : ExternalTarget}
    (evidence : CheckedOriginalImportEvidence program sourceTargetId
      continuation imported)
    (arguments : List Word) (continuationReachable : continuation ∈ targetIds) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.externalCall imported arguments continuation) := by
  cases evidence
  exact .externalCall imported arguments continuation continuationReachable

def CheckedOriginalImportEvidence.externalJumpControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {program : DecodedWorldProgram} {sourceTargetId continuation : Nat}
    {state : MachineState} {imported : ExternalTarget}
    (evidence : CheckedOriginalImportEvidence program sourceTargetId
      continuation imported)
    (arguments : List Word) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.externalJump imported arguments) := by
  cases evidence
  exact .externalJump imported arguments

def CheckedOriginalStaticTargetEvidence.bulkCopyControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId continuation : Nat} {state : MachineState}
    (evidence : CheckedOriginalStaticTargetEvidence targetIds continuation)
    (destination source count : Word) (direction : Bool) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.bulkCopy destination source count direction continuation) :=
  .bulkCopy destination source count direction continuation evidence.reachable

def CheckedOriginalStaticTargetEvidence.bulkFillControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId continuation : Nat} {state : MachineState}
    (evidence : CheckedOriginalStaticTargetEvidence targetIds continuation)
    (destination value count : Word) (direction : Bool) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.bulkFill destination value count direction continuation) :=
  .bulkFill destination value count direction continuation evidence.reachable

def CheckedOriginalStaticTargetEvidence.checkedContinueControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId continuation : Nat} {state : MachineState}
    (evidence : CheckedOriginalStaticTargetEvidence targetIds continuation)
    (valid : Bool) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.checkedContinue valid continuation) :=
  .checkedContinue valid continuation evidence.reachable

def CheckedOriginalStaticTargetEvidence.atomicCompareExchangeControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId continuation : Nat} {state : MachineState}
    (evidence : CheckedOriginalStaticTargetEvidence targetIds continuation)
    (address expected replacement : Word) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.atomicCompareExchange address expected replacement continuation) :=
  .atomicCompareExchange address expected replacement continuation
    evidence.reachable

/-- Existing canonical indirect resolution is the sole internal-indirect
authority accepted by the control layer. -/
def CheckedOriginalIndirectTargetResolution.indirectCallControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId : Nat} {state : MachineState} {target : Word}
    (resolution : CheckedOriginalIndirectTargetResolution context targetIds
      sourceTargetId state target)
    (continuation : Nat) (continuationReachable : continuation ∈ targetIds) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.indirectCall target continuation) :=
  .indirectCall target continuation resolution continuationReachable

def CheckedOriginalIndirectTargetResolution.indirectJumpControl
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId : Nat} {state : MachineState} {target : Word}
    (resolution : CheckedOriginalIndirectTargetResolution context targetIds
      sourceTargetId state target) :
    CheckedOriginalOutcomeEvidence context targetIds sourceTargetId state
      (.indirectJump target) :=
  .indirectJump target resolution

/-- `callUnmappedReturn` always routes to a blocked execution and has no
constructor in the checked control language. -/
theorem callUnmappedReturn_not_classified
    {context : OriginalDecodedStaticContext} {targetIds : List Nat}
    {sourceTargetId target : Nat} {state : MachineState}
    (evidence : CheckedOriginalOutcomeEvidence context targetIds sourceTargetId
      state (.callUnmappedReturn target)) : False := by
  cases evidence

#print axioms CheckedOriginalTargetControlEvidence.toPreservationCase
#print axioms CheckedOriginalControlPost.running
#print axioms CheckedOriginalControlPost.callbackRunning
#print axioms CheckedOriginalControlPost.awaitingExternal
#print axioms CheckedOriginalControlPost.returned
#print axioms CheckedOriginalControlPost.terminated
#print axioms CheckedOriginalControlPost.fault
#print axioms CheckedOriginalControlPost.resumed
#print axioms originalNormalizedResume_execution
#print axioms controlPostOfPreservedFrames
#print axioms callUnmappedReturn_not_classified

end StageA.Relational.OriginalTargetControlPreservation
