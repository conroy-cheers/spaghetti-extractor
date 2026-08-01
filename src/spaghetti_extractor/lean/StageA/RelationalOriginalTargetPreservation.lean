import StageA.RelationalOriginalCombinedTargetStepIndex
import StageA.RelationalSourceOrdinaryTargetRouting
import StageA.RelationalSourceX87TargetRouting

namespace StageA.Relational.OriginalTargetPreservation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.OrdinaryTargetRouting
open StageA.Relational.SourceWorld.ProgramCertificate
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

/-!
# One-sided original target preservation

This is the non-erasing bridge between checked ordinary/x87 target semantics
and the seven-family original execution invariant.  A generated target shard
must retain its successful evaluator, classify its exact effect, name the
non-blocked successor, and provide finite evidence for every protected word,
value-flow fact, and indirect-control requirement.

The kernel deliberately has no constructor for a failed evaluator, a blocked
successor, or `callUnmappedReturn`.  Indirect control requires a concrete
`OriginalResolvedCodeTarget`; protected memory updates require a per-word
frame or an explicit checked replacement.
-/

/-- Whether an active target is running normally or inside a nested callback.
Using an option keeps the machine inputs shared while preserving the semantic
difference between `running` and `callbackRunning`, including the latter with
an empty callback list. -/
structure OriginalTargetInvocation (targetId : Nat) where
  state : MachineState
  calls : List Nat
  eventIndex : Nat
  world : RelationalWorld
  callbacks : Option (List WorldExternalCallbackRuntime)

def OriginalTargetInvocation.execution
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId) :
    WorldExecution :=
  match invocation.callbacks with
  | none => .running targetId invocation.state invocation.calls
      invocation.eventIndex invocation.world
  | some callbacks => .callbackRunning targetId invocation.state
      invocation.calls invocation.eventIndex invocation.world callbacks

def OriginalTargetInvocation.routingCallbacks
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId) :
    List WorldExternalCallbackRuntime :=
  invocation.callbacks.getD []

/-- The two accepted sources of pre-erasure target semantics.  The ordinary
case retains the checked evaluator/effect object.  The x87 case retains the
exact singleton schedule facts and separately requires successful components
bound to the same operational target. -/
inductive CheckedOriginalTargetSemanticSource
    (program : Program) (targetId : Nat) : Prop where
  | ordinary
      {pe : PE32} {sourceRva : Nat} {record : ProgramRecord}
      {path : InterpreterNormalization.ExactNormalizedTransferPath}
      {transfer : SemanticTransfer}
      {region : RegionRelation}
      {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva
        record path transfer region}
      {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
      (checked : CheckedOrdinaryTargetEffect binding decoded) :
      CheckedOriginalTargetSemanticSource program targetId
  | x87
      {pe : PE32} {witness : ExactInterpreterX87ScheduleWitness pe}
      {schedule : ExactX87SingletonScheduleFacts pe witness}
      (facts : ExactX87SingletonTargetFacts pe program targetId witness
        schedule) : CheckedOriginalTargetSemanticSource program targetId

/-- Successful target-local semantics.  `SuccessfulTargetEffectComponents`
rules out both source and decoded `none` results.  Exact PE adequacy connects
the decoded evaluator back to instruction fetch from the authoritative image. -/
structure CheckedOriginalTargetEffect
    (program : Program) (targetId : Nat) where
  source : CheckedOriginalTargetSemanticSource program targetId
  components : SuccessfulTargetEffectComponents program targetId
  peAdequate : program.worldProgram.InstructionSemanticsAdequate

def CheckedOriginalTargetEffect.ofOrdinary
    {program : Program} {targetId : Nat}
    {pe : PE32} {sourceRva : Nat} {record : ProgramRecord}
    {path : InterpreterNormalization.ExactNormalizedTransferPath}
    {transfer : SemanticTransfer}
    {region : RegionRelation}
    {binding : ExactOrdinaryTargetBinding pe program targetId sourceRva record
      path transfer region}
    {decoded : ExactDecodedOrdinaryTargetEvaluator binding}
    (checked : CheckedOrdinaryTargetEffect binding decoded)
    (adequate : program.worldProgram.InstructionSemanticsAdequate) :
    CheckedOriginalTargetEffect program targetId where
  source := .ordinary checked
  components := checked.toSuccessfulTargetEffectComponents
  peAdequate := adequate

def CheckedOriginalTargetEffect.ofX87
    {program : Program} {targetId : Nat}
    {pe : PE32} {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule)
    (components : SuccessfulTargetEffectComponents program targetId)
    (adequate : program.worldProgram.InstructionSemanticsAdequate) :
    CheckedOriginalTargetEffect program targetId where
  source := .x87 facts
  components := components
  peAdequate := adequate

/-- Exact PE execution at an admitted target is the canonical world routing of
the retained pre-erasure effect.  No later proof re-runs decoding or symbolic
execution. -/
theorem CheckedOriginalTargetEffect.peStep_eq_effect
    {program : Program} {targetId : Nat}
    (checked : CheckedOriginalTargetEffect program targetId)
    (invocation : OriginalTargetInvocation targetId) :
    program.worldProgram.pe32TransitionSystem.step invocation.execution =
      transitionFromEvaluatedEffect program targetId invocation.calls
        invocation.eventIndex invocation.world invocation.routingCallbacks
        (checked.components.sourceStep invocation.state invocation.calls).effect := by
  rw [program.worldProgram.pe32TransitionSystem_eq_transitionSystem
    checked.peAdequate]
  cases callbackCase : invocation.callbacks with
  | none =>
      simp [DecodedWorldProgram.transitionSystem, stepWorldExecution,
        OriginalTargetInvocation.execution, OriginalTargetInvocation.routingCallbacks,
        callbackCase, checked.components.decodedBehaviorExact]
      rw [<- transitionFromEvaluatedEffect_of_behavior]
      rw [checked.components.effectsExact]
  | some callbacks =>
      simp [DecodedWorldProgram.transitionSystem, stepWorldExecution,
        OriginalTargetInvocation.execution, OriginalTargetInvocation.routingCallbacks,
        callbackCase, checked.components.decodedBehaviorExact]
      rw [<- transitionFromEvaluatedEffect_of_behavior]
      rw [checked.components.effectsExact]

/-- A normalized successor excludes `blocked` by construction. -/
inductive OriginalNormalizedSuccessor where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
  | returned (state : MachineState) (world : RelationalWorld)
  | terminated (world : RelationalWorld)
  | fault (cause : ModeledFault)

def OriginalNormalizedSuccessor.execution :
    OriginalNormalizedSuccessor -> WorldExecution
  | .running targetId state calls eventIndex world =>
      .running targetId state calls eventIndex world
  | .callbackRunning targetId state calls eventIndex world callbacks =>
      .callbackRunning targetId state calls eventIndex world callbacks
  | .awaitingExternal suspension callbacks =>
      .awaitingExternal suspension callbacks
  | .returned state world => .returned state world
  | .terminated world => .terminated world
  | .fault cause => .fault cause

theorem OriginalNormalizedSuccessor.notBlocked
    (successor : OriginalNormalizedSuccessor) (reason : ExecutionBlock) :
    successor.execution ≠ .blocked reason := by
  cases successor <;> simp [OriginalNormalizedSuccessor.execution]

/-- Explicit checked resolution for an indirect outcome.  The evaluated word
must be the site's target expression, resolve to a canonical code-map entry,
and remain inside the exact reachable target inventory. -/
structure CheckedOriginalIndirectTargetResolution
    (context : OriginalDecodedStaticContext)
    (reachableTargetIds : List Nat) (sourceTargetId : Nat)
    (state : MachineState) (targetWord : Word) where
  site : OriginalIndirectControlSite
  sourceExact : site.sourceTargetId = sourceTargetId
  targetWordExact : site.target.expression.eval state = targetWord
  resolved : OriginalResolvedCodeTarget context site state
  resolvedReachable : resolved.targetId ∈ reachableTargetIds

/-- Outcome classification retains the control operation that produced the
successor.  There is intentionally no `callUnmappedReturn` constructor.
Indirect outcomes additionally require finite checked resolution. -/
inductive CheckedOriginalOutcomeEvidence
    (context : OriginalDecodedStaticContext) (reachableTargetIds : List Nat)
    (sourceTargetId : Nat) (state : MachineState) : PureOutcome -> Prop where
  | returned (target : Word) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.returned target)
  | jump (target : Nat) (reachable : target ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.jump target)
  | branch (condition : Bool) (taken fallthrough : Nat)
      (takenReachable : taken ∈ reachableTargetIds)
      (fallthroughReachable : fallthrough ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.branch condition taken fallthrough)
  | call (target continuation : Nat)
      (targetReachable : target ∈ reachableTargetIds)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.call target continuation)
  | externalCall (imported : ExternalTarget) (arguments : List Word)
      (continuation : Nat)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.externalCall imported arguments continuation)
  | externalJump (imported : ExternalTarget) (arguments : List Word) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.externalJump imported arguments)
  | bulkCopy (destination source count : Word) (direction : Bool)
      (continuation : Nat)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.bulkCopy destination source count direction continuation)
  | bulkFill (destination value count : Word) (direction : Bool)
      (continuation : Nat)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.bulkFill destination value count direction continuation)
  | indirectCall (target : Word) (continuation : Nat)
      (resolved : CheckedOriginalIndirectTargetResolution context
        reachableTargetIds sourceTargetId state target)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.indirectCall target continuation)
  | indirectJump (target : Word)
      (resolved : CheckedOriginalIndirectTargetResolution context
        reachableTargetIds sourceTargetId state target) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.indirectJump target)
  | checkedContinue (valid : Bool) (continuation : Nat)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.checkedContinue valid continuation)
  | atomicCompareExchange (address expected replacement : Word)
      (continuation : Nat)
      (continuationReachable : continuation ∈ reachableTargetIds) :
      CheckedOriginalOutcomeEvidence context reachableTargetIds sourceTargetId
        state (.atomicCompareExchange address expected replacement continuation)

/-- Retained result of the successful local evaluator.  For ordinary and x87
outcomes the concrete decoded writes and exact resulting machine state remain
available to protected-memory and value-flow checkers. -/
inductive CheckedOriginalTargetEffectCase
    {program : Program} {targetId : Nat}
    (checked : CheckedOriginalTargetEffect program targetId)
    (originalContext : OriginalDecodedStaticContext)
    (reachableTargetIds : List Nat)
    (invocation : OriginalTargetInvocation targetId) : Prop where
  | outcome (afterState : MachineState) (outcome : PureOutcome)
      (effectExact :
        (checked.components.sourceStep invocation.state invocation.calls).effect =
          EvaluatedEffect.outcome afterState outcome)
      (decodedFaultFree :
        (checked.components.decodedBehavior invocation.state invocation.calls).x87Fault =
          none)
      (afterStateExact : afterState =
        (checked.components.decodedBehavior invocation.state
          invocation.calls).nextMachineState invocation.state)
      (control : CheckedOriginalOutcomeEvidence originalContext
        reachableTargetIds targetId afterState outcome) :
      CheckedOriginalTargetEffectCase checked originalContext
        reachableTargetIds invocation
  | fault (cause : ModeledFault)
      (effectExact :
        (checked.components.sourceStep invocation.state invocation.calls).effect =
          EvaluatedEffect.fault cause) :
      CheckedOriginalTargetEffectCase checked originalContext
        reachableTargetIds invocation

/-- Exact non-blocked routing of one retained effect.  The successor equality
is an operational equality, not a submitted invariant postcondition. -/
structure CheckedOriginalTargetTransition
    {program : Program} {targetId : Nat}
    (checked : CheckedOriginalTargetEffect program targetId)
    (originalContext : OriginalDecodedStaticContext)
    (reachableTargetIds : List Nat)
    (invocation : OriginalTargetInvocation targetId) where
  effect : CheckedOriginalTargetEffectCase checked originalContext
    reachableTargetIds invocation
  successor : OriginalNormalizedSuccessor
  successorExact :
    (transitionFromEvaluatedEffect program targetId invocation.calls
      invocation.eventIndex invocation.world invocation.routingCallbacks
      (checked.components.sourceStep invocation.state invocation.calls).effect).next =
        successor.execution

theorem CheckedOriginalTargetTransition.peSuccessorExact
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {reachableTargetIds : List Nat}
    {invocation : OriginalTargetInvocation targetId}
    (transition : CheckedOriginalTargetTransition checked originalContext
      reachableTargetIds invocation) :
    (program.worldProgram.pe32TransitionSystem.step invocation.execution).next =
      transition.successor.execution := by
  rw [checked.peStep_eq_effect invocation]
  exact transition.successorExact

/-! ## Finite family evidence -/

inductive OriginalReachabilityPostEvidence (targetIds : List Nat) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (targetReachable : targetId ∈ targetIds)
      (callsReachable : forall continuation,
        continuation ∈ calls -> continuation ∈ targetIds) :
      OriginalReachabilityPostEvidence targetIds
        (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (targetReachable : targetId ∈ targetIds)
      (callsReachable : forall continuation,
        continuation ∈ calls -> continuation ∈ targetIds)
      (callbacksReachable : originalCallbackTargetsReachable targetIds callbacks) :
      OriginalReachabilityPostEvidence targetIds
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (sourceReachable : suspension.sourceTargetId ∈ targetIds)
      (continuationReachable : suspension.continuationTargetId ∈ targetIds)
      (callsReachable : forall continuation,
        continuation ∈ suspension.calls -> continuation ∈ targetIds)
      (callbacksReachable : originalCallbackTargetsReachable targetIds callbacks) :
      OriginalReachabilityPostEvidence targetIds
        (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld) :
      OriginalReachabilityPostEvidence targetIds (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalReachabilityPostEvidence targetIds (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalReachabilityPostEvidence targetIds (.fault cause)

theorem OriginalReachabilityPostEvidence.holds
    {targetIds : List Nat} {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalReachabilityPostEvidence targetIds successor) :
    OriginalExecutionReachable targetIds successor.execution := by
  cases evidence <;> simp_all [OriginalNormalizedSuccessor.execution,
    OriginalExecutionReachable]

/-- One protected word is either outside a checked concrete write set, has an
exact unchanged read under a more general effect such as x87 memory, or is
replaced with a fully checked related value. -/
inductive OriginalProtectedWordUpdate
    (context : StaticProofContext) (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement) : Prop where
  | concreteWrites (writes : List (Word × Word))
      (afterMemoryExact : afterMemory = applyConcreteWrites beforeMemory writes)
      (frame : OriginalStaticWordWriteFrame context beforeWorld afterWorld
        beforeMemory writes requirement) :
      OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
        afterMemory requirement
  | unchangedRead
      (readExact : Memory.read32 afterMemory requirement.slot.originalAddress =
        Memory.read32 beforeMemory requirement.slot.originalAddress)
      (originsPreserved : requirement.OriginsPreserved context beforeWorld
        afterWorld) :
      OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
        afterMemory requirement
  | relatedUpdate (afterHolds : requirement.Holds context afterWorld afterMemory) :
      OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
        afterMemory requirement

theorem OriginalProtectedWordUpdate.preserves
    {context : StaticProofContext} {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    {requirement : OriginalStaticWordRequirement}
    (update : OriginalProtectedWordUpdate context beforeWorld afterWorld
      beforeMemory afterMemory requirement)
    (before : requirement.Holds context beforeWorld beforeMemory) :
    requirement.Holds context afterWorld afterMemory := by
  cases update with
  | concreteWrites writes memoryExact frame =>
      subst afterMemory
      exact requirement.afterInternalWrites context beforeWorld afterWorld
        beforeMemory writes before frame
  | unchangedRead readExact originsPreserved =>
      exact requirement.afterReadExact context beforeWorld afterWorld
        beforeMemory afterMemory before readExact originsPreserved
  | relatedUpdate afterHolds => exact afterHolds

structure OriginalProtectedMemoryUpdate
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory) : Prop where
  words : forall requirement, requirement ∈ inventory.requirements ->
    OriginalProtectedWordUpdate context beforeWorld afterWorld beforeMemory
      afterMemory requirement

theorem OriginalProtectedMemoryUpdate.preserves
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld afterWorld : RelationalWorld}
    {beforeMemory afterMemory : Memory}
    (update : OriginalProtectedMemoryUpdate context inventory beforeWorld
      afterWorld beforeMemory afterMemory)
    (before : inventory.HoldsIn context beforeWorld beforeMemory) :
    inventory.HoldsIn context afterWorld afterMemory := by
  intro requirement member
  exact (update.words requirement member).preserves
    (before requirement member)

inductive OriginalStaticWordPostEvidence
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (beforeWorld : RelationalWorld) (beforeMemory : Memory) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (update : OriginalProtectedMemoryUpdate context inventory beforeWorld world
        beforeMemory state.memory) :
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (update : OriginalProtectedMemoryUpdate context inventory beforeWorld world
        beforeMemory state.memory)
      (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (update : OriginalProtectedMemoryUpdate context inventory beforeWorld
        suspension.world beforeMemory suspension.state.memory)
      (suspended : SuspendedOriginalStaticWordsHold context inventory callbacks) :
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld)
      (update : OriginalProtectedMemoryUpdate context inventory beforeWorld world
        beforeMemory state.memory) :
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalStaticWordPostEvidence context inventory beforeWorld beforeMemory
        (.fault cause)

theorem OriginalStaticWordPostEvidence.preserves
    {context : StaticProofContext} {inventory : OriginalStaticWordInventory}
    {beforeWorld : RelationalWorld} {beforeMemory : Memory}
    {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalStaticWordPostEvidence context inventory beforeWorld
      beforeMemory successor)
    (before : inventory.HoldsIn context beforeWorld beforeMemory) :
    inventory.Holds context successor.execution := by
  cases evidence with
  | running _ _ _ _ _ update =>
      exact update.preserves before
  | callbackRunning _ _ _ _ _ _ update suspended =>
      exact ⟨update.preserves before, suspended⟩
  | awaitingExternal _ _ update suspended =>
      exact ⟨update.preserves before, suspended⟩
  | returned _ _ update => exact update.preserves before
  | terminated _ => trivial
  | fault _ => trivial

/-- Call-frame post evidence names the exact active and suspended frame lists.
The low-level predicates check every return slot, continuation, callback, and
caller-value fact; no whole-family preservation proposition is accepted. -/
inductive OriginalCallFramePostEvidence (context : StaticProofContext) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (frames : List DormantOriginalCallFrame)
      (framesHold : OriginalCallFramesHold context world state frames calls) :
      OriginalCallFramePostEvidence context
        (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (frames : List DormantOriginalCallFrame)
      (suspended : List (List DormantOriginalCallFrame))
      (framesHold : OriginalCallFramesHold context world state frames calls)
      (suspendedHold : SuspendedOriginalCallFramesHold context callbacks suspended) :
      OriginalCallFramePostEvidence context
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (frames : List DormantOriginalCallFrame)
      (suspended : List (List DormantOriginalCallFrame))
      (framesHold : OriginalCallFramesHold context suspension.world
        suspension.state frames suspension.calls)
      (suspendedHold : SuspendedOriginalCallFramesHold context callbacks suspended) :
      OriginalCallFramePostEvidence context
        (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld) :
      OriginalCallFramePostEvidence context (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalCallFramePostEvidence context (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalCallFramePostEvidence context (.fault cause)

theorem OriginalCallFramePostEvidence.holds
    {context : StaticProofContext} {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalCallFramePostEvidence context successor) :
    OriginalCallFrameExecutionHolds context successor.execution := by
  cases evidence with
  | running _ _ _ _ _ frames framesHold =>
      exact ⟨{ active := frames, suspended := [] }, rfl, framesHold⟩
  | callbackRunning _ _ _ _ _ _ frames suspended framesHold suspendedHold =>
      exact ⟨{ active := frames, suspended := suspended }, framesHold,
        suspendedHold⟩
  | awaitingExternal _ _ frames suspended framesHold suspendedHold =>
      exact ⟨{ active := frames, suspended := suspended }, framesHold,
        suspendedHold⟩
  | returned _ _ => exact ⟨{}, rfl, rfl⟩
  | terminated _ => exact ⟨{}, rfl, rfl⟩
  | fault _ => exact ⟨{}, rfl, rfl⟩

/-- A concrete value-flow endpoint is established from a finite origin, an
unchanged-location world frame, or a checked decoded source-to-target transfer. -/
inductive OriginalValueFlowAtEvidence
    (program : DecodedWorldProgram)
    (fact : OriginalFiniteValueFlowFact program.context)
    (state : MachineState) (world : RelationalWorld) : Prop where
  | origin (selected : ValueOriginAtom)
      (member : selected ∈ fact.alternatives)
      (holds : OriginalValueOriginAtomHolds program.context world
        (originalLocationValue fact.location state) selected) :
      OriginalValueFlowAtEvidence program fact state world
  | afterFrame (beforeState : MachineState) (beforeWorld : RelationalWorld)
      (before : fact.HoldsAt beforeState beforeWorld)
      (valueExact : originalLocationValue fact.location state =
        originalLocationValue fact.location beforeState)
      (frame : OriginalValueFlowWorldFrame program.context beforeWorld world
        fact.alternatives) :
      OriginalValueFlowAtEvidence program fact state world
  | decodedTransfer (sourceLocation : ControlValueProvenance.Location)
      (beforeState : MachineState) (selected : ValueOriginAtom)
      (member : selected ∈ fact.alternatives)
      (source : OriginalValueOriginAtomHolds program.context world
        (originalLocationValue sourceLocation beforeState) selected)
      (transfer : CheckedOriginalDecodedLocationTransfer program sourceLocation
        fact.location)
      (stateExact : state =
        (transfer.behavior.eval beforeState).nextMachineState beforeState) :
      OriginalValueFlowAtEvidence program fact state world

theorem OriginalValueFlowAtEvidence.holdsAt
    {program : DecodedWorldProgram}
    {fact : OriginalFiniteValueFlowFact program.context}
    {state : MachineState} {world : RelationalWorld}
    (evidence : OriginalValueFlowAtEvidence program fact state world) :
    fact.HoldsAt state world := by
  cases evidence with
  | origin selected member holds => exact ⟨selected, member, holds⟩
  | afterFrame beforeState beforeWorld before valueExact frame =>
      exact fact.holdsAt_afterFrame beforeState state beforeWorld world before
        valueExact frame
  | decodedTransfer sourceLocation beforeState selected member source transfer
      stateExact =>
      subst state
      exact ⟨selected, member, transfer.preservesOrigin beforeState world
        selected source⟩

inductive OriginalValueFlowFactPostEvidence
    (program : DecodedWorldProgram)
    (fact : OriginalFiniteValueFlowFact program.context) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (endpoint : targetId ∈ fact.targetIds ->
        OriginalValueFlowAtEvidence program fact state world) :
      OriginalValueFlowFactPostEvidence program fact
        (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (endpoint : targetId ∈ fact.targetIds ->
        OriginalValueFlowAtEvidence program fact state world) :
      OriginalValueFlowFactPostEvidence program fact
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
      (endpoint : (suspension.sourceTargetId ∈ fact.targetIds \/
          suspension.continuationTargetId ∈ fact.targetIds) ->
        OriginalValueFlowAtEvidence program fact suspension.state
          suspension.world) :
      OriginalValueFlowFactPostEvidence program fact
        (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld) :
      OriginalValueFlowFactPostEvidence program fact (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalValueFlowFactPostEvidence program fact (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalValueFlowFactPostEvidence program fact (.fault cause)

theorem OriginalValueFlowFactPostEvidence.holds
    {program : DecodedWorldProgram}
    {fact : OriginalFiniteValueFlowFact program.context}
    {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalValueFlowFactPostEvidence program fact successor) :
    fact.Holds successor.execution := by
  cases evidence with
  | running _ _ _ _ _ endpoint =>
      exact fun member => (endpoint member).holdsAt
  | callbackRunning _ _ _ _ _ _ endpoint =>
      exact fun member => (endpoint member).holdsAt
  | awaitingExternal _ _ endpoint =>
      exact fun member => (endpoint member).holdsAt
  | returned _ _ => trivial
  | terminated _ => trivial
  | fault _ => trivial

structure OriginalValueFlowPostInventoryEvidence
    (program : DecodedWorldProgram)
    (inventory : OriginalValueFlowInventory program.context)
    (successor : OriginalNormalizedSuccessor) : Prop where
  facts : forall fact, fact ∈ inventory.facts ->
    OriginalValueFlowFactPostEvidence program fact successor

theorem OriginalValueFlowPostInventoryEvidence.holds
    {program : DecodedWorldProgram}
    {inventory : OriginalValueFlowInventory program.context}
    {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalValueFlowPostInventoryEvidence program inventory
      successor) : inventory.Holds successor.execution := by
  intro fact member
  exact (evidence.facts fact member).holds

inductive OriginalRegisterTargetPostEvidence
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalRegisterTargetRequirement context) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (member : targetId = requirement.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember context world
          (state.registers.get requirement.certificate.certificate.register)
          requirement.certificate.certificate.inventory) :
      OriginalRegisterTargetPostEvidence requirement
        (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (member : targetId = requirement.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember context world
          (state.registers.get requirement.certificate.certificate.register)
          requirement.certificate.certificate.inventory) :
      OriginalRegisterTargetPostEvidence requirement
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime) :
      OriginalRegisterTargetPostEvidence requirement
        (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld) :
      OriginalRegisterTargetPostEvidence requirement (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalRegisterTargetPostEvidence requirement (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalRegisterTargetPostEvidence requirement (.fault cause)

theorem OriginalRegisterTargetPostEvidence.holds
    {context : OriginalDecodedStaticContext}
    {requirement : OriginalRegisterTargetRequirement context}
    {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalRegisterTargetPostEvidence requirement successor) :
    requirement.Holds successor.execution := by
  cases evidence <;> simp_all [OriginalNormalizedSuccessor.execution,
    OriginalRegisterTargetRequirement.Holds]

inductive OriginalStackDynamicTargetPostEvidence
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalStackDynamicTargetRequirement context) :
    OriginalNormalizedSuccessor -> Prop where
  | running (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (source : targetId = requirement.site.sourceTargetId ->
        requirement.sourceFact world state) :
      OriginalStackDynamicTargetPostEvidence requirement
        (.running targetId state calls eventIndex world)
  | callbackRunning (targetId : Nat) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
      (source : targetId = requirement.site.sourceTargetId ->
        requirement.sourceFact world state) :
      OriginalStackDynamicTargetPostEvidence requirement
        (.callbackRunning targetId state calls eventIndex world callbacks)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime) :
      OriginalStackDynamicTargetPostEvidence requirement
        (.awaitingExternal suspension callbacks)
  | returned (state : MachineState) (world : RelationalWorld) :
      OriginalStackDynamicTargetPostEvidence requirement (.returned state world)
  | terminated (world : RelationalWorld) :
      OriginalStackDynamicTargetPostEvidence requirement (.terminated world)
  | fault (cause : ModeledFault) :
      OriginalStackDynamicTargetPostEvidence requirement (.fault cause)

theorem OriginalStackDynamicTargetPostEvidence.holds
    {context : OriginalDecodedStaticContext}
    {requirement : OriginalStackDynamicTargetRequirement context}
    {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalStackDynamicTargetPostEvidence requirement successor) :
    requirement.Holds successor.execution := by
  cases evidence <;> simp_all [OriginalNormalizedSuccessor.execution,
    OriginalStackDynamicTargetRequirement.Holds, OriginalSourceFactAt]

structure OriginalTargetPostEvidence
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (beforeWorld : RelationalWorld) (beforeMemory : Memory)
    (successor : OriginalNormalizedSuccessor) : Prop where
  reachability : OriginalReachabilityPostEvidence
    inventory.reachableTargets.targetIds successor
  staticWords : OriginalStaticWordPostEvidence program.context
    inventory.staticWords beforeWorld beforeMemory successor
  callFrames : OriginalCallFramePostEvidence program.context successor
  valueFlows : OriginalValueFlowPostInventoryEvidence program
    inventory.valueFlows successor
  registerTargets : forall requirement,
    requirement ∈ inventory.registerTargets ->
      OriginalRegisterTargetPostEvidence requirement successor
  stackDynamicTargets : forall requirement,
    requirement ∈ inventory.stackDynamicTargets ->
      OriginalStackDynamicTargetPostEvidence requirement successor
  runtimeMemory : OriginalRuntimeMemoryPartition.ExecutionHolds
    program.context successor.execution

theorem OriginalTargetPostEvidence.toPostFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {beforeWorld : RelationalWorld} {beforeMemory : Memory}
    {successor : OriginalNormalizedSuccessor}
    (evidence : OriginalTargetPostEvidence inventory beforeWorld beforeMemory
      successor)
    (staticBefore : inventory.staticWords.HoldsIn program.context beforeWorld
      beforeMemory) : OriginalCombinedPostFamilies inventory successor.execution := by
  refine {
    reachability := evidence.reachability.holds
    staticWords := evidence.staticWords.preserves staticBefore
    callFrames := evidence.callFrames.holds
    valueFlows := evidence.valueFlows.holds
    registerTargets := ?_
    stackDynamicTargets := ?_
    runtimeMemory := evidence.runtimeMemory
  }
  · intro requirement member
    exact (evidence.registerTargets requirement member).holds
  · intro requirement member
    exact (evidence.stackDynamicTargets requirement member).holds

theorem activeStaticWordsHold
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    inventory.staticWords.HoldsIn program.context invocation.world
      invocation.state.memory := by
  have staticHolds := holds.2.1
  cases callbackCase : invocation.callbacks with
  | none =>
      simpa [OriginalTargetInvocation.execution, callbackCase,
        OriginalStaticWordInventory.Holds] using staticHolds
  | some callbacks =>
      have paired : inventory.staticWords.HoldsIn program.context
          invocation.world invocation.state.memory /\
          SuspendedOriginalStaticWordsHold program.context inventory.staticWords
            callbacks := by
        simpa [OriginalTargetInvocation.execution, callbackCase,
          OriginalStaticWordInventory.Holds] using staticHolds
      exact paired.1

theorem activeRuntimeMemoryHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (holds : inventory.Holds invocation.execution) :
    OriginalRuntimeMemoryPartition.HoldsIn program.context invocation.world /\
      OriginalRuntimeMemoryPartition.SuspendedHold program.context
        invocation.routingCallbacks := by
  have runtime := inventory.runtimeMemoryHolds holds
  cases callbackCase : invocation.callbacks with
  | none =>
      simpa [OriginalTargetInvocation.execution,
        OriginalTargetInvocation.routingCallbacks, callbackCase,
        OriginalRuntimeMemoryPartition.ExecutionHolds,
        OriginalRuntimeMemoryPartition.SuspendedHold] using
        And.intro runtime trivial
  | some callbacks =>
      simpa [OriginalTargetInvocation.execution,
        OriginalTargetInvocation.routingCallbacks, callbackCase,
        OriginalRuntimeMemoryPartition.ExecutionHolds] using runtime

/-- One fully explicit target case.  The semantic transition and every family
certificate share the same normalized successor. -/
structure CheckedOriginalTargetPreservationCase
    {program : Program} {targetId : Nat}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (checked : CheckedOriginalTargetEffect program targetId)
    (invocation : OriginalTargetInvocation targetId) where
  transition : CheckedOriginalTargetTransition checked originalContext
    inventory.reachableTargets.targetIds invocation
  post : OriginalTargetPostEvidence inventory invocation.world
    invocation.state.memory transition.successor

theorem CheckedOriginalTargetPreservationCase.postFamilies
    {program : Program} {targetId : Nat}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {checked : CheckedOriginalTargetEffect program targetId}
    {invocation : OriginalTargetInvocation targetId}
    (preservation : CheckedOriginalTargetPreservationCase originalContext
      inventory checked invocation)
    (holds : inventory.Holds invocation.execution) :
    OriginalCombinedPostFamilies inventory
      (program.worldProgram.pe32TransitionSystem.step invocation.execution).next := by
  have post := preservation.post.toPostFamilies
    (activeStaticWordsHold invocation holds)
  rw [preservation.transition.peSuccessorExact]
  exact post

/-- Shardable universal provider for one indexed target.  The provider may
inspect the complete pre-invariant, but it must return the structured effect,
successor, protected-write, and finite per-requirement certificates above. -/
structure CheckedOriginalTargetPreservationProvider
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext)
    (certificate : ActiveTargetTransitionCertificate binding) where
  checked : CheckedOriginalTargetEffect program certificate.targetId
  cases : forall invocation : OriginalTargetInvocation certificate.targetId,
    inventory.Holds invocation.execution ->
      CheckedOriginalTargetPreservationCase originalContext inventory checked
        invocation

def CheckedOriginalTargetPreservationProvider.toFamilyPreservation
    {pe : PE32} {program : Program} {binding : ExactBinding pe program}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {certificate : ActiveTargetTransitionCertificate binding}
    (provider : CheckedOriginalTargetPreservationProvider originalContext
      inventory certificate) :
    OriginalCombinedTargetFamilyPreservation originalContext inventory
      certificate where
  running state calls eventIndex world holds := by
    let invocation : OriginalTargetInvocation certificate.targetId := {
      state, calls, eventIndex, world, callbacks := none
    }
    exact (provider.cases invocation holds).postFamilies holds
  callbackRunning state calls eventIndex world callbacks holds := by
    let invocation : OriginalTargetInvocation certificate.targetId := {
      state, calls, eventIndex, world, callbacks := some callbacks
    }
    exact (provider.cases invocation holds).postFamilies holds

#print axioms CheckedOriginalTargetEffect.peStep_eq_effect
#print axioms CheckedOriginalTargetTransition.peSuccessorExact
#print axioms OriginalProtectedWordUpdate.preserves
#print axioms OriginalValueFlowAtEvidence.holdsAt
#print axioms OriginalTargetPostEvidence.toPostFamilies
#print axioms activeRuntimeMemoryHolds
#print axioms CheckedOriginalTargetPreservationCase.postFamilies
#print axioms CheckedOriginalTargetPreservationProvider.toFamilyPreservation

end StageA.Relational.OriginalTargetPreservation
