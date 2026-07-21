import StageA.RelationalLinkedExecution

namespace StageA.Relational

open StageA.Formal

/-- The concrete image base selected by a one-sided decoded program. -/
def DecodedWorldProgram.sideImageBase (program : DecodedWorldProgram) : Nat :=
  if program.candidate then
    program.context.candidatePe.imageBase
  else
    program.context.originalPe.imageBase

def DecodedWorldProgram.resolveRawEip (program : DecodedWorldProgram)
    (eip : Word) : Option Nat :=
  program.context.codeMap.resolveRawEip program.candidate
    program.sideImageBase eip

def DecodedWorldProgram.canonicalRawEip? (program : DecodedWorldProgram)
    (targetId : Nat) : Option Word :=
  program.context.codeMap.canonicalRawEip? program.candidate
    program.sideImageBase targetId

/-- Whole-program state with concrete EIP at both executable frontiers. All
external suspension, world, fault, and proof-block data is reused unchanged. -/
inductive RawEipWorldExecution where
  | running (eip : Word) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
  | returned (state : MachineState) (world : RelationalWorld)
  | terminated (world : RelationalWorld)
  | awaitingExternal (suspension : WorldExternalSuspension)
      (callbacks : List WorldExternalCallbackRuntime)
  | callbackRunning (eip : Word) (state : MachineState) (calls : List Nat)
      (eventIndex : Nat) (world : RelationalWorld)
      (callbacks : List WorldExternalCallbackRuntime)
  | fault (cause : ModeledFault)
  | blocked (reason : ExecutionBlock)

/-- Resolve raw running EIPs and otherwise forget only the raw wrapper. -/
def RawEipWorldExecution.project? (program : DecodedWorldProgram) :
    RawEipWorldExecution -> Option WorldExecution
  | .running eip state calls eventIndex world => do
      let targetId <- program.resolveRawEip eip
      pure (.running targetId state calls eventIndex world)
  | .returned state world => some (.returned state world)
  | .terminated world => some (.terminated world)
  | .awaitingExternal suspension callbacks =>
      some (.awaitingExternal suspension callbacks)
  | .callbackRunning eip state calls eventIndex world callbacks => do
      let targetId <- program.resolveRawEip eip
      pure (.callbackRunning targetId state calls eventIndex world callbacks)
  | .fault cause => some (.fault cause)
  | .blocked reason => some (.blocked reason)

/-- Canonicalize logical running target IDs into side-specific concrete EIPs. -/
def WorldExecution.concretizeRawEip? (program : DecodedWorldProgram) :
    WorldExecution -> Option RawEipWorldExecution
  | .running targetId state calls eventIndex world => do
      let eip <- program.canonicalRawEip? targetId
      pure (.running eip state calls eventIndex world)
  | .returned state world => some (.returned state world)
  | .terminated world => some (.terminated world)
  | .awaitingExternal suspension callbacks =>
      some (.awaitingExternal suspension callbacks)
  | .callbackRunning targetId state calls eventIndex world callbacks => do
      let eip <- program.canonicalRawEip? targetId
      pure (.callbackRunning eip state calls eventIndex world callbacks)
  | .fault cause => some (.fault cause)
  | .blocked reason => some (.blocked reason)

def RawEipWorldExecution.ProjectsTo (program : DecodedWorldProgram)
    (raw : RawEipWorldExecution) (logical : WorldExecution) : Prop :=
  raw.project? program = some logical

/-- Concretization includes the round trip needed to execute the resulting raw
state, rather than merely asserting that a canonical address can be formed. -/
def WorldExecution.ConcretizesToRawEip (program : DecodedWorldProgram)
    (logical : WorldExecution) (raw : RawEipWorldExecution) : Prop :=
  logical.concretizeRawEip? program = some raw ∧ raw.ProjectsTo program logical

def blockedRawEipWorldTransition (reason : ExecutionBlock) :
    RelatedTransition RawEipWorldExecution WorldRelationalObservable :=
  { next := .blocked reason, observation := some (.proofBlocked reason) }

def rawConcretizationFailure : WorldExecution -> ExecutionBlock
  | .running targetId _ _ _ _ => .missingRegionBehavior targetId
  | .callbackRunning targetId _ _ _ _ _ => .missingRegionBehavior targetId
  | _ => .missingRuntimeContinuation

def rawProjectionFailure : RawEipWorldExecution -> ExecutionBlock
  | .running eip _ _ _ _ => .unmappedEip eip
  | .callbackRunning eip _ _ _ _ _ => .unmappedEip eip
  | _ => .missingRuntimeContinuation

/-- Preserve a logical transition's observation while canonicalizing its next
executable frontier. Missing logical targets remain proof blocks. -/
def concretizeRawEipTransition (program : DecodedWorldProgram)
    (transition : RelatedTransition WorldExecution WorldRelationalObservable) :
    RelatedTransition RawEipWorldExecution WorldRelationalObservable :=
  match transition.next.concretizeRawEip? program with
  | some next => { next, observation := transition.observation }
  | none => blockedRawEipWorldTransition (rawConcretizationFailure transition.next)

/-- Exact PE macro-execution selected by concrete EIP. Unmapped and ambiguous
EIPs are proof blocks and never modeled faults. -/
def stepPE32RawEipWorldExecution (program : DecodedWorldProgram) :
    RawEipWorldExecution ->
      RelatedTransition RawEipWorldExecution WorldRelationalObservable
  | raw =>
      match raw.project? program with
      | none => blockedRawEipWorldTransition (rawProjectionFailure raw)
      | some logical =>
          concretizeRawEipTransition program
            (stepPE32WorldExecution program logical)

def DecodedWorldProgram.pe32RawEipTransitionSystem
    (program : DecodedWorldProgram) :
    RelatedTransitionSystem RawEipWorldExecution WorldRelationalObservable := {
  step := stepPE32RawEipWorldExecution program
}

/-- Exact closure condition needed to lift a logical execution relation to raw
EIP states. It says every related pair has canonical, executable round trips
on both sides; it does not alter the target-indexed relation itself. -/
def RawEipPairBridgeClosed (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop) : Prop :=
  forall originalExecution candidateExecution,
    executionRelation originalExecution candidateExecution ->
    exists originalRaw candidateRaw,
      originalExecution.ConcretizesToRawEip original originalRaw ∧
      candidateExecution.ConcretizesToRawEip candidate candidateRaw

/-- The raw relation is the checked target-indexed relation plus concrete EIP
round trips on both sides. -/
def RawEipLiftedExecutionRelation (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop) :
    RawEipWorldExecution -> RawEipWorldExecution -> Prop :=
  fun originalRaw candidateRaw =>
    exists originalExecution candidateExecution,
      originalExecution.ConcretizesToRawEip original originalRaw ∧
      candidateExecution.ConcretizesToRawEip candidate candidateRaw ∧
      executionRelation originalExecution candidateExecution

theorem RelationalProductGraph.nodeCodeTargetFound
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (valid : graph.IndexedValid context) (nodeId : Nat)
    (node : RelationalProductNode)
    (nodeFound : graph.getNode? nodeId = some node) :
    exists target, context.codeMap.get? node.targetId = some target := by
  have nodeBefore : nodeId < graph.nodes.size :=
    Array.getElem?_eq_some_iff.mp nodeFound |>.1
  have nodeValid := valid.1 nodeId nodeBefore
  unfold RelationalProductGraph.nodeAtValid at nodeValid
  rw [nodeFound] at nodeValid
  cases targetResult : context.codeMap.get? node.targetId with
  | none => simp [targetResult] at nodeValid
  | some target => exact ⟨target, rfl⟩

/-- Stack representation is irrelevant to raw-EIP lifting.  This compact
frontier relation records exactly the constructor agreement and mapped logical
target needed to obtain canonical concrete EIPs. -/
def ExecutionFrontiersMapped (graph : RelationalProductGraph) :
    WorldExecution -> WorldExecution -> Prop
  | .running originalTarget _ _ _ _, .running candidateTarget _ _ _ _ =>
      originalTarget = candidateTarget ∧
        ∃ nodeId node, graph.getNode? nodeId = some node ∧
          node.targetId = originalTarget
  | .returned _ _, .returned _ _ => True
  | .terminated _, .terminated _ => True
  | .awaitingExternal _ _, .awaitingExternal _ _ => True
  | .callbackRunning originalTarget _ _ _ _ _,
      .callbackRunning candidateTarget _ _ _ _ _ =>
      originalTarget = candidateTarget ∧
        ∃ nodeId node, graph.getNode? nodeId = some node ∧
          node.targetId = originalTarget
  | .fault _, .fault _ => True
  | .blocked _, .blocked _ => True
  | _, _ => False

theorem executionFrontiersMapped_rawEipPairBridgeClosed
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop)
    (frontiers : ∀ originalExecution candidateExecution,
      executionRelation originalExecution candidateExecution →
        ExecutionFrontiersMapped graph originalExecution candidateExecution)
    (originalContext : original.context = context)
    (candidateContext : candidate.context = context)
    (originalSide : original.candidate = false)
    (candidateSide : candidate.candidate = true)
    (contextValid : context.StructurallyValid)
    (graphValid : graph.IndexedValid context) :
    RawEipPairBridgeClosed original candidate executionRelation := by
  rcases contextValid with
    ⟨_, _, _, _, _, _, codeMapValid, _, _, _, _, _, _, _, _, _, _⟩
  rcases codeMapValid with
    ⟨_, _, _, _, _, _, _, _, originalRoundTrips, candidateRoundTrips⟩
  intro originalExecution candidateExecution related
  have mapped := frontiers originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution
  case running.running originalTarget originalState originalCalls originalEventIndex
      originalWorld candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld =>
      rcases mapped with
        ⟨targetEqual, nodeId, node, nodeFound, nodeTarget⟩
      subst candidateTarget
      subst originalTarget
      rcases graph.nodeCodeTargetFound context graphValid nodeId node nodeFound with
        ⟨target, targetFound⟩
      rcases context.codeMap.canonicalRawEip_roundTrip false
          context.originalPe.imageBase originalRoundTrips node.targetId target
          targetFound with ⟨originalEip, originalCanonical, originalResolved⟩
      rcases context.codeMap.canonicalRawEip_roundTrip true
          context.candidatePe.imageBase candidateRoundTrips node.targetId target
          targetFound with ⟨candidateEip, candidateCanonical, candidateResolved⟩
      refine ⟨.running originalEip originalState originalCalls originalEventIndex
          originalWorld,
        .running candidateEip candidateState candidateCalls candidateEventIndex
          candidateWorld, ?_, ?_⟩
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            originalContext, originalSide, originalCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, originalContext, originalSide,
            originalResolved]
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            candidateContext, candidateSide, candidateCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, candidateContext, candidateSide,
            candidateResolved]
  case returned.returned originalState originalWorld candidateState candidateWorld =>
      exact ⟨.returned originalState originalWorld,
        .returned candidateState candidateWorld,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case terminated.terminated originalWorld candidateWorld =>
      exact ⟨.terminated originalWorld, .terminated candidateWorld,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case awaitingExternal.awaitingExternal originalSuspension originalCallbacks
      candidateSuspension candidateCallbacks =>
      exact ⟨.awaitingExternal originalSuspension originalCallbacks,
        .awaitingExternal candidateSuspension candidateCallbacks,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case callbackRunning.callbackRunning originalTarget originalState originalCalls
      originalEventIndex originalWorld originalCallbacks candidateTarget candidateState
      candidateCalls candidateEventIndex candidateWorld candidateCallbacks =>
      rcases mapped with
        ⟨targetEqual, nodeId, node, nodeFound, nodeTarget⟩
      subst candidateTarget
      subst originalTarget
      rcases graph.nodeCodeTargetFound context graphValid nodeId node nodeFound with
        ⟨target, targetFound⟩
      rcases context.codeMap.canonicalRawEip_roundTrip false
          context.originalPe.imageBase originalRoundTrips node.targetId target
          targetFound with ⟨originalEip, originalCanonical, originalResolved⟩
      rcases context.codeMap.canonicalRawEip_roundTrip true
          context.candidatePe.imageBase candidateRoundTrips node.targetId target
          targetFound with ⟨candidateEip, candidateCanonical, candidateResolved⟩
      refine ⟨.callbackRunning originalEip originalState originalCalls
          originalEventIndex originalWorld originalCallbacks,
        .callbackRunning candidateEip candidateState candidateCalls candidateEventIndex
          candidateWorld candidateCallbacks, ?_, ?_⟩
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            originalContext, originalSide, originalCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, originalContext, originalSide,
            originalResolved]
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            candidateContext, candidateSide, candidateCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, candidateContext, candidateSide,
            candidateResolved]
  case fault.fault originalCause candidateCause =>
      exact ⟨.fault originalCause, .fault candidateCause,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case blocked.blocked originalReason candidateReason =>
      exact ⟨.blocked originalReason, .blocked candidateReason,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  all_goals simp [ExecutionFrontiersMapped] at mapped

theorem linkedWorldExecutionsRelated_frontiersMapped
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract) :
    ∀ originalExecution candidateExecution,
      LinkedWorldExecutionsRelated context graph invariants reachability control
          callbackTargets sites originalExecution candidateExecution →
        ExecutionFrontiersMapped graph originalExecution candidateExecution := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution
  case running.running =>
      rcases related with
        ⟨targetEqual, _, _, _, nodeId, node, _, _, _, _, nodeFound, nodeTarget, _⟩
      exact ⟨targetEqual, nodeId, node, nodeFound, nodeTarget⟩
  case callbackRunning.callbackRunning =>
      rcases related with
        ⟨targetEqual, _, _, _, _, nodeId, node, _, _, _, _, nodeFound, _,
          nodeTarget, _⟩
      exact ⟨targetEqual, nodeId, node, nodeFound, nodeTarget⟩
  case returned.returned => trivial
  case terminated.terminated => trivial
  case awaitingExternal.awaitingExternal => trivial
  case fault.fault => trivial
  all_goals simp [LinkedWorldExecutionsRelated] at related

theorem worldExecutionsRelated_rawEipPairBridgeClosed
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (original candidate : DecodedWorldProgram)
    (originalContext : original.context = context)
    (candidateContext : candidate.context = context)
    (originalSide : original.candidate = false)
    (candidateSide : candidate.candidate = true)
    (contextValid : context.StructurallyValid)
    (graphValid : graph.IndexedValid context) :
    RawEipPairBridgeClosed original candidate
      (WorldExecutionsRelated context graph invariants reachability control
        callbackTargets sites) := by
  rcases contextValid with
    ⟨_, _, _, _, _, _, codeMapValid, _, _, _, _, _, _, _, _, _, _⟩
  rcases codeMapValid with
    ⟨_, _, _, _, _, _, _, _, originalRoundTrips, candidateRoundTrips⟩
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution
  case running.running originalTarget originalState originalCalls originalEventIndex
      originalWorld candidateTarget candidateState candidateCalls candidateEventIndex
      candidateWorld =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual,
          nodeId, node, invariant, frames, frameOffsets, nodeFound, nodeTarget,
          reachable, invariantFound, controlAllowed, stackHolds, frameImportsHold,
          frameTargetsReachable, statesRelated⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      subst originalTarget
      rcases graph.nodeCodeTargetFound context graphValid nodeId node nodeFound with
        ⟨target, targetFound⟩
      rcases context.codeMap.canonicalRawEip_roundTrip false
          context.originalPe.imageBase originalRoundTrips node.targetId target
          targetFound with ⟨originalEip, originalCanonical, originalResolved⟩
      rcases context.codeMap.canonicalRawEip_roundTrip true
          context.candidatePe.imageBase candidateRoundTrips node.targetId target
          targetFound with ⟨candidateEip, candidateCanonical, candidateResolved⟩
      refine ⟨.running originalEip originalState originalCalls originalEventIndex
          originalWorld,
        .running candidateEip candidateState originalCalls originalEventIndex
          originalWorld, ?_, ?_⟩
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            originalContext, originalSide]
          simp [originalCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, originalContext, originalSide]
          simp [originalResolved]
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            candidateContext, candidateSide]
          simp [candidateCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, candidateContext, candidateSide]
          simp [candidateResolved]
  case returned.returned originalState originalWorld candidateState candidateWorld =>
      exact ⟨.returned originalState originalWorld,
        .returned candidateState candidateWorld, by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?], by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case terminated.terminated originalWorld candidateWorld =>
      exact ⟨.terminated originalWorld, .terminated candidateWorld,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case awaitingExternal.awaitingExternal originalSuspension originalCallbacks
      candidateSuspension candidateCallbacks =>
      exact ⟨.awaitingExternal originalSuspension originalCallbacks,
        .awaitingExternal candidateSuspension candidateCallbacks,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  case callbackRunning.callbackRunning originalTarget originalState originalCalls
      originalEventIndex originalWorld originalCallbacks candidateTarget candidateState
      candidateCalls candidateEventIndex candidateWorld candidateCallbacks =>
      rcases related with
        ⟨targetEqual, callsEqual, eventEqual, worldEqual, callbacksNonempty,
          nodeId, node, invariant, frames, frameOffsets, nodeFound,
          callbackTargetAllowed, nodeTarget, reachable, invariantFound, controlAllowed,
          stackHolds, frameImportsHold, frameTargetsReachable, statesRelated,
          callbacksRelated, callbackFramesHold⟩
      subst candidateTarget
      subst candidateCalls
      subst candidateEventIndex
      subst candidateWorld
      subst originalTarget
      rcases graph.nodeCodeTargetFound context graphValid nodeId node nodeFound with
        ⟨target, targetFound⟩
      rcases context.codeMap.canonicalRawEip_roundTrip false
          context.originalPe.imageBase originalRoundTrips node.targetId target
          targetFound with ⟨originalEip, originalCanonical, originalResolved⟩
      rcases context.codeMap.canonicalRawEip_roundTrip true
          context.candidatePe.imageBase candidateRoundTrips node.targetId target
          targetFound with ⟨candidateEip, candidateCanonical, candidateResolved⟩
      refine ⟨.callbackRunning originalEip originalState originalCalls
          originalEventIndex originalWorld originalCallbacks,
        .callbackRunning candidateEip candidateState originalCalls originalEventIndex
          originalWorld candidateCallbacks, ?_, ?_⟩
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            originalContext, originalSide]
          simp [originalCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, originalContext, originalSide]
          simp [originalResolved]
      · constructor
        · simp [WorldExecution.concretizeRawEip?,
            DecodedWorldProgram.canonicalRawEip?, DecodedWorldProgram.sideImageBase,
            candidateContext, candidateSide]
          simp [candidateCanonical]
        · simp [RawEipWorldExecution.ProjectsTo,
            RawEipWorldExecution.project?, DecodedWorldProgram.resolveRawEip,
            DecodedWorldProgram.sideImageBase, candidateContext, candidateSide]
          simp [candidateResolved]
  case fault.fault originalCause candidateCause =>
      exact ⟨.fault originalCause, .fault candidateCause,
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?],
        by simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  all_goals simp [WorldExecutionsRelated] at related

theorem concretizeRawEipTransition_of_mapped (program : DecodedWorldProgram)
    (transition : RelatedTransition WorldExecution WorldRelationalObservable)
    (rawNext : RawEipWorldExecution)
    (mapped : transition.next.concretizeRawEip? program = some rawNext) :
    concretizeRawEipTransition program transition =
      { next := rawNext, observation := transition.observation } := by
  simp [concretizeRawEipTransition, mapped]

theorem stepPE32RawEipWorldExecution_of_concretizes
    (program : DecodedWorldProgram) (logical : WorldExecution)
    (raw rawNext : RawEipWorldExecution)
    (current : logical.ConcretizesToRawEip program raw)
    (next : (stepPE32WorldExecution program logical).next.ConcretizesToRawEip
      program rawNext) :
    stepPE32RawEipWorldExecution program raw = {
      next := rawNext
      observation := (stepPE32WorldExecution program logical).observation
    } := by
  rcases current with ⟨_, currentProjects⟩
  rcases next with ⟨nextConcrete, _⟩
  unfold RawEipWorldExecution.ProjectsTo at currentProjects
  simp [stepPE32RawEipWorldExecution, currentProjects,
    concretizeRawEipTransition, nextConcrete]

theorem relationalWeakBisimulation_rawEip_of_logical
    (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop)
    (logicalBisimulation :
      RelationalWeakBisimulation original.pe32TransitionSystem
        candidate.pe32TransitionSystem executionRelation
        (worldRelationalObservationsRelated original.context))
    (bridge : RawEipPairBridgeClosed original candidate executionRelation) :
    RelationalWeakBisimulation original.pe32RawEipTransitionSystem
      candidate.pe32RawEipTransitionSystem
      (RawEipLiftedExecutionRelation original candidate executionRelation)
      (worldRelationalObservationsRelated original.context) := by
  intro originalRaw candidateRaw related
  rcases related with
    ⟨originalExecution, candidateExecution, originalConcrete,
      candidateConcrete, logicalRelated⟩
  have logicalStep := logicalBisimulation originalExecution candidateExecution
    logicalRelated
  rcases bridge (original.pe32TransitionSystem.step originalExecution).next
      (candidate.pe32TransitionSystem.step candidateExecution).next logicalStep.2 with
    ⟨originalNext, candidateNext, originalNextConcrete, candidateNextConcrete⟩
  have originalStep := stepPE32RawEipWorldExecution_of_concretizes original
    originalExecution originalRaw originalNext originalConcrete originalNextConcrete
  have candidateStep := stepPE32RawEipWorldExecution_of_concretizes candidate
    candidateExecution candidateRaw candidateNext candidateConcrete candidateNextConcrete
  change worldRelationalObservationsRelated original.context
      (stepPE32RawEipWorldExecution original originalRaw).observation
      (stepPE32RawEipWorldExecution candidate candidateRaw).observation ∧
    RawEipLiftedExecutionRelation original candidate executionRelation
      (stepPE32RawEipWorldExecution original originalRaw).next
      (stepPE32RawEipWorldExecution candidate candidateRaw).next
  rw [originalStep, candidateStep]
  exact ⟨logicalStep.1, ⟨_, _, originalNextConcrete, candidateNextConcrete,
    logicalStep.2⟩⟩

theorem stepPE32RawEipWorldExecution_running_corresponds
    (program : DecodedWorldProgram) (eip : Word) (targetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (rawNext : RawEipWorldExecution)
    (resolved : program.resolveRawEip eip = some targetId)
    (mapped : (stepPE32WorldExecution program
      (.running targetId state calls eventIndex world)).next.concretizeRawEip?
        program = some rawNext) :
    stepPE32RawEipWorldExecution program
        (.running eip state calls eventIndex world) =
      { next := rawNext,
        observation := (stepPE32WorldExecution program
          (.running targetId state calls eventIndex world)).observation } := by
  simp [stepPE32RawEipWorldExecution, RawEipWorldExecution.project?, resolved,
    concretizeRawEipTransition, mapped]

theorem stepPE32RawEipWorldExecution_running_projects
    (program : DecodedWorldProgram) (eip : Word) (targetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (rawNext : RawEipWorldExecution)
    (resolved : program.resolveRawEip eip = some targetId)
    (mapped : (stepPE32WorldExecution program
      (.running targetId state calls eventIndex world)).next.ConcretizesToRawEip
        program rawNext) :
    (stepPE32RawEipWorldExecution program
        (.running eip state calls eventIndex world)).observation =
        (stepPE32WorldExecution program
          (.running targetId state calls eventIndex world)).observation ∧
      (stepPE32RawEipWorldExecution program
        (.running eip state calls eventIndex world)).next.ProjectsTo program
        (stepPE32WorldExecution program
          (.running targetId state calls eventIndex world)).next := by
  have corresponds := stepPE32RawEipWorldExecution_running_corresponds program
    eip targetId state calls eventIndex world rawNext resolved mapped.1
  rw [corresponds]
  exact ⟨rfl, mapped.2⟩

theorem stepPE32RawEipWorldExecution_callbackRunning_corresponds
    (program : DecodedWorldProgram) (eip : Word) (targetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime)
    (rawNext : RawEipWorldExecution)
    (resolved : program.resolveRawEip eip = some targetId)
    (mapped : WorldExecution.concretizeRawEip? program
      (stepPE32WorldExecution program
        (.callbackRunning targetId state calls eventIndex world callbacks)).next =
          some rawNext) :
    stepPE32RawEipWorldExecution program
        (.callbackRunning eip state calls eventIndex world callbacks) =
      { next := rawNext,
        observation := (stepPE32WorldExecution program
          (.callbackRunning targetId state calls eventIndex world callbacks)).observation } := by
  simp [stepPE32RawEipWorldExecution, RawEipWorldExecution.project?, resolved,
    concretizeRawEipTransition, mapped]

theorem stepPE32RawEipWorldExecution_callbackRunning_projects
    (program : DecodedWorldProgram) (eip : Word) (targetId : Nat)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) (callbacks : List WorldExternalCallbackRuntime)
    (rawNext : RawEipWorldExecution)
    (resolved : program.resolveRawEip eip = some targetId)
    (mapped : WorldExecution.ConcretizesToRawEip program
      (stepPE32WorldExecution program
        (.callbackRunning targetId state calls eventIndex world callbacks)).next rawNext) :
    (stepPE32RawEipWorldExecution program
        (.callbackRunning eip state calls eventIndex world callbacks)).observation =
        (stepPE32WorldExecution program
          (.callbackRunning targetId state calls eventIndex world callbacks)).observation ∧
      (stepPE32RawEipWorldExecution program
        (.callbackRunning eip state calls eventIndex world callbacks)).next.ProjectsTo
        program (stepPE32WorldExecution program
          (.callbackRunning targetId state calls eventIndex world callbacks)).next := by
  have corresponds := stepPE32RawEipWorldExecution_callbackRunning_corresponds program
    eip targetId state calls eventIndex world callbacks rawNext resolved mapped.1
  rw [corresponds]
  exact ⟨rfl, mapped.2⟩

theorem stepPE32RawEipWorldExecution_running_unmapped
    (program : DecodedWorldProgram) (eip : Word) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (unmapped : program.resolveRawEip eip = none) :
    stepPE32RawEipWorldExecution program
        (.running eip state calls eventIndex world) =
      blockedRawEipWorldTransition (.unmappedEip eip) := by
  simp [stepPE32RawEipWorldExecution, RawEipWorldExecution.project?, unmapped,
    rawProjectionFailure]

theorem stepPE32RawEipWorldExecution_callbackRunning_unmapped
    (program : DecodedWorldProgram) (eip : Word) (state : MachineState)
    (calls : List Nat) (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (unmapped : program.resolveRawEip eip = none) :
    stepPE32RawEipWorldExecution program
        (.callbackRunning eip state calls eventIndex world callbacks) =
      blockedRawEipWorldTransition (.unmappedEip eip) := by
  simp [stepPE32RawEipWorldExecution, RawEipWorldExecution.project?, unmapped,
    rawProjectionFailure]

theorem pairedRawEipBlocksAreUnrelated (context : StaticProofContext)
    (originalEip candidateEip : Word) :
    Not (worldRelationalObservationsRelated context
      (some (.proofBlocked (.unmappedEip originalEip)))
      (some (.proofBlocked (.unmappedEip candidateEip)))) := by
  simp [worldRelationalObservationsRelated]

/-- Acceptance-facing raw-EIP observational equivalence. The target-indexed
product relation remains internal to the projected logical executions. -/
def PE32RawProgramsObservationallyEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram) : Prop :=
  launch.Realizable context graph reachability ∧
    exists executionRelation : RawEipWorldExecution -> RawEipWorldExecution -> Prop,
      (forall world originalState candidateState,
        launch.StatesRelated context graph reachability world originalState candidateState ->
        match original.canonicalRawEip? launch.rootTargetId,
            candidate.canonicalRawEip? launch.rootTargetId with
        | some originalEip, some candidateEip =>
            executionRelation
              (.running originalEip originalState launch.continuationTargetIds 0 world)
              (.running candidateEip candidateState launch.continuationTargetIds 0 world)
        | _, _ => False) ∧
      RelationalWeakBisimulation original.pe32RawEipTransitionSystem
        candidate.pe32RawEipTransitionSystem executionRelation
        (worldRelationalObservationsRelated context)

/-- Lift the acceptance certificate all the way to concrete-EIP PE execution.
The logical product graph remains the compositional proof device, while this
theorem checks that every related executable frontier has a unique canonical
address on both images. -/
theorem pe32ProgramsEquivalent_raw (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (certificate : WholeProgramCertificate context graph regions invariants reachability control
      callbackTargets externalCallSites launch originalEnvironment candidateEnvironment
      originalProtocolEnvironment candidateProtocolEnvironment) :
    PE32RawProgramsObservationallyEquivalent context graph invariants reachability control launch
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
        protocolEnvironment := originalProtocolEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
        protocolEnvironment := candidateProtocolEnvironment
      } := by
  let original : DecodedWorldProgram := {
    candidate := false
    context
    regions
    externalCallSites
    environment := originalEnvironment
    protocolEnvironment := originalProtocolEnvironment
  }
  let candidate : DecodedWorldProgram := {
    candidate := true
    context
    regions
    externalCallSites
    environment := candidateEnvironment
    protocolEnvironment := candidateProtocolEnvironment
  }
  let executionRelation := WorldExecutionsRelated context graph invariants reachability
    control callbackTargets externalCallSites
  have initialRelated : forall world originalState candidateState,
      launch.StatesRelated context graph reachability world originalState candidateState ->
      executionRelation
        (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
        (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world) := by
    intro world originalState candidateState related
    rcases related with
      ⟨frames, _worldValid, _originalImageMapped, _candidateImageMapped,
        stackHolds, frameImportsHold, frameTargetsReachable,
        _processAttachArgumentsHold, statesRelated⟩
    rcases certificate.launchValid.2.2.2.2.2.2.2.2.1 with
      ⟨node, nodeFound, targetFound, rootFound, rootListed, invariantFound⟩
    refine ⟨rfl, rfl, rfl, rfl, launch.rootNodeId, node,
      launch.rootInvariant, frames, launch.frameOffsets, nodeFound, targetFound, ?_,
      invariantFound, certificate.launchControlAllowed, stackHolds,
      frameImportsHold, frameTargetsReachable, statesRelated⟩
    have allRoots := certificate.reachabilityClosed.2.1.2.1
    unfold RelationalProductReachabilityEvidence.rootsIncluded at allRoots
    exact List.all_eq_true.mp allRoots launch.rootNodeId
      (List.contains_iff_mem.mp rootListed)
  have logicalBisimulation :
      RelationalWeakBisimulation original.pe32TransitionSystem
        candidate.pe32TransitionSystem executionRelation
        (worldRelationalObservationsRelated context) := by
    have decodedBisimulation := productStepRefinement_of_reachable_nodes context graph
      invariants reachability control callbackTargets original candidate
      certificate.environmentsRefined certificate.protocolEnvironmentsRefined
      certificate.runningProductNodesRefined
      certificate.callbackRunningProductNodesRefined
    have originalAdequate : original.InstructionSemanticsAdequate := by
      simpa [original] using certificate.originalInstructionSemanticsAdequate
    have candidateAdequate : candidate.InstructionSemanticsAdequate := by
      simpa [candidate] using certificate.candidateInstructionSemanticsAdequate
    rw [original.pe32TransitionSystem_eq_transitionSystem originalAdequate,
      candidate.pe32TransitionSystem_eq_transitionSystem candidateAdequate]
    exact decodedBisimulation
  have bridge : RawEipPairBridgeClosed original candidate executionRelation :=
    worldExecutionsRelated_rawEipPairBridgeClosed context graph invariants reachability
      control callbackTargets externalCallSites original candidate rfl rfl rfl rfl
      certificate.staticContextValid certificate.productGraphValid
  refine ⟨certificate.launchRealizable,
    RawEipLiftedExecutionRelation original candidate executionRelation, ?_,
    relationalWeakBisimulation_rawEip_of_logical original candidate executionRelation
      logicalBisimulation bridge⟩
  intro world originalState candidateState statesRelated
  have logicalInitial := initialRelated world originalState candidateState statesRelated
  rcases bridge
      (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
      (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world)
      logicalInitial with
    ⟨originalRaw, candidateRaw, originalConcrete, candidateConcrete⟩
  rcases originalConcrete with ⟨originalCanonical, originalProjects⟩
  rcases candidateConcrete with ⟨candidateCanonical, candidateProjects⟩
  cases originalRoot : original.canonicalRawEip? launch.rootTargetId with
  | none => simp [WorldExecution.concretizeRawEip?, originalRoot] at originalCanonical
  | some originalEip =>
      cases candidateRoot : candidate.canonicalRawEip? launch.rootTargetId with
      | none => simp [WorldExecution.concretizeRawEip?, candidateRoot] at candidateCanonical
      | some candidateEip =>
          simp [WorldExecution.concretizeRawEip?, originalRoot] at originalCanonical
          simp [WorldExecution.concretizeRawEip?, candidateRoot] at candidateCanonical
          subst originalRaw
          subst candidateRaw
          change RawEipLiftedExecutionRelation original candidate executionRelation
            (.running originalEip originalState launch.continuationTargetIds 0 world)
            (.running candidateEip candidateState launch.continuationTargetIds 0 world)
          refine ⟨.running launch.rootTargetId originalState
              launch.continuationTargetIds 0 world,
            .running launch.rootTargetId candidateState
              launch.continuationTargetIds 0 world, ?_, ?_, logicalInitial⟩
          · exact ⟨by simp [WorldExecution.concretizeRawEip?, originalRoot],
              originalProjects⟩
          · exact ⟨by simp [WorldExecution.concretizeRawEip?, candidateRoot],
              candidateProjects⟩

def PE32RawProgramsLinkedObservationallyEquivalent (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram) : Prop :=
  launch.LinkedRealizable context graph reachability control ∧
    exists executionRelation : RawEipWorldExecution -> RawEipWorldExecution -> Prop,
      (forall world originalState candidateState,
        launch.LinkedStatesRelated context graph reachability control world
          originalState candidateState ->
        match original.canonicalRawEip? launch.rootTargetId,
            candidate.canonicalRawEip? launch.rootTargetId with
        | some originalEip, some candidateEip =>
            executionRelation
              (.running originalEip originalState launch.continuationTargetIds 0 world)
              (.running candidateEip candidateState launch.continuationTargetIds 0 world)
        | _, _ => False) ∧
      RelationalWeakBisimulation original.pe32RawEipTransitionSystem
        candidate.pe32RawEipTransitionSystem executionRelation
        (worldRelationalObservationsRelated context)

/-- Acceptance-facing linked theorem over concrete EIPs.  No finite inventory
of complete call stacks occurs in its statement or proof. -/
theorem pe32ProgramsEquivalentLinked_raw (context : StaticProofContext)
    (graph : RelationalProductGraph) (regions : List RegionRelation)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : LinkedControlAuthority)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (externalCallSites : List ExternalCallSiteContract)
    (launch : PE32ConsoleLaunchV2)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment)
    (certificate : LinkedWholeProgramCertificate context graph regions invariants
      reachability control callbackTargets externalCallSites launch originalEnvironment
      candidateEnvironment originalProtocolEnvironment candidateProtocolEnvironment) :
    PE32RawProgramsLinkedObservationallyEquivalent context graph invariants reachability
      control launch
      {
        candidate := false
        context
        regions
        externalCallSites
        environment := originalEnvironment
        protocolEnvironment := originalProtocolEnvironment
      }
      {
        candidate := true
        context
        regions
        externalCallSites
        environment := candidateEnvironment
        protocolEnvironment := candidateProtocolEnvironment
      } := by
  let original : DecodedWorldProgram := {
    candidate := false
    context
    regions
    externalCallSites
    environment := originalEnvironment
    protocolEnvironment := originalProtocolEnvironment
  }
  let candidate : DecodedWorldProgram := {
    candidate := true
    context
    regions
    externalCallSites
    environment := candidateEnvironment
    protocolEnvironment := candidateProtocolEnvironment
  }
  let executionRelation := LinkedWorldExecutionsRelated context graph invariants
    reachability control callbackTargets externalCallSites
  have initialRelated : forall world originalState candidateState,
      launch.LinkedStatesRelated context graph reachability control world
          originalState candidateState ->
      executionRelation
        (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
        (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world) := by
    intro world originalState candidateState related
    rcases related with
      ⟨frames, links, _worldValid, _originalImageMapped, _candidateImageMapped,
        stackHolds, linksAllowed, frameFactsHold, frameTargetsReachable,
        _processAttachArgumentsHold, statesRelated⟩
    rcases certificate.launchValid.2.2.2.2.2.2.2.2.1 with
      ⟨node, nodeFound, targetFound, rootFound, rootListed, invariantFound⟩
    refine ⟨rfl, rfl, rfl, rfl, launch.rootNodeId, node,
      launch.rootInvariant, frames, launch.frameOffsets.head?, links, nodeFound,
      targetFound, ?_, invariantFound, certificate.launchControlAllowed, stackHolds,
      linksAllowed, frameFactsHold, frameTargetsReachable, statesRelated⟩
    have allRoots := certificate.reachabilityClosed.2.1.2.1
    unfold RelationalProductReachabilityEvidence.rootsIncluded at allRoots
    exact List.all_eq_true.mp allRoots launch.rootNodeId
      (List.contains_iff_mem.mp rootListed)
  have logicalBisimulation :
      RelationalWeakBisimulation original.pe32TransitionSystem
        candidate.pe32TransitionSystem executionRelation
        (worldRelationalObservationsRelated context) := by
    have decodedBisimulation := linkedProductStepRefinement_of_reachable_nodes context
      graph invariants reachability control callbackTargets original candidate
      certificate.environmentsRefined certificate.protocolEnvironmentsRefined
      certificate.runningProductNodesRefined
      certificate.callbackRunningProductNodesRefined
    have originalAdequate : original.InstructionSemanticsAdequate := by
      simpa [original] using certificate.originalInstructionSemanticsAdequate
    have candidateAdequate : candidate.InstructionSemanticsAdequate := by
      simpa [candidate] using certificate.candidateInstructionSemanticsAdequate
    rw [original.pe32TransitionSystem_eq_transitionSystem originalAdequate,
      candidate.pe32TransitionSystem_eq_transitionSystem candidateAdequate]
    exact decodedBisimulation
  have bridge : RawEipPairBridgeClosed original candidate executionRelation :=
    executionFrontiersMapped_rawEipPairBridgeClosed context graph original candidate
      executionRelation
      (linkedWorldExecutionsRelated_frontiersMapped context graph invariants reachability
        control callbackTargets externalCallSites)
      rfl rfl rfl rfl certificate.staticContextValid certificate.productGraphValid
  refine ⟨certificate.launchRealizable,
    RawEipLiftedExecutionRelation original candidate executionRelation, ?_,
    relationalWeakBisimulation_rawEip_of_logical original candidate executionRelation
      logicalBisimulation bridge⟩
  intro world originalState candidateState statesRelated
  have logicalInitial := initialRelated world originalState candidateState statesRelated
  rcases bridge
      (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
      (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world)
      logicalInitial with
    ⟨originalRaw, candidateRaw, originalConcrete, candidateConcrete⟩
  rcases originalConcrete with ⟨originalCanonical, originalProjects⟩
  rcases candidateConcrete with ⟨candidateCanonical, candidateProjects⟩
  cases originalRoot : original.canonicalRawEip? launch.rootTargetId with
  | none => simp [WorldExecution.concretizeRawEip?, originalRoot] at originalCanonical
  | some originalEip =>
      cases candidateRoot : candidate.canonicalRawEip? launch.rootTargetId with
      | none => simp [WorldExecution.concretizeRawEip?, candidateRoot] at candidateCanonical
      | some candidateEip =>
          simp [WorldExecution.concretizeRawEip?, originalRoot] at originalCanonical
          simp [WorldExecution.concretizeRawEip?, candidateRoot] at candidateCanonical
          subst originalRaw
          subst candidateRaw
          change RawEipLiftedExecutionRelation original candidate executionRelation
            (.running originalEip originalState launch.continuationTargetIds 0 world)
            (.running candidateEip candidateState launch.continuationTargetIds 0 world)
          refine ⟨.running launch.rootTargetId originalState
              launch.continuationTargetIds 0 world,
            .running launch.rootTargetId candidateState
              launch.continuationTargetIds 0 world, ?_, ?_, logicalInitial⟩
          · exact ⟨by simp [WorldExecution.concretizeRawEip?, originalRoot],
              originalProjects⟩
          · exact ⟨by simp [WorldExecution.concretizeRawEip?, candidateRoot],
              candidateProjects⟩

end StageA.Relational
