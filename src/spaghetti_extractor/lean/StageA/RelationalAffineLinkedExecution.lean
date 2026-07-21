import StageA.RelationalLinkedExecution
import StageA.RelationalAffineLinkedFrames

namespace StageA.Relational

open StageA.Formal

/-- A returning-import certificate inventory covers a direct-call node only
when every active affine control state admitted at that node names a submitted
certificate for the exact decoded call edge.  The finite inventory is merely a
dispatch table: each selected certificate is checked separately against the
canonical graph, semantics, invariant, and import contract. -/
def affineReturningImportCertificatesCoverActiveCallNode
    (certificates : List
      SingletonAffineReturningImportDirectCallExecutionCertificate)
    (control : AffineLinkedProductControlProfile) (nodeId edgeId : Nat) : Bool :=
  control.states.all fun state =>
    if state.nodeId == nodeId && state.activeShape.isSome then
      certificates.any fun certificate =>
        certificate.binding.base.linkShape.callSourceNodeId == nodeId &&
          certificate.binding.base.linkShape.callEdgeId == edgeId &&
          control.states[certificate.binding.base.sourceControlStateIndex]? ==
            some state &&
          state.continuation ==
            some certificate.binding.base.linkShape.resumeContinuation
    else true

/-- Select a checked returning-import certificate from an arbitrary concrete
runtime state authorized by the affine control profile.  Coverage is checked
over the complete finite control-state inventory; the runtime `Allows` witness
then chooses the applicable row and carries the concrete affine realization. -/
theorem affineReturningImportCertificate_of_allowed
    (certificates : List
      SingletonAffineReturningImportDirectCallExecutionCertificate)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (nodeId edgeId continuation : Nat)
    (continuations : List Nat)
    (inventory : ReturnSlotOffsetInventory)
    (certificatesChecked : certificates.all (fun certificate =>
      certificate.checked context
        certificate.binding.base.sourceToSuspended.region.inputInvariant
        control affine graph) = true)
    (covered : affineReturningImportCertificatesCoverActiveCallNode certificates
      control nodeId edgeId = true)
    (allowed : control.Allows affine graph nodeId
      (continuation :: continuations) (some inventory)) :
    ∃ certificate ∈ certificates,
      certificate.checked context
          certificate.binding.base.sourceToSuspended.region.inputInvariant
          control affine graph = true ∧
        certificate.binding.base.linkShape.callSourceNodeId = nodeId ∧
        certificate.binding.base.linkShape.callEdgeId = edgeId ∧
        continuation =
          certificate.binding.base.linkShape.resumeContinuation ∧
        ∃ sourceState sourceShape,
          control.states[certificate.binding.base.sourceControlStateIndex]? =
              some sourceState ∧
            sourceState.activeShape = some sourceShape ∧
            sourceShape.Realizes affine nodeId inventory := by
  rcases allowed with
    ⟨_controlChecked, state, stateMember, stateMatches, _depthEnough⟩
  have stateRow := List.all_eq_true.mp covered state stateMember
  have stateNode : state.nodeId = nodeId := stateMatches.1
  cases shapeFound : state.activeShape with
  | none =>
      simp [AffineLinkedProductControlState.Matches, shapeFound] at stateMatches
  | some shape =>
      have activeSome : state.activeShape.isSome = true := by simp [shapeFound]
      simp [stateNode, shapeFound] at stateRow
      rcases stateRow with ⟨certificate, certificateMember, certificateRow⟩
      have certificateChecked :=
        List.all_eq_true.mp certificatesChecked certificate certificateMember
      have sourceFound :
          control.states[certificate.binding.base.sourceControlStateIndex]? =
            some state := certificateRow.1.2
      have continuationExact : continuation =
          certificate.binding.base.linkShape.resumeContinuation := by
        have continuationMatch := stateMatches.2.1
        rw [certificateRow.2] at continuationMatch
        exact Option.some.inj continuationMatch.symm
      have sourceRealizes : shape.Realizes affine nodeId inventory := by
        simpa only [shapeFound, stateNode] using stateMatches.2.2
      exact ⟨certificate, certificateMember, certificateChecked,
        certificateRow.1.1.1, certificateRow.1.1.2, continuationExact,
        state, shape, sourceFound, shapeFound, sourceRealizes⟩

/-- A finite ordinary-transition inventory covers one product-node exit when
every active affine control state at that node names a checked binding for the
exit.  The selected source state, continuation, shape, and semantic source ID
are repeated in the Boolean witness so runtime dispatch never trusts a Python
list index or an implicit uniqueness assumption. -/
def affineOrdinaryBindingsCoverActiveNodeEdge
    (bindings : List AffineLinkedOrdinaryTransitionBinding)
    (control : AffineLinkedProductControlProfile)
    (nodeId edgeId : Nat)
    (frameBinding : ReturnSlotAffineFrameSemanticTransitionBinding) : Bool :=
  control.states.all fun state =>
    if state.nodeId == nodeId && state.activeShape.isSome then
      bindings.any fun binding =>
        binding.edgeId == edgeId &&
          control.states[binding.sourceControlStateIndex]? == some state &&
          state.continuation == some binding.continuationTargetId &&
          state.activeShape == some binding.frameBinding.sourceShape &&
          binding.frameBinding.claim.transition.source.nodeId == nodeId &&
          binding.frameBinding == frameBinding
    else true

/-- Select a semantically checked ordinary binding for a concrete active
affine frame.  Coverage is checked over every submitted control state, then
the runtime `Allows` witness chooses the applicable row. -/
theorem affineOrdinaryBinding_of_allowed
    (bindings : List AffineLinkedOrdinaryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (frameBinding : ReturnSlotAffineFrameSemanticTransitionBinding)
    (nodeId edgeId continuation : Nat)
    (continuations : List Nat)
    (inventory : ReturnSlotOffsetInventory)
    (bindingsChecked : bindings.all (fun binding =>
      binding.checked context control affine graph) = true)
    (covered : affineOrdinaryBindingsCoverActiveNodeEdge bindings control
      nodeId edgeId frameBinding = true)
    (allowed : control.Allows affine graph nodeId
      (continuation :: continuations) (some inventory)) :
    ∃ binding ∈ bindings,
      binding.checked context control affine graph = true ∧
        binding.edgeId = edgeId ∧
        binding.frameBinding.claim.transition.source.nodeId = nodeId ∧
        binding.frameBinding = frameBinding ∧
        continuation = binding.continuationTargetId ∧
        binding.frameBinding.sourceShape.Realizes affine
          binding.frameBinding.claim.transition.source.nodeId inventory := by
  rcases allowed with
    ⟨_controlChecked, state, stateMember, stateMatches, _depthEnough⟩
  have stateRow := List.all_eq_true.mp covered state stateMember
  have stateNode : state.nodeId = nodeId := stateMatches.1
  cases shapeFound : state.activeShape with
  | none =>
      simp [AffineLinkedProductControlState.Matches, shapeFound] at stateMatches
  | some shape =>
      have activeSome : state.activeShape.isSome = true := by
        simp [shapeFound]
      simp [stateNode, shapeFound] at stateRow
      rcases stateRow with ⟨binding, bindingMember, bindingRow⟩
      have bindingChecked :=
        List.all_eq_true.mp bindingsChecked binding bindingMember
      have sourceShape :
          state.activeShape = some binding.frameBinding.sourceShape :=
        by rw [shapeFound, bindingRow.1.1.2]
      have sourceNode :
          binding.frameBinding.claim.transition.source.nodeId = nodeId :=
        bindingRow.1.2
      have frameBindingExact : binding.frameBinding = frameBinding :=
        bindingRow.2
      have selectedMatches := stateMatches
      simp only [AffineLinkedProductControlState.Matches, sourceShape,
        List.head?_cons] at selectedMatches
      have continuationExact :
          continuation = binding.continuationTargetId := by
        have stateContinuation := selectedMatches.2.1
        rw [bindingRow.1.1.1.2] at stateContinuation
        exact Option.some.inj stateContinuation.symm
      have sourceRealizes : binding.frameBinding.sourceShape.Realizes affine
          binding.frameBinding.claim.transition.source.nodeId inventory := by
        rw [sourceNode]
        exact selectedMatches.2.2
      exact ⟨binding, bindingMember, bindingChecked, bindingRow.1.1.1.1.1,
        sourceNode, frameBindingExact, continuationExact, sourceRealizes⟩

/-- Combine the affine control/frame transfer with the active-fact obligation
used by linked whole-program execution.  Payload preservation is checked from
the exact normalized behaviors, not inferred from proposal metadata. -/
theorem AffineLinkedOrdinaryTransitionBinding.afterNoWriteNestedWithFacts
    (binding : AffineLinkedOrdinaryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context control affine graph = true)
    (sourceRealizes : binding.frameBinding.sourceShape.Realizes affine
      binding.frameBinding.claim.transition.source.nodeId sourceInventory)
    (continuationExact : continuation = binding.continuationTargetId)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some sourceInventory) originalState.registers candidateState.registers)
    (originalMemory :
      ((binding.frameBinding.claim.originalNormalized.eval
        originalState).nextMachineState originalState).memory =
        originalState.memory)
    (candidateMemory :
      ((binding.frameBinding.claim.candidateNormalized.eval
        candidateState).nextMachineState candidateState).memory =
        candidateState.memory) :
    ∃ targetInventory,
      binding.frameBinding.targetShape.Realizes affine
          binding.frameBinding.claim.transition.target.nodeId targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds context
          ((binding.frameBinding.claim.originalNormalized.eval
            originalState).nextMachineState originalState)
          ((binding.frameBinding.claim.candidateNormalized.eval
            candidateState).nextMachineState candidateState)
          (frame :: frames) (continuation :: continuations)
          (some targetInventory) links ∧
        control.Allows affine graph
          binding.frameBinding.claim.transition.target.nodeId
          (continuation :: continuations) (some targetInventory) ∧
        RelationalLinkedRuntimeCallFactsHold context world (some targetInventory)
          (binding.frameBinding.claim.originalNormalized.eval
            originalState).registers
          (binding.frameBinding.claim.candidateNormalized.eval
            candidateState).registers := by
  obtain ⟨targetInventory, targetRealizes, targetStack, targetControl⟩ :=
    binding.afterNoWriteNested context control affine graph originalState
      candidateState frame frames continuation continuations links sourceInventory
      checked sourceRealizes continuationExact stackHolds originalMemory candidateMemory
  have frameChecked := binding.frame_checked_of_checked context control affine graph
    checked
  have payloadFacts := binding.frameBinding.facts_checked_of_checked context affine
    graph frameChecked
  have payloadExact := binding.frameBinding.payload_eq_of_checked context affine
    graph frameChecked
  have sourcePayload := binding.frameBinding.sourceShape.payload_eq_of_realizes
    affine binding.frameBinding.claim.transition.source.nodeId sourceInventory
    sourceRealizes
  have targetPayload := binding.frameBinding.targetShape.payload_eq_of_realizes
    affine binding.frameBinding.claim.transition.target.nodeId targetInventory
    targetRealizes
  have sourceStackFacts := stackHolds
  simp only [RelationalLinkedRuntimeCallStackHolds] at sourceStackFacts
  have sourceChecked := sourceStackFacts.1
  simp only [ReturnSlotAffineInventoryShape.factsPreservedAcross,
    Bool.and_eq_true] at payloadFacts
  rcases payloadFacts with
    ⟨⟨⟨importsPreserved, relationsUnambiguous⟩, relationsStatic⟩,
      relationsPreserved⟩
  have sourceImportsAcross : sourceInventory.preservesImportsAcross
      binding.frameBinding.claim.originalNormalized
      binding.frameBinding.claim.candidateNormalized = true := by
    simp only [ReturnSlotOffsetInventory.preservesImportsAcross,
      Bool.and_eq_true]
    refine ⟨sourceChecked, ?_⟩
    simpa only [sourcePayload.2.1] using importsPreserved
  have sourceRelationsAcross : sourceInventory.preservesRelationsAcross context
      binding.frameBinding.claim.originalNormalized
      binding.frameBinding.claim.candidateNormalized = true := by
    simp only [ReturnSlotOffsetInventory.preservesRelationsAcross,
      ReturnSlotOffsetInventory.preservedRelationsChecked, Bool.and_eq_true]
    refine ⟨⟨⟨sourceChecked, ?_⟩, ?_⟩, ?_⟩
    · unfold ReturnSlotOffsetInventory.preservedRelationsUnambiguous at relationsUnambiguous
      unfold ReturnSlotOffsetInventory.preservedRelationsUnambiguous
      simpa only [sourcePayload.2.2,
        ReturnSlotAffineInventoryShape.toInventory] using relationsUnambiguous
    · rw [sourcePayload.2.2]
      exact relationsStatic
    · rw [sourcePayload.2.2]
      exact relationsPreserved
  have importsAfter := sourceInventory.preservedImportsHold_after_of_checked
    world binding.frameBinding.claim.originalNormalized
    binding.frameBinding.claim.candidateNormalized originalState candidateState
    sourceImportsAcross factsHold.1
  have relationsAfter := sourceInventory.preservedRelationsHold_after_of_checked
    context world binding.frameBinding.claim.originalNormalized
    binding.frameBinding.claim.candidateNormalized originalState candidateState
    sourceRelationsAcross factsHold.2
  have targetImports : targetInventory.preservedImports =
      sourceInventory.preservedImports := by
    calc
      targetInventory.preservedImports =
          binding.frameBinding.targetShape.preservedImports := targetPayload.2.1
      _ = binding.frameBinding.sourceShape.preservedImports := payloadExact.2.1.symm
      _ = sourceInventory.preservedImports := sourcePayload.2.1.symm
  have targetRelations : targetInventory.preservedRelations =
      sourceInventory.preservedRelations := by
    calc
      targetInventory.preservedRelations =
          binding.frameBinding.targetShape.preservedRelations := targetPayload.2.2
      _ = binding.frameBinding.sourceShape.preservedRelations := payloadExact.2.2.symm
      _ = sourceInventory.preservedRelations := sourcePayload.2.2.symm
  refine ⟨targetInventory, targetRealizes, targetStack, targetControl, ?_⟩
  simp only [RelationalLinkedRuntimeCallFactsHold]
  constructor
  · unfold ReturnSlotOffsetInventory.preservedImportsHold at importsAfter ⊢
    rw [targetImports]
    exact importsAfter
  · unfold ReturnSlotOffsetInventory.preservedRelationsHold at relationsAfter ⊢
    rw [targetRelations]
    exact relationsAfter

/-- Lift a checked ordinary affine transition to the successor-state relation
used by linked whole-program execution.  The caller supplies the ordinary
segment refinement's target `StateRel`; this theorem assembles that result with
the affine control, runtime-frame, dormant-link, and active-fact witnesses. -/
theorem AffineLinkedOrdinaryTransitionBinding.nextRunningRelated
    (binding : AffineLinkedOrdinaryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (eventIndex : Nat)
    (targetNode : RelationalProductNode)
    (targetInvariant : StateInvariant)
    (checked : binding.checked context control affine graph = true)
    (sourceRealizes : binding.frameBinding.sourceShape.Realizes affine
      binding.frameBinding.claim.transition.source.nodeId sourceInventory)
    (continuationExact : continuation = binding.continuationTargetId)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (linksAllowed : control.LinksAllowed affine graph links)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some sourceInventory) originalState.registers candidateState.registers)
    (targetNodeFound : graph.getNode?
      binding.frameBinding.claim.transition.target.nodeId = some targetNode)
    (targetInvariantFound : invariants.nodeInvariants[
      binding.frameBinding.claim.transition.target.nodeId]? = some targetInvariant)
    (targetReachable : reachability.contains
      binding.frameBinding.claim.transition.target.nodeId = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped graph reachability
      (continuation :: continuations))
    (nextStatesRelated : StateRel context world targetInvariant
      ((binding.frameBinding.claim.originalNormalized.eval
        originalState).nextMachineState originalState)
      ((binding.frameBinding.claim.candidateNormalized.eval
        candidateState).nextMachineState candidateState))
    (originalMemory :
      ((binding.frameBinding.claim.originalNormalized.eval
        originalState).nextMachineState originalState).memory =
        originalState.memory)
    (candidateMemory :
      ((binding.frameBinding.claim.candidateNormalized.eval
        candidateState).nextMachineState candidateState).memory =
        candidateState.memory) :
    LinkedWorldExecutionsRelated context graph invariants reachability
      (control.authority affine graph) callbackTargets sites
      (.running targetNode.targetId
        ((binding.frameBinding.claim.originalNormalized.eval
          originalState).nextMachineState originalState)
        (continuation :: continuations) eventIndex world)
      (.running targetNode.targetId
        ((binding.frameBinding.claim.candidateNormalized.eval
          candidateState).nextMachineState candidateState)
        (continuation :: continuations) eventIndex world) := by
  obtain ⟨targetInventory, targetRealizes, targetStack, targetControl,
      targetFacts⟩ :=
    binding.afterNoWriteNestedWithFacts context control affine graph world
      originalState candidateState frame frames continuation continuations links
      sourceInventory checked sourceRealizes continuationExact stackHolds factsHold
      originalMemory candidateMemory
  refine ⟨rfl, rfl, rfl, rfl,
    binding.frameBinding.claim.transition.target.nodeId, targetNode,
    targetInvariant, frame :: frames, some targetInventory, links,
    targetNodeFound, rfl, targetReachable, targetInvariantFound, ?_, targetStack,
    linksAllowed, targetFacts, stackTargetsMapped, nextStatesRelated⟩
  change control.Allows affine graph
    binding.frameBinding.claim.transition.target.nodeId
    (continuation :: continuations) (some targetInventory)
  exact targetControl

/-- Lift one checked singleton returning-import call into the linked execution
relation at the import thunk.  The static call binding deliberately does not
invent the caller inventory transfer or a concrete runtime link: both remain
explicit checked evidence.  Likewise the local segment proof supplies the
target `StateRel`; this theorem only performs sound call-stack and control
composition around it. -/
theorem SingletonAffineReturningImportDirectCallControlBinding.nextRunningRelatedAtThunk
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (eventIndex : Nat)
    (targetNode : RelationalProductNode)
    (outerClaim : ReturnSlotFrameInventoryTransferClaim)
    (checked : binding.checked context sourceInvariant control affine graph = true)
    (sourceStack : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (outer :: frames)
      (link.resumeContinuation :: continuations) (some sourceInventory) links)
    (linksAllowed : control.LinksAllowed affine graph links)
    (linkRealizes : binding.base.linkShape.Realizes affine link)
    (linkHolds : link.holds inner outer)
    (frameResult : binding.base.innerSeed.callPush.runtimeFrame context
      originalState candidateState = some inner)
    (innerHolds : link.innerInventory.holds inner
      (binding.base.sourceToSuspended.originalNormalized.eval
        originalState).registers
      (binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).registers)
    (innerExactWords : link.innerInventory.boundedExactWordsHold inner
      ((binding.base.sourceToSuspended.originalNormalized.eval
        originalState).nextMachineState originalState).memory
      ((binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).nextMachineState candidateState).memory)
    (innerValid : inner.valid context = true)
    (innerResolves : inner.toRelationalCallFrame.resolves context = true)
    (outerClaimSource : outerClaim.source = sourceInventory)
    (outerClaimTarget : outerClaim.target = link.suspendedInventory)
    (outerClaimChecked : outerClaim.checked context sourceInvariant
      binding.base.sourceToSuspended.originalNormalized
      binding.base.sourceToSuspended.candidateNormalized = true)
    (sourceRelated : StateRel context world sourceInvariant
      originalState candidateState)
    (targetNodeFound : graph.getNode? binding.externalSummary.thunkNodeId =
      some targetNode)
    (targetInvariantFound : invariants.nodeInvariants[
      binding.externalSummary.thunkNodeId]? = some targetInvariant)
    (targetReachable : reachability.contains
      binding.externalSummary.thunkNodeId = true)
    (targetControl : control.Allows affine graph
      binding.externalSummary.thunkNodeId
      (link.resumeTargetId :: link.resumeContinuation :: continuations)
      (some link.innerInventory))
    (targetSeeded : link.innerInventory.seededByInvariant targetInvariant = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped graph reachability
      (link.resumeTargetId :: link.resumeContinuation :: continuations))
    (targetRelated : StateRel context world targetInvariant
      ((binding.base.sourceToSuspended.originalNormalized.eval
        originalState).nextMachineState originalState)
      ((binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).nextMachineState candidateState)) :
    LinkedWorldExecutionsRelated context graph invariants reachability
      (control.authority affine graph) callbackTargets sites
      (.running targetNode.targetId
        ((binding.base.sourceToSuspended.originalNormalized.eval
          originalState).nextMachineState originalState)
        (link.resumeTargetId :: link.resumeContinuation :: continuations)
        eventIndex world)
      (.running targetNode.targetId
        ((binding.base.sourceToSuspended.candidateNormalized.eval
          candidateState).nextMachineState candidateState)
        (link.resumeTargetId :: link.resumeContinuation :: continuations)
        eventIndex world) := by
  have semanticFacts := binding.semantic_facts_of_checked context sourceInvariant
    control affine graph checked
  rcases semanticFacts with
    ⟨_returnsEmpty, _sourceTransferChecked, _innerSeedChecked,
      _sourceTransitionMember, _seedMember, shapeAllowed, _ordinary,
      _transitionEdge, _linkEdge, _sourceNode, _innerNode, _suspendedNode,
      _seedNode, _continuation, _sourceTarget, _sourceRegion,
      _originalNormalized, _candidateNormalized, _thunkNode,
      _externalSummaryChecked, singletonWriteChecked⟩
  have pushedMemory :=
    binding.base.innerSeed.callPush.singletonWriteMemory_of_checked context
      binding.base.sourceToSuspended.originalNormalized
      binding.base.sourceToSuspended.candidateNormalized inner originalState
      candidateState singletonWriteChecked frameResult
  have innerMemory : inner.memoryHolds
      ((binding.base.sourceToSuspended.originalNormalized.eval
        originalState).nextMachineState originalState).memory
      ((binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).nextMachineState candidateState).memory := by
    rw [pushedMemory.1, pushedMemory.2]
    exact inner.memoryHolds_afterOwnWrite originalState.memory candidateState.memory
      linkHolds.2.2.1 linkHolds.2.2.2.1
  have sourceForClaim : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (outer :: frames)
      (link.resumeContinuation :: continuations) (some outerClaim.source) links := by
    simpa only [outerClaimSource] using sourceStack
  have stackNext :=
    RelationalLinkedRuntimeCallStackHolds.pushNestedAfterSingletonWrite
      context world sourceInvariant
      binding.base.sourceToSuspended.originalNormalized
      binding.base.sourceToSuspended.candidateNormalized outerClaim originalState
      candidateState inner outer frames continuations link links sourceForClaim
      outerClaimChecked sourceRelated linkHolds outerClaimTarget innerHolds
      innerExactWords innerValid innerResolves innerMemory pushedMemory.1 pushedMemory.2
  have linksNext : control.LinksAllowed affine graph (link :: links) :=
    AffineLinkedProductControlProfile.LinksAllowed.cons control affine graph
      binding.base.linkShape link links shapeAllowed linkRealizes linksAllowed
  have factsNext := RelationalLinkedRuntimeCallFactsHold.of_stateRel context world
    targetInvariant link.innerInventory
    ((binding.base.sourceToSuspended.originalNormalized.eval
      originalState).nextMachineState originalState)
    ((binding.base.sourceToSuspended.candidateNormalized.eval
      candidateState).nextMachineState candidateState)
    targetSeeded targetRelated
  refine ⟨rfl, rfl, rfl, rfl, binding.externalSummary.thunkNodeId,
    targetNode, targetInvariant, inner :: outer :: frames,
    some link.innerInventory, link :: links, targetNodeFound, rfl,
    targetReachable, targetInvariantFound, targetControl, stackNext, linksNext,
    factsNext, stackTargetsMapped, targetRelated⟩

/-- Execution-facing call-entry wrapper for one checked certificate.  Runtime
shape equalities remain explicit because they connect the static affine family
to the concrete frame/link chosen for this execution. -/
theorem SingletonAffineReturningImportDirectCallExecutionCertificate.nextRunningRelatedAtThunk
    (certificate : SingletonAffineReturningImportDirectCallExecutionCertificate)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (world : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (eventIndex : Nat)
    (targetNode : RelationalProductNode)
    (checked : certificate.checked context sourceInvariant control affine graph = true)
    (sourceStack : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (outer :: frames)
      (link.resumeContinuation :: continuations) (some sourceInventory) links)
    (linksAllowed : control.LinksAllowed affine graph links)
    (linkRealizes : certificate.binding.base.linkShape.Realizes affine link)
    (linkHolds : link.holds inner outer)
    (frameResult : certificate.binding.base.innerSeed.callPush.runtimeFrame context
      originalState candidateState = some inner)
    (innerHolds : link.innerInventory.holds inner
      (certificate.binding.base.sourceToSuspended.originalNormalized.eval
        originalState).registers
      (certificate.binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).registers)
    (innerExactWords : link.innerInventory.boundedExactWordsHold inner
      ((certificate.binding.base.sourceToSuspended.originalNormalized.eval
        originalState).nextMachineState originalState).memory
      ((certificate.binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).nextMachineState candidateState).memory)
    (innerValid : inner.valid context = true)
    (innerResolves : inner.toRelationalCallFrame.resolves context = true)
    (entrySource : certificate.entryClaim.source = sourceInventory)
    (entryTarget : certificate.entryClaim.target = link.suspendedInventory)
    (sourceRelated : StateRel context world sourceInvariant
      originalState candidateState)
    (targetNodeFound : graph.getNode?
      certificate.binding.externalSummary.thunkNodeId = some targetNode)
    (targetInvariantFound : invariants.nodeInvariants[
      certificate.binding.externalSummary.thunkNodeId]? = some targetInvariant)
    (targetReachable : reachability.contains
      certificate.binding.externalSummary.thunkNodeId = true)
    (targetControl : control.Allows affine graph
      certificate.binding.externalSummary.thunkNodeId
      (link.resumeTargetId :: link.resumeContinuation :: continuations)
      (some link.innerInventory))
    (targetSeeded : link.innerInventory.seededByInvariant targetInvariant = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped graph reachability
      (link.resumeTargetId :: link.resumeContinuation :: continuations))
    (targetRelated : StateRel context world targetInvariant
      ((certificate.binding.base.sourceToSuspended.originalNormalized.eval
        originalState).nextMachineState originalState)
      ((certificate.binding.base.sourceToSuspended.candidateNormalized.eval
        candidateState).nextMachineState candidateState)) :
    LinkedWorldExecutionsRelated context graph invariants reachability
      (control.authority affine graph) callbackTargets sites
      (.running targetNode.targetId
        ((certificate.binding.base.sourceToSuspended.originalNormalized.eval
          originalState).nextMachineState originalState)
        (link.resumeTargetId :: link.resumeContinuation :: continuations)
        eventIndex world)
      (.running targetNode.targetId
        ((certificate.binding.base.sourceToSuspended.candidateNormalized.eval
          candidateState).nextMachineState candidateState)
        (link.resumeTargetId :: link.resumeContinuation :: continuations)
        eventIndex world) := by
  let facts := certificate.checkedFacts context sourceInvariant control affine graph
    checked
  exact certificate.binding.nextRunningRelatedAtThunk context control affine graph
    invariants reachability callbackTargets sites world sourceInvariant
    targetInvariant originalState candidateState inner outer frames continuations link
    links sourceInventory eventIndex targetNode certificate.entryClaim
    facts.bindingChecked sourceStack linksAllowed linkRealizes linkHolds frameResult
    innerHolds innerExactWords innerValid innerResolves entrySource entryTarget
    facts.entryChecked sourceRelated targetNodeFound targetInvariantFound
    targetReachable targetControl targetSeeded stackTargetsMapped targetRelated

/-- Resume the suspended caller after one exact returning imported interaction.
The environment may change unrelated memory and the relational world, but it
must supply the machine ABI results and preserve every dormant frame word.  A
full inventory transfer, rather than the pair-level diagnostic summary, carries
the suspended caller facts to the resume cutpoint. -/
theorem SingletonAffineReturningImportDirectCallControlBinding.nextRunningRelatedAfterExternalJump
    (binding : SingletonAffineReturningImportDirectCallControlBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (sourceWorld resultWorld : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState originalResult candidateResult : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (eventIndex : Nat)
    (targetNode : RelationalProductNode)
    (contract : MachineImportCallContract)
    (inventoryClaim : ExternalJumpReturnSlotInventoryTransferClaim)
    (checked : binding.checked context sourceInvariant control affine graph = true)
    (sourceStack : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (inner :: outer :: frames)
      (link.resumeTargetId :: link.resumeContinuation :: continuations)
      (some link.innerInventory) (link :: links))
    (linksAllowed : control.LinksAllowed affine graph (link :: links))
    (sourceRelated : StateRel context sourceWorld sourceInvariant
      originalState candidateState)
    (inventorySource : inventoryClaim.source = link.suspendedInventory)
    (inventoryTarget : inventoryClaim.target = link.resumeInventory)
    (canonicalInventoryChecked :
      machineImportCallContractById? context
          binding.externalSummary.machineContractId = some contract ∧
        inventoryClaim.checked context sourceInvariant
          binding.externalSummary.originalNormalized
          binding.externalSummary.candidateNormalized contract = true)
    (originalAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((binding.externalSummary.originalNormalized.eval
          originalState).nextMachineState originalState)) originalResult = true)
    (candidateAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((binding.externalSummary.candidateNormalized.eval
          candidateState).nextMachineState candidateState)) candidateResult = true)
    (boundaryFrames : RelationalRuntimeCallFramesHold context
      (normalizeImportReturnSlotState
        ((binding.externalSummary.originalNormalized.eval
          originalState).nextMachineState originalState))
      (normalizeImportReturnSlotState
        ((binding.externalSummary.candidateNormalized.eval
          candidateState).nextMachineState candidateState))
      (outer :: frames) (link.resumeContinuation :: continuations))
    (boundaryLinks : RelationalRuntimeCallFrameLinksHold
      (normalizeImportReturnSlotState
        ((binding.externalSummary.originalNormalized.eval
          originalState).nextMachineState originalState)).memory
      (normalizeImportReturnSlotState
        ((binding.externalSummary.candidateNormalized.eval
          candidateState).nextMachineState candidateState)).memory
      (outer :: frames) links)
    (framesPreserved : ∀ (frame : RelationalRuntimeCallFrame)
        (inventory : ReturnSlotOffsetInventory),
      frame.memoryHolds
          (normalizeImportReturnSlotState
            ((binding.externalSummary.originalNormalized.eval
              originalState).nextMachineState originalState)).memory
          (normalizeImportReturnSlotState
            ((binding.externalSummary.candidateNormalized.eval
              candidateState).nextMachineState candidateState)).memory →
      inventory.exactWordsHold frame
          (normalizeImportReturnSlotState
            ((binding.externalSummary.originalNormalized.eval
              originalState).nextMachineState originalState)).memory
          (normalizeImportReturnSlotState
            ((binding.externalSummary.candidateNormalized.eval
              candidateState).nextMachineState candidateState)).memory →
        frame.memoryHolds originalResult.memory candidateResult.memory ∧
          inventory.exactWordsHold frame originalResult.memory candidateResult.memory)
    (targetNodeFound : graph.getNode? link.resumeNodeId = some targetNode)
    (targetTargetExact : targetNode.targetId = link.resumeTargetId)
    (targetInvariantFound : invariants.nodeInvariants[link.resumeNodeId]? =
      some targetInvariant)
    (targetReachable : reachability.contains link.resumeNodeId = true)
    (resumeShapesUnique : control.linkShapes.all (fun candidate =>
      decide (candidate.resumeTargetId = link.resumeTargetId →
        candidate = binding.base.linkShape)) = true)
    (targetSeeded : link.resumeInventory.seededByInvariant targetInvariant = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped graph reachability
      (link.resumeContinuation :: continuations))
    (targetRelated : StateRel context resultWorld targetInvariant
      originalResult candidateResult) :
    LinkedWorldExecutionsRelated context graph invariants reachability
      (control.authority affine graph) callbackTargets sites
      (.running link.resumeTargetId originalResult
        (link.resumeContinuation :: continuations) (eventIndex + 1) resultWorld)
      (.running link.resumeTargetId candidateResult
        (link.resumeContinuation :: continuations) (eventIndex + 1) resultWorld) := by
  have stackParts := sourceStack
  simp only [RelationalLinkedRuntimeCallStackHolds] at stackParts
  rcases stackParts with
    ⟨_activeChecked, activeHolds, _activeExactWords, sourceFrames,
      sourceLinks⟩
  have sourceFramesParts := sourceFrames
  simp only [RelationalRuntimeCallFramesHold] at sourceFramesParts
  have outerFramesSource := sourceFramesParts.2.2.2.2
  have sourceLinksParts := sourceLinks
  simp only [RelationalRuntimeCallFrameLinksHold] at sourceLinksParts
  have linkHolds := sourceLinksParts.1
  have suspendedHolds := link.suspendedInventoryHolds inner outer
    originalState.registers candidateState.registers linkHolds activeHolds
  have outerMemory := outerFramesSource.2.2.2.1
  have suspendedExact := sourceLinksParts.2.1
  have outerProtected : outer.protectedSpanValid context = true := by
    have outerValid := outerFramesSource.2.1
    simp only [RelationalRuntimeCallFrame.valid, Bool.and_eq_true] at outerValid
    exact outerValid.2
  have semanticFacts := binding.semantic_facts_of_checked context sourceInvariant
    control affine graph checked
  rcases semanticFacts with
    ⟨_returnsEmpty, _sourceTransferChecked, _innerSeedChecked,
      _sourceTransitionMember, _seedMember, shapeAllowed, _ordinary,
      _transitionEdge, _linkEdge, _sourceNode, _innerNode, _suspendedNode,
      _seedNode, _continuation, _sourceTarget, _sourceRegion,
      _originalNormalized, _candidateNormalized, _thunkNode,
      _externalSummaryChecked, _singletonWriteChecked⟩
  have resumeUnique : control.selectsUniqueResumeShape affine graph
      link.resumeTargetId binding.base.linkShape = true := by
    simp only [AffineLinkedProductControlProfile.selectsUniqueResumeShape,
      Bool.and_eq_true]
    exact ⟨shapeAllowed, resumeShapesUnique⟩
  have transferred := externalJumpReturnSlotInventoryTransferHolds_of_checked
    context sourceWorld sourceInvariant binding.externalSummary.originalNormalized
    binding.externalSummary.candidateNormalized contract inventoryClaim outer
    originalState candidateState originalResult candidateResult
    canonicalInventoryChecked.2
    (by simpa only [inventorySource] using suspendedHolds) outerMemory
    (by simpa only [inventorySource] using suspendedExact) outerProtected
    sourceRelated originalAbi candidateAbi
    (framesPreserved outer inventoryClaim.target)
  have tailAfter := RelationalRuntimeCallTailHolds.afterMemory context
    (normalizeImportReturnSlotState
      ((binding.externalSummary.originalNormalized.eval
        originalState).nextMachineState originalState))
    (normalizeImportReturnSlotState
      ((binding.externalSummary.candidateNormalized.eval
        candidateState).nextMachineState candidateState))
    originalResult candidateResult (outer :: frames)
    (link.resumeContinuation :: continuations) links boundaryFrames boundaryLinks
    framesPreserved
  have stackNext := RelationalLinkedRuntimeCallStackHolds.popNestedAfter context
    originalState candidateState originalResult candidateResult inner outer frames
    link.resumeTargetId link.resumeContinuation continuations link.innerInventory
    link links sourceStack tailAfter.1 tailAfter.2
    (by simpa only [inventoryTarget] using transferred.1)
    (by simpa only [inventoryTarget] using transferred.2.2)
  have controlNext := control.allowsResumeOfRealizedHead affine graph
    binding.base.linkShape link links continuations resumeUnique linksAllowed
  have linksNext := AffineLinkedProductControlProfile.LinksAllowed.tail control
    affine graph link links linksAllowed
  have factsNext := RelationalLinkedRuntimeCallFactsHold.of_stateRel context
    resultWorld targetInvariant link.resumeInventory originalResult candidateResult
    targetSeeded targetRelated
  refine ⟨rfl, rfl, rfl, rfl, link.resumeNodeId, targetNode, targetInvariant,
    outer :: frames, some link.resumeInventory, links, targetNodeFound,
    targetTargetExact, targetReachable, targetInvariantFound, controlNext, stackNext,
    linksNext, factsNext, stackTargetsMapped, targetRelated⟩

/-- Execution-facing import-return wrapper for one checked certificate.  The
external environment still supplies its concrete ABI result and preservation
witnesses; the static inventory and canonical-contract checks come exclusively
from the certificate. -/
theorem SingletonAffineReturningImportDirectCallExecutionCertificate.nextRunningRelatedAfterExternalJump
    (certificate : SingletonAffineReturningImportDirectCallExecutionCertificate)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (callbackTargets : ProtocolCallbackTargetProfile)
    (sites : List ExternalCallSiteContract)
    (sourceWorld resultWorld : RelationalWorld)
    (sourceInvariant targetInvariant : StateInvariant)
    (originalState candidateState originalResult candidateResult : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuations : List Nat)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (eventIndex : Nat)
    (targetNode : RelationalProductNode)
    (contract : MachineImportCallContract)
    (checked : certificate.checked context sourceInvariant control affine graph = true)
    (sourceStack : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (inner :: outer :: frames)
      (link.resumeTargetId :: link.resumeContinuation :: continuations)
      (some link.innerInventory) (link :: links))
    (linksAllowed : control.LinksAllowed affine graph (link :: links))
    (sourceRelated : StateRel context sourceWorld sourceInvariant
      originalState candidateState)
    (resumeSource : certificate.resumeClaim.source = link.suspendedInventory)
    (resumeTarget : certificate.resumeClaim.target = link.resumeInventory)
    (canonicalContract : machineImportCallContractById? context
      certificate.binding.externalSummary.machineContractId = some contract)
    (originalAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((certificate.binding.externalSummary.originalNormalized.eval
          originalState).nextMachineState originalState)) originalResult = true)
    (candidateAbi : machineCallAbiResultHolds contract
      (normalizeImportReturnSlotState
        ((certificate.binding.externalSummary.candidateNormalized.eval
          candidateState).nextMachineState candidateState)) candidateResult = true)
    (boundaryFrames : RelationalRuntimeCallFramesHold context
      (normalizeImportReturnSlotState
        ((certificate.binding.externalSummary.originalNormalized.eval
          originalState).nextMachineState originalState))
      (normalizeImportReturnSlotState
        ((certificate.binding.externalSummary.candidateNormalized.eval
          candidateState).nextMachineState candidateState))
      (outer :: frames) (link.resumeContinuation :: continuations))
    (boundaryLinks : RelationalRuntimeCallFrameLinksHold
      (normalizeImportReturnSlotState
        ((certificate.binding.externalSummary.originalNormalized.eval
          originalState).nextMachineState originalState)).memory
      (normalizeImportReturnSlotState
        ((certificate.binding.externalSummary.candidateNormalized.eval
          candidateState).nextMachineState candidateState)).memory
      (outer :: frames) links)
    (framesPreserved : ∀ (frame : RelationalRuntimeCallFrame)
        (inventory : ReturnSlotOffsetInventory),
      frame.memoryHolds
          (normalizeImportReturnSlotState
            ((certificate.binding.externalSummary.originalNormalized.eval
              originalState).nextMachineState originalState)).memory
          (normalizeImportReturnSlotState
            ((certificate.binding.externalSummary.candidateNormalized.eval
              candidateState).nextMachineState candidateState)).memory →
      inventory.exactWordsHold frame
          (normalizeImportReturnSlotState
            ((certificate.binding.externalSummary.originalNormalized.eval
              originalState).nextMachineState originalState)).memory
          (normalizeImportReturnSlotState
            ((certificate.binding.externalSummary.candidateNormalized.eval
              candidateState).nextMachineState candidateState)).memory →
        frame.memoryHolds originalResult.memory candidateResult.memory ∧
          inventory.exactWordsHold frame originalResult.memory candidateResult.memory)
    (targetNodeFound : graph.getNode? link.resumeNodeId = some targetNode)
    (targetTargetExact : targetNode.targetId = link.resumeTargetId)
    (targetInvariantFound : invariants.nodeInvariants[link.resumeNodeId]? =
      some targetInvariant)
    (targetReachable : reachability.contains link.resumeNodeId = true)
    (resumeShapesUnique : control.linkShapes.all (fun candidate =>
      decide (candidate.resumeTargetId = link.resumeTargetId →
        candidate = certificate.binding.base.linkShape)) = true)
    (targetSeeded : link.resumeInventory.seededByInvariant targetInvariant = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped graph reachability
      (link.resumeContinuation :: continuations))
    (targetRelated : StateRel context resultWorld targetInvariant
      originalResult candidateResult) :
    LinkedWorldExecutionsRelated context graph invariants reachability
      (control.authority affine graph) callbackTargets sites
      (.running link.resumeTargetId originalResult
        (link.resumeContinuation :: continuations) (eventIndex + 1) resultWorld)
      (.running link.resumeTargetId candidateResult
        (link.resumeContinuation :: continuations) (eventIndex + 1) resultWorld) := by
  let facts := certificate.checkedFacts context sourceInvariant control affine graph
    checked
  have contractExact : facts.contract = contract := by
    rw [facts.contractFound] at canonicalContract
    exact Option.some.inj canonicalContract
  subst contract
  exact certificate.binding.nextRunningRelatedAfterExternalJump context control affine
    graph invariants reachability callbackTargets sites sourceWorld resultWorld
    sourceInvariant targetInvariant originalState candidateState originalResult
    candidateResult inner outer frames continuations link links eventIndex targetNode
    facts.contract certificate.resumeClaim facts.bindingChecked sourceStack linksAllowed
    sourceRelated resumeSource resumeTarget ⟨facts.contractFound, facts.resumeChecked⟩
    originalAbi candidateAbi boundaryFrames boundaryLinks framesPreserved targetNodeFound
    targetTargetExact targetInvariantFound targetReachable resumeShapesUnique targetSeeded
    stackTargetsMapped targetRelated

end StageA.Relational
