import StageA.RelationalInternalDirectCallRegisterSummary
import StageA.RelationalCertificates

namespace StageA.Relational.InternalDirectCallComposition

open StageA.Formal StageA.Relational
open StageA.Relational.InternalDirectCallRegisterSummary

/-!
# Semantic composition for exact internal direct-call summaries

`RelationalInternalDirectCallRegisterSummary` deliberately checks only finite
structural evidence.  This module is the semantic boundary that may consume
that evidence.  In particular, graph reachability is never interpreted as an
execution theorem.

The semantic object below has three layers:

* exact call-entry and edge authorities connect the summary to the canonical
  PE decoder, `RelationalSegmentRefinement`, external-call refinement, and a
  concrete runtime return frame;
* an explicit inductive invariant is proved along every finite admitted path;
* a checked return step turns that invariant into the requested register and
  frame postcondition.

Nested calls consume another semantic contract, not another bare structural
summary.  Cyclic graphs additionally require an acyclic proof or a ranking
function.  An incomplete loop frontier is representable, but it cannot inhabit
`IntegratedSummaryPremises` and therefore cannot authorize composition.
-/

abbrev SummaryCertificate :=
  StageA.Relational.InternalDirectCallRegisterSummary.Certificate
abbrev SummaryTree :=
  StageA.Relational.InternalDirectCallRegisterSummary.SummaryTree
abbrev SummaryEdge :=
  StageA.Relational.InternalDirectCallRegisterSummary.CalleeEdge
abbrev SummaryEdgeKind :=
  StageA.Relational.InternalDirectCallRegisterSummary.CalleeEdgeKind

structure PairedCalleeCursor where
  regionId : Nat
  original : MachineState
  candidate : MachineState
  world : RelationalWorld

def requestedReturnRegistersHold (certificate : SummaryCertificate)
    (entryOriginal entryCandidate exitOriginal exitCandidate : MachineState) : Prop :=
  forall register, register ∈ certificate.requestedRegisters ->
    if register == .esp then
      exitOriginal.registers.get register =
          entryOriginal.registers.get register + BitVec.ofNat 32 4 /\
        exitCandidate.registers.get register =
          entryCandidate.registers.get register + BitVec.ofNat 32 4
    else
      exitOriginal.registers.get register = entryOriginal.registers.get register /\
        exitCandidate.registers.get register = entryCandidate.registers.get register

/-- Postcondition at the caller continuation.  Unlike the callee-entry
postcondition above, ESP has returned to its pre-call value. -/
def requestedCallReturnRegistersHold (certificate : SummaryCertificate)
    (sourceOriginal sourceCandidate exitOriginal exitCandidate : MachineState) : Prop :=
  forall register, register ∈ certificate.requestedRegisters ->
    exitOriginal.registers.get register = sourceOriginal.registers.get register /\
      exitCandidate.registers.get register = sourceCandidate.registers.get register

/-- Exact register relationship produced by the architectural call push. -/
def callEntryRegistersHold (certificate : SummaryCertificate)
    (sourceOriginal sourceCandidate entryOriginal entryCandidate : MachineState) : Prop :=
  forall register, register ∈ certificate.requestedRegisters ->
    if register == .esp then
      entryOriginal.registers.get register + BitVec.ofNat 32 4 =
          sourceOriginal.registers.get register /\
        entryCandidate.registers.get register + BitVec.ofNat 32 4 =
          sourceCandidate.registers.get register
    else
      entryOriginal.registers.get register = sourceOriginal.registers.get register /\
        entryCandidate.registers.get register = sourceCandidate.registers.get register

theorem requestedCallReturnRegistersHold_of_entry_and_return
    (certificate : SummaryCertificate)
    (sourceOriginal sourceCandidate entryOriginal entryCandidate
      exitOriginal exitCandidate : MachineState)
    (entry : callEntryRegistersHold certificate sourceOriginal sourceCandidate
      entryOriginal entryCandidate)
    (returned : requestedReturnRegistersHold certificate entryOriginal entryCandidate
      exitOriginal exitCandidate) :
    requestedCallReturnRegistersHold certificate sourceOriginal sourceCandidate
      exitOriginal exitCandidate := by
  intro register member
  have entryRegister := entry register member
  have returnedRegister := returned register member
  by_cases stackPointer : register == .esp
  · simp only [stackPointer, if_true] at entryRegister returnedRegister
    exact ⟨returnedRegister.1.trans entryRegister.1,
      returnedRegister.2.trans entryRegister.2⟩
  · simp only [stackPointer, if_false] at entryRegister returnedRegister
    exact ⟨returnedRegister.1.trans entryRegister.1,
      returnedRegister.2.trans entryRegister.2⟩

def callFrameHolds (context : StaticProofContext)
    (frame : RelationalRuntimeCallFrame) (cursor : PairedCalleeCursor) : Prop :=
  frame.valid context = true /\
    frame.memoryHolds cursor.original.memory cursor.candidate.memory

/-- One machine word at a checked offset from a live call frame.  The relation
may be exact, pointer-related, or tied to a specific mapped code target; this is
machine-level evidence and does not assert a recovered source prototype. -/
structure RuntimeFrameArgumentWord where
  originalOffset : Nat
  candidateOffset : Nat
  relation : StaticWordRelationKind
deriving Repr, DecidableEq

def RuntimeFrameArgumentWord.checked (context : StaticProofContext)
    (word : RuntimeFrameArgumentWord) : Bool :=
  word.originalOffset <= ReturnSlotExactWordPair.maxOffset &&
    word.candidateOffset <= ReturnSlotExactWordPair.maxOffset &&
    match word.relation with
    | .fixedCodePointer targetId => (context.codeMap.get? targetId).isSome
    | _ => true

def RuntimeFrameArgumentWord.holds (context : StaticProofContext)
    (world : RelationalWorld) (word : RuntimeFrameArgumentWord)
    (frame : RelationalRuntimeCallFrame) (original candidate : Memory) : Bool :=
  word.relation.holds context world
    (Memory.read32 original
      (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset))
    (Memory.read32 candidate
      (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset))

/-- A child summary is usable at a nested edge only through this semantic
contract.  The contract quantifies over concrete states and the checked return
frame; a child's structural checker result cannot inhabit it by itself. -/
structure DirectCallSemanticContract (context : StaticProofContext)
    (tree : SummaryTree) where
  invocation : MachineState -> MachineState -> MachineState -> MachineState ->
    RelationalWorld -> RelationalRuntimeCallFrame -> Prop
  preserves : forall entryOriginal entryCandidate exitOriginal exitCandidate world frame,
    invocation entryOriginal entryCandidate exitOriginal exitCandidate world frame ->
      requestedCallReturnRegistersHold tree.certificate entryOriginal entryCandidate
        exitOriginal exitCandidate
  framePreserved : forall entryOriginal entryCandidate exitOriginal exitCandidate world frame,
    invocation entryOriginal entryCandidate exitOriginal exitCandidate world frame ->
      frame.valid context = true /\
        frame.memoryHolds exitOriginal.memory exitCandidate.memory
  continuationRelated : forall entryOriginal entryCandidate exitOriginal exitCandidate
      world frame,
    invocation entryOriginal entryCandidate exitOriginal exitCandidate world frame ->
      exists invariant, StateRel context world invariant exitOriginal exitCandidate

/-- Canonical decoded segment evidence for an ordinary direct or conditional
edge.  The fields expose the witness used by `RelationalSegmentRefinement`, so
the local summary cannot replace the shared segment semantics. -/
structure ExactInternalSegmentAuthority (context : StaticProofContext)
    (certificate : SummaryCertificate) (edge : SummaryEdge) where
  sourceRegion : ExactRegionPair
  targetRegion : ExactRegionPair
  sourceRegionFound : findRegion? certificate.calleeRegions edge.sourceRegionId =
    some sourceRegion
  targetRegionFound : findRegion? certificate.calleeRegions edge.targetRegionId =
    some targetRegion
  ordinaryKind : edge.kind = .direct \/ edge.kind = .directTail \/
    (exists dependencyId, edge.kind = .machineImportTail dependencyId) \/
    edge.kind = .branchTaken \/ edge.kind = .branchFallthrough
  segment : RelationalSegmentEdge
  sourceInvariant : StateInvariant
  targetInvariant : StateInvariant
  sourceTargetId : Nat
  targetTargetId : Nat
  sourceCodeTarget : CodeTargetPair
  targetCodeTarget : CodeTargetPair
  sourceMapped : context.codeMap.get? sourceTargetId = some sourceCodeTarget
  targetMapped : context.codeMap.get? targetTargetId = some targetCodeTarget
  sourceRegionIndex : sourceCodeTarget.regionIndex = edge.sourceRegionId
  targetRegionIndex : targetCodeTarget.regionIndex = edge.targetRegionId
  sourceRvas : sourceCodeTarget.originalRva = sourceRegion.original.start /\
    sourceCodeTarget.candidateRva = sourceRegion.candidate.start
  targetRvas : targetCodeTarget.originalRva = targetRegion.original.start /\
    targetCodeTarget.candidateRva = targetRegion.candidate.start
  segmentSource : segment.sourceTargetId = sourceTargetId
  segmentExit : segment.exit = .internal targetTargetId
  segmentSpans : segment.originalSpan = sourceRegion.original /\
    segment.candidateSpan = sourceRegion.candidate
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalDecoded : regionBehaviorWithMachineCallContracts context.originalPe
    context.originalImports context.machineImportCallContracts sourceRegion.original =
      some originalBehavior
  candidateDecoded : regionBehaviorWithMachineCallContracts context.candidatePe
    context.candidateImports context.machineImportCallContracts sourceRegion.candidate =
      some candidateBehavior
  transition : SegmentTransitionClosed context segment sourceInvariant targetInvariant
    originalBehavior candidateBehavior

def ExactInternalSegmentAuthority.refinement
    {context : StaticProofContext} {certificate : SummaryCertificate}
    {edge : SummaryEdge}
    (authority : ExactInternalSegmentAuthority context certificate edge) :
    RelationalSegmentRefinement context authority.segment authority.sourceInvariant
      authority.targetInvariant :=
  relationalSegmentRefinement_of_decoded context authority.segment
    authority.sourceInvariant authority.targetInvariant authority.originalBehavior
    authority.candidateBehavior
    (by rw [authority.segmentSpans.1]; exact authority.originalDecoded)
    (by rw [authority.segmentSpans.2]; exact authority.candidateDecoded)
    authority.transition

/-- An actual internal transition, including exact decoder outputs and concrete
evaluation results.  `targetRelated` below derives its post-state relation from
`SegmentTransitionClosed`; it is not a submitted Boolean status. -/
structure ExactInternalSegmentStep (context : StaticProofContext)
    (certificate : SummaryCertificate)
    (before after : PairedCalleeCursor) where
  edge : SummaryEdge
  edgeMember : edge ∈ certificate.edges
  authority : ExactInternalSegmentAuthority context certificate edge
  originalResult : RelationalBehavior
  candidateResult : RelationalBehavior
  localCodeTargets : List CodeTargetPair
  localValues : List ValueTargetPair
  codeTargetsResolved : context.codeMap.resolveIds authority.segment.localCodeTargetIds =
    some localCodeTargets
  valuesResolved : context.dataMap.resolveIds authority.segment.localValueTargetIds =
    some localValues
  originalEvaluated : evalBehavior false localCodeTargets before.original
    authority.originalBehavior = some originalResult
  candidateEvaluated : evalBehavior true localCodeTargets before.candidate
    authority.candidateBehavior = some candidateResult
  sourceRelated : StateRel context before.world authority.sourceInvariant
    before.original before.candidate
  guardTrue : authority.segment.originalGuard.eval before.original = true
  sameWorld : after.world = before.world
  sourceId : before.regionId = edge.sourceRegionId
  targetId : after.regionId = edge.targetRegionId
  originalAfter : after.original = originalResult.nextMachineState before.original
  candidateAfter : after.candidate = candidateResult.nextMachineState before.candidate

theorem ExactInternalSegmentStep.targetRelated
    {context : StaticProofContext} {certificate : SummaryCertificate}
    {before after : PairedCalleeCursor}
    (step : ExactInternalSegmentStep context certificate before after) :
    StateRel context after.world step.authority.targetInvariant
      after.original after.candidate := by
  have transition := step.authority.transition
  unfold SegmentTransitionClosed at transition
  rw [step.codeTargetsResolved, step.valuesResolved] at transition
  have closed := transition before.world before.original
    before.candidate step.sourceRelated
  have body := closed.2 step.guardTrue
  rw [step.originalEvaluated, step.candidateEvaluated] at body
  have related := body.2.2.2
  rw [step.authority.segmentExit] at related
  simpa [step.sameWorld, step.originalAfter, step.candidateAfter] using related

/-- A nested transition consumes the child's semantic contract and binds it to
the exact dependency row. -/
structure ExactNestedSummaryStep (context : StaticProofContext)
    (parentTree childTree : SummaryTree)
    (before after : PairedCalleeCursor) where
  edge : SummaryEdge
  edgeMember : edge ∈ parentTree.certificate.edges
  dependency : NestedSummaryDependency
  dependencyMember : dependency ∈ parentTree.certificate.nestedDependencies
  edgeKind : edge.kind = .nestedSummary dependency.id
  edgeSource : edge.sourceRegionId = dependency.callRegionId
  edgeTarget : edge.targetRegionId = dependency.continuationRegionId
  childId : childTree.summaryId = dependency.summaryId
  childStructuralChecked : childTree.checked context.originalPe context.candidatePe
    context.originalImports context.candidateImports = true
  child : DirectCallSemanticContract context childTree
  frame : RelationalRuntimeCallFrame
  invoked : child.invocation before.original before.candidate after.original
    after.candidate before.world frame
  sameWorld : after.world = before.world
  sourceId : before.regionId = edge.sourceRegionId
  targetId : after.regionId = edge.targetRegionId

/-- Static grounding for one machine-import edge.  Source and continuation
regions, canonical code-map entries, exact spans, the submitted dependency, and
the shared external-call refinement must all describe the same boundary. -/
structure ExactMachineImportAuthority (context : StaticProofContext)
    (tree : SummaryTree) (edge : SummaryEdge) where
  dependency : MachineImportDependency
  dependencyMember : dependency ∈ tree.certificate.machineImportDependencies
  edgeKind : edge.kind = .machineImport dependency.id
  edgeSource : edge.sourceRegionId = dependency.sourceRegionId
  edgeTarget : edge.targetRegionId = dependency.continuationRegionId
  sourceRegion : ExactRegionPair
  targetRegion : ExactRegionPair
  sourceFound : findRegion? tree.certificate.calleeRegions edge.sourceRegionId =
    some sourceRegion
  targetFound : findRegion? tree.certificate.calleeRegions edge.targetRegionId =
    some targetRegion
  site : ExternalCallSiteContract
  segment : RelationalSegmentEdge
  sourceInvariant : StateInvariant
  sourceCodeTarget : CodeTargetPair
  targetCodeTarget : CodeTargetPair
  sourceMapped : context.codeMap.get? site.sourceTargetId = some sourceCodeTarget
  targetMapped : context.codeMap.get? site.continuationTargetId = some targetCodeTarget
  sourceRegionIndex : sourceCodeTarget.regionIndex = edge.sourceRegionId
  targetRegionIndex : targetCodeTarget.regionIndex = edge.targetRegionId
  sourceRvas : sourceCodeTarget.originalRva = sourceRegion.original.start /\
    sourceCodeTarget.candidateRva = sourceRegion.candidate.start
  targetRvas : targetCodeTarget.originalRva = targetRegion.original.start /\
    targetCodeTarget.candidateRva = targetRegion.candidate.start
  segmentSource : segment.sourceTargetId = site.sourceTargetId
  segmentSpans : segment.originalSpan = sourceRegion.original /\
    segment.candidateSpan = sourceRegion.candidate
  canonicalRefinement : RelationalExternalCallRefinement context site segment
    sourceInvariant

/-- Machine-import execution remains tied to the static authority above.  The
result fields are the machine-level environment theorem; matching an import
name alone is insufficient. -/
structure ExactMachineImportStep (context : StaticProofContext)
    (tree : SummaryTree) (before after : PairedCalleeCursor) where
  edge : SummaryEdge
  edgeMember : edge ∈ tree.certificate.edges
  authority : ExactMachineImportAuthority context tree edge
  frame : RelationalRuntimeCallFrame
  sourceRelated : StateRel context before.world authority.sourceInvariant before.original
    before.candidate
  resultRelated : StateRel context after.world authority.site.targetInvariant after.original
    after.candidate
  requestedPreserved : forall register,
    register ∈ tree.certificate.requestedRegisters ->
      before.original.registers.get register = after.original.registers.get register /\
        before.candidate.registers.get register = after.candidate.registers.get register
  framePreserved : callFrameHolds context frame before -> callFrameHolds context frame after
  sourceId : before.regionId = edge.sourceRegionId
  targetId : after.regionId = edge.targetRegionId

inductive AdmittedCalleeStep (context : StaticProofContext) (tree : SummaryTree) :
    PairedCalleeCursor -> PairedCalleeCursor -> Prop where
  | internal {before after} (step : ExactInternalSegmentStep context
      tree.certificate before after) : AdmittedCalleeStep context tree before after
  | nested {before after childTree} (step : ExactNestedSummaryStep context tree childTree
      before after) : AdmittedCalleeStep context tree before after
  | machineImport {before after} (step : ExactMachineImportStep context tree before after) :
      AdmittedCalleeStep context tree before after

inductive AdmittedCalleeStepUsesEdge {context : StaticProofContext} {tree : SummaryTree} :
    {before after : PairedCalleeCursor} ->
      AdmittedCalleeStep context tree before after -> SummaryEdge -> Prop where
  | internal (actual : ExactInternalSegmentStep context tree.certificate before after) :
      AdmittedCalleeStepUsesEdge (.internal actual) actual.edge
  | nested (actual : ExactNestedSummaryStep context tree childTree before after) :
      AdmittedCalleeStepUsesEdge (.nested actual) actual.edge
  | machineImport (actual : ExactMachineImportStep context tree before after) :
      AdmittedCalleeStepUsesEdge (.machineImport actual) actual.edge

inductive FiniteCalleePath (context : StaticProofContext) (tree : SummaryTree)
    (entry : PairedCalleeCursor) : PairedCalleeCursor -> Prop where
  | entry : FiniteCalleePath context tree entry entry
  | step {before after} : FiniteCalleePath context tree entry before ->
      AdmittedCalleeStep context tree before after ->
      FiniteCalleePath context tree entry after

theorem FiniteCalleePath.prepend
    {context : StaticProofContext} {tree : SummaryTree}
    {before middle after : PairedCalleeCursor}
    (head : AdmittedCalleeStep context tree before middle)
    (tail : FiniteCalleePath context tree middle after) :
    FiniteCalleePath context tree before after := by
  induction tail with
  | entry => exact .step .entry head
  | step prior transition induction => exact .step induction transition

/-- Exact return semantics at one declared return.  It binds the decoded return
target to the live runtime frame and requires the shared continuation relation
after applying the concrete decoded effects. -/
structure ExactReturningStep (context : StaticProofContext) (tree : SummaryTree)
    (before : PairedCalleeCursor) where
  returnEntry : ReturnInventoryEntry
  returnMember : returnEntry ∈ tree.certificate.returns
  returnRegion : ExactRegionPair
  returnRegionFound : findRegion? tree.certificate.calleeRegions
    returnEntry.returnRegionId = some returnRegion
  continuationId : returnEntry.continuationRegionId = tree.certificate.continuation.id
  regionId : before.regionId = returnEntry.returnRegionId
  frame : RelationalRuntimeCallFrame
  frameContinuation : frame.continuationTargetId = returnEntry.continuationRegionId
  frameAtReturn : callFrameHolds context frame before
  originalBehavior : SymbolicBehavior
  candidateBehavior : SymbolicBehavior
  originalDecoded : regionBehaviorWithImports context.originalPe context.originalImports
    returnRegion.original = some originalBehavior
  candidateDecoded : regionBehaviorWithImports context.candidatePe context.candidateImports
    returnRegion.candidate = some candidateBehavior
  originalReturned : (originalBehavior.eval before.original).outcome =
    some (.returned frame.originalReturnAddress)
  candidateReturned : (candidateBehavior.eval before.candidate).outcome =
    some (.returned frame.candidateReturnAddress)
  afterOriginal : MachineState
  afterCandidate : MachineState
  originalAfter : afterOriginal =
    StageA.Relational.InternalDirectCallRegisterSummary.applySymbolicBehavior
      originalBehavior before.original
  candidateAfter : afterCandidate =
    StageA.Relational.InternalDirectCallRegisterSummary.applySymbolicBehavior
      candidateBehavior before.candidate
  continuationInvariant : StateInvariant
  continuationRelated : StateRel context before.world continuationInvariant
    afterOriginal afterCandidate

structure FiniteReturningExecution (context : StaticProofContext) (tree : SummaryTree)
    (entry : PairedCalleeCursor) where
  beforeReturn : PairedCalleeCursor
  path : FiniteCalleePath context tree entry beforeReturn
  returning : ExactReturningStep context tree beforeReturn

/-- The invariant is deliberately a proposition over concrete paired cursors.
This is expressive enough for stack save/restore protocols: an implementation
may record the entry register value and the exact saved word while the register
itself is temporarily clobbered. -/
structure CalleeInductiveInvariant (context : StaticProofContext) (tree : SummaryTree)
    (entry : PairedCalleeCursor) where
  holds : PairedCalleeCursor -> Prop
  atEntry : holds entry
  preserved : forall before after,
    holds before -> AdmittedCalleeStep context tree before after -> holds after
  closesReturn : forall before (returning : ExactReturningStep context tree before),
    holds before ->
      requestedReturnRegistersHold tree.certificate entry.original entry.candidate
        returning.afterOriginal returning.afterCandidate /\
      returning.frame.valid context = true /\
      returning.frame.memoryHolds returning.afterOriginal.memory
        returning.afterCandidate.memory

theorem FiniteCalleePath.invariant
    {context : StaticProofContext} {tree : SummaryTree}
    {entry cursor : PairedCalleeCursor}
    (invariant : CalleeInductiveInvariant context tree entry)
    (path : FiniteCalleePath context tree entry cursor) : invariant.holds cursor := by
  induction path
  case entry => exact invariant.atEntry
  case step before after prior transition ih =>
    exact invariant.preserved before after ih transition

structure ReturningExecutionResult (context : StaticProofContext) (tree : SummaryTree)
    (entry : PairedCalleeCursor) (execution : FiniteReturningExecution context tree entry) where
  registers : requestedReturnRegistersHold tree.certificate entry.original entry.candidate
    execution.returning.afterOriginal execution.returning.afterCandidate
  frameValid : execution.returning.frame.valid context = true
  frameMemory : execution.returning.frame.memoryHolds
    execution.returning.afterOriginal.memory execution.returning.afterCandidate.memory
  continuationRelated : exists invariant,
    StateRel context execution.beforeReturn.world invariant
      execution.returning.afterOriginal execution.returning.afterCandidate

/-- Main finite-path theorem.  It applies to every concrete returning path made
from exact internal segments, recursively certified nested calls, and grounded
machine-import transitions. -/
theorem finiteReturningExecution_preserves
    {context : StaticProofContext} {tree : SummaryTree}
    {entry : PairedCalleeCursor}
    (invariant : CalleeInductiveInvariant context tree entry)
    (execution : FiniteReturningExecution context tree entry) :
    ReturningExecutionResult context tree entry execution := by
  have atReturn := execution.path.invariant invariant
  rcases invariant.closesReturn execution.beforeReturn execution.returning atReturn with
    ⟨registers, frameValid, frameMemory⟩
  exact ⟨registers, frameValid, frameMemory,
    ⟨execution.returning.continuationInvariant,
      execution.returning.continuationRelated⟩⟩

def cyclicSummaryEdge (certificate : SummaryCertificate) (edge : SummaryEdge) : Bool :=
  reachesWithin certificate.edges certificate.calleeRegions.length
    edge.targetRegionId edge.sourceRegionId

structure RankedLoopDischarge (context : StaticProofContext) (tree : SummaryTree) where
  rank : PairedCalleeCursor -> Nat
  decreases : forall before after (step : AdmittedCalleeStep context tree before after)
      edge,
    AdmittedCalleeStepUsesEdge step edge ->
      cyclicSummaryEdge tree.certificate edge = true ->
      rank after < rank before

inductive LoopDischarge (context : StaticProofContext) (tree : SummaryTree) where
  | acyclic (checked : forall edge, edge ∈ tree.certificate.edges ->
      cyclicSummaryEdge tree.certificate edge = false)
  | ranked (witness : RankedLoopDischarge context tree)
  | incomplete (reason : String)

def LoopDischarge.Complete {context : StaticProofContext} {tree : SummaryTree} :
    LoopDischarge context tree -> Prop
  | .acyclic _ | .ranked _ => True
  | .incomplete _ => False

theorem LoopDischarge.incomplete_not_complete
    {context : StaticProofContext} {tree : SummaryTree} (reason : String) :
    ¬ (LoopDischarge.incomplete reason : LoopDischarge context tree).Complete := by
  simp [LoopDischarge.Complete]

/-- Static edge authority inventory.  This prevents a semantic path relation
from silently omitting a structurally checked outgoing edge. -/
inductive SemanticEdgeAuthority (context : StaticProofContext) (tree : SummaryTree) :
    SummaryEdge -> Prop where
  | internal (edge) (authority : ExactInternalSegmentAuthority context
      tree.certificate edge) : SemanticEdgeAuthority context tree edge
  | nested (edge) (dependency : NestedSummaryDependency)
      (dependencyMember : dependency ∈ tree.certificate.nestedDependencies)
      (edgeKind : edge.kind = .nestedSummary dependency.id)
      (childTree : SummaryTree)
      (childId : childTree.summaryId = dependency.summaryId)
      (childChecked : childTree.checked context.originalPe context.candidatePe
        context.originalImports context.candidateImports = true)
      (child : DirectCallSemanticContract context childTree) :
      SemanticEdgeAuthority context tree edge
  | machineImport (edge)
      (authority : ExactMachineImportAuthority context tree edge) :
      SemanticEdgeAuthority context tree edge

structure GraphExecutionCompleteness (context : StaticProofContext) (tree : SummaryTree) where
  everyEdge : forall edge, edge ∈ tree.certificate.edges ->
    SemanticEdgeAuthority context tree edge
  everyReturn : forall entry, entry ∈ tree.certificate.returns ->
    exists region originalBehavior candidateBehavior,
      findRegion? tree.certificate.calleeRegions entry.returnRegionId = some region /\
      regionBehaviorWithImports context.originalPe context.originalImports region.original =
        some originalBehavior /\
      regionBehaviorWithImports context.candidatePe context.candidateImports region.candidate =
        some candidateBehavior

/-- Structural grounding for each register named by the semantic invariant.
The grounding does not itself prove path preservation; it prevents an
independently supplied invariant from claiming a register that the exact
decoded summary never checked. -/
inductive RequestedRegisterGrounding (context : StaticProofContext)
    (tree : SummaryTree) : Reg -> Prop where
  | identity (register : Reg)
      (checked : tree.certificate.identityRegisterChecked context.originalPe
        context.candidatePe context.originalImports context.candidateImports
        register = true) : RequestedRegisterGrounding context tree register
  | stackPointer
      (checked : tree.certificate.stackPointerPreservedChecked context.originalPe
        context.candidatePe context.originalImports context.candidateImports = true) :
      RequestedRegisterGrounding context tree .esp
  | saveRestore (witness : StackSaveRestoreWitness)
      (member : witness ∈ tree.certificate.stackWitnesses)
      (checked : witness.checked tree.certificate context.originalPe
        context.candidatePe context.originalImports context.candidateImports = true) :
      RequestedRegisterGrounding context tree witness.register

/-- Exact entry binding.  The canonical direct-call segment establishes the
callee relation, while `entered` checks the runtime return frame for every
related concrete source state. -/
structure ExactDirectCallEntryBinding (context : StaticProofContext) (tree : SummaryTree) where
  sourceInvariant : StateInvariant
  entryInvariant : StateInvariant
  segment : RelationalSegmentEdge
  sourceTargetId : Nat
  calleeTargetId : Nat
  continuationTargetId : Nat
  callPush : DirectCallPushClaim
  /-- Machine-level scalar inputs named relative to the architectural return
  slot.  Offset 4 is the first caller stack word after a plain IA-32 call. -/
  argumentWords : List RuntimeFrameArgumentWord := []
  argumentWordsChecked : argumentWords.all (RuntimeFrameArgumentWord.checked context) =
      true := by
    simp
  segmentSpans : segment.originalSpan = tree.certificate.callsite.original /\
    segment.candidateSpan = tree.certificate.callsite.candidate
  segmentSource : segment.sourceTargetId = sourceTargetId
  segmentExit : segment.exit = .internal calleeTargetId
  callPushTargets : callPush.calleeTargetId = calleeTargetId /\
    callPush.continuationTargetId = continuationTargetId
  sourceCodeTarget : CodeTargetPair
  calleeCodeTarget : CodeTargetPair
  sourceMapped : context.codeMap.get? sourceTargetId = some sourceCodeTarget
  calleeMapped : context.codeMap.get? calleeTargetId = some calleeCodeTarget
  sourceRegionIndex : sourceCodeTarget.regionIndex = tree.certificate.callsite.id
  calleeRegionIndex : calleeCodeTarget.regionIndex = tree.certificate.calleeEntry.id
  sourceRvas : sourceCodeTarget.originalRva = tree.certificate.callsite.original.start /\
    sourceCodeTarget.candidateRva = tree.certificate.callsite.candidate.start
  calleeRvas : calleeCodeTarget.originalRva = tree.certificate.calleeEntry.original.start /\
    calleeCodeTarget.candidateRva = tree.certificate.calleeEntry.candidate.start
  continuationMapped : exists target,
    context.codeMap.get? continuationTargetId = some target /\
      target.originalRva = tree.certificate.continuation.original.start /\
      target.candidateRva = tree.certificate.continuation.candidate.start
  refinement : RelationalSegmentRefinement context segment sourceInvariant entryInvariant
  entered : forall world original candidate,
    StateRel context world sourceInvariant original candidate ->
      exists originalBehavior candidateBehavior originalNormalized candidateNormalized,
        exists originalResult candidateResult frame,
        regionBehaviorWithMachineCallContracts context.originalPe context.originalImports
            context.machineImportCallContracts tree.certificate.callsite.original =
              some originalBehavior /\
        regionBehaviorWithMachineCallContracts context.candidatePe context.candidateImports
            context.machineImportCallContracts tree.certificate.callsite.candidate =
              some candidateBehavior /\
        normalizeSymbolicBehavior false context.codeMap.entries.toList originalBehavior =
          some originalNormalized /\
        normalizeSymbolicBehavior true context.codeMap.entries.toList candidateBehavior =
          some candidateNormalized /\
        callPush.checked context originalNormalized candidateNormalized = true /\
        evalBehavior false context.codeMap.entries.toList original originalBehavior =
          some originalResult /\
        evalBehavior true context.codeMap.entries.toList candidate candidateBehavior =
          some candidateResult /\
        callPush.runtimeFrame context original candidate = some frame /\
        frame.valid context = true /\
        frame.memoryHolds (originalResult.nextMachineState original).memory
          (candidateResult.nextMachineState candidate).memory /\
        StateRel context world entryInvariant
          (originalResult.nextMachineState original)
          (candidateResult.nextMachineState candidate)

/-! ## Operational call-to-return completeness

The structural graph and the finite semantic path above are not execution
authorities by themselves.  The following relation is deliberately defined by
the canonical PE32 transition function.  Its only base cases are executions
currently stopped at the declared continuation, so terminal, faulted, blocked,
or infinitely running executions cannot manufacture a returning witness.
-/

/-- A concrete running point, including callback nesting when the call occurs
inside an external callback. -/
structure WorldExecutionPoint where
  targetId : Nat
  state : MachineState
  calls : List Nat
  eventIndex : Nat
  world : RelationalWorld
  callbacks : Option (List WorldExternalCallbackRuntime) := none

def WorldExecutionPoint.execution (point : WorldExecutionPoint) : WorldExecution :=
  match point.callbacks with
  | none => .running point.targetId point.state point.calls point.eventIndex point.world
  | some callbacks => .callbackRunning point.targetId point.state point.calls
      point.eventIndex point.world callbacks

def worldExecutionRunningTarget? : WorldExecution -> Option Nat
  | .running targetId _ _ _ _ => some targetId
  | .callbackRunning targetId _ _ _ _ _ => some targetId
  | _ => none

def worldExecutionMayProgress : WorldExecution -> Prop
  | .running _ _ _ _ _ | .awaitingExternal _ _ | .callbackRunning _ _ _ _ _ _ => True
  | _ => False

/-- Exact finite execution from a callee point to the *first* occurrence of its
declared continuation.  Every inductive step is definitionally the next
`pe32TransitionSystem` step; there is no submitted edge relation here. -/
inductive WorldCallRun (program : DecodedWorldProgram) (continuationTargetId : Nat) :
    WorldExecution -> List WorldRelationalObservable -> WorldExecution -> Prop where
  | doneRunning (state calls eventIndex world) :
      WorldCallRun program continuationTargetId
        (.running continuationTargetId state calls eventIndex world) []
        (.running continuationTargetId state calls eventIndex world)
  | doneCallback (state calls eventIndex world callbacks) :
      WorldCallRun program continuationTargetId
        (.callbackRunning continuationTargetId state calls eventIndex world callbacks) []
        (.callbackRunning continuationTargetId state calls eventIndex world callbacks)
  | step {before observations after}
      (notAtContinuation : worldExecutionRunningTarget? before ≠ some continuationTargetId)
      (mayProgress : worldExecutionMayProgress before)
      (tail : WorldCallRun program continuationTargetId
        (program.pe32TransitionSystem.step before).next observations after) :
      WorldCallRun program continuationTargetId before
        ((program.pe32TransitionSystem.step before).observation.toList ++ observations) after

/-- The PE32 transition system is a function and `WorldCallRun` stops at the
first continuation, so the existential return witness cannot select a more
convenient alternative execution. -/
theorem WorldCallRun.deterministic
    {program : DecodedWorldProgram} {continuationTargetId : Nat}
    {source : WorldExecution} {leftObservations} {leftAfter}
    (left : WorldCallRun program continuationTargetId source leftObservations leftAfter)
    {rightObservations rightAfter}
    (right : WorldCallRun program continuationTargetId source rightObservations rightAfter) :
    leftObservations = rightObservations /\ leftAfter = rightAfter := by
  induction left generalizing rightObservations rightAfter with
  | doneRunning =>
      cases right with
      | doneRunning => exact ⟨rfl, rfl⟩
      | step notAtContinuation mayProgress tail =>
          exact False.elim (notAtContinuation rfl)
  | doneCallback =>
      cases right with
      | doneCallback => exact ⟨rfl, rfl⟩
      | step notAtContinuation mayProgress tail =>
          exact False.elim (notAtContinuation rfl)
  | step notAtContinuation mayProgress tail induction =>
      cases right with
      | doneRunning => exact False.elim (notAtContinuation rfl)
      | doneCallback => exact False.elim (notAtContinuation rfl)
      | step rightNotAtContinuation rightMayProgress rightTail =>
          rcases induction rightTail with ⟨observationsEqual, afterEqual⟩
          constructor
          · simpa only [observationsEqual]
          · exact afterEqual

def worldExecutionFailed : WorldExecution -> Prop
  | .returned _ _ | .terminated _ | .fault _ | .blocked _ => True
  | _ => False

theorem WorldCallRun.source_not_failed
    {program : DecodedWorldProgram} {continuationTargetId : Nat}
    {before : WorldExecution} {observations} {after}
    (run : WorldCallRun program continuationTargetId before observations after) :
    Not (worldExecutionFailed before) := by
  cases run with
  | doneRunning => simp [worldExecutionFailed]
  | doneCallback => simp [worldExecutionFailed]
  | step notAtContinuation mayProgress tail =>
      cases before <;> simp_all [worldExecutionFailed, worldExecutionMayProgress]

theorem WorldCallRun.not_from_returned
    (program : DecodedWorldProgram) (continuationTargetId : Nat)
    (state : MachineState) (world : RelationalWorld) (observations) (after) :
    Not (WorldCallRun program continuationTargetId (.returned state world)
      observations after) := by
  intro run
  exact run.source_not_failed trivial

theorem WorldCallRun.not_from_terminated
    (program : DecodedWorldProgram) (continuationTargetId : Nat)
    (world : RelationalWorld) (observations) (after) :
    Not (WorldCallRun program continuationTargetId (.terminated world)
      observations after) := by
  intro run
  exact run.source_not_failed trivial

theorem WorldCallRun.not_from_fault
    (program : DecodedWorldProgram) (continuationTargetId : Nat)
    (cause : ModeledFault) (observations) (after) :
    Not (WorldCallRun program continuationTargetId (.fault cause)
      observations after) := by
  intro run
  exact run.source_not_failed trivial

theorem WorldCallRun.not_from_blocked
    (program : DecodedWorldProgram) (continuationTargetId : Nat)
    (reason : ExecutionBlock) (observations) (after) :
    Not (WorldCallRun program continuationTargetId (.blocked reason)
      observations after) := by
  intro run
  exact run.source_not_failed trivial

/-- Related concrete source point at the callsite.  This is the domain over
which a returning direct-call summary must be operationally total. -/
structure RelatedDirectCallSource (context : StaticProofContext) (tree : SummaryTree)
    (binding : ExactDirectCallEntryBinding context tree) where
  original : WorldExecutionPoint
  candidate : WorldExecutionPoint
  originalTarget : original.targetId = binding.sourceTargetId
  candidateTarget : candidate.targetId = binding.sourceTargetId
  sharedWorld : original.world = candidate.world
  sourceRelated : StateRel context original.world binding.sourceInvariant
    original.state candidate.state

/-- One actual paired invocation.  The call transition and every subsequent
callee transition are exact `WorldExecution` steps over the embedded PE bytes.
The call-stack equations additionally bind the operational run to the declared
runtime return frame rather than merely reaching a numerically equal target. -/
structure ActualDirectCallReturnExecution (context : StaticProofContext)
    (tree : SummaryTree) (binding : ExactDirectCallEntryBinding context tree)
    (originalProgram candidateProgram : DecodedWorldProgram) where
  source : RelatedDirectCallSource context tree binding
  originalEntry : WorldExecutionPoint
  candidateEntry : WorldExecutionPoint
  originalExit : WorldExecutionPoint
  candidateExit : WorldExecutionPoint
  originalCallStep : originalProgram.pe32TransitionSystem.step
    source.original.execution = { next := originalEntry.execution, observation := none }
  candidateCallStep : candidateProgram.pe32TransitionSystem.step
    source.candidate.execution = { next := candidateEntry.execution, observation := none }
  originalEntryTarget : originalEntry.targetId = binding.calleeTargetId
  candidateEntryTarget : candidateEntry.targetId = binding.calleeTargetId
  originalExitTarget : originalExit.targetId = binding.continuationTargetId
  candidateExitTarget : candidateExit.targetId = binding.continuationTargetId
  originalEntryCalls : originalEntry.calls =
    binding.continuationTargetId :: source.original.calls
  candidateEntryCalls : candidateEntry.calls =
    binding.continuationTargetId :: source.candidate.calls
  originalExitCalls : originalExit.calls = source.original.calls
  candidateExitCalls : candidateExit.calls = source.candidate.calls
  entryWorld : originalEntry.world = source.original.world /\
    candidateEntry.world = source.original.world
  exitWorld : originalExit.world = source.original.world /\
    candidateExit.world = source.original.world
  originalObservations : List WorldRelationalObservable
  candidateObservations : List WorldRelationalObservable
  originalRun : WorldCallRun originalProgram binding.continuationTargetId
    originalEntry.execution originalObservations originalExit.execution
  candidateRun : WorldCallRun candidateProgram binding.continuationTargetId
    candidateEntry.execution candidateObservations candidateExit.execution
  observationsRelated : RelatedObservationLists
    (worldRelationalObservationsRelated context) originalObservations candidateObservations
  frame : RelationalRuntimeCallFrame
  runtimeFrame : binding.callPush.runtimeFrame context source.original.state
    source.candidate.state = some frame
  frameValid : frame.valid context = true
  frameAtEntry : frame.memoryHolds originalEntry.state.memory candidateEntry.state.memory
  frameContinuation : frame.continuationTargetId = binding.continuationTargetId
  entryArgumentWords : forall word, word ∈ binding.argumentWords ->
    word.holds context source.original.world frame originalEntry.state.memory
      candidateEntry.state.memory = true
  entryRegisters : callEntryRegistersHold tree.certificate source.original.state
    source.candidate.state originalEntry.state candidateEntry.state

  /-- The operational execution is connected to the relational summary by
  exact endpoints.  This evidence belongs to the invocation itself; it is not
  supplied later by an unconstrained lifting function. -/
  finiteExecution : FiniteReturningExecution context tree {
    regionId := tree.certificate.calleeEntry.id
    original := originalEntry.state
    candidate := candidateEntry.state
    world := source.original.world
  }
  finiteFrameExact : finiteExecution.returning.frame = frame
  finiteReturnWorldExact : finiteExecution.beforeReturn.world = source.original.world
  finiteOriginalExitExact : finiteExecution.returning.afterOriginal = originalExit.state
  finiteCandidateExitExact : finiteExecution.returning.afterCandidate = candidateExit.state

def ActualDirectCallReturnExecution.entryCursor
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) : PairedCalleeCursor := {
  regionId := tree.certificate.calleeEntry.id
  original := actual.originalEntry.state
  candidate := actual.candidateEntry.state
  world := actual.source.original.world
}

/-- Checked bridge from one exact operational invocation into the finite path
language used by the relational segment composition theorem. -/
structure OperationalFiniteReturningExecution
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) where
  execution : FiniteReturningExecution context tree actual.entryCursor
  frameExact : execution.returning.frame = actual.frame
  returnWorldExact : execution.beforeReturn.world = actual.source.original.world
  originalExitExact : execution.returning.afterOriginal = actual.originalExit.state
  candidateExitExact : execution.returning.afterCandidate = actual.candidateExit.state

def ActualDirectCallReturnExecution.finite
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution context tree binding
      originalProgram candidateProgram) :
    OperationalFiniteReturningExecution actual := {
  execution := actual.finiteExecution
  frameExact := actual.finiteFrameExact
  returnWorldExact := actual.finiteReturnWorldExact
  originalExitExact := actual.finiteOriginalExitExact
  candidateExitExact := actual.finiteCandidateExitExact
}

/-! ## Checked total-return certificates

The certificate below is intentionally operational.  Its progress cases are
equations for the canonical `DecodedWorldProgram` transition function, and its
termination argument decreases on every admitted edge.  Lean derives the
finite `WorldCallRun` and `FiniteReturningExecution`; neither may be supplied
as a detached status assertion.
-/

structure PairedOperationalCalleePoint where
  original : WorldExecutionPoint
  candidate : WorldExecutionPoint
  /-- Canonical code-map target used by `WorldExecution`. -/
  targetId : Nat
  /-- Summary-region identifier used by the finite call graph. -/
  regionId : Nat
  originalTarget : original.targetId = targetId
  candidateTarget : candidate.targetId = targetId
  world : RelationalWorld
  originalWorld : original.world = world
  candidateWorld : candidate.world = world

def PairedOperationalCalleePoint.cursor
    (point : PairedOperationalCalleePoint) : PairedCalleeCursor := {
  regionId := point.regionId
  original := point.original.state
  candidate := point.candidate.state
  world := point.world
}

theorem WorldExecutionPoint.mayProgress (point : WorldExecutionPoint) :
    worldExecutionMayProgress point.execution := by
  cases callbacks : point.callbacks <;>
    simp [WorldExecutionPoint.execution, callbacks, worldExecutionMayProgress]

theorem WorldExecutionPoint.runningTarget (point : WorldExecutionPoint) :
    worldExecutionRunningTarget? point.execution = some point.targetId := by
  cases callbacks : point.callbacks <;>
    simp [WorldExecutionPoint.execution, callbacks, worldExecutionRunningTarget?]

theorem WorldExecutionPoint.doneAt
    (program : DecodedWorldProgram) (targetId : Nat)
    (point : WorldExecutionPoint) (atTarget : point.targetId = targetId) :
    WorldCallRun program targetId point.execution [] point.execution := by
  cases callbacks : point.callbacks with
  | none =>
      rw [WorldExecutionPoint.execution, callbacks, atTarget]
      exact .doneRunning _ _ _ _
  | some values =>
      rw [WorldExecutionPoint.execution, callbacks, atTarget]
      exact .doneCallback _ _ _ _ _

theorem prependWorldObservationOptions
    (context : StaticProofContext)
    {original candidate : Option WorldRelationalObservable}
    {originalTail candidateTail : List WorldRelationalObservable}
    (head : worldRelationalObservationsRelated context original candidate)
    (tail : RelatedObservationLists
      (worldRelationalObservationsRelated context) originalTail candidateTail) :
    RelatedObservationLists (worldRelationalObservationsRelated context)
      (original.toList ++ originalTail) (candidate.toList ++ candidateTail) := by
  cases original <;> cases candidate <;>
    simp_all [worldRelationalObservationsRelated, RelatedObservationLists]

/-- Exact canonical call-entry step, including the live frame and all declared
frame-relative argument words. -/
structure ExactOperationalDirectCallEntry
    (context : StaticProofContext) (tree : SummaryTree)
    (binding : ExactDirectCallEntryBinding context tree)
    (originalProgram candidateProgram : DecodedWorldProgram)
    (source : RelatedDirectCallSource context tree binding) where
  originalEntry : WorldExecutionPoint
  candidateEntry : WorldExecutionPoint
  originalCallStep : originalProgram.pe32TransitionSystem.step
    source.original.execution = { next := originalEntry.execution, observation := none }
  candidateCallStep : candidateProgram.pe32TransitionSystem.step
    source.candidate.execution = { next := candidateEntry.execution, observation := none }
  originalEntryTarget : originalEntry.targetId = binding.calleeTargetId
  candidateEntryTarget : candidateEntry.targetId = binding.calleeTargetId
  originalEntryCalls : originalEntry.calls = binding.continuationTargetId :: source.original.calls
  candidateEntryCalls : candidateEntry.calls = binding.continuationTargetId :: source.candidate.calls
  entryWorld : originalEntry.world = source.original.world /\
    candidateEntry.world = source.original.world
  frame : RelationalRuntimeCallFrame
  runtimeFrame : binding.callPush.runtimeFrame context source.original.state
    source.candidate.state = some frame
  frameValid : frame.valid context = true
  frameAtEntry : frame.memoryHolds originalEntry.state.memory candidateEntry.state.memory
  frameContinuation : frame.continuationTargetId = binding.continuationTargetId
  entryArgumentWords : forall word, word ∈ binding.argumentWords ->
    word.holds context source.original.world frame originalEntry.state.memory
      candidateEntry.state.memory = true
  entryRegisters : callEntryRegistersHold tree.certificate source.original.state
    source.candidate.state originalEntry.state candidateEntry.state

def ExactOperationalDirectCallEntry.point
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {source : RelatedDirectCallSource context tree binding}
    (entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source) : PairedOperationalCalleePoint := {
  original := entry.originalEntry
  candidate := entry.candidateEntry
  targetId := binding.calleeTargetId
  regionId := tree.certificate.calleeEntry.id
  originalTarget := entry.originalEntryTarget
  candidateTarget := entry.candidateEntryTarget
  world := source.original.world
  originalWorld := entry.entryWorld.1
  candidateWorld := entry.entryWorld.2
}

/-- One exact paired transition corresponding to one checked summary edge. -/
structure ExactOperationalCalleeStep
    (context : StaticProofContext) (tree : SummaryTree)
    (originalProgram candidateProgram : DecodedWorldProgram)
    (before after : PairedOperationalCalleePoint) where
  edge : SummaryEdge
  edgeMember : edge ∈ tree.certificate.edges
  admitted : AdmittedCalleeStep context tree before.cursor after.cursor
  usesEdge : AdmittedCalleeStepUsesEdge admitted edge
  sourceTarget : before.regionId = edge.sourceRegionId
  targetTarget : after.regionId = edge.targetRegionId
  originalObservation : Option WorldRelationalObservable
  candidateObservation : Option WorldRelationalObservable
  originalStep : originalProgram.pe32TransitionSystem.step before.original.execution = {
    next := after.original.execution, observation := originalObservation
  }
  candidateStep : candidateProgram.pe32TransitionSystem.step before.candidate.execution = {
    next := after.candidate.execution, observation := candidateObservation
  }
  observationRelated : worldRelationalObservationsRelated context
    originalObservation candidateObservation

/-- The final exact `ret` transition and its checked relational return row. -/
structure ExactOperationalReturningStep
    (context : StaticProofContext) (tree : SummaryTree)
    (binding : ExactDirectCallEntryBinding context tree)
    (originalProgram candidateProgram : DecodedWorldProgram)
    (source : RelatedDirectCallSource context tree binding)
    (entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source)
    (before : PairedOperationalCalleePoint) where
  originalExit : WorldExecutionPoint
  candidateExit : WorldExecutionPoint
  originalObservation : Option WorldRelationalObservable
  candidateObservation : Option WorldRelationalObservable
  originalStep : originalProgram.pe32TransitionSystem.step before.original.execution = {
    next := originalExit.execution, observation := originalObservation
  }
  candidateStep : candidateProgram.pe32TransitionSystem.step before.candidate.execution = {
    next := candidateExit.execution, observation := candidateObservation
  }
  observationRelated : worldRelationalObservationsRelated context
    originalObservation candidateObservation
  sourceNotContinuation : before.targetId ≠ binding.continuationTargetId
  originalExitTarget : originalExit.targetId = binding.continuationTargetId
  candidateExitTarget : candidateExit.targetId = binding.continuationTargetId
  originalExitCalls : originalExit.calls = source.original.calls
  candidateExitCalls : candidateExit.calls = source.candidate.calls
  exitWorld : originalExit.world = source.original.world /\
    candidateExit.world = source.original.world
  returning : ExactReturningStep context tree before.cursor
  frameExact : returning.frame = entry.frame
  returnWorldExact : before.world = source.original.world
  originalAfterExact : returning.afterOriginal = originalExit.state
  candidateAfterExact : returning.afterCandidate = candidateExit.state

/-- A finite acyclic region ranking.  Every submitted summary edge, not merely
the edge observed in one trace, must strictly decrease. -/
structure FiniteCallRegionRanking (tree : SummaryTree) where
  rank : Nat -> Nat
  decreases : forall edge, edge ∈ tree.certificate.edges ->
    rank edge.targetRegionId < rank edge.sourceRegionId

/-- A state-sensitive ranking for an SCC.  This is the only cyclic authority;
without such a theorem the summary remains incomplete. -/
structure RankedCallRegionSCC
    (context : StaticProofContext) (tree : SummaryTree)
    (originalProgram candidateProgram : DecodedWorldProgram) where
  rank : PairedOperationalCalleePoint -> Nat
  decreases : forall before after,
    ExactOperationalCalleeStep context tree originalProgram candidateProgram
      before after -> rank after < rank before

inductive CallRegionTerminationCertificate
    (context : StaticProofContext) (tree : SummaryTree)
    (originalProgram candidateProgram : DecodedWorldProgram) where
  | finiteGraph (ranking : FiniteCallRegionRanking tree)
  | rankedScc (ranking : RankedCallRegionSCC context tree
      originalProgram candidateProgram)
  | incomplete (reason : String)

def CallRegionTerminationCertificate.Complete
    {context : StaticProofContext} {tree : SummaryTree}
    {originalProgram candidateProgram : DecodedWorldProgram} :
    CallRegionTerminationCertificate context tree originalProgram candidateProgram -> Prop
  | .finiteGraph _ | .rankedScc _ => True
  | .incomplete _ => False

def CallRegionTerminationCertificate.rank
    {context : StaticProofContext} {tree : SummaryTree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (certificate : CallRegionTerminationCertificate context tree
      originalProgram candidateProgram)
    (point : PairedOperationalCalleePoint) : Nat :=
  match certificate with
  | .finiteGraph ranking => ranking.rank point.regionId
  | .rankedScc ranking => ranking.rank point
  | .incomplete _ => 0

theorem CallRegionTerminationCertificate.decreases
    {context : StaticProofContext} {tree : SummaryTree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    (certificate : CallRegionTerminationCertificate context tree
      originalProgram candidateProgram)
    (complete : certificate.Complete)
    {before after : PairedOperationalCalleePoint}
    (step : ExactOperationalCalleeStep context tree originalProgram candidateProgram
      before after) : certificate.rank after < certificate.rank before := by
  cases certificate with
  | finiteGraph ranking =>
      simpa [CallRegionTerminationCertificate.rank, step.sourceTarget,
        step.targetTarget] using ranking.decreases step.edge step.edgeMember
  | rankedScc ranking => exact ranking.decreases before after step
  | incomplete reason => contradiction

theorem CallRegionTerminationCertificate.incomplete_not_complete
    {context : StaticProofContext} {tree : SummaryTree}
    {originalProgram candidateProgram : DecodedWorldProgram} (reason : String) :
    ¬ (CallRegionTerminationCertificate.incomplete reason :
      CallRegionTerminationCertificate context tree originalProgram candidateProgram).Complete := by
  simp [CallRegionTerminationCertificate.Complete]

inductive ExactOperationalCalleeClassification
    (context : StaticProofContext) (tree : SummaryTree)
    (binding : ExactDirectCallEntryBinding context tree)
    (originalProgram candidateProgram : DecodedWorldProgram)
    (source : RelatedDirectCallSource context tree binding)
    (entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source)
    (before : PairedOperationalCalleePoint) where
  | returning (step : ExactOperationalReturningStep context tree binding
      originalProgram candidateProgram source entry before)
  | progress (after : PairedOperationalCalleePoint)
      (step : ExactOperationalCalleeStep context tree originalProgram
        candidateProgram before after)
      (sourceNotContinuation : before.targetId ≠ binding.continuationTargetId)

/-- Complete outgoing classification over every point reachable through the
checked summary path from this exact call entry. -/
structure CheckedFiniteCallRegionExecution
    (context : StaticProofContext) (tree : SummaryTree)
    (binding : ExactDirectCallEntryBinding context tree)
    (originalProgram candidateProgram : DecodedWorldProgram)
    (source : RelatedDirectCallSource context tree binding)
    (entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source) where
  termination : CallRegionTerminationCertificate context tree
    originalProgram candidateProgram
  terminationComplete : termination.Complete
  classify : forall before : PairedOperationalCalleePoint,
    FiniteCalleePath context tree entry.point.cursor before.cursor ->
      ExactOperationalCalleeClassification context tree binding
        originalProgram candidateProgram source entry before

structure CheckedOperationalReturnResult
    (context : StaticProofContext) (tree : SummaryTree)
    (binding : ExactDirectCallEntryBinding context tree)
    (originalProgram candidateProgram : DecodedWorldProgram)
    (source : RelatedDirectCallSource context tree binding)
    (entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source)
    (before : PairedOperationalCalleePoint) where
  originalExit : WorldExecutionPoint
  candidateExit : WorldExecutionPoint
  originalObservations : List WorldRelationalObservable
  candidateObservations : List WorldRelationalObservable
  originalRun : WorldCallRun originalProgram binding.continuationTargetId
    before.original.execution originalObservations originalExit.execution
  candidateRun : WorldCallRun candidateProgram binding.continuationTargetId
    before.candidate.execution candidateObservations candidateExit.execution
  observationsRelated : RelatedObservationLists
    (worldRelationalObservationsRelated context) originalObservations candidateObservations
  finiteExecution : FiniteReturningExecution context tree entry.point.cursor
  frameExact : finiteExecution.returning.frame = entry.frame
  returnWorldExact : finiteExecution.beforeReturn.world = source.original.world
  originalExitExact : finiteExecution.returning.afterOriginal = originalExit.state
  candidateExitExact : finiteExecution.returning.afterCandidate = candidateExit.state
  originalExitTarget : originalExit.targetId = binding.continuationTargetId
  candidateExitTarget : candidateExit.targetId = binding.continuationTargetId
  originalExitCalls : originalExit.calls = source.original.calls
  candidateExitCalls : candidateExit.calls = source.candidate.calls
  exitWorld : originalExit.world = source.original.world /\
    candidateExit.world = source.original.world

noncomputable def CheckedFiniteCallRegionExecution.returns
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {source : RelatedDirectCallSource context tree binding}
    {entry : ExactOperationalDirectCallEntry context tree binding
      originalProgram candidateProgram source}
    (certificate : CheckedFiniteCallRegionExecution context tree binding
      originalProgram candidateProgram source entry)
    (before : PairedOperationalCalleePoint)
    (path : FiniteCalleePath context tree entry.point.cursor before.cursor) :
    CheckedOperationalReturnResult context tree binding originalProgram
      candidateProgram source entry before := by
  generalize rankEquation : certificate.termination.rank before = fuel
  induction fuel using Nat.strongRecOn generalizing before with
  | ind fuel induction =>
      cases classified : certificate.classify before path with
      | returning final =>
          let originalTail := final.originalExit.doneAt originalProgram
            binding.continuationTargetId final.originalExitTarget
          let candidateTail := final.candidateExit.doneAt candidateProgram
            binding.continuationTargetId final.candidateExitTarget
          have originalRun : WorldCallRun originalProgram binding.continuationTargetId
              before.original.execution final.originalObservation.toList
              final.originalExit.execution := by
            have notTarget : worldExecutionRunningTarget? before.original.execution ≠
                some binding.continuationTargetId := by
              rw [before.original.runningTarget, before.originalTarget]
              exact fun equality => final.sourceNotContinuation (Option.some.inj equality)
            have tailAtNext : WorldCallRun originalProgram binding.continuationTargetId
                (originalProgram.pe32TransitionSystem.step before.original.execution).next []
                final.originalExit.execution := by
              rw [final.originalStep]
              exact originalTail
            have raw := WorldCallRun.step (program := originalProgram)
              (continuationTargetId := binding.continuationTargetId)
              notTarget before.original.mayProgress tailAtNext
            simpa [final.originalStep] using raw
          have candidateRun : WorldCallRun candidateProgram binding.continuationTargetId
              before.candidate.execution final.candidateObservation.toList
              final.candidateExit.execution := by
            have notTarget : worldExecutionRunningTarget? before.candidate.execution ≠
                some binding.continuationTargetId := by
              rw [before.candidate.runningTarget, before.candidateTarget]
              exact fun equality => final.sourceNotContinuation (Option.some.inj equality)
            have tailAtNext : WorldCallRun candidateProgram binding.continuationTargetId
                (candidateProgram.pe32TransitionSystem.step before.candidate.execution).next []
                final.candidateExit.execution := by
              rw [final.candidateStep]
              exact candidateTail
            have raw := WorldCallRun.step (program := candidateProgram)
              (continuationTargetId := binding.continuationTargetId)
              notTarget before.candidate.mayProgress tailAtNext
            simpa [final.candidateStep] using raw
          exact {
            originalExit := final.originalExit
            candidateExit := final.candidateExit
            originalObservations := final.originalObservation.toList
            candidateObservations := final.candidateObservation.toList
            originalRun := originalRun
            candidateRun := candidateRun
            observationsRelated := by
              simpa using prependWorldObservationOptions context
                final.observationRelated
                (show RelatedObservationLists
                  (worldRelationalObservationsRelated context) [] [] from by trivial)
            finiteExecution := {
              beforeReturn := before.cursor
              path := path
              returning := final.returning
            }
            frameExact := final.frameExact
            returnWorldExact := final.returnWorldExact
            originalExitExact := final.originalAfterExact
            candidateExitExact := final.candidateAfterExact
            originalExitTarget := final.originalExitTarget
            candidateExitTarget := final.candidateExitTarget
            originalExitCalls := final.originalExitCalls
            candidateExitCalls := final.candidateExitCalls
            exitWorld := final.exitWorld
          }
      | progress after step sourceNotContinuation =>
          have decrease := certificate.termination.decreases
            certificate.terminationComplete step
          have afterPath : FiniteCalleePath context tree entry.point.cursor
              after.cursor := .step path step.admitted
          have tail := induction (certificate.termination.rank after)
            (by simpa [rankEquation] using decrease) after afterPath rfl
          have originalRun : WorldCallRun originalProgram binding.continuationTargetId
              before.original.execution
              (step.originalObservation.toList ++ tail.originalObservations)
              tail.originalExit.execution := by
            have notTarget : worldExecutionRunningTarget? before.original.execution ≠
                some binding.continuationTargetId := by
              rw [before.original.runningTarget, before.originalTarget]
              exact fun equality => sourceNotContinuation (Option.some.inj equality)
            have tailAtNext : WorldCallRun originalProgram binding.continuationTargetId
                (originalProgram.pe32TransitionSystem.step before.original.execution).next
                tail.originalObservations tail.originalExit.execution := by
              rw [step.originalStep]
              exact tail.originalRun
            have raw := WorldCallRun.step (program := originalProgram)
              (continuationTargetId := binding.continuationTargetId)
              notTarget before.original.mayProgress tailAtNext
            simpa [step.originalStep] using raw
          have candidateRun : WorldCallRun candidateProgram binding.continuationTargetId
              before.candidate.execution
              (step.candidateObservation.toList ++ tail.candidateObservations)
              tail.candidateExit.execution := by
            have notTarget : worldExecutionRunningTarget? before.candidate.execution ≠
                some binding.continuationTargetId := by
              rw [before.candidate.runningTarget, before.candidateTarget]
              exact fun equality => sourceNotContinuation (Option.some.inj equality)
            have tailAtNext : WorldCallRun candidateProgram binding.continuationTargetId
                (candidateProgram.pe32TransitionSystem.step before.candidate.execution).next
                tail.candidateObservations tail.candidateExit.execution := by
              rw [step.candidateStep]
              exact tail.candidateRun
            have raw := WorldCallRun.step (program := candidateProgram)
              (continuationTargetId := binding.continuationTargetId)
              notTarget before.candidate.mayProgress tailAtNext
            simpa [step.candidateStep] using raw
          exact {
            originalExit := tail.originalExit
            candidateExit := tail.candidateExit
            originalObservations := step.originalObservation.toList ++
              tail.originalObservations
            candidateObservations := step.candidateObservation.toList ++
              tail.candidateObservations
            originalRun := originalRun
            candidateRun := candidateRun
            observationsRelated := prependWorldObservationOptions context
              step.observationRelated tail.observationsRelated
            finiteExecution := tail.finiteExecution
            frameExact := tail.frameExact
            returnWorldExact := tail.returnWorldExact
            originalExitExact := tail.originalExitExact
            candidateExitExact := tail.candidateExitExact
            originalExitTarget := tail.originalExitTarget
            candidateExitTarget := tail.candidateExitTarget
            originalExitCalls := tail.originalExitCalls
            candidateExitCalls := tail.candidateExitCalls
            exitWorld := tail.exitWorld
          }

def programUsesCanonicalCodeMap
    (program : DecodedWorldProgram) (context : StaticProofContext) : Prop :=
  forall targetId target, context.codeMap.get? targetId = some target ->
    exists region, regionById program.regions targetId = some region /\
      region.id = targetId /\
      region.original.start = target.originalRva /\
      region.candidate.start = target.candidateRva

/-- Operational completeness is represented by exact call-entry witnesses and
a checked, terminating outgoing classifier for every related source.  The
derived `returnsFromEverySource` theorem rules out faults, blocks, premature
terminal states, and divergence; there is no independent return-status field. -/
structure OperationalCallReturnCompleteness (context : StaticProofContext)
    (tree : SummaryTree) (binding : ExactDirectCallEntryBinding context tree) where
  originalProgram : DecodedWorldProgram
  candidateProgram : DecodedWorldProgram
  originalContext : originalProgram.context = context
  candidateContext : candidateProgram.context = context
  originalSide : originalProgram.candidate = false
  candidateSide : candidateProgram.candidate = true
  originalRegions : programUsesCanonicalCodeMap originalProgram context
  candidateRegions : programUsesCanonicalCodeMap candidateProgram context
  originalInstructionSemantics : originalProgram.InstructionSemanticsAdequate
  candidateInstructionSemantics : candidateProgram.InstructionSemanticsAdequate
  entryForSource : forall source : RelatedDirectCallSource context tree binding,
    ExactOperationalDirectCallEntry context tree binding originalProgram
      candidateProgram source
  executionForSource : forall source : RelatedDirectCallSource context tree binding,
    CheckedFiniteCallRegionExecution context tree binding originalProgram
      candidateProgram source (entryForSource source)

theorem OperationalCallReturnCompleteness.returnsFromEverySource
    {context : StaticProofContext} {tree : SummaryTree}
    {binding : ExactDirectCallEntryBinding context tree}
    (complete : OperationalCallReturnCompleteness context tree binding)
    (source : RelatedDirectCallSource context tree binding) :
    exists actual : ActualDirectCallReturnExecution context tree binding
      complete.originalProgram complete.candidateProgram, actual.source = source := by
  let entry := complete.entryForSource source
  let result := (complete.executionForSource source).returns entry.point .entry
  let actual : ActualDirectCallReturnExecution context tree binding
      complete.originalProgram complete.candidateProgram := {
    source := source
    originalEntry := entry.originalEntry
    candidateEntry := entry.candidateEntry
    originalExit := result.originalExit
    candidateExit := result.candidateExit
    originalCallStep := entry.originalCallStep
    candidateCallStep := entry.candidateCallStep
    originalEntryTarget := entry.originalEntryTarget
    candidateEntryTarget := entry.candidateEntryTarget
    originalExitTarget := result.originalExitTarget
    candidateExitTarget := result.candidateExitTarget
    originalEntryCalls := entry.originalEntryCalls
    candidateEntryCalls := entry.candidateEntryCalls
    originalExitCalls := result.originalExitCalls
    candidateExitCalls := result.candidateExitCalls
    entryWorld := entry.entryWorld
    exitWorld := result.exitWorld
    originalObservations := result.originalObservations
    candidateObservations := result.candidateObservations
    originalRun := result.originalRun
    candidateRun := result.candidateRun
    observationsRelated := result.observationsRelated
    frame := entry.frame
    runtimeFrame := entry.runtimeFrame
    frameValid := entry.frameValid
    frameAtEntry := entry.frameAtEntry
    frameContinuation := entry.frameContinuation
    entryArgumentWords := entry.entryArgumentWords
    entryRegisters := entry.entryRegisters
    finiteExecution := result.finiteExecution
    finiteFrameExact := result.frameExact
    finiteReturnWorldExact := result.returnWorldExact
    finiteOriginalExitExact := result.originalExitExact
    finiteCandidateExitExact := result.candidateExitExact
  }
  exact ⟨actual, rfl⟩

/-- All shared semantic premises needed before the summary may be used as a
`checked_direct_call_summary` provenance edge. -/
structure IntegratedSummaryPremises (context : StaticProofContext) (tree : SummaryTree) where
  structuralChecked : tree.checked context.originalPe context.candidatePe
    context.originalImports context.candidateImports = true
  callEntry : ExactDirectCallEntryBinding context tree
  operational : OperationalCallReturnCompleteness context tree callEntry
  graphComplete : GraphExecutionCompleteness context tree
  registerGrounded : forall register,
    register ∈ tree.certificate.requestedRegisters ->
      RequestedRegisterGrounding context tree register
  loops : LoopDischarge context tree
  loopsComplete : loops.Complete
  invariant : forall entry : PairedCalleeCursor,
    entry.regionId = tree.certificate.calleeEntry.id ->
      CalleeInductiveInvariant context tree entry

/-- Requested-register preservation for an actual canonical `call_return`
execution.  This is the theorem consumed by mixed-original integration. -/
theorem actualDirectCallReturn_preserves
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram) :
    requestedCallReturnRegistersHold tree.certificate
      actual.source.original.state actual.source.candidate.state
      actual.originalExit.state actual.candidateExit.state := by
  let lifted := actual.finite
  have result := finiteReturningExecution_preserves
    (premises.invariant actual.entryCursor rfl) lifted.execution
  have returned := result.registers
  rw [lifted.originalExitExact, lifted.candidateExitExact] at returned
  exact requestedCallReturnRegistersHold_of_entry_and_return tree.certificate
    actual.source.original.state actual.source.candidate.state
    actual.originalEntry.state actual.candidateEntry.state
    actual.originalExit.state actual.candidateExit.state actual.entryRegisters returned

theorem actualDirectCallReturn_entryArgumentWord
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram)
    (word : RuntimeFrameArgumentWord) (member : word ∈ premises.callEntry.argumentWords) :
    word.holds context actual.source.original.world actual.frame
      actual.originalEntry.state.memory actual.candidateEntry.state.memory = true :=
  actual.entryArgumentWords word member

/-- Generic continuation postcondition for writable static words.  Fixed code
pointer slots can feed the existing static-slot indirect-call certificates. -/
theorem actualDirectCallReturn_staticWordSlot
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram)
    (slot : StaticWordRelationSlotPair) (member : slot ∈ context.staticWordRelationSlots) :
    slot.memoryHolds context actual.source.original.world
      actual.originalExit.state.memory actual.candidateExit.state.memory = true := by
  let lifted := actual.finite
  have result := finiteReturningExecution_preserves
    (premises.invariant actual.entryCursor rfl) lifted.execution
  rcases result.continuationRelated with ⟨continuationInvariant, continuationRelated⟩
  rw [lifted.returnWorldExact] at continuationRelated
  have slots := continuationRelated.staticWordRelationSlotsMemoryHold
    context actual.source.original.world continuationInvariant
      lifted.execution.returning.afterOriginal lifted.execution.returning.afterCandidate
  have selected := slots slot member
  rw [lifted.originalExitExact, lifted.candidateExitExact] at selected
  exact selected

/-- Exact machine-level dataflow for a caller argument copied into a writable
static word.  The witness states the two concrete read/write equations; the
shared relation kind then transports the checked argument relation to the
post-call slot.  Merely naming the same relation kind is insufficient. -/
structure RuntimeFrameArgumentStaticWrite
    (word : RuntimeFrameArgumentWord) (slot : StaticWordRelationSlotPair)
    (frame : RelationalRuntimeCallFrame)
    (entryOriginal entryCandidate exitOriginal exitCandidate : Memory) where
  sameRelation : word.relation = slot.relation
  originalCopied : Memory.read32 exitOriginal slot.originalAddress =
    Memory.read32 entryOriginal
      (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset)
  candidateCopied : Memory.read32 exitCandidate slot.candidateAddress =
    Memory.read32 entryCandidate
      (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset)

theorem RuntimeFrameArgumentStaticWrite.slotHolds
    {context : StaticProofContext} {world : RelationalWorld}
    {word : RuntimeFrameArgumentWord} {slot : StaticWordRelationSlotPair}
    {frame : RelationalRuntimeCallFrame}
    {entryOriginal entryCandidate exitOriginal exitCandidate : Memory}
    (copy : RuntimeFrameArgumentStaticWrite word slot frame
      entryOriginal entryCandidate exitOriginal exitCandidate)
    (argument : word.holds context world frame entryOriginal entryCandidate = true) :
    slot.memoryHolds context world exitOriginal exitCandidate = true := by
  unfold RuntimeFrameArgumentWord.holds at argument
  unfold StaticWordRelationSlotPair.memoryHolds
  rw [← copy.sameRelation, copy.originalCopied, copy.candidateCopied]
  exact argument

theorem actualDirectCallReturn_argumentToStaticSlot
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram)
    (word : RuntimeFrameArgumentWord) (wordMember : word ∈ premises.callEntry.argumentWords)
    (slot : StaticWordRelationSlotPair) (slotMember : slot ∈ context.staticWordRelationSlots)
    (copy : RuntimeFrameArgumentStaticWrite word slot actual.frame
      actual.originalEntry.state.memory actual.candidateEntry.state.memory
      actual.originalExit.state.memory actual.candidateExit.state.memory) :
    word.holds context actual.source.original.world actual.frame
          actual.originalEntry.state.memory actual.candidateEntry.state.memory = true /\
      slot.memoryHolds context actual.source.original.world
          actual.originalExit.state.memory actual.candidateExit.state.memory = true := by
  have argument := actualDirectCallReturn_entryArgumentWord premises actual word wordMember
  exact ⟨argument, copy.slotHolds argument⟩

theorem noIntegratedSummaryPremises_of_structural_rejection
    {context : StaticProofContext} {tree : SummaryTree}
    (rejected : tree.checked context.originalPe context.candidatePe
      context.originalImports context.candidateImports = false) :
    IntegratedSummaryPremises context tree -> False := by
  intro premises
  have checked := premises.structuralChecked
  rw [rejected] at checked
  contradiction

def integratedInvocation {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree)
    (sourceOriginal sourceCandidate exitOriginal exitCandidate : MachineState)
    (world : RelationalWorld) (frame : RelationalRuntimeCallFrame) : Prop :=
  exists actual : ActualDirectCallReturnExecution context tree premises.callEntry
      premises.operational.originalProgram premises.operational.candidateProgram,
    actual.source.original.state = sourceOriginal /\
      actual.source.candidate.state = sourceCandidate /\
      actual.source.original.world = world /\
      actual.frame = frame /\
      actual.originalExit.state = exitOriginal /\
      actual.candidateExit.state = exitCandidate

/-- Conversion into the compact recursive contract consumed by nested calls.
This theorem is the composable semantic witness used by mixed-original; the
structural summary alone cannot produce it. -/
def IntegratedSummaryPremises.toSemanticContract
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree) :
    DirectCallSemanticContract context tree where
  invocation := integratedInvocation premises
  preserves := by
    intro sourceOriginal sourceCandidate exitOriginal exitCandidate world frame invocation
    rcases invocation with ⟨actual, rfl, rfl, rfl, rfl, rfl, rfl⟩
    exact actualDirectCallReturn_preserves premises actual
  framePreserved := by
    intro sourceOriginal sourceCandidate exitOriginal exitCandidate world frame invocation
    rcases invocation with ⟨actual, rfl, rfl, rfl, rfl, rfl, rfl⟩
    let lifted := actual.finite
    have result := finiteReturningExecution_preserves
      (premises.invariant actual.entryCursor rfl) lifted.execution
    have frameValid := result.frameValid
    have frameMemory := result.frameMemory
    rw [lifted.frameExact] at frameValid frameMemory
    rw [lifted.originalExitExact, lifted.candidateExitExact] at frameMemory
    exact ⟨frameValid, frameMemory⟩
  continuationRelated := by
    intro sourceOriginal sourceCandidate exitOriginal exitCandidate world frame invocation
    rcases invocation with ⟨actual, rfl, rfl, rfl, rfl, rfl, rfl⟩
    let lifted := actual.finite
    have result := finiteReturningExecution_preserves
      (premises.invariant actual.entryCursor rfl) lifted.execution
    rcases result.continuationRelated with ⟨continuationInvariant, related⟩
    refine ⟨continuationInvariant, ?_⟩
    rw [lifted.returnWorldExact] at related
    rw [lifted.originalExitExact, lifted.candidateExitExact] at related
    exact related

/-- A mixed-original provenance row may cite this witness.  Its fields expose
the exact tree and semantic contract, avoiding a second diagnostic-only model. -/
structure CheckedDirectCallSummaryProvenance (context : StaticProofContext) where
  tree : SummaryTree
  premises : IntegratedSummaryPremises context tree
  contract : DirectCallSemanticContract context tree
  contractExact : contract = premises.toSemanticContract

def IntegratedSummaryPremises.provenance
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree) :
    CheckedDirectCallSummaryProvenance context := {
  tree := tree
  premises := premises
  contract := premises.toSemanticContract
  contractExact := rfl
}

/-- Authority is represented as the presence of the complete semantic witness.
`none` is the only value an incomplete generator may emit. -/
def StandaloneAcceptanceAuthority {context : StaticProofContext} {tree : SummaryTree}
    (premises : Option (IntegratedSummaryPremises context tree)) : Bool :=
  premises.isSome

theorem standaloneAcceptanceAuthority_false_of_missing
    {context : StaticProofContext} {tree : SummaryTree} :
    StandaloneAcceptanceAuthority
      (none : Option (IntegratedSummaryPremises context tree)) = false := rfl

theorem standaloneAcceptanceAuthority_true_of_complete
    {context : StaticProofContext} {tree : SummaryTree}
    (premises : IntegratedSummaryPremises context tree) :
    StandaloneAcceptanceAuthority (some premises) = true := rfl

#print axioms ExactInternalSegmentStep.targetRelated
#print axioms FiniteCalleePath.invariant
#print axioms finiteReturningExecution_preserves
#print axioms WorldCallRun.not_from_returned
#print axioms WorldCallRun.not_from_terminated
#print axioms WorldCallRun.not_from_fault
#print axioms WorldCallRun.not_from_blocked
#print axioms WorldCallRun.deterministic
#print axioms CallRegionTerminationCertificate.decreases
#print axioms CallRegionTerminationCertificate.incomplete_not_complete
#print axioms CheckedFiniteCallRegionExecution.returns
#print axioms OperationalCallReturnCompleteness.returnsFromEverySource
#print axioms actualDirectCallReturn_preserves
#print axioms actualDirectCallReturn_entryArgumentWord
#print axioms actualDirectCallReturn_staticWordSlot
#print axioms RuntimeFrameArgumentStaticWrite.slotHolds
#print axioms actualDirectCallReturn_argumentToStaticSlot
#print axioms IntegratedSummaryPremises.toSemanticContract
#print axioms noIntegratedSummaryPremises_of_structural_rejection
#print axioms standaloneAcceptanceAuthority_false_of_missing
#print axioms standaloneAcceptanceAuthority_true_of_complete

end StageA.Relational.InternalDirectCallComposition
