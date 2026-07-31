import StageA.RelationalComposition
import StageA.RelationalNullableCodePointerTable
import StageA.RelationalOriginalStackDynamicControlClosure

namespace StageA.Relational.NullableCodePointerDispatch

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.NullableCodePointerTable
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalStackDynamicControlClosure

/-- A region identity is checked against the canonical code map before its
exact bytes are decoded.  Spans are carried explicitly because a code target
does not, by itself, determine the end of a mixed region. -/
structure PairedDecodedRegionRef where
  targetId : Nat
  originalSpan : Span
  candidateSpan : Span
deriving Repr, DecidableEq

structure DecodedRegionBehavior where
  original : NormalizedSymbolicBehavior
  candidate : NormalizedSymbolicBehavior
deriving Repr, DecidableEq

def PairedDecodedRegionRef.decode? (context : StaticProofContext)
    (region : PairedDecodedRegionRef) : Option DecodedRegionBehavior := do
  let target <- context.codeMap.get? region.targetId
  if target.id != region.targetId || target.originalRva != region.originalSpan.start ||
      target.candidateRva != region.candidateSpan.start ||
      region.originalSpan.size == 0 || region.candidateSpan.size == 0 then
    none
  else
    let original <- regionBehaviorWithMachineCallContracts context.originalPe
      context.originalImports context.machineImportCallContracts region.originalSpan
    let candidate <- regionBehaviorWithMachineCallContracts context.candidatePe
      context.candidateImports context.machineImportCallContracts region.candidateSpan
    let original <- normalizeSymbolicBehavior false context.codeMap.entries.toList original
    let candidate <- normalizeSymbolicBehavior true context.codeMap.entries.toList candidate
    pure { original, candidate }

structure DecodedDispatchCluster where
  scanner : DecodedRegionBehavior
  test : DecodedRegionBehavior
  bridge : DecodedRegionBehavior
  guard : DecodedRegionBehavior
  dispatch : DecodedRegionBehavior
deriving Repr, DecidableEq

/-- The submitted table certificate is used only for exact original-byte and
finite-row facts.  Its writer/alias proposal fields are intentionally absent
from this check: immutability is re-established by the PE reader and by the
paired bounded-table checker, rather than by trusting empty proposal lists. -/
def tableCertificateTargetsMatch (context : StaticProofContext)
    (targets : List NullableCodePointerTable.CodeTarget)
    (rows : List ImmutableCodePointerTableRow) : Bool :=
  NullableCodePointerTable.sameFiniteSet (targets.map (·.targetId))
      (rows.map (·.targetId)).eraseDups &&
    targets.all fun proposed =>
      match context.codeMap.get? proposed.targetId with
      | some target => target.id == proposed.targetId && target.originalRva == proposed.rva
      | none => false

def tableCertificateRowsMatch (certificate : NullableCodePointerTable.Certificate)
    (table : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  match certificate.callerRange, certificate.codeMap,
      certificate.nonNullTargetIds, certificate.edges, certificate.loop,
      certificate.guard with
  | .exact range, .exact _targets, .exact targetIds, .exact edges,
      .exact loop, .exact guard =>
      range.startRva == certificate.tableRva + certificate.headerWords.length * 4 &&
        range.endRva == certificate.tableRva + table.tableSpanWords * 4 &&
        NullableCodePointerTable.sameFiniteSet targetIds
          (table.rows.map (·.targetId)).eraseDups &&
        NullableCodePointerTable.sameFiniteSet edges
          (NullableCodePointerTable.expectedEdges certificate.contextId targetIds) &&
        loop.lowerInclusive == 0 &&
        loop.upperExclusive == NullableCodePointerTable.entryCount range &&
        loop.step == 1 && loop.addressBaseRva == range.startRva &&
        loop.addressScale == 4 && loop.alignment == 4 && guard == .nonzero
  | _, _, _, _, _, _ => false

def tableCertificateCheckedAgainst (context : StaticProofContext)
    (certificate : NullableCodePointerTable.Certificate)
    (table : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  ByteTree.ofBytes certificate.peBytes == context.originalPe.bytes &&
    certificate.tableRva + context.originalPe.imageBase == table.originalBase &&
    tableCertificateRowsMatch certificate table &&
    match certificate.callerRange, certificate.codeMap,
        certificate.nonNullTargetIds, certificate.edges, certificate.loop,
        certificate.guard, parsePE32Tree (ByteTree.ofBytes certificate.peBytes) with
    | .exact range, .exact targets, .exact targetIds, .exact edges,
        .exact loop, .exact guard, some pe =>
        pe == context.originalPe &&
          tableCertificateTargetsMatch context targets table.rows &&
          match parseRelocations pe with
          | some relocations =>
              certificate.checkedParsed pe relocations range targets targetIds
                edges loop guard
          | none => false
    | _, _, _, _, _, _, _ => false

/-- The table proposal must describe the one-word reverse sentinel literally.
The bounded table checker independently reads the zero terminator and every
relocation-backed non-null row from both immutable images. -/
def exactReverseSentinelTableChecked (context : StaticProofContext)
    (certificate : NullableCodePointerTable.Certificate)
    (table : BoundedImmutableCodePointerTableCallClaim) : Bool :=
  certificate.headerWords == [2 ^ 32 - 1] &&
    table.layout == .sentinelTerminatedReverseCount &&
    readImmutableImageWord context.originalPe table.originalBase 4 ==
      some (2 ^ 32 - 1) &&
    readImmutableImageWord context.candidatePe table.candidateBase 4 ==
      some (2 ^ 32 - 1) &&
    readImmutableImageWord context.originalPe
        (table.originalAddress table.upperExclusive) 4 == some 0 &&
    readImmutableImageWord context.candidatePe
        (table.candidateAddress table.upperExclusive) 4 == some 0 &&
    table.staticShapeChecked context &&
    table.rowsChecked context &&
    tableCertificateCheckedAgainst context certificate table

def bridgeBehaviorChecked (claim : ReverseSentinelScannerClaim)
    (guardTargetId : Nat) (behavior : DecodedRegionBehavior) : Bool :=
  behavior.original.registers.get claim.originalCountRegister ==
      .inputReg claim.originalCountRegister &&
    behavior.candidate.registers.get claim.candidateCountRegister ==
      .inputReg claim.candidateCountRegister &&
    behavior.original.writes.isEmpty && behavior.candidate.writes.isEmpty &&
    normalizedFlagsPreserveInputs behavior.original.flags &&
    normalizedFlagsPreserveInputs behavior.candidate.flags &&
    behavior.original.outcome == .jump guardTargetId &&
    behavior.candidate.outcome == .jump guardTargetId

def NormalizedOutcomeExpr.guardForTarget
    (outcome : NormalizedOutcomeExpr) (targetId : Nat) : Option BoolExpr :=
  match outcome with
  | .branch guard taken fallthrough =>
      if taken == targetId && fallthrough != targetId then some guard
      else if fallthrough == targetId && taken != targetId then some (.not guard)
      else none
  | _ => none

def dispatchGuardBehaviorChecked (claim : ReverseSentinelScannerClaim)
    (dispatchTargetId : Nat) (behavior : DecodedRegionBehavior) : Bool :=
  behavior.original.registers.get claim.originalCountRegister ==
      .inputReg claim.originalCountRegister &&
    behavior.candidate.registers.get claim.candidateCountRegister ==
      .inputReg claim.candidateCountRegister &&
    behavior.original.writes.isEmpty && behavior.candidate.writes.isEmpty &&
    NormalizedOutcomeExpr.guardForTarget behavior.original.outcome dispatchTargetId ==
      some (registerNonzeroGuard claim.originalCountRegister) &&
    NormalizedOutcomeExpr.guardForTarget behavior.candidate.outcome dispatchTargetId ==
      some (registerNonzeroGuard claim.candidateCountRegister)

def NormalizedOutcomeExpr.bypassForTarget
    (outcome : NormalizedOutcomeExpr) (targetId : Nat) : Option Nat :=
  match outcome with
  | .branch _ taken fallthrough =>
      if taken == targetId && fallthrough != targetId then some fallthrough
      else if fallthrough == targetId && taken != targetId then some taken
      else none
  | _ => none

/-- The nonzero guard alone is not enough: the opposite branch must be the
declared bypass, so the checked gate has exactly the two intended successors. -/
def dispatchGateBehaviorChecked (claim : ReverseSentinelScannerClaim)
    (dispatchTargetId bypassTargetId : Nat)
    (behavior : DecodedRegionBehavior) : Bool :=
  dispatchGuardBehaviorChecked claim dispatchTargetId behavior &&
    NormalizedOutcomeExpr.bypassForTarget behavior.original.outcome
        dispatchTargetId ==
      some bypassTargetId &&
    NormalizedOutcomeExpr.bypassForTarget behavior.candidate.outcome
        dispatchTargetId ==
      some bypassTargetId

/-- A local mixed-dispatch binding. `dispatchPredecessorIds` is checked for
shape here. Its global completeness is supplied either by the legacy typed
composition premise below or by the checked rooted certificate. -/
structure Claim where
  tableCertificate : NullableCodePointerTable.Certificate
  tableCall : BoundedImmutableCodePointerTableCallClaim
  scanner : ReverseSentinelScannerClaim
  scannerSourceInvariant : StateInvariant
  scannerPostInvariant : StateInvariant
  scannerFinishedInvariant : StateInvariant
  dispatchInvariant : StateInvariant
  scannerRegion : PairedDecodedRegionRef
  testRegion : PairedDecodedRegionRef
  bridgeRegion : PairedDecodedRegionRef
  guardRegion : PairedDecodedRegionRef
  dispatchRegion : PairedDecodedRegionRef
  dispatchBypassTargetId : Nat
  dispatchPredecessorIds : List Nat
  originalDispatchBase : Nat
  candidateDispatchBase : Nat
  dispatchScale : Nat
  dispatchIndexOffset : Nat
deriving Repr, DecidableEq

def Claim.cluster? (context : StaticProofContext)
    (claim : Claim) : Option DecodedDispatchCluster := do
  let scanner <- claim.scannerRegion.decode? context
  let test <- claim.testRegion.decode? context
  let bridge <- claim.bridgeRegion.decode? context
  let guard <- claim.guardRegion.decode? context
  let dispatch <- claim.dispatchRegion.decode? context
  pure { scanner, test, bridge, guard, dispatch }

def Claim.bindingShapeChecked (context : StaticProofContext) (claim : Claim) : Bool :=
  claim.scanner.table == claim.tableCall &&
    claim.tableCertificate.contextId == claim.dispatchRegion.targetId &&
    claim.tableCertificate.dispatchRva == claim.dispatchRegion.originalSpan.start &&
    claim.scannerRegion.targetId == claim.scanner.scannerTargetId &&
    claim.testRegion.targetId == claim.scanner.testTargetId &&
    claim.bridgeRegion.targetId == claim.scanner.bridgeTargetId &&
    claim.tableCall.continuationTargetId != claim.dispatchRegion.targetId &&
    claim.originalDispatchBase == claim.tableCall.originalBase &&
    claim.candidateDispatchBase == claim.tableCall.candidateBase &&
    claim.dispatchScale == 4 && claim.dispatchIndexOffset == 0 &&
    NullableCodePointerTable.sameFiniteSet claim.dispatchPredecessorIds
      [claim.guardRegion.targetId] &&
    claim.dispatchBypassTargetId != claim.dispatchRegion.targetId &&
    (context.codeMap.get? claim.dispatchBypassTargetId).isSome

def Claim.identityChecked (context : StaticProofContext) (claim : Claim) : Bool :=
  claim.bindingShapeChecked context &&
    exactReverseSentinelTableChecked context claim.tableCertificate claim.tableCall

def Claim.semanticChecked (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster) : Bool :=
  claim.scanner.table == claim.tableCall &&
    claim.scanner.checked context claim.scannerSourceInvariant
      claim.scannerPostInvariant cluster.scanner.original cluster.scanner.candidate &&
    claim.scanner.exitChecked claim.scannerPostInvariant
      claim.scannerFinishedInvariant cluster.test.original cluster.test.candidate &&
    bridgeBehaviorChecked claim.scanner claim.guardRegion.targetId cluster.bridge &&
    dispatchGateBehaviorChecked claim.scanner claim.dispatchRegion.targetId
      claim.dispatchBypassTargetId cluster.guard &&
    claim.tableCall.staticShapeChecked context &&
    claim.tableCall.rowsChecked context &&
    claim.tableCall.behaviorChecked cluster.dispatch.original cluster.dispatch.candidate &&
    (if claim.tableCall.entryCount == 0 then true
      else claim.tableCall.checked context claim.dispatchInvariant
        cluster.dispatch.original cluster.dispatch.candidate)

def Claim.checked (context : StaticProofContext) (claim : Claim) : Bool :=
  claim.identityChecked context &&
    match claim.cluster? context with
    | some cluster => claim.semanticChecked context cluster
    | none => false

def scannerOriginalNext (cluster : DecodedDispatchCluster)
    (state : MachineState) : MachineState :=
  (cluster.scanner.original.eval state).nextMachineState state

def scannerCandidateNext (cluster : DecodedDispatchCluster)
    (state : MachineState) : MachineState :=
  (cluster.scanner.candidate.eval state).nextMachineState state

def testOriginalNext (cluster : DecodedDispatchCluster)
    (state : MachineState) : MachineState :=
  (cluster.test.original.eval state).nextMachineState state

def testCandidateNext (cluster : DecodedDispatchCluster)
    (state : MachineState) : MachineState :=
  (cluster.test.candidate.eval state).nextMachineState state

def bridgeOriginalNext (cluster : DecodedDispatchCluster)
    (state : MachineState) : MachineState :=
  (cluster.bridge.original.eval state).nextMachineState state

def bridgeCandidateNext (cluster : DecodedDispatchCluster)
    (state : MachineState) : MachineState :=
  (cluster.bridge.candidate.eval state).nextMachineState state

/-- This is the exact local path that composition must establish.  The second
`StateRel` is intentionally explicit: the current shared composition API does
not yet expose a theorem upgrading the scanner's checked post-predicate to a
full successor `StateRel`. -/
structure EmptyScannerDispatchPath (context : StaticProofContext)
    (claim : Claim) (cluster : DecodedDispatchCluster) where
  world : RelationalWorld
  originalScannerState : MachineState
  candidateScannerState : MachineState
  scannerRelated : StateRel context world claim.scannerSourceInvariant
    originalScannerState candidateScannerState
  scannerSuccessorRelated : StateRel context world claim.scannerPostInvariant
    (scannerOriginalNext cluster originalScannerState)
    (scannerCandidateNext cluster candidateScannerState)
  scannerExitTaken : claim.scanner.exitGuard.eval
    (scannerOriginalNext cluster originalScannerState) = true
  dispatchEdgeTaken : (registerNonzeroGuard claim.scanner.originalCountRegister).eval
    (bridgeOriginalNext cluster
      (testOriginalNext cluster (scannerOriginalNext cluster originalScannerState))) = true

def EmptyLocalDispatchClosed (context : StaticProofContext)
    (claim : Claim) (cluster : DecodedDispatchCluster) : Prop :=
  ∀ _path : EmptyScannerDispatchPath context claim cluster, False

theorem emptyLocalDispatchClosed_of_semantic_checked
    (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster)
    (empty : claim.tableCall.entryCount = 0)
    (checked : Claim.semanticChecked context claim cluster = true) :
    EmptyLocalDispatchClosed context claim cluster := by
  simp only [Claim.semanticChecked, Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨⟨sameTable, _scannerChecked⟩, exitChecked⟩, bridgeChecked⟩, _guardChecked⟩,
      _staticChecked⟩, _rowsChecked⟩, _dispatchBehaviorChecked⟩, _domainChecked⟩
  intro path
  simp only [ReverseSentinelScannerClaim.exitChecked, Bool.and_eq_true,
    beq_iff_eq] at exitChecked
  have sourceShape := exitChecked.1.1.1.1
  have testBehaviorChecked := exitChecked.2
  have predicates := path.scannerSuccessorRelated.predicatesHold
  rw [sourceShape] at predicates
  simp only [pairedStatePredicatesHold, List.all_cons, List.all_nil,
    Bool.and_true, PairedStatePredicate.holds, Bool.and_eq_true] at predicates
  have originalPost := predicates.1.1
  simp only [ReverseSentinelScannerClaim.postPredicate,
    reverseSentinelScannerPostExpression, BoolExpr.eval, Expr.eval,
    Bool.and_eq_true, Bool.or_eq_true] at originalPost
  have originalFlagTrue :
      (BoolExpr.inputFlag claim.scanner.zeroFlagBit).eval
        (scannerOriginalNext cluster path.originalScannerState) = true := by
    simpa [ReverseSentinelScannerClaim.exitGuard,
      ReverseSentinelScannerClaim.loopGuard, BoolExpr.eval] using
      path.scannerExitTaken
  have originalFlagTrueRaw :
      ((scannerOriginalNext cluster path.originalScannerState).eflags.extractLsb'
        claim.scanner.zeroFlagBit 1 == BitVec.ofNat 1 1) = true := by
    simpa only [BoolExpr.eval] using originalFlagTrue
  have countAtScannerExit :
      (scannerOriginalNext cluster path.originalScannerState).registers.get
          claim.scanner.originalCountRegister =
        BitVec.ofNat 32 claim.scanner.table.entryCount := by
    rcases originalPost.2.2 with nonzero | zero
    · rw [originalFlagTrueRaw] at nonzero
      simp at nonzero
    · exact of_decide_eq_true zero.2
  simp only [ReverseSentinelScannerClaim.testBehaviorChecked,
    Bool.and_eq_true, beq_iff_eq] at testBehaviorChecked
  rcases testBehaviorChecked with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨_originalScannerIdentity, _candidateScannerIdentity⟩,
      originalCountIdentity⟩, _candidateCountIdentity⟩, _originalTestWrites⟩,
      _candidateTestWrites⟩, _originalTestFlags⟩, _candidateTestFlags⟩,
      _originalTestOutcome⟩, _candidateTestOutcome⟩
  have countAfterTest :
      (testOriginalNext cluster (scannerOriginalNext cluster
        path.originalScannerState)).registers.get claim.scanner.originalCountRegister =
        BitVec.ofNat 32 claim.scanner.table.entryCount := by
    change (cluster.test.original.eval
      (scannerOriginalNext cluster path.originalScannerState)).registers.get
        claim.scanner.originalCountRegister =
      BitVec.ofNat 32 claim.scanner.table.entryCount
    simp [NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      originalCountIdentity, Expr.eval, countAtScannerExit]
  have originalCountZero :
      (testOriginalNext cluster (scannerOriginalNext cluster
        path.originalScannerState)).registers.get claim.scanner.originalCountRegister =
        BitVec.ofNat 32 0 := by
    have sameTableEq := beq_iff_eq.mp sameTable
    rw [sameTableEq, empty] at countAfterTest
    exact countAfterTest
  simp only [bridgeBehaviorChecked, Bool.and_eq_true, beq_iff_eq] at bridgeChecked
  rcases bridgeChecked with
    ⟨⟨⟨⟨⟨⟨⟨bridgeCount, _candidateBridgeCount⟩, _originalWrites⟩,
      _candidateWrites⟩, _originalFlags⟩, _candidateFlags⟩, _originalOutcome⟩,
      _candidateOutcome⟩
  have countAfterBridge :
      (bridgeOriginalNext cluster
        (testOriginalNext cluster (scannerOriginalNext cluster
          path.originalScannerState))).registers.get
          claim.scanner.originalCountRegister = BitVec.ofNat 32 0 := by
    change (cluster.bridge.original.eval
      (testOriginalNext cluster (scannerOriginalNext cluster
        path.originalScannerState))).registers.get
        claim.scanner.originalCountRegister = BitVec.ofNat 32 0
    simp [NormalizedSymbolicBehavior.eval_registers, evalNormalizedRegisters_get,
      bridgeCount, Expr.eval, originalCountZero]
  have impossible :
      (registerNonzeroGuard claim.scanner.originalCountRegister).eval
        (bridgeOriginalNext cluster
          (testOriginalNext cluster (scannerOriginalNext cluster
            path.originalScannerState))) = false := by
    simp [registerNonzeroGuard, BoolExpr.eval, Expr.eval, countAfterBridge]
  have taken := path.dispatchEdgeTaken
  rw [impossible] at taken
  contradiction

/-- Composition supplies the meaning of `actualReachable`.  This premise is
the typed integration point currently missing from the shared product graph:
it must prove that the complete predecessor inventory is exactly the checked
scanner/test/bridge/guard path, and return the corresponding path witness. -/
structure CompleteDispatchPredecessorPremise (context : StaticProofContext)
    (claim : Claim) (cluster : DecodedDispatchCluster)
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop) : Prop where
  exactPredecessors : claim.dispatchPredecessorIds = [claim.guardRegion.targetId]
  everyReachableHasCheckedPath :
    ∀ world originalState candidateState,
      actualReachable world originalState candidateState →
        ∃ path : EmptyScannerDispatchPath context claim cluster,
          bridgeOriginalNext cluster
              (testOriginalNext cluster
                (scannerOriginalNext cluster path.originalScannerState)) = originalState ∧
            bridgeCandidateNext cluster
              (testCandidateNext cluster
                (scannerCandidateNext cluster path.candidateScannerState)) = candidateState

def ActualDispatchSourceUninhabited
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop) : Prop :=
  ¬ ∃ world originalState candidateState,
    actualReachable world originalState candidateState

theorem actualDispatchSourceUninhabited_of_complete_predecessors
    (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster)
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop)
    (empty : claim.tableCall.entryCount = 0)
    (checked : Claim.semanticChecked context claim cluster = true)
    (complete : CompleteDispatchPredecessorPremise context claim cluster
      actualReachable) :
    ActualDispatchSourceUninhabited actualReachable := by
  intro reachable
  rcases reachable with ⟨world, originalState, candidateState, reached⟩
  rcases complete.everyReachableHasCheckedPath world originalState candidateState
    reached with ⟨path, _originalState, _candidateState⟩
  exact emptyLocalDispatchClosed_of_semantic_checked context claim cluster empty
    checked path

inductive ActualDecodedMixedDispatchClosure (context : StaticProofContext)
    (claim : Claim) (cluster : DecodedDispatchCluster)
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop) : Prop where
  | unreachable : ActualDispatchSourceUninhabited actualReachable →
      ActualDecodedMixedDispatchClosure context claim cluster actualReachable
  | finiteTargets :
      BoundedImmutableCodePointerTableCallTargetsClosed context
        claim.dispatchInvariant cluster.dispatch.original cluster.dispatch.candidate
        claim.tableCall →
      ActualDecodedMixedDispatchClosure context claim cluster actualReachable

theorem actualDecodedMixedDispatchClosure_of_checked
    (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster)
    (actualReachable : RelationalWorld → MachineState → MachineState → Prop)
    (structurallyValid : context.StructurallyValid)
    (decoded : claim.cluster? context = some cluster)
    (checked : claim.checked context = true)
    (complete : claim.tableCall.entryCount = 0 →
      CompleteDispatchPredecessorPremise context claim cluster actualReachable) :
    ActualDecodedMixedDispatchClosure context claim cluster actualReachable := by
  simp only [Claim.checked, Bool.and_eq_true, decoded] at checked
  have semanticChecked := checked.2
  by_cases empty : claim.tableCall.entryCount = 0
  · exact .unreachable (actualDispatchSourceUninhabited_of_complete_predecessors
      context claim cluster actualReachable empty semanticChecked (complete empty))
  · apply ActualDecodedMixedDispatchClosure.finiteTargets
    simp only [Claim.semanticChecked, Bool.and_eq_true] at semanticChecked
    have boundedChecked := semanticChecked.2
    simp [empty] at boundedChecked
    exact boundedImmutableCodePointerTableCallTargetsClosed_of_checked context
      claim.dispatchInvariant cluster.dispatch.original cluster.dispatch.candidate
      claim.tableCall structurallyValid boundedChecked

/-! ## Checked rooted unreachability

The original cutpoint graph may contain a constructor-scanner loop immediately
before a nullable dispatch.  A unique-predecessor chain is therefore not a
sound graph model.  The certificate below instead checks an exact root path,
the maximal strongly connected component containing the source, and every
incoming edge of that component against the decoded-original context.

These static graph facts do not prove a register value.  Whole-program
composition must still establish the empty interval bound for every reachable
source state.  Keeping that fact as an explicit premise prevents graph
reachability from being mistaken for an EBX-value proof.
-/

structure OriginalIncomingEdge where
  sourceTargetId : Nat
  targetTargetId : Nat
deriving Repr, DecidableEq

/-- Compact decoded-graph data derived from the canonical code-map and region
indices. ExactOriginalDecodedAuthority separately establishes that every
indexed source passes the expensive PE-span and destination checks, so graph
algorithms must not repeat those checks for every lookup. -/
structure OriginalDecodedGraphSource where
  root : Bool
  targets : List Nat
deriving Repr, DecidableEq

def originalGraphSource?
    (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option OriginalDecodedGraphSource := do
  let target <- context.codeMap.get? targetId
  let region <- context.regions.get? target.regionIndex
  if target.id != targetId || region.id != target.id then
    none
  else
    pure { root := region.root, targets := region.targets }

def originalRootTargetIds (context : OriginalDecodedStaticContext) : List Nat :=
  (List.range context.codeMap.entries.size).filter fun targetId =>
    match originalGraphSource? context targetId with
    | some source => source.root
    | none => false

def originalIncomingEdgesForTarget (context : OriginalDecodedStaticContext)
    (targetTargetId : Nat) : List OriginalIncomingEdge :=
  (List.range context.codeMap.entries.size).filterMap fun sourceTargetId =>
    match originalGraphSource? context sourceTargetId with
    | some source =>
        if source.targets.contains targetTargetId then
          some { sourceTargetId, targetTargetId }
        else
          none
    | none => none

def originalIncomingEdgesForTargets (context : OriginalDecodedStaticContext)
    (targetTargetIds : List Nat) : List OriginalIncomingEdge :=
  targetTargetIds.flatMap (originalIncomingEdgesForTarget context)

def originalSuccessorTargetIds (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) : List Nat :=
  match originalGraphSource? context sourceTargetId with
  | some source => source.targets
  | none => []

def originalReachabilityStepWithin (context : OriginalDecodedStaticContext)
    (allowedTargetIds targetIds : List Nat) : List Nat :=
  (targetIds ++ targetIds.flatMap fun targetId =>
    (originalSuccessorTargetIds context targetId).filter
      allowedTargetIds.contains).eraseDups

def originalReachabilityWithinAux (context : OriginalDecodedStaticContext)
    (allowedTargetIds : List Nat) :
    Nat → List Nat → List Nat
  | 0, targetIds => targetIds
  | fuel + 1, targetIds =>
      let next :=
        originalReachabilityStepWithin context allowedTargetIds targetIds
      if next == targetIds then targetIds
      else originalReachabilityWithinAux context allowedTargetIds fuel next

def originalReachabilityWithin (context : OriginalDecodedStaticContext)
    (allowedTargetIds : List Nat) (sourceTargetId : Nat) : List Nat :=
  originalReachabilityWithinAux context allowedTargetIds
    (allowedTargetIds.length + 1) [sourceTargetId]

def originalForwardReachabilityStep
    (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : List Nat :=
  (targetIds ++ targetIds.flatMap
    (originalSuccessorTargetIds context)).eraseDups

def originalForwardReachabilityAux
    (context : OriginalDecodedStaticContext) :
    Nat → List Nat → List Nat
  | 0, targetIds => targetIds
  | fuel + 1, targetIds =>
      let next := originalForwardReachabilityStep context targetIds
      if next == targetIds then targetIds
      else originalForwardReachabilityAux context fuel next

def originalForwardReachability
    (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) : List Nat :=
  originalForwardReachabilityAux context
    (context.codeMap.entries.size + 1) [sourceTargetId]

/-- One reverse step scans each canonical source once, avoiding the quadratic
target-by-source predecessor enumeration used for report serialization. -/
def originalReverseReachabilityStep
    (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : List Nat :=
  (targetIds ++ (List.range context.codeMap.entries.size).filter fun sourceId =>
    (originalSuccessorTargetIds context sourceId).any
      targetIds.contains).eraseDups

def originalReverseReachabilityAux
    (context : OriginalDecodedStaticContext) :
    Nat → List Nat → List Nat
  | 0, targetIds => targetIds
  | fuel + 1, targetIds =>
      let next := originalReverseReachabilityStep context targetIds
      if next == targetIds then targetIds
      else originalReverseReachabilityAux context fuel next

def originalReverseReachability
    (context : OriginalDecodedStaticContext)
    (targetTargetId : Nat) : List Nat :=
  originalReverseReachabilityAux context
    (context.codeMap.entries.size + 1) [targetTargetId]

/-- The maximal source SCC is the intersection of exact forward and reverse
closures.  Reverse closure scans the image once per frontier round, so callers
do not rerun a whole-image closure for every forward target. -/
def originalSccTargetIds (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) : List Nat :=
  let reverse := originalReverseReachability context sourceTargetId
  (originalForwardReachability context sourceTargetId).filter reverse.contains

def originalSccChecked (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) (sccTargetIds : List Nat) : Bool :=
  !sccTargetIds.isEmpty &&
    NullableCodePointerTable.noDuplicates sccTargetIds &&
    NullableCodePointerTable.sameFiniteSet sccTargetIds
      (originalSccTargetIds context sourceTargetId) &&
    sccTargetIds.contains sourceTargetId &&
    sccTargetIds.all fun targetId =>
      (originalGraphSource? context targetId).isSome &&
        (originalReachabilityWithin context sccTargetIds
          sourceTargetId).contains targetId &&
        (originalReachabilityWithin context sccTargetIds
          targetId).contains sourceTargetId

/- A forward-closed target set containing the source is a checked superset of
all targets reachable from that source. This is the fact SCC maximality needs,
without recomputing a whole-image forward and reverse fixed point. -/
def originalForwardClosedChecked (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) (forwardTargetIds : List Nat) : Bool :=
  NullableCodePointerTable.noDuplicates forwardTargetIds &&
    forwardTargetIds.contains sourceTargetId &&
    forwardTargetIds.all fun targetId =>
      (originalGraphSource? context targetId).isSome &&
        (originalSuccessorTargetIds context targetId).all
          forwardTargetIds.contains

/- A strongly connected set is maximal when every source-reachable target is
inside a checked forward-closed superset and no outside member of that
superset has an edge back into the set. The exact incoming inventory is
recomputed from the decoded graph. -/
def originalSccBoundaryChecked (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) (forwardTargetIds sccTargetIds : List Nat)
    (incomingEdges : List OriginalIncomingEdge) : Bool :=
  !sccTargetIds.isEmpty &&
    NullableCodePointerTable.noDuplicates sccTargetIds &&
    sccTargetIds.contains sourceTargetId &&
    originalForwardClosedChecked context sourceTargetId forwardTargetIds &&
    (sccTargetIds.all fun targetId =>
      (originalGraphSource? context targetId).isSome &&
        (originalReachabilityWithin context sccTargetIds
          sourceTargetId).contains targetId &&
        (originalReachabilityWithin context sccTargetIds
          targetId).contains sourceTargetId) &&
    incomingEdges == originalIncomingEdgesForTargets context sccTargetIds &&
    incomingEdges.all fun edge =>
      sccTargetIds.contains edge.sourceTargetId ||
        !forwardTargetIds.contains edge.sourceTargetId

def originalPathEdgesChecked (context : OriginalDecodedStaticContext) :
    List Nat → Bool
  | [] | [_] => true
  | sourceTargetId :: targetTargetId :: rest =>
      (originalSuccessorTargetIds context sourceTargetId).contains
          targetTargetId &&
        originalPathEdgesChecked context (targetTargetId :: rest)

def originalRootPathChecked (context : OriginalDecodedStaticContext)
    (sourceTargetId : Nat) (rootPathTargetIds : List Nat) : Bool :=
  match rootPathTargetIds with
  | [] => false
  | rootTargetId :: _ =>
      originalRootTargetIds context |>.contains rootTargetId &&
        rootPathTargetIds.reverse.head? == some sourceTargetId &&
        NullableCodePointerTable.noDuplicates rootPathTargetIds &&
        originalPathEdgesChecked context rootPathTargetIds

/-- Canonical finite graph data. Roots, path edges, the maximal source SCC,
strong connectivity, and the complete incoming boundary are recomputed by
Lean. -/
structure RootedSccCertificate where
  rootTargetIds : List Nat
  rootPathTargetIds : List Nat
  forwardTargetIds : List Nat
  sccTargetIds : List Nat
  incomingEdges : List OriginalIncomingEdge
deriving Repr, DecidableEq

def RootedSccCertificate.checked
    (originalContext : OriginalDecodedStaticContext)
    (_decodedAuthority : ExactOriginalDecodedAuthority originalContext)
    (site : OriginalIndirectControlSite)
    (certificate : RootedSccCertificate) : Bool :=
  site.checked originalContext &&
  !certificate.rootTargetIds.isEmpty &&
    certificate.rootTargetIds == originalRootTargetIds originalContext &&
    originalRootPathChecked originalContext site.sourceTargetId
      certificate.rootPathTargetIds &&
    originalSccBoundaryChecked originalContext site.sourceTargetId
      certificate.forwardTargetIds certificate.sccTargetIds
      certificate.incomingEdges &&
    (certificate.sccTargetIds.all fun targetId =>
      !certificate.rootTargetIds.contains targetId)

structure CheckedRootedSccCertificate
    (originalContext : OriginalDecodedStaticContext)
    (site : OriginalIndirectControlSite) where
  decodedAuthority : ExactOriginalDecodedAuthority originalContext
  certificate : RootedSccCertificate
  checked :
    certificate.checked originalContext decodedAuthority site = true

/-- Graph closure and register-value closure remain separate.  The checked SCC
authority rules out omissions in the static constructor loop, while the
runtime premise must be derived from exact scanner/test/loop semantics by the
whole-program composition proof. -/
structure CompleteRootedSccDispatchPremise
    (emptyAuthority : CheckedEmptyIndexedSourceAuthority originalContext)
    (graphAuthority :
      CheckedRootedSccCertificate originalContext emptyAuthority.site)
    (reachable : ActualSourceReachability) : Prop where
  everyReachableIndexBound : emptyAuthority.ReachabilityBound reachable

theorem sourceUninhabited_of_checkedRootedScc
    (emptyAuthority : CheckedEmptyIndexedSourceAuthority originalContext)
    (graphAuthority :
      CheckedRootedSccCertificate originalContext emptyAuthority.site)
    (reachable : ActualSourceReachability)
    (complete :
      CompleteRootedSccDispatchPremise emptyAuthority graphAuthority reachable) :
    SourceUninhabited reachable := by
  rintro ⟨world, originalState, reached⟩
  exact emptyAuthority.noRuntimeIndex originalState
    (complete.everyReachableIndexBound world originalState reached)

theorem originalIndirectControlClosure_of_checkedRootedScc
    (emptyAuthority : CheckedEmptyIndexedSourceAuthority originalContext)
    (graphAuthority :
      CheckedRootedSccCertificate originalContext emptyAuthority.site)
    (reachable : ActualSourceReachability)
    (complete :
      CompleteRootedSccDispatchPremise emptyAuthority graphAuthority reachable) :
    OriginalIndirectControlClosure originalContext emptyAuthority.site reachable :=
  OriginalIndirectControlClosure.unreachable
    (sourceUninhabited_of_checkedRootedScc emptyAuthority graphAuthority
      reachable complete)

end StageA.Relational.NullableCodePointerDispatch
