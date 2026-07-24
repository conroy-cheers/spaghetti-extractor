import StageA.RelationalComposition
import StageA.RelationalNullableCodePointerTable

namespace StageA.Relational.NullableCodePointerDispatch

open StageA.Formal
open StageA.Relational
open StageA.Relational.NullableCodePointerTable

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

/-- A local mixed-dispatch binding.  `dispatchPredecessorIds` is checked for
shape here, but its global completeness is deliberately a proposition supplied
by product-graph composition below. -/
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
    tableCertificateCheckedAgainst context claim.tableCertificate claim.tableCall

def Claim.semanticChecked (context : StaticProofContext) (claim : Claim)
    (cluster : DecodedDispatchCluster) : Bool :=
  claim.scanner.table == claim.tableCall &&
    claim.scanner.checked context claim.scannerSourceInvariant
      claim.scannerPostInvariant cluster.scanner.original cluster.scanner.candidate &&
    claim.scanner.exitChecked claim.scannerPostInvariant
      claim.scannerFinishedInvariant cluster.test.original cluster.test.candidate &&
    bridgeBehaviorChecked claim.scanner claim.guardRegion.targetId cluster.bridge &&
    dispatchGuardBehaviorChecked claim.scanner claim.dispatchRegion.targetId cluster.guard &&
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

end StageA.Relational.NullableCodePointerDispatch
