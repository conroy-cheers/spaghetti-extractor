import StageA.RelationalInterpreterMixedProfile
import StageA.RelationalReachableStaticPointerSlot
import StageA.RelationalCallableExternalMixedBridge

namespace StageA.Relational.RuntimeIndirectEffects

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedProfile

/-!
# Runtime-indirect framed effects

Runtime-address writes may preserve a static pointer slot only when their
concrete access span is contained in a checked stack or dynamic range.  The
range/image disjointness check then supplies the separation proof consumed by
`ReachableStaticPointerSlot.RuntimeSeparations`.
-/

theorem canonicalMixedRelationalWorldValid_range_disjoint
    (valid :
      CanonicalMixedRelationalWorldValid original candidate anchors world =
        true)
    (rangeMember :
      range ∈ world.dynamicRanges ++ world.stackRanges) :
    mixedRangeDisjointFromImages original.pe candidate.pe range = true := by
  simp only [CanonicalMixedRelationalWorldValid, Bool.and_eq_true,
    List.all_eq_true] at valid
  rcases valid with
    ⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨⟨_ids, rangesDisjoint⟩, _wordRelations⟩,
      _dynamicOriginal⟩, _dynamicCandidate⟩, _stackOriginal⟩,
      _stackCandidate⟩, _crossOriginal⟩, _crossCandidate⟩,
      _opaqueResources⟩, _importIds⟩, _importIats⟩,
      _importIdentities⟩, _imports⟩, _callbacks⟩, _tls⟩
  exact rangesDisjoint range rangeMember

theorem canonicalMixedWorldsRelated_range_disjoint
    (related :
      CanonicalMixedWorldsRelated original candidate anchors
        originalWorld candidateWorld)
    (rangeMember :
      range ∈ originalWorld.dynamicRanges ++ originalWorld.stackRanges) :
    mixedRangeDisjointFromImages original.pe candidate.pe range = true :=
  canonicalMixedRelationalWorldValid_range_disjoint related.2 rangeMember

theorem write32AvoidsStaticWord_of_mixedRange_original
    (rangeDisjoint :
      mixedRangeDisjointFromImages originalPe candidatePe range = true)
    (writeContained :
      AccessSpanContained range.originalBase.toNat range.size
        writeAddress.toNat 4)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (slotInImage :
      originalPe.imageBase <= slotAddress.toNat /\
        slotAddress.toNat + 4 <=
          originalPe.imageBase + originalPe.sizeOfImage) :
    Write32AvoidsWord slotAddress writeAddress := by
  simp only [mixedRangeDisjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeDisjoint
  rcases rangeDisjoint with
    ⟨⟨⟨⟨_positive, originalRangeBounded⟩, _candidateRangeBounded⟩,
      originalDisjoint⟩, _candidateDisjoint⟩
  rcases writeContained with
    ⟨_writePositive, _rangeBounded, writeBounded, writeLower, writeUpper⟩
  apply write32AvoidsWord_of_nat_disjoint slotAddress writeAddress
  · exact slotFits
  · exact writeBounded
  · rcases originalDisjoint with beforeImage | afterImage
    · right
      omega
    · left
      omega

theorem write32AvoidsStaticWord_of_mixedRange_candidate
    (rangeDisjoint :
      mixedRangeDisjointFromImages originalPe candidatePe range = true)
    (writeContained :
      AccessSpanContained range.candidateBase.toNat range.size
        writeAddress.toNat 4)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (slotInImage :
      candidatePe.imageBase <= slotAddress.toNat /\
        slotAddress.toNat + 4 <=
          candidatePe.imageBase + candidatePe.sizeOfImage) :
    Write32AvoidsWord slotAddress writeAddress := by
  simp only [mixedRangeDisjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeDisjoint
  rcases rangeDisjoint with
    ⟨⟨⟨⟨_positive, _originalRangeBounded⟩, candidateRangeBounded⟩,
      _originalDisjoint⟩, candidateDisjoint⟩
  rcases writeContained with
    ⟨_writePositive, _rangeBounded, writeBounded, writeLower, writeUpper⟩
  apply write32AvoidsWord_of_nat_disjoint slotAddress writeAddress
  · exact slotFits
  · exact writeBounded
  · rcases candidateDisjoint with beforeImage | afterImage
    · right
      omega
    · left
      omega

theorem writeSpanAvoidsStaticWord_of_mixedRange_original
    (width : MemoryWidth)
    (rangeDisjoint :
      mixedRangeDisjointFromImages originalPe candidatePe range = true)
    (writeContained :
      AccessSpanContained range.originalBase.toNat range.size
        writeAddress.toNat width.bytes)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (slotInImage :
      originalPe.imageBase <= slotAddress.toNat /\
        slotAddress.toNat + 4 <=
          originalPe.imageBase + originalPe.sizeOfImage) :
    ReachableStaticPointerSlot.WriteSpanAvoidsWord
      slotAddress writeAddress width := by
  simp only [mixedRangeDisjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeDisjoint
  rcases rangeDisjoint with
    ⟨⟨⟨⟨_positive, _originalRangeBounded⟩, _candidateRangeBounded⟩,
      originalDisjoint⟩, _candidateDisjoint⟩
  rcases writeContained with
    ⟨_writePositive, _rangeBounded, writeBounded, writeLower, writeUpper⟩
  apply ReachableStaticPointerSlot.writeSpanAvoidsWord_of_nat_disjoint
    slotAddress writeAddress width slotFits writeBounded
  rcases originalDisjoint with beforeImage | afterImage
  · right
    omega
  · left
    omega

theorem write32AvoidsReachableStaticSlot_of_worldRange
    (related :
      CanonicalMixedWorldsRelated original candidate anchors
        originalWorld candidateWorld)
    (rangeMember :
      range ∈ originalWorld.stackRanges ++ originalWorld.dynamicRanges)
    (writeContained :
      AccessSpanContained range.originalBase.toNat range.size
        writeAddress.toNat 4)
    (slotWritable :
      writableStaticWordInPe original.pe
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress original certificate)) =
        true) :
    Write32AvoidsWord
      (BitVec.ofNat 32
        (ReachableStaticPointerSlot.slotAddress original certificate))
      writeAddress := by
  have rangeMember' :
      range ∈ originalWorld.dynamicRanges ++ originalWorld.stackRanges := by
    simpa [List.mem_append, or_comm] using rangeMember
  have rangeDisjoint :=
    canonicalMixedWorldsRelated_range_disjoint related rangeMember'
  have slotBounds :=
    writableStaticWordInPe_bounds original.pe
      (BitVec.ofNat 32
        (ReachableStaticPointerSlot.slotAddress original certificate))
      slotWritable
  exact write32AvoidsStaticWord_of_mixedRange_original rangeDisjoint
    writeContained slotBounds.2.2 ⟨slotBounds.1, slotBounds.2.1⟩

theorem writeSpanAvoidsReachableStaticSlot_of_worldRange
    (width : MemoryWidth)
    (related :
      CanonicalMixedWorldsRelated original candidate anchors
        originalWorld candidateWorld)
    (rangeMember :
      range ∈ originalWorld.stackRanges ++ originalWorld.dynamicRanges)
    (writeContained :
      AccessSpanContained range.originalBase.toNat range.size
        writeAddress.toNat width.bytes)
    (slotWritable :
      writableStaticWordInPe original.pe
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress original certificate)) =
        true) :
    ReachableStaticPointerSlot.WriteSpanAvoidsWord
      (BitVec.ofNat 32
        (ReachableStaticPointerSlot.slotAddress original certificate))
      writeAddress width := by
  have rangeMember' :
      range ∈ originalWorld.dynamicRanges ++ originalWorld.stackRanges := by
    simpa [List.mem_append, or_comm] using rangeMember
  have rangeDisjoint :=
    canonicalMixedWorldsRelated_range_disjoint related rangeMember'
  have slotBounds :=
    writableStaticWordInPe_bounds original.pe
      (BitVec.ofNat 32
        (ReachableStaticPointerSlot.slotAddress original certificate))
      slotWritable
  exact writeSpanAvoidsStaticWord_of_mixedRange_original width rangeDisjoint
    writeContained slotBounds.2.2 ⟨slotBounds.1, slotBounds.2.1⟩

theorem originalRangeOffsetAccessContained
    (rangeDisjoint :
      mixedRangeDisjointFromImages originalPe candidatePe range = true)
    (offsetFits : offset + 4 <= range.size) :
    AccessSpanContained range.originalBase.toNat range.size
      (range.originalBase + BitVec.ofNat 32 offset).toNat 4 := by
  simp only [mixedRangeDisjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeDisjoint
  rcases rangeDisjoint with
    ⟨⟨⟨⟨rangePositive, originalRangeBounded⟩, _candidateRangeBounded⟩,
      _originalDisjoint⟩, _candidateDisjoint⟩
  have offsetSmall : offset < 2 ^ 32 := by
    omega
  have addressSmall :
      range.originalBase.toNat + offset < 2 ^ 32 := by
    omega
  simp only [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt offsetSmall, Nat.mod_eq_of_lt addressSmall]
  refine ⟨by omega, ?_, ?_, ?_, ?_⟩
  · simpa [pe32AddressSpaceSize] using originalRangeBounded
  · simp only [pe32AddressSpaceSize]
    omega
  · omega
  · omega

theorem originalRangeOffsetAccessContainedWidth
    (width : MemoryWidth)
    (rangeDisjoint :
      mixedRangeDisjointFromImages originalPe candidatePe range = true)
    (offsetFits : offset + width.bytes <= range.size) :
    AccessSpanContained range.originalBase.toNat range.size
      (range.originalBase + BitVec.ofNat 32 offset).toNat width.bytes := by
  simp only [mixedRangeDisjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at rangeDisjoint
  rcases rangeDisjoint with
    ⟨⟨⟨⟨rangePositive, originalRangeBounded⟩, _candidateRangeBounded⟩,
      _originalDisjoint⟩, _candidateDisjoint⟩
  have widthPositive : 0 < width.bytes := by
    cases width <;> decide
  have offsetSmall : offset < 2 ^ 32 := by
    omega
  have addressSmall :
      range.originalBase.toNat + offset < 2 ^ 32 := by
    omega
  simp only [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt offsetSmall, Nat.mod_eq_of_lt addressSmall]
  refine ⟨widthPositive, ?_, ?_, ?_, ?_⟩
  · simpa [pe32AddressSpaceSize] using originalRangeBounded
  · simp only [pe32AddressSpaceSize]
    omega
  · omega
  · omega

/-- Convert a checked range-relative address witness into the concrete
separation required by a `runtimeSeparated` static-slot write.  The caller
supplies only the range identity/offset fact produced by value provenance;
world validity supplies non-wrap and image disjointness. -/
theorem write32AvoidsReachableStaticSlot_of_worldRangeOffset
    (related :
      CanonicalMixedWorldsRelated original candidate anchors
        originalWorld candidateWorld)
    (rangeMember :
      range ∈ originalWorld.stackRanges ++ originalWorld.dynamicRanges)
    (offsetFits : offset + 4 <= range.size)
    (writeAddressExact :
      writeAddress =
        range.originalBase + BitVec.ofNat 32 offset)
    (slotWritable :
      writableStaticWordInPe original.pe
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress original certificate)) =
        true) :
    Write32AvoidsWord
      (BitVec.ofNat 32
        (ReachableStaticPointerSlot.slotAddress original certificate))
      writeAddress := by
  subst writeAddress
  apply write32AvoidsReachableStaticSlot_of_worldRange related rangeMember
    (originalRangeOffsetAccessContained
      (canonicalMixedWorldsRelated_range_disjoint related (by
        simpa [List.mem_append, or_comm] using rangeMember))
      offsetFits)
    slotWritable

theorem writeSpanAvoidsReachableStaticSlot_of_worldRangeOffset
    (width : MemoryWidth)
    (related :
      CanonicalMixedWorldsRelated original candidate anchors
        originalWorld candidateWorld)
    (rangeMember :
      range ∈ originalWorld.stackRanges ++ originalWorld.dynamicRanges)
    (offsetFits : offset + width.bytes <= range.size)
    (writeAddressExact :
      writeAddress =
        range.originalBase + BitVec.ofNat 32 offset)
    (slotWritable :
      writableStaticWordInPe original.pe
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress original certificate)) =
        true) :
    ReachableStaticPointerSlot.WriteSpanAvoidsWord
      (BitVec.ofNat 32
        (ReachableStaticPointerSlot.slotAddress original certificate))
      writeAddress width := by
  subst writeAddress
  apply writeSpanAvoidsReachableStaticSlot_of_worldRange width related rangeMember
    (originalRangeOffsetAccessContainedWidth width
      (canonicalMixedWorldsRelated_range_disjoint related (by
        simpa [List.mem_append, or_comm] using rangeMember))
      offsetFits)
    slotWritable

def BulkWritesContained (rangeBase : Word) (rangeSize : Nat)
    (direction : Bool) : Word -> Nat -> Prop
  | _, 0 => True
  | writeAddress, count + 1 =>
      AccessSpanContained rangeBase.toNat rangeSize writeAddress.toNat 4 /\
        BulkWritesContained rangeBase rangeSize direction
          (ReachableStaticPointerSlot.nextBulkWriteAddress
            writeAddress direction) count

theorem bulkWritesAvoidReachableStaticSlot_of_worldRange
    (related :
      CanonicalMixedWorldsRelated original candidate anchors
        originalWorld candidateWorld)
    (rangeMember :
      range ∈ originalWorld.stackRanges ++ originalWorld.dynamicRanges)
    (slotWritable :
      writableStaticWordInPe original.pe
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress original certificate)) =
        true) :
    forall (destination : Word) (direction : Bool) (count : Nat),
      BulkWritesContained range.originalBase range.size
        direction destination count ->
      ReachableStaticPointerSlot.BulkWritesAvoidWord
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress original certificate))
        direction destination count := by
  intro destination direction count
  induction count generalizing destination with
  | zero =>
      intro contained
      trivial
  | succ count induction =>
      intro contained
      simp only [BulkWritesContained] at contained
      simp only [ReachableStaticPointerSlot.BulkWritesAvoidWord]
      constructor
      · exact write32AvoidsReachableStaticSlot_of_worldRange related rangeMember
          contained.1 slotWritable
      · exact induction
          (ReachableStaticPointerSlot.nextBulkWriteAddress
            destination direction)
          contained.2

theorem machineCallMemoryEffectFootprintBoundedChecked_sound
    {effect : MachineCallMemoryEffect}
    (checked :
      ReachableStaticPointerSlot.machineCallMemoryEffectFootprintBoundedChecked
        effect = true) :
    MachineCallMemoryEffectFootprintBounded effect := by
  cases effect <;>
    simp [ReachableStaticPointerSlot.machineCallMemoryEffectFootprintBoundedChecked,
      MachineCallMemoryEffectFootprintBounded] at checked ⊢

def ExternalOutcomeMatchesEvent (state : MachineState)
    (outcome : NormalizedOutcomeExpr) (event : WorldExternalEvent) : Prop :=
  match outcome with
  | .externalCall imported arguments _ | .externalJump imported arguments =>
      event.imported = imported /\
        event.arguments = arguments.map fun argument => argument.eval state
  | _ => False

/-- A reachable external transition tied to the exact decoded outcome and its
unique checked machine-call contract. The frame is the complete write
footprint obligation for that call. -/
structure ExternalWriteTransition
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (staticContext : StaticProofContext) (candidate : Bool)
    (before after : Memory) where
  reachableTargetIds : List Nat
  targetId : Nat
  behavior : NormalizedSymbolicBehavior
  inventory : ReachableStaticPointerSlot.DecodedWriteInventory
  contract : MachineImportCallContract
  event : WorldExternalEvent
  result : WorldExternalResult
  reachableExact :
    certificate.reachableTargetIds = .exact reachableTargetIds
  targetMember : targetId ∈ reachableTargetIds
  normalized :
    ReachableStaticPointerSlot.normalizedRegionWriteInventory?
      originalContext targetId = some (behavior, inventory)
  contractFound :
    ReachableStaticPointerSlot.checkedExternalOutcomeContract?
      originalContext behavior = some contract
  outcomeMatches : ExternalOutcomeMatchesEvent event.state behavior.outcome event
  beforeExact : event.state.memory = before
  afterExact : result.state.memory = after
  conforms :
    machineCallResultConforms candidate staticContext contract event result
  avoids :
    ExternalWriteFootprintsAvoidWord contract.memoryFootprints
      event.state.memory event.arguments
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate))

theorem ExternalWriteTransition.preserves
    {originalContext : OriginalDecodedStaticContext}
    {certificate : ReachableStaticPointerSlot.Certificate}
    {staticContext : StaticProofContext} {candidate : Bool}
    {before after : Memory}
    (checked : certificate.checked originalContext = true)
    (transition : ExternalWriteTransition originalContext certificate
      staticContext candidate before after)
    (prior :
      ReachableStaticPointerSlot.SlotValueAllowed
        originalContext certificate before) :
    ReachableStaticPointerSlot.SlotValueAllowed
      originalContext certificate after := by
  rcases transition with
    ⟨reachableTargetIds, targetId, behavior, inventory, contract, event, result,
      reachableExact, targetMember, normalized, contractFound, outcomeMatches,
      beforeExact, afterExact, conforms, avoids⟩
  subst before
  subst after
  let facts := certificate.checkedFactsOfChecked checked
  have supportedChecked :=
    ReachableStaticPointerSlot.checkedExternalOutcomeContract?_bounded contractFound
  have supported :=
    machineCallMemoryEffectFootprintBoundedChecked_sound supportedChecked
  apply machineCallResultConforms_preservesReachableStaticPointerSlot candidate
    staticContext originalContext certificate facts.allowedTargetIds contract
    event result facts.allowedExact conforms
  · exact MachineCallStaticWordFrame.footprints supported avoids
  · exact prior

inductive CompleteWriteFootprintTransition
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (staticContext : StaticProofContext) (candidate : Bool) :
    Memory -> Memory -> Prop where
  | decoded {before after}
      (transition :
        ReachableStaticPointerSlot.RegionTransition
          originalContext certificate before after) :
      CompleteWriteFootprintTransition originalContext certificate
        staticContext candidate before after
  | external {before after}
      (transition :
        ExternalWriteTransition originalContext certificate staticContext
          candidate before after) :
      CompleteWriteFootprintTransition originalContext certificate
        staticContext candidate before after

/-- Preservation term consumed by the GNU runtime-indirect invariant: every
reachable write is either an exact decoded scalar/REP footprint or a checked
external contract footprint. -/
theorem completeWriteFootprintTransition_preserves
    {originalContext : OriginalDecodedStaticContext}
    {certificate : ReachableStaticPointerSlot.Certificate}
    {staticContext : StaticProofContext} {candidate : Bool}
    {before after : Memory}
    (checked : certificate.checked originalContext = true)
    (prior :
      ReachableStaticPointerSlot.SlotValueAllowed
        originalContext certificate before)
    (transition : CompleteWriteFootprintTransition originalContext certificate
      staticContext candidate before after) :
    ReachableStaticPointerSlot.SlotValueAllowed
      originalContext certificate after := by
  cases transition with
  | decoded transition =>
      exact certificate.transition_preserves checked prior transition
  | external transition =>
      exact transition.preserves checked prior

inductive CompleteWriteFootprintTrace
    (originalContext : OriginalDecodedStaticContext)
    (certificate : ReachableStaticPointerSlot.Certificate)
    (staticContext : StaticProofContext) (candidate : Bool) :
    Memory -> Memory -> Prop where
  | refl (memory) :
      CompleteWriteFootprintTrace originalContext certificate
        staticContext candidate memory memory
  | step {start middle finish} :
      CompleteWriteFootprintTrace originalContext certificate
        staticContext candidate start middle ->
      CompleteWriteFootprintTransition originalContext certificate
        staticContext candidate middle finish ->
      CompleteWriteFootprintTrace originalContext certificate
        staticContext candidate start finish

theorem completeWriteFootprintTrace_preserves
    {originalContext : OriginalDecodedStaticContext}
    {certificate : ReachableStaticPointerSlot.Certificate}
    {staticContext : StaticProofContext} {candidate : Bool}
    {start finish : Memory}
    (checked : certificate.checked originalContext = true)
    (initial :
      ReachableStaticPointerSlot.SlotValueAllowed
        originalContext certificate start)
    (trace : CompleteWriteFootprintTrace originalContext certificate
      staticContext candidate start finish) :
    ReachableStaticPointerSlot.SlotValueAllowed
      originalContext certificate finish := by
  induction trace with
  | refl => exact initial
  | step trace transition traceIH =>
      exact completeWriteFootprintTransition_preserves checked traceIH transition

/-- A checked empty target inventory turns complete footprint preservation into
the concrete zero-word fact used to exclude a nullable indirect source. -/
theorem completeWriteFootprintTrace_preserves_zero
    {originalContext : OriginalDecodedStaticContext}
    {certificate : ReachableStaticPointerSlot.Certificate}
    {staticContext : StaticProofContext} {candidate : Bool}
    {start finish : Memory}
    (checked : certificate.checked originalContext = true)
    (noTargets : certificate.allowedTargetIds = .exact [])
    (initial :
      ReachableStaticPointerSlot.SlotValueAllowed
        originalContext certificate start)
    (trace : CompleteWriteFootprintTrace originalContext certificate
      staticContext candidate start finish) :
    Memory.read32 finish
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate)) =
      0 := by
  apply certificate.no_writers_allowed_is_zero checked noTargets finish
  exact completeWriteFootprintTrace_preserves checked initial trace

/-- End-to-end static-slot preservation from exact loader initialization. The
only dynamic input is the complete typed write trace; missing or
runtime-separated writes cannot be hidden by this theorem. -/
theorem completeWriteFootprintTrace_from_launch_is_zero
    {originalContext : OriginalDecodedStaticContext}
    {certificate : ReachableStaticPointerSlot.Certificate}
    {staticContext : StaticProofContext} {candidate : Bool}
    {start finish : Memory}
    (checked : certificate.checked originalContext = true)
    (noTargets : certificate.allowedTargetIds = .exact [])
    (initialized :
      ReachableStaticPointerSlot.LaunchSlotInitialized
        originalContext certificate start)
    (trace : CompleteWriteFootprintTrace originalContext certificate
      staticContext candidate start finish) :
    Memory.read32 finish
        (BitVec.ofNat 32
          (ReachableStaticPointerSlot.slotAddress originalContext certificate)) =
      0 :=
  completeWriteFootprintTrace_preserves_zero checked noTargets
    (certificate.launch_slot_allowed checked start initialized) trace

#print axioms canonicalMixedRelationalWorldValid_range_disjoint
#print axioms canonicalMixedWorldsRelated_range_disjoint
#print axioms write32AvoidsStaticWord_of_mixedRange_original
#print axioms write32AvoidsStaticWord_of_mixedRange_candidate
#print axioms writeSpanAvoidsStaticWord_of_mixedRange_original
#print axioms write32AvoidsReachableStaticSlot_of_worldRange
#print axioms writeSpanAvoidsReachableStaticSlot_of_worldRange
#print axioms originalRangeOffsetAccessContained
#print axioms originalRangeOffsetAccessContainedWidth
#print axioms write32AvoidsReachableStaticSlot_of_worldRangeOffset
#print axioms writeSpanAvoidsReachableStaticSlot_of_worldRangeOffset
#print axioms bulkWritesAvoidReachableStaticSlot_of_worldRange
#print axioms machineCallMemoryEffectFootprintBoundedChecked_sound
#print axioms ExternalWriteTransition.preserves
#print axioms completeWriteFootprintTransition_preserves
#print axioms completeWriteFootprintTrace_preserves
#print axioms completeWriteFootprintTrace_preserves_zero
#print axioms completeWriteFootprintTrace_from_launch_is_zero

end StageA.Relational.RuntimeIndirectEffects
