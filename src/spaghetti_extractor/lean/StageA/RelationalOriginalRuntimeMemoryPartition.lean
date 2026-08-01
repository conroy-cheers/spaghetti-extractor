import StageA.RelationalCertificates
import StageA.RelationalEnvironment

namespace StageA.Relational.OriginalRuntimeMemoryPartition

open StageA.Formal StageA.Relational

/-!
# Original runtime-memory partition

This module is the one-sided, execution-facing authority for runtime address
ranges.  Flat `Memory` remains the machine semantics.  Stack and dynamic ranges
are checked witnesses over concrete 32-bit addresses; they are not object-model
assumptions.

The invariant covers every active world and every world retained by a nested
callback.  The span lemmas below make byte width and modular wraparound
explicit, and turn a checked range-membership witness into disjointness from
the original PE image and its protected static words.
-/

def addressSpaceSize : Nat := 2 ^ 32

/-- A concrete half-open byte span is meaningful only when it is nonempty and
does not cross the 32-bit address-space boundary. -/
def OriginalByteSpanValid (address : Word) (bytes : Nat) : Prop :=
  0 < bytes /\ address.toNat + bytes <= addressSpaceSize

/-- Two concrete, non-wrapping half-open spans are disjoint. -/
def OriginalByteSpansDisjoint (left : Word) (leftBytes : Nat)
    (right : Word) (rightBytes : Nat) : Prop :=
  left.toNat + leftBytes <= right.toNat \/
    right.toNat + rightBytes <= left.toNat

/-- Byte-level form consumed by memory-effect preservation. -/
def OriginalAccessAvoidsWord (wordAddress writeAddress : Word)
    (writeBytes : Nat) : Prop :=
  forall wordByte, wordByte < 4 -> forall writeByte, writeByte < writeBytes ->
    wordAddress + BitVec.ofNat 32 wordByte ≠
      writeAddress + BitVec.ofNat 32 writeByte

theorem memoryWidth_bytes_positive (width : Interpreter.MemoryWidth) :
    0 < width.bytes := by
  cases width <;> decide

theorem memoryWidth_bytes_le_four (width : Interpreter.MemoryWidth) :
    width.bytes <= 4 := by
  cases width <;> decide

theorem originalAccessAvoidsWord_of_spansDisjoint
    (wordAddress writeAddress : Word) (writeBytes : Nat)
    (wordValid : OriginalByteSpanValid wordAddress 4)
    (writeValid : OriginalByteSpanValid writeAddress writeBytes)
    (disjoint : OriginalByteSpansDisjoint wordAddress 4 writeAddress
      writeBytes) :
    OriginalAccessAvoidsWord wordAddress writeAddress writeBytes := by
  simp only [OriginalByteSpanValid, addressSpaceSize] at wordValid writeValid
  intro wordByte wordByteBefore writeByte writeByteBefore same
  have wordByteSmall : wordByte < 2 ^ 32 := by omega
  have writeByteSmall : writeByte < 2 ^ 32 := by omega
  have wordAddressBefore : wordAddress.toNat + wordByte < 2 ^ 32 := by
    omega
  have writeAddressBefore :
      writeAddress.toNat + writeByte < 2 ^ 32 := by omega
  have sameNat := congrArg BitVec.toNat same
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt wordByteSmall, Nat.mod_eq_of_lt writeByteSmall,
    Nat.mod_eq_of_lt wordAddressBefore,
    Nat.mod_eq_of_lt writeAddressBefore] at sameNat
  unfold OriginalByteSpansDisjoint at disjoint
  omega

/-- The runtime-range facts needed by the original execution invariant.  The
existing checked Boolean predicates include positive range sizes, non-wrapping
end addresses, PE-image disjointness, unique IDs, pairwise disjointness, and
stack/dynamic cross-disjointness. -/
def HoldsIn (context : StaticProofContext) (world : RelationalWorld) : Prop :=
  world.dynamicRangesValid context = true /\
    world.stackRangesValid context = true

theorem holdsIn_of_worldValid (context : StaticProofContext)
    (world : RelationalWorld) (valid : world.valid context = true) :
    HoldsIn context world := by
  simp only [RelationalWorld.valid, Bool.and_eq_true] at valid
  exact ⟨valid.1.1.1.1, valid.1.1.1.2⟩

theorem dynamicRangeDisjointFromImages
    (context : StaticProofContext) (world : RelationalWorld)
    (partition : HoldsIn context world) (range : DynamicAddressRangePair)
    (member : range ∈ world.dynamicRanges) :
    range.disjointFromImages context = true := by
  have valid := partition.1
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true,
    List.all_eq_true] at valid
  exact valid.1.1.1.1.1.2 range member

theorem stackRangeDisjointFromImages
    (context : StaticProofContext) (world : RelationalWorld)
    (partition : HoldsIn context world) (range : DynamicAddressRangePair)
    (member : range ∈ world.stackRanges) :
    range.disjointFromImages context = true := by
  have valid := partition.2
  simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
    List.all_eq_true] at valid
  exact (valid.1.1.2 range member).1.1.1

theorem dynamicStackRangesDisjointOriginal
    (context : StaticProofContext) (world : RelationalWorld)
    (partition : HoldsIn context world)
    (dynamicRange stackRange : DynamicAddressRangePair)
    (dynamicMember : dynamicRange ∈ world.dynamicRanges)
    (stackMember : stackRange ∈ world.stackRanges) :
    dynamicRange.originalBase.toNat + dynamicRange.size <=
        stackRange.originalBase.toNat \/
      stackRange.originalBase.toNat + stackRange.size <=
        dynamicRange.originalBase.toNat := by
  have valid := partition.1
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true] at valid
  have cross := valid.1.2
  simp only [dynamicAddressRangesCrossDisjointOn, List.all_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at cross
  exact cross dynamicRange dynamicMember stackRange stackMember

theorem dynamicRangesDisjointOriginal
    (context : StaticProofContext) (world : RelationalWorld)
    (partition : HoldsIn context world)
    (left right : DynamicAddressRangePair)
    (leftMember : left ∈ world.dynamicRanges)
    (rightMember : right ∈ world.dynamicRanges)
    (different : left.id ≠ right.id) :
    left.originalBase.toNat + left.size <= right.originalBase.toNat \/
      right.originalBase.toNat + right.size <= left.originalBase.toNat := by
  have valid := partition.1
  simp only [RelationalWorld.dynamicRangesValid, Bool.and_eq_true] at valid
  have disjoint := valid.1.1.1.2
  simp only [dynamicAddressRangesDisjointOn, List.all_eq_true, Bool.or_eq_true,
    beq_iff_eq, decide_eq_true_eq] at disjoint
  rcases disjoint left leftMember right rightMember with same | separated
  · exact (different same).elim
  · exact separated

theorem stackRangesDisjointOriginal
    (context : StaticProofContext) (world : RelationalWorld)
    (partition : HoldsIn context world)
    (left right : DynamicAddressRangePair)
    (leftMember : left ∈ world.stackRanges)
    (rightMember : right ∈ world.stackRanges)
    (different : left.id ≠ right.id) :
    left.originalBase.toNat + left.size <= right.originalBase.toNat \/
      right.originalBase.toNat + right.size <= left.originalBase.toNat := by
  have valid := partition.2
  simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true] at valid
  have disjoint := valid.1.2
  simp only [dynamicAddressRangesDisjointOn, List.all_eq_true, Bool.or_eq_true,
    beq_iff_eq, decide_eq_true_eq] at disjoint
  rcases disjoint left leftMember right rightMember with same | separated
  · exact (different same).elim
  · exact separated

theorem originalRangeNoWrap
    (context : StaticProofContext) (range : DynamicAddressRangePair)
    (valid : range.disjointFromImages context = true) :
    range.originalBase.toNat + range.size < addressSpaceSize := by
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at valid
  exact valid.1.1.1.2

theorem originalRangeDisjointFromImage
    (context : StaticProofContext) (range : DynamicAddressRangePair)
    (valid : range.disjointFromImages context = true) :
    range.originalBase.toNat + range.size <= context.originalPe.imageBase \/
      context.originalPe.imageBase + context.originalPe.sizeOfImage <=
        range.originalBase.toNat := by
  simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
    Bool.or_eq_true, decide_eq_true_eq] at valid
  exact valid.1.2

inductive OriginalRuntimeRangeKind where
  | stack
  | dynamic
deriving Repr, DecidableEq

/-- Untrusted proposal classification retained for diagnostics.  The checker
below binds addresses and widths to exact normalized writes, but this tag does
not establish range membership. -/
inductive OriginalRuntimeWriteClass where
  | imageStatic
  | stack
  | dynamic
deriving Repr, DecidableEq

structure OriginalRuntimeWriteCheckProposal where
  address : Expr
  bytes : Nat
  classification : OriginalRuntimeWriteClass
deriving Repr, DecidableEq

/-- Ordinary normalized writes are 32-bit writes.  This checker prevents a
proposal producer from dropping, reordering, or changing an exact write while
retaining storage classification as non-authoritative metadata. -/
def normalizedWriteProposalsChecked (writes : List (Expr × Expr))
    (proposals : List OriginalRuntimeWriteCheckProposal) : Bool :=
  writes.map Prod.fst == proposals.map (fun proposal => proposal.address) &&
    proposals.all fun proposal => proposal.bytes == 4

theorem normalizedWriteProposalsChecked_addresses
    (writes : List (Expr × Expr))
    (proposals : List OriginalRuntimeWriteCheckProposal)
    (checked : normalizedWriteProposalsChecked writes proposals = true) :
    writes.map Prod.fst = proposals.map (fun proposal => proposal.address) := by
  simp only [normalizedWriteProposalsChecked, Bool.and_eq_true, beq_iff_eq]
    at checked
  exact checked.1

theorem normalizedWriteProposalsChecked_widths
    (writes : List (Expr × Expr))
    (proposals : List OriginalRuntimeWriteCheckProposal)
    (checked : normalizedWriteProposalsChecked writes proposals = true) :
    forall proposal, proposal ∈ proposals -> proposal.bytes = 4 := by
  simp only [normalizedWriteProposalsChecked, Bool.and_eq_true,
    List.all_eq_true, beq_iff_eq] at checked
  exact checked.2

/-- A checked proposal that one concrete original-side access is wholly inside
one declared runtime range.  Width is an arbitrary positive byte count so the
same witness language covers scalar, x87, bulk, callback, and external-memory
effects. -/
structure OriginalRuntimeAccessWitness
    (world : RelationalWorld) (address : Word) (bytes : Nat) where
  range : DynamicAddressRangePair
  kind : OriginalRuntimeRangeKind
  rangeMember : match kind with
    | .stack => range ∈ world.stackRanges
    | .dynamic => range ∈ world.dynamicRanges
  bytesPositive : 0 < bytes
  startsInside : range.originalBase.toNat <= address.toNat
  endsInside : address.toNat + bytes <=
    range.originalBase.toNat + range.size

def OriginalRuntimeAccessWitness.ofMemoryWidth
    (world : RelationalWorld) (address : Word)
    (width : Interpreter.MemoryWidth) (range : DynamicAddressRangePair)
    (kind : OriginalRuntimeRangeKind)
    (rangeMember : match kind with
      | .stack => range ∈ world.stackRanges
      | .dynamic => range ∈ world.dynamicRanges)
    (startsInside : range.originalBase.toNat <= address.toNat)
    (endsInside : address.toNat + width.bytes <=
      range.originalBase.toNat + range.size) :
    OriginalRuntimeAccessWitness world address width.bytes := {
  range
  kind
  rangeMember
  bytesPositive := memoryWidth_bytes_positive width
  startsInside
  endsInside
}

theorem OriginalRuntimeAccessWitness.rangeDisjointFromImages
    {context : StaticProofContext} {world : RelationalWorld}
    {address : Word} {bytes : Nat}
    (witness : OriginalRuntimeAccessWitness world address bytes)
    (partition : HoldsIn context world) :
    witness.range.disjointFromImages context = true := by
  cases kindExact : witness.kind with
  | stack =>
      apply stackRangeDisjointFromImages context world partition witness.range
      simpa [kindExact] using witness.rangeMember
  | dynamic =>
      apply dynamicRangeDisjointFromImages context world partition witness.range
      simpa [kindExact] using witness.rangeMember

theorem OriginalRuntimeAccessWitness.spanValid
    {context : StaticProofContext} {world : RelationalWorld}
    {address : Word} {bytes : Nat}
    (witness : OriginalRuntimeAccessWitness world address bytes)
    (partition : HoldsIn context world) :
    OriginalByteSpanValid address bytes := by
  have noWrap := originalRangeNoWrap context witness.range
    (witness.rangeDisjointFromImages partition)
  have accessBefore := Nat.lt_of_le_of_lt witness.endsInside noWrap
  exact ⟨witness.bytesPositive, Nat.le_of_lt accessBefore⟩

/-- A protected word occupies four non-wrapping bytes in the original image. -/
def OriginalProtectedImageWord (context : StaticProofContext)
    (address : Word) : Prop :=
  context.originalPe.imageBase <= address.toNat /\
    address.toNat + 4 <=
      context.originalPe.imageBase + context.originalPe.sizeOfImage /\
    address.toNat + 4 <= addressSpaceSize

theorem protectedImageWord_of_writableStaticWord
    (context : StaticProofContext) (address : Word)
    (valid : writableStaticWordInPe context.originalPe address = true) :
    OriginalProtectedImageWord context address := by
  simp only [writableStaticWordInPe, Bool.and_eq_true, List.any_eq_true,
    decide_eq_true_eq] at valid
  exact ⟨valid.1.1.1, valid.1.2, by
    simpa [addressSpaceSize] using valid.1.1.2⟩

theorem OriginalRuntimeAccessWitness.disjointFromProtectedImageWord
    {context : StaticProofContext} {world : RelationalWorld}
    {writeAddress wordAddress : Word} {writeBytes : Nat}
    (witness : OriginalRuntimeAccessWitness world writeAddress writeBytes)
    (partition : HoldsIn context world)
    (protectedWord : OriginalProtectedImageWord context wordAddress) :
    OriginalByteSpansDisjoint wordAddress 4 writeAddress writeBytes := by
  have rangeDisjoint := originalRangeDisjointFromImage context witness.range
    (witness.rangeDisjointFromImages partition)
  have startsInside := witness.startsInside
  have endsInside := witness.endsInside
  unfold OriginalProtectedImageWord at protectedWord
  unfold OriginalByteSpansDisjoint
  rcases rangeDisjoint with rangeBefore | imageBefore
  · right
    omega
  · left
    omega

/-- Range partitioning automatically separates accesses in stack versus
dynamic ranges, or in distinct ranges of the same class.  Accesses in the same
range deliberately remain an explicit offset-level obligation. -/
theorem OriginalRuntimeAccessWitness.disjointFromOtherRange
    {context : StaticProofContext} {world : RelationalWorld}
    {leftAddress rightAddress : Word} {leftBytes rightBytes : Nat}
    (left : OriginalRuntimeAccessWitness world leftAddress leftBytes)
    (right : OriginalRuntimeAccessWitness world rightAddress rightBytes)
    (partition : HoldsIn context world)
    (separate : left.kind ≠ right.kind \/ left.range.id ≠ right.range.id) :
    OriginalByteSpansDisjoint leftAddress leftBytes rightAddress rightBytes := by
  have leftStarts := left.startsInside
  have leftEnds := left.endsInside
  have rightStarts := right.startsInside
  have rightEnds := right.endsInside
  unfold OriginalByteSpansDisjoint
  cases leftKind : left.kind <;> cases rightKind : right.kind
  · have different : left.range.id ≠ right.range.id := by
      rcases separate with kindDifferent | rangeDifferent
      · exact (kindDifferent (leftKind.trans rightKind.symm)).elim
      · exact rangeDifferent
    rcases stackRangesDisjointOriginal context world partition left.range
      right.range (by simpa [leftKind] using left.rangeMember)
      (by simpa [rightKind] using right.rangeMember) different with
      leftBefore | rightBefore
    · left; omega
    · right; omega
  · rcases dynamicStackRangesDisjointOriginal context world partition
      right.range left.range
      (by simpa [rightKind] using right.rangeMember)
      (by simpa [leftKind] using left.rangeMember) with
      rightBefore | leftBefore
    · right; omega
    · left; omega
  · rcases dynamicStackRangesDisjointOriginal context world partition
      left.range right.range
      (by simpa [leftKind] using left.rangeMember)
      (by simpa [rightKind] using right.rangeMember) with
      leftBefore | rightBefore
    · left; omega
    · right; omega
  · have different : left.range.id ≠ right.range.id := by
      rcases separate with kindDifferent | rangeDifferent
      · exact (kindDifferent (leftKind.trans rightKind.symm)).elim
      · exact rangeDifferent
    rcases dynamicRangesDisjointOriginal context world partition left.range
      right.range (by simpa [leftKind] using left.rangeMember)
      (by simpa [rightKind] using right.rangeMember) different with
      leftBefore | rightBefore
    · left; omega
    · right; omega
theorem OriginalRuntimeAccessWitness.avoidsProtectedImageWord
    {context : StaticProofContext} {world : RelationalWorld}
    {writeAddress wordAddress : Word} {writeBytes : Nat}
    (witness : OriginalRuntimeAccessWitness world writeAddress writeBytes)
    (partition : HoldsIn context world)
    (protectedWord : OriginalProtectedImageWord context wordAddress) :
    OriginalAccessAvoidsWord wordAddress writeAddress writeBytes := by
  apply originalAccessAvoidsWord_of_spansDisjoint wordAddress writeAddress
    writeBytes
  · exact ⟨by omega, protectedWord.2.2⟩
  · exact witness.spanValid partition
  · exact witness.disjointFromProtectedImageWord partition protectedWord

theorem OriginalRuntimeAccessWitness.avoidsWritableStaticWord
    {context : StaticProofContext} {world : RelationalWorld}
    {writeAddress wordAddress : Word} {writeBytes : Nat}
    (witness : OriginalRuntimeAccessWitness world writeAddress writeBytes)
    (partition : HoldsIn context world)
    (wordValid : writableStaticWordInPe context.originalPe wordAddress = true) :
    OriginalAccessAvoidsWord wordAddress writeAddress writeBytes :=
  witness.avoidsProtectedImageWord partition
    (protectedImageWord_of_writableStaticWord context wordAddress wordValid)

/-- Every retained callback layer carries two worlds: the external suspension
that will resume after callback return and the world supplied at callback
entry.  Both are checked, as are all outer layers. -/
def SuspendedHold (context : StaticProofContext) :
    List WorldExternalCallbackRuntime -> Prop
  | [] => True
  | callback :: callbacks =>
      HoldsIn context callback.suspension.world /\
        HoldsIn context callback.entry.world /\
        SuspendedHold context callbacks

/-- Runtime partition predicate over every execution shape. -/
def ExecutionHolds (context : StaticProofContext) : WorldExecution -> Prop
  | .running _ _ _ _ world => HoldsIn context world
  | .returned _ world => HoldsIn context world
  | .terminated world => HoldsIn context world
  | .awaitingExternal suspension callbacks =>
      HoldsIn context suspension.world /\ SuspendedHold context callbacks
  | .callbackRunning _ _ _ _ world callbacks =>
      HoldsIn context world /\ SuspendedHold context callbacks
  | .fault _ => True
  | .blocked _ => False

theorem suspendedHold_tail (context : StaticProofContext)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : SuspendedHold context (callback :: callbacks)) :
    SuspendedHold context callbacks :=
  holds.2.2

theorem executionHolds_blockedFalse (context : StaticProofContext)
    (reason : ExecutionBlock) :
    Not (ExecutionHolds context (.blocked reason)) := by
  simp [ExecutionHolds]

/-- Calls, direct control, internal returns, and ordinary callback-local steps
all preserve the same active world and suspended callback inventory. -/
theorem executionHolds_resume
    (context : StaticProofContext) (callbacks : List WorldExternalCallbackRuntime)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (active : HoldsIn context world)
    (suspended : SuspendedHold context callbacks) :
    ExecutionHolds context
      (resumeWorldExecution callbacks targetId state calls eventIndex world) := by
  cases callbacks <;> simp_all [resumeWorldExecution, ExecutionHolds]

theorem executionHolds_returned (context : StaticProofContext)
    (state : MachineState) (world : RelationalWorld)
    (active : HoldsIn context world) :
    ExecutionHolds context (.returned state world) :=
  active

theorem executionHolds_terminated (context : StaticProofContext)
    (world : RelationalWorld) (active : HoldsIn context world) :
    ExecutionHolds context (.terminated world) :=
  active

theorem executionHolds_awaitingExternal (context : StaticProofContext)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (active : HoldsIn context suspension.world)
    (suspended : SuspendedHold context callbacks) :
    ExecutionHolds context (.awaitingExternal suspension callbacks) :=
  ⟨active, suspended⟩

/-- Protocol callback entry pushes the old suspension and supplies a checked
successor world for the active callback frame. -/
theorem executionHolds_callbackEntry (context : StaticProofContext)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (entry : WorldExternalCallbackAction)
    (before : ExecutionHolds context (.awaitingExternal suspension callbacks))
    (entryWorldValid : entry.world.valid context = true) :
    ExecutionHolds context
      (.callbackRunning entry.targetId entry.state [] suspension.eventIndex
        entry.world ({ suspension, entry } :: callbacks)) := by
  refine ⟨holdsIn_of_worldValid context entry.world entryWorldValid, ?_⟩
  exact ⟨before.1, holdsIn_of_worldValid context entry.world entryWorldValid,
    before.2⟩

/-- Returning from a callback restores the outer protocol suspension while the
active callback world becomes the new suspension world. -/
theorem executionHolds_callbackReturn (context : StaticProofContext)
    (callback : WorldExternalCallbackRuntime)
    (outerCallbacks : List WorldExternalCallbackRuntime)
    (state : MachineState) (world : RelationalWorld)
    (active : HoldsIn context world)
    (suspended : SuspendedHold context (callback :: outerCallbacks)) :
    ExecutionHolds context
      (.awaitingExternal {
        callback.suspension with
        phaseIndex := callback.suspension.phaseIndex + 1
        resumeInvariant := callback.entry.returnInvariant
        state
        world
      } outerCallbacks) :=
  ⟨active, suspended.2.2⟩

theorem holdsIn_of_machineCallWorldEffect
    (candidate : Bool) (context : StaticProofContext)
    (effect : MachineCallWorldEffect) (arguments : List Word)
    (before after : RelationalWorld)
    (holds : machineCallWorldEffectHolds candidate context effect arguments
      before after) :
    HoldsIn context after :=
  holdsIn_of_worldValid context after holds.1

theorem holdsIn_of_machineCallResult
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract) (event : WorldExternalEvent)
    (result : WorldExternalResult)
    (conforms : machineCallResultConforms candidate context contract event result) :
    HoldsIn context result.world :=
  holdsIn_of_machineCallWorldEffect candidate context contract.worldEffect
    event.arguments event.world result.world conforms.2.2.2

/-- A returning external call may change the dynamic world, but only through a
machine contract whose world-effect checker validates the successor partition. -/
theorem executionHolds_externalReturn
    (candidate : Bool) (context : StaticProofContext)
    (contract : MachineImportCallContract) (event : WorldExternalEvent)
    (result : WorldExternalResult)
    (conforms : machineCallResultConforms candidate context contract event result)
    (callbacks : List WorldExternalCallbackRuntime)
    (continuationTargetId : Nat) (calls : List Nat) (eventIndex : Nat)
    (suspended : SuspendedHold context callbacks) :
    ExecutionHolds context
      (resumeWorldExecution callbacks continuationTargetId result.state calls
        eventIndex result.world) :=
  executionHolds_resume context callbacks continuationTargetId result.state calls
    eventIndex result.world
    (holdsIn_of_machineCallResult candidate context contract event result conforms)
    suspended

theorem executionHolds_externalTermination
    (context : StaticProofContext) (world : RelationalWorld)
    (worldValid : world.valid context = true) :
    ExecutionHolds context (.terminated world) :=
  holdsIn_of_worldValid context world worldValid

#print axioms originalAccessAvoidsWord_of_spansDisjoint
#print axioms OriginalRuntimeAccessWitness.spanValid
#print axioms OriginalRuntimeAccessWitness.avoidsWritableStaticWord
#print axioms OriginalRuntimeAccessWitness.disjointFromOtherRange
#print axioms normalizedWriteProposalsChecked_addresses
#print axioms normalizedWriteProposalsChecked_widths
#print axioms executionHolds_resume
#print axioms executionHolds_callbackEntry
#print axioms executionHolds_callbackReturn
#print axioms executionHolds_externalReturn

end StageA.Relational.OriginalRuntimeMemoryPartition
