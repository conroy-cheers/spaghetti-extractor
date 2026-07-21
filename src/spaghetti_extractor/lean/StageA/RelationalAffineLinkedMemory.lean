import StageA.RelationalAffineLinkedExecution

namespace StageA.Relational

open StageA.Formal

/-- One proof-relevant pair of decoded writes.  Addresses and values are both
kept exact; pairing writes by count alone is not accepted. -/
structure PairedDecodedWrite where
  originalAddress : Expr
  originalValue : Expr
  candidateAddress : Expr
  candidateValue : Expr
deriving Repr, DecidableEq

def PairedDecodedWrite.original (write : PairedDecodedWrite) : Expr × Expr :=
  (write.originalAddress, write.originalValue)

def PairedDecodedWrite.candidate (write : PairedDecodedWrite) : Expr × Expr :=
  (write.candidateAddress, write.candidateValue)

def PairedDecodedWrite.originalConcrete (write : PairedDecodedWrite)
    (state : MachineState) : Word × Word :=
  (write.originalAddress.eval state, write.originalValue.eval state)

def PairedDecodedWrite.candidateConcrete (write : PairedDecodedWrite)
    (state : MachineState) : Word × Word :=
  (write.candidateAddress.eval state, write.candidateValue.eval state)

/-- A nonempty ordered list of paired decoded writes.  The checker fails
closed on an empty frontier and compares both fields of every decoded write. -/
structure PairedDecodedWritesClaim where
  writes : List PairedDecodedWrite
deriving Repr, DecidableEq

def PairedDecodedWritesClaim.originalSymbolicWrites
    (claim : PairedDecodedWritesClaim) : List (Expr × Expr) :=
  claim.writes.map PairedDecodedWrite.original

def PairedDecodedWritesClaim.candidateSymbolicWrites
    (claim : PairedDecodedWritesClaim) : List (Expr × Expr) :=
  claim.writes.map PairedDecodedWrite.candidate

def PairedDecodedWritesClaim.originalConcreteWrites
    (claim : PairedDecodedWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.writes.map fun write => write.originalConcrete state

def PairedDecodedWritesClaim.candidateConcreteWrites
    (claim : PairedDecodedWritesClaim) (state : MachineState) :
    List (Word × Word) :=
  claim.writes.map fun write => write.candidateConcrete state

/-- A statically checked signed displacement from ESP.  Keeping the direction
explicit lets the stack-window checker prove non-wrapping subtraction instead
of interpreting a large unsigned bitvector as an address near 4 GiB. -/
inductive StackRelativeWordOffset where
  | above (amount : Nat)
  | below (amount : Nat)
deriving Repr, DecidableEq

def StackRelativeWordOffset.word : StackRelativeWordOffset -> Word
  | .above amount => BitVec.ofNat 32 amount
  | .below amount => 0 - BitVec.ofNat 32 amount

def StackRelativeWordOffset.address (offset : StackRelativeWordOffset)
    (registers : PureState) : Word :=
  registers.esp + offset.word

/-- Proof data for the deliberately small ESP-affine expression grammar.  The
checker compares `expression` with the exact decoded expression, so this is a
witness over binary semantics rather than a trusted Python normalization. -/
inductive StackRelativeExpr where
  | esp
  | add (base : StackRelativeExpr) (amount : Nat)
  | sub (base : StackRelativeExpr) (amount : Nat)
deriving Repr, DecidableEq

def StackRelativeExpr.expression : StackRelativeExpr -> Expr
  | .esp => .inputReg .esp
  | .add base amount => .add base.expression (.constant amount)
  | .sub base amount => .sub base.expression (.constant amount)

def StackRelativeExpr.wordOffset : StackRelativeExpr -> Word
  | .esp => 0
  | .add base amount => base.wordOffset + BitVec.ofNat 32 amount
  | .sub base amount => base.wordOffset - BitVec.ofNat 32 amount

@[simp] theorem StackRelativeExpr.expression_eval
    (expression : StackRelativeExpr) (state : MachineState) :
    expression.expression.eval state =
      state.registers.esp + expression.wordOffset := by
  induction expression with
  | esp => simp [StackRelativeExpr.expression, StackRelativeExpr.wordOffset,
      Expr.eval, Registers.get]
  | add base amount induction =>
      simp [StackRelativeExpr.expression, StackRelativeExpr.wordOffset,
        Expr.eval, induction, BitVec.add_assoc]
  | sub base amount induction =>
      simp [StackRelativeExpr.expression, StackRelativeExpr.wordOffset,
        Expr.eval, induction, BitVec.sub_eq_add_neg, BitVec.add_assoc]

structure StackRelativeWordWrite where
  expression : StackRelativeExpr
  offset : StackRelativeWordOffset
deriving Repr, DecidableEq

def StackRelativeWordWrite.checked (write : StackRelativeWordWrite) : Bool :=
  write.expression.wordOffset == write.offset.word

structure PairedStackRelativeWordWrite where
  original : StackRelativeWordWrite
  candidate : StackRelativeWordWrite
deriving Repr, DecidableEq

def PairedDecodedWrite.stackOffsetChecked (write : PairedDecodedWrite)
    (offset : PairedStackRelativeWordWrite) : Bool :=
  offset.original.checked && offset.candidate.checked &&
    write.originalAddress == offset.original.expression.expression &&
    write.candidateAddress == offset.candidate.expression.expression

def PairedDecodedWritesClaim.stackOffsetsChecked
    (claim : PairedDecodedWritesClaim)
    (offsets : List PairedStackRelativeWordWrite) : Bool :=
  claim.writes.length == offsets.length &&
    (claim.writes.zip offsets).all fun row => row.1.stackOffsetChecked row.2

theorem PairedDecodedWrite.concreteAddresses_of_stackOffsetChecked
    (write : PairedDecodedWrite) (offset : PairedStackRelativeWordWrite)
    (originalState candidateState : MachineState)
    (checked : write.stackOffsetChecked offset = true) :
    (write.originalConcrete originalState).1 =
        offset.original.offset.address originalState.registers ∧
      (write.candidateConcrete candidateState).1 =
        offset.candidate.offset.address candidateState.registers := by
  simp only [PairedDecodedWrite.stackOffsetChecked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨⟨originalOffset, candidateOffset⟩,
    originalExpression⟩, candidateExpression⟩
  unfold StackRelativeWordWrite.checked at originalOffset candidateOffset
  simp only [beq_iff_eq] at originalOffset candidateOffset
  constructor
  · simp [PairedDecodedWrite.originalConcrete, originalExpression,
      StackRelativeWordOffset.address, originalOffset]
  · simp [PairedDecodedWrite.candidateConcrete, candidateExpression,
      StackRelativeWordOffset.address, candidateOffset]

theorem StackRelativeWordOffset.write32Avoids_of_disjoint
    (offset : StackRelativeWordOffset) (registers : PureState) (base : Word)
    (disjoint : wordOffsetsDisjoint base offset.word = true) :
    Write32AvoidsWord (registers.esp + base) (offset.address registers) := by
  intro wordByte wordByteBefore writeByte writeByteBefore overlap
  simp only [wordOffsetsDisjoint, List.all_eq_true] at disjoint
  have wordChecked := disjoint wordByte (by simpa using wordByteBefore)
  have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
  simp only [decide_eq_true_eq] at writeChecked
  apply writeChecked
  apply (BitVec.add_right_inj registers.esp).mp
  simpa only [StackRelativeWordOffset.address, BitVec.add_assoc] using overlap

theorem PairedDecodedWrite.concreteAvoids_of_stackOffsetChecked
    (write : PairedDecodedWrite) (offset : PairedStackRelativeWordWrite)
    (originalState candidateState : MachineState)
    (originalBase candidateBase : Word)
    (checked : write.stackOffsetChecked offset = true)
    (disjoint : wordOffsetsDisjoint originalBase offset.original.offset.word = true ∧
      wordOffsetsDisjoint candidateBase offset.candidate.offset.word = true) :
    Write32AvoidsWord (originalState.registers.esp + originalBase)
        (write.originalConcrete originalState).1 ∧
      Write32AvoidsWord (candidateState.registers.esp + candidateBase)
        (write.candidateConcrete candidateState).1 := by
  have addresses := write.concreteAddresses_of_stackOffsetChecked offset
    originalState candidateState checked
  constructor
  · rw [addresses.1]
    exact offset.original.offset.write32Avoids_of_disjoint
      originalState.registers originalBase disjoint.1
  · rw [addresses.2]
    exact offset.candidate.offset.write32Avoids_of_disjoint
      candidateState.registers candidateBase disjoint.2

theorem PairedDecodedWritesClaim.concreteWritesAvoid_of_stackOffsetsChecked
    (claim : PairedDecodedWritesClaim)
    (offsets : List PairedStackRelativeWordWrite)
    (originalState candidateState : MachineState)
    (originalBase candidateBase : Word)
    (checked : claim.stackOffsetsChecked offsets = true)
    (disjoint : (offsets.all fun offset =>
      wordOffsetsDisjoint originalBase offset.original.offset.word &&
        wordOffsetsDisjoint candidateBase offset.candidate.offset.word) = true) :
    WritesAvoidWord (originalState.registers.esp + originalBase)
        (claim.originalConcreteWrites originalState) ∧
      WritesAvoidWord (candidateState.registers.esp + candidateBase)
        (claim.candidateConcreteWrites candidateState) := by
  cases claim with
  | mk writes =>
      induction writes generalizing offsets with
      | nil =>
          cases offsets <;> simp [PairedDecodedWritesClaim.originalConcreteWrites,
            PairedDecodedWritesClaim.candidateConcreteWrites, WritesAvoidWord]
      | cons write writes induction =>
          cases offsets with
          | nil =>
              simp [PairedDecodedWritesClaim.stackOffsetsChecked] at checked
          | cons offset offsets =>
              simp only [PairedDecodedWritesClaim.stackOffsetsChecked,
                List.length_cons, List.zip_cons_cons, List.all_cons,
                Bool.and_eq_true, beq_iff_eq] at checked
              simp only [List.all_cons, Bool.and_eq_true] at disjoint
              have tailChecked :
                  PairedDecodedWritesClaim.stackOffsetsChecked
                    ({ writes := writes } : PairedDecodedWritesClaim)
                    offsets = true := by
                change (writes.length == offsets.length &&
                  (writes.zip offsets).all fun row =>
                    row.1.stackOffsetChecked row.2) = true
                simp only [Bool.and_eq_true, beq_iff_eq]
                exact ⟨Nat.succ.inj checked.1, checked.2.2⟩
              have tail := induction offsets disjoint.2 tailChecked
              have head := write.concreteAvoids_of_stackOffsetChecked offset
                originalState candidateState originalBase candidateBase
                checked.2.1 disjoint.1
              constructor
              · intro concreteWrite member
                simp only [PairedDecodedWritesClaim.originalConcreteWrites,
                  List.map_cons, List.mem_cons] at member
                rcases member with rfl | member
                · exact head.1
                · exact tail.1 concreteWrite member
              · intro concreteWrite member
                simp only [PairedDecodedWritesClaim.candidateConcreteWrites,
                  List.map_cons, List.mem_cons] at member
                rcases member with rfl | member
                · exact head.2
                · exact tail.2 concreteWrite member

def PairedDecodedWritesClaim.checked (claim : PairedDecodedWritesClaim)
    (original candidate : NormalizedSymbolicBehavior) : Bool :=
  !claim.writes.isEmpty &&
    original.writes == claim.originalSymbolicWrites &&
    candidate.writes == claim.candidateSymbolicWrites

def PairedDecodedWritesClaim.ConcreteWritesExact
    (claim : PairedDecodedWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState) : Prop :=
  evalNormalizedWrites originalState originalBehavior.writes =
      claim.originalConcreteWrites originalState ∧
    evalNormalizedWrites candidateState candidateBehavior.writes =
      claim.candidateConcreteWrites candidateState

theorem PairedDecodedWritesClaim.concreteWritesExact_of_checked
    (claim : PairedDecodedWritesClaim)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (originalState candidateState : MachineState)
    (checked : claim.checked originalBehavior candidateBehavior = true) :
    claim.ConcreteWritesExact originalBehavior candidateBehavior
      originalState candidateState := by
  simp only [PairedDecodedWritesClaim.checked, Bool.and_eq_true,
    beq_iff_eq] at checked
  rcases checked with ⟨⟨_nonempty, originalExact⟩, candidateExact⟩
  constructor
  · rw [originalExact]
    simp [evalNormalizedWrites,
      PairedDecodedWritesClaim.originalSymbolicWrites,
      PairedDecodedWritesClaim.originalConcreteWrites,
      PairedDecodedWrite.original, PairedDecodedWrite.originalConcrete]
  · rw [candidateExact]
    simp [evalNormalizedWrites,
      PairedDecodedWritesClaim.candidateSymbolicWrites,
      PairedDecodedWritesClaim.candidateConcreteWrites,
      PairedDecodedWrite.candidate, PairedDecodedWrite.candidateConcrete]

/-- Executable disjointness for one protected word and an exact concrete write
list.  It is the finite checker counterpart of `WritesAvoidWord`. -/
def concreteWritesAvoidWordChecked (wordAddress : Word)
    (writes : List (Word × Word)) : Bool :=
  writes.all fun write => wordOffsetsDisjoint wordAddress write.1

theorem concreteWritesAvoidWord_of_checked (wordAddress : Word)
    (writes : List (Word × Word))
    (checked : concreteWritesAvoidWordChecked wordAddress writes = true) :
    WritesAvoidWord wordAddress writes := by
  simp only [concreteWritesAvoidWordChecked, List.all_eq_true] at checked
  intro write member
  have disjoint := checked write member
  simp only [wordOffsetsDisjoint, List.all_eq_true] at disjoint
  intro wordByte wordByteBefore writeByte writeByteBefore
  have wordChecked := disjoint wordByte (by simpa using wordByteBefore)
  have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
  simpa only [decide_eq_true_eq] using writeChecked

theorem concreteWritesAvoidWordChecked_of_avoids (wordAddress : Word)
    (writes : List (Word × Word))
    (avoids : WritesAvoidWord wordAddress writes) :
    concreteWritesAvoidWordChecked wordAddress writes = true := by
  simp only [concreteWritesAvoidWordChecked, List.all_eq_true]
  intro write member
  have writeAvoids := avoids write member
  simp only [wordOffsetsDisjoint, List.all_eq_true]
  intro wordByte wordByteMember writeByte writeByteMember
  simp only [List.mem_range] at wordByteMember writeByteMember
  simp only [decide_eq_true_eq]
  exact writeAvoids wordByte wordByteMember writeByte writeByteMember

/-- Every concrete write is a non-wrapping four-byte word strictly below the
given boundary.  This is the reusable frame rule for downward-growing IA-32
stacks; it talks only about concrete flat-memory addresses. -/
def concreteWritesBeforeChecked (boundary : Word)
    (writes : List (Word × Word)) : Bool :=
  writes.all fun write => write.1.toNat + 4 <= boundary.toNat

theorem concreteWritesBeforeChecked.mono (left right : Word)
    (writes : List (Word × Word))
    (checked : concreteWritesBeforeChecked left writes = true)
    (ordered : left.toNat <= right.toNat) :
    concreteWritesBeforeChecked right writes = true := by
  simp only [concreteWritesBeforeChecked, List.all_eq_true,
    decide_eq_true_eq] at checked ⊢
  intro write member
  exact Nat.le_trans (checked write member) ordered

theorem concreteWritesAvoidWordChecked_of_before (wordAddress : Word)
    (writes : List (Word × Word))
    (wordFits : wordAddress.toNat + 4 <= 2 ^ 32)
    (before : concreteWritesBeforeChecked wordAddress writes = true) :
    concreteWritesAvoidWordChecked wordAddress writes = true := by
  apply concreteWritesAvoidWordChecked_of_avoids
  intro write member
  have writeBefore : write.1.toNat + 4 <= wordAddress.toNat := by
    simp only [concreteWritesBeforeChecked, List.all_eq_true,
      decide_eq_true_eq] at before
    exact before write member
  exact write32AvoidsWord_of_nat_disjoint wordAddress write.1 wordFits
    (by omega) (Or.inr writeBefore)

def ReturnSlotOffsetInventory.writesAvoidChecked
    (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word)) : Bool :=
  inventory.exactWords.all fun word =>
    concreteWritesAvoidWordChecked
        (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset)
        originalWrites &&
      concreteWritesAvoidWordChecked
        (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset)
        candidateWrites

theorem ReturnSlotOffsetInventory.writesAvoid_of_checked
    (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word))
    (checked : inventory.writesAvoidChecked frame originalWrites
      candidateWrites = true) :
    ∀ word ∈ inventory.exactWords,
      WritesAvoidWord
          (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset)
          originalWrites ∧
        WritesAvoidWord
          (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset)
          candidateWrites := by
  simp only [ReturnSlotOffsetInventory.writesAvoidChecked, List.all_eq_true,
    Bool.and_eq_true] at checked
  intro word member
  have wordChecked := checked word member
  exact ⟨concreteWritesAvoidWord_of_checked _ _ wordChecked.1,
    concreteWritesAvoidWord_of_checked _ _ wordChecked.2⟩

theorem ReturnSlotOffsetInventory.boundedExactWordsHold_afterWrites
    (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame)
    (original candidate : Memory)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : inventory.boundedExactWordsHold frame original candidate)
    (checked : inventory.writesAvoidChecked frame originalWrites
      candidateWrites = true) :
    inventory.boundedExactWordsHold frame
      (applyConcreteWrites original originalWrites)
      (applyConcreteWrites candidate candidateWrites) := by
  rcases holds with ⟨fits, wordsHold⟩
  refine ⟨fits, ?_⟩
  intro word member
  have prior := wordsHold word member
  have avoids := inventory.writesAvoid_of_checked frame originalWrites
    candidateWrites checked word member
  unfold ReturnSlotExactWordPair.holds at prior ⊢
  calc
    Memory.read32 (applyConcreteWrites original originalWrites)
        (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset) =
      Memory.read32 original
        (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset) :=
          Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.1
    _ = Memory.read32 candidate
        (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset) := prior
    _ = Memory.read32 (applyConcreteWrites candidate candidateWrites)
        (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset) :=
          (Memory.read32_applyConcreteWrites_of_avoids _ _ _ avoids.2).symm

def RelationalRuntimeCallFrame.writesAvoidChecked
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word)) : Bool :=
  concreteWritesAvoidWordChecked frame.originalStackAddress originalWrites &&
    concreteWritesAvoidWordChecked frame.candidateStackAddress candidateWrites

theorem RelationalRuntimeCallFrame.writesAvoid_of_checked
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word))
    (checked : frame.writesAvoidChecked originalWrites candidateWrites = true) :
    frame.writesAvoid originalWrites candidateWrites := by
  simp only [RelationalRuntimeCallFrame.writesAvoidChecked,
    Bool.and_eq_true] at checked
  exact ⟨concreteWritesAvoidWord_of_checked _ _ checked.1,
    concreteWritesAvoidWord_of_checked _ _ checked.2⟩

theorem RelationalRuntimeCallFrame.writesAvoidChecked_of_before
    (context : StaticProofContext) (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word))
    (valid : frame.valid context = true)
    (originalBefore : concreteWritesBeforeChecked frame.originalStackAddress
      originalWrites = true)
    (candidateBefore : concreteWritesBeforeChecked frame.candidateStackAddress
      candidateWrites = true) :
    frame.writesAvoidChecked originalWrites candidateWrites = true := by
  have spanValid : frame.protectedSpanValid context = true := by
    have validParts := valid
    simp only [RelationalRuntimeCallFrame.valid, Bool.and_eq_true] at validParts
    exact validParts.2
  simp only [RelationalRuntimeCallFrame.protectedSpanValid,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at spanValid
  have originalFits : frame.originalStackAddress.toNat + 4 <= 2 ^ 32 := by
    omega
  have candidateFits : frame.candidateStackAddress.toNat + 4 <= 2 ^ 32 := by
    omega
  simp only [RelationalRuntimeCallFrame.writesAvoidChecked, Bool.and_eq_true]
  exact ⟨concreteWritesAvoidWordChecked_of_before _ _ originalFits
      originalBefore,
    concreteWritesAvoidWordChecked_of_before _ _ candidateFits
      candidateBefore⟩

theorem ReturnSlotOffsetInventory.writesAvoidChecked_of_beforeFrame
    (context : StaticProofContext) (inventory : ReturnSlotOffsetInventory)
    (frame : RelationalRuntimeCallFrame)
    (originalWrites candidateWrites : List (Word × Word))
    (frameValid : frame.valid context = true)
    (wordsFit : inventory.exactWordsFit frame = true)
    (originalBefore : concreteWritesBeforeChecked frame.originalStackAddress
      originalWrites = true)
    (candidateBefore : concreteWritesBeforeChecked frame.candidateStackAddress
      candidateWrites = true) :
    inventory.writesAvoidChecked frame originalWrites candidateWrites = true := by
  have spanValid : frame.protectedSpanValid context = true := by
    have validParts := frameValid
    simp only [RelationalRuntimeCallFrame.valid, Bool.and_eq_true] at validParts
    exact validParts.2
  simp only [RelationalRuntimeCallFrame.protectedSpanValid,
    Bool.and_eq_true, Bool.or_eq_true, decide_eq_true_eq] at spanValid
  simp only [ReturnSlotOffsetInventory.exactWordsFit, List.all_eq_true,
    Bool.and_eq_true, decide_eq_true_eq] at wordsFit
  simp only [ReturnSlotOffsetInventory.writesAvoidChecked, List.all_eq_true,
    Bool.and_eq_true]
  intro word member
  have offsetsFit := wordsFit word member
  have originalOffsetSmall : word.originalOffset < 2 ^ 32 := by omega
  have candidateOffsetSmall : word.candidateOffset < 2 ^ 32 := by omega
  have originalSumSmall :
      frame.originalStackAddress.toNat + word.originalOffset < 2 ^ 32 := by
    omega
  have candidateSumSmall :
      frame.candidateStackAddress.toNat + word.candidateOffset < 2 ^ 32 := by
    omega
  have originalAddressNat :
      (frame.originalStackAddress +
        BitVec.ofNat 32 word.originalOffset).toNat =
          frame.originalStackAddress.toNat + word.originalOffset := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt originalOffsetSmall,
      Nat.mod_eq_of_lt originalSumSmall]
  have candidateAddressNat :
      (frame.candidateStackAddress +
        BitVec.ofNat 32 word.candidateOffset).toNat =
          frame.candidateStackAddress.toNat + word.candidateOffset := by
    simp [BitVec.toNat_add, BitVec.toNat_ofNat,
      Nat.mod_eq_of_lt candidateOffsetSmall,
      Nat.mod_eq_of_lt candidateSumSmall]
  have originalWordFits :
      (frame.originalStackAddress +
        BitVec.ofNat 32 word.originalOffset).toNat + 4 <= 2 ^ 32 := by
    rw [originalAddressNat]
    omega
  have candidateWordFits :
      (frame.candidateStackAddress +
        BitVec.ofNat 32 word.candidateOffset).toNat + 4 <= 2 ^ 32 := by
    rw [candidateAddressNat]
    omega
  have originalBeforeWord : concreteWritesBeforeChecked
      (frame.originalStackAddress + BitVec.ofNat 32 word.originalOffset)
      originalWrites = true := by
    apply concreteWritesBeforeChecked.mono frame.originalStackAddress
    · exact originalBefore
    · rw [originalAddressNat]
      omega
  have candidateBeforeWord : concreteWritesBeforeChecked
      (frame.candidateStackAddress + BitVec.ofNat 32 word.candidateOffset)
      candidateWrites = true := by
    apply concreteWritesBeforeChecked.mono frame.candidateStackAddress
    · exact candidateBefore
    · rw [candidateAddressNat]
      omega
  exact ⟨concreteWritesAvoidWordChecked_of_before _ _ originalWordFits
      originalBeforeWord,
    concreteWritesAvoidWordChecked_of_before _ _ candidateWordFits
      candidateBeforeWord⟩

/-- Check exactly the dormant inventories represented by a concrete frame/link
tail.  Shape mismatches fail closed. -/
def relationalRuntimeCallFrameLinksWritesAvoidChecked
    (originalWrites candidateWrites : List (Word × Word)) :
    List RelationalRuntimeCallFrame ->
      List RelationalRuntimeCallFrameLink -> Bool
  | [], [] => true
  | [_], [] => true
  | _inner :: outer :: frames, link :: links =>
      link.suspendedInventory.writesAvoidChecked outer originalWrites
          candidateWrites &&
        relationalRuntimeCallFrameLinksWritesAvoidChecked originalWrites
          candidateWrites (outer :: frames) links
  | _, _ => false

theorem RelationalRuntimeCallFrameLinksHold.afterWritesChecked
    (beforeOriginal beforeCandidate : Memory)
    (frames : List RelationalRuntimeCallFrame)
    (links : List RelationalRuntimeCallFrameLink)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : RelationalRuntimeCallFrameLinksHold beforeOriginal beforeCandidate
      frames links)
    (checked : relationalRuntimeCallFrameLinksWritesAvoidChecked originalWrites
      candidateWrites frames links = true) :
    RelationalRuntimeCallFrameLinksHold
      (applyConcreteWrites beforeOriginal originalWrites)
      (applyConcreteWrites beforeCandidate candidateWrites) frames links := by
  induction frames generalizing links with
  | nil =>
      cases links <;> simp_all [RelationalRuntimeCallFrameLinksHold,
        relationalRuntimeCallFrameLinksWritesAvoidChecked]
  | cons inner frames ih =>
      cases frames with
      | nil =>
          cases links <;> simp_all [RelationalRuntimeCallFrameLinksHold,
            relationalRuntimeCallFrameLinksWritesAvoidChecked]
      | cons outer frames =>
          cases links with
          | nil => simp [RelationalRuntimeCallFrameLinksHold] at holds
          | cons link links =>
              simp only [RelationalRuntimeCallFrameLinksHold] at holds ⊢
              simp only [relationalRuntimeCallFrameLinksWritesAvoidChecked,
                Bool.and_eq_true] at checked
              exact ⟨holds.1,
                link.suspendedInventory.boundedExactWordsHold_afterWrites outer
                  beforeOriginal beforeCandidate originalWrites candidateWrites
                  holds.2.1 checked.1,
                ih links holds.2.2 checked.2⟩

/-- The complete memory footprint needed by one ordinary linked transition:
the active exact-word inventory, every active/dormant return slot, and every
dormant suspended inventory. -/
def relationalLinkedStackWritesAvoidChecked
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (active : ReturnSlotOffsetInventory)
    (links : List RelationalRuntimeCallFrameLink)
    (originalWrites candidateWrites : List (Word × Word)) : Bool :=
  active.writesAvoidChecked frame originalWrites candidateWrites &&
    (frame :: frames).all (fun selected =>
      selected.writesAvoidChecked originalWrites candidateWrites) &&
    relationalRuntimeCallFrameLinksWritesAvoidChecked originalWrites
      candidateWrites (frame :: frames) links

/-- Once every write finishes before the first dormant frame, the checked
natural ordering of runtime-frame links protects every deeper return slot and
suspended exact-word inventory.  The proof is depth-independent. -/
theorem relationalLinkedStackTailWritesAvoidChecked_of_beforeOuter
    (context : StaticProofContext)
    (original candidate : MachineState)
    (inner outer : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (outerContinuation : Nat) (continuations : List Nat)
    (link : RelationalRuntimeCallFrameLink)
    (links : List RelationalRuntimeCallFrameLink)
    (originalWrites candidateWrites : List (Word × Word))
    (framesHold : RelationalRuntimeCallFramesHold context original candidate
      (outer :: frames) (outerContinuation :: continuations))
    (linksHold : RelationalRuntimeCallFrameLinksHold original.memory
      candidate.memory (inner :: outer :: frames) (link :: links))
    (originalBefore : concreteWritesBeforeChecked outer.originalStackAddress
      originalWrites = true)
    (candidateBefore : concreteWritesBeforeChecked outer.candidateStackAddress
      candidateWrites = true) :
    (outer :: frames).all (fun selected =>
        selected.writesAvoidChecked originalWrites candidateWrites) = true ∧
      relationalRuntimeCallFrameLinksWritesAvoidChecked originalWrites
        candidateWrites (inner :: outer :: frames) (link :: links) = true := by
  induction frames generalizing inner outer outerContinuation continuations link
      links with
  | nil =>
      cases continuations with
      | cons continuation continuations =>
          simp [RelationalRuntimeCallFramesHold] at framesHold
      | nil =>
          cases links with
          | cons nextLink links =>
              simp [RelationalRuntimeCallFrameLinksHold] at linksHold
          | nil =>
              simp only [RelationalRuntimeCallFramesHold] at framesHold
              simp only [RelationalRuntimeCallFrameLinksHold] at linksHold
              have outerAvoid :=
                outer.writesAvoidChecked_of_before context originalWrites
                  candidateWrites framesHold.2.1 originalBefore candidateBefore
              have suspendedAvoid :=
                link.suspendedInventory.writesAvoidChecked_of_beforeFrame
                  context outer originalWrites candidateWrites framesHold.2.1
                  linksHold.2.1.1 originalBefore candidateBefore
              simp [relationalRuntimeCallFrameLinksWritesAvoidChecked,
                outerAvoid, suspendedAvoid]
  | cons next frames induction =>
      cases continuations with
      | nil => simp [RelationalRuntimeCallFramesHold] at framesHold
      | cons nextContinuation continuations =>
          cases links with
          | nil => simp [RelationalRuntimeCallFrameLinksHold] at linksHold
          | cons nextLink links =>
              simp only [RelationalRuntimeCallFramesHold] at framesHold
              simp only [RelationalRuntimeCallFrameLinksHold] at linksHold
              have outerAvoid :=
                outer.writesAvoidChecked_of_before context originalWrites
                  candidateWrites framesHold.2.1 originalBefore candidateBefore
              have suspendedAvoid :=
                link.suspendedInventory.writesAvoidChecked_of_beforeFrame
                  context outer originalWrites candidateWrites framesHold.2.1
                  linksHold.2.1.1 originalBefore candidateBefore
              have outerBelowNext :=
                nextLink.strictlyBelow_of_holds outer next linksHold.2.2.1
              have originalOuterBeforeNext := outerBelowNext.1
              have candidateOuterBeforeNext := outerBelowNext.2
              have originalBeforeNext : concreteWritesBeforeChecked
                  next.originalStackAddress originalWrites = true :=
                concreteWritesBeforeChecked.mono outer.originalStackAddress
                  next.originalStackAddress originalWrites originalBefore
                  (by omega)
              have candidateBeforeNext : concreteWritesBeforeChecked
                  next.candidateStackAddress candidateWrites = true :=
                concreteWritesBeforeChecked.mono outer.candidateStackAddress
                  next.candidateStackAddress candidateWrites candidateBefore
                  (by omega)
              have tail := induction
                (inner := outer) (outer := next)
                (outerContinuation := nextContinuation)
                (continuations := continuations)
                (link := nextLink) (links := links)
                framesHold.2.2.2.2 linksHold.2.2 originalBeforeNext
                candidateBeforeNext
              have tailFrames :
                  next.writesAvoidChecked originalWrites candidateWrites = true ∧
                    frames.all (fun selected => selected.writesAvoidChecked
                      originalWrites candidateWrites) = true := by
                simpa only [List.all_cons, Bool.and_eq_true] using tail.1
              have tailLinks :
                  nextLink.suspendedInventory.writesAvoidChecked next
                      originalWrites candidateWrites = true ∧
                    relationalRuntimeCallFrameLinksWritesAvoidChecked
                      originalWrites candidateWrites (next :: frames) links = true := by
                simpa only [relationalRuntimeCallFrameLinksWritesAvoidChecked,
                  Bool.and_eq_true] using tail.2
              simp only [List.all_cons,
                relationalRuntimeCallFrameLinksWritesAvoidChecked,
                Bool.and_eq_true]
              exact ⟨⟨outerAvoid, tailFrames⟩, suspendedAvoid, tailLinks⟩

/-- Preserve a linked runtime stack across exact paired concrete writes.  The
two memories are updated independently; no original/candidate memory equality
is assumed. -/
theorem RelationalLinkedRuntimeCallStackHolds.afterPairedWrites
    (context : StaticProofContext)
    (beforeOriginal beforeCandidate afterOriginal afterCandidate : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (source target : ReturnSlotOffsetInventory)
    (originalWrites candidateWrites : List (Word × Word))
    (holds : RelationalLinkedRuntimeCallStackHolds context beforeOriginal
      beforeCandidate (frame :: frames) (continuation :: continuations)
      (some source) links)
    (targetChecked : target.checked = true)
    (targetHolds : target.holds frame afterOriginal.registers
      afterCandidate.registers)
    (targetWords : target.exactWords = source.exactWords)
    (footprintChecked : relationalLinkedStackWritesAvoidChecked frame frames
      source links originalWrites candidateWrites = true)
    (originalMemory : afterOriginal.memory =
      applyConcreteWrites beforeOriginal.memory originalWrites)
    (candidateMemory : afterCandidate.memory =
      applyConcreteWrites beforeCandidate.memory candidateWrites) :
    RelationalLinkedRuntimeCallStackHolds context afterOriginal afterCandidate
      (frame :: frames) (continuation :: continuations) (some target) links := by
  have stackFacts := holds
  simp only [RelationalLinkedRuntimeCallStackHolds] at stackFacts ⊢
  simp only [relationalLinkedStackWritesAvoidChecked,
    Bool.and_eq_true] at footprintChecked
  rcases footprintChecked with
    ⟨⟨activeAvoids, framesAvoid⟩, linksAvoid⟩
  have sourceWordsAfter := source.boundedExactWordsHold_afterWrites frame
    beforeOriginal.memory beforeCandidate.memory originalWrites candidateWrites
    stackFacts.2.2.1 activeAvoids
  have targetWordsAfter : target.boundedExactWordsHold frame
      afterOriginal.memory afterCandidate.memory := by
    rw [originalMemory, candidateMemory]
    constructor
    · unfold ReturnSlotOffsetInventory.exactWordsFit
      rw [targetWords]
      exact sourceWordsAfter.1
    · simpa [ReturnSlotOffsetInventory.exactWordsHold, targetWords] using
        sourceWordsAfter.2
  have framesAvoidProp : ∀ selected, selected ∈ frame :: frames ->
      selected.writesAvoid originalWrites candidateWrites := by
    simp only [List.all_eq_true] at framesAvoid
    intro selected member
    exact selected.writesAvoid_of_checked originalWrites candidateWrites
      (framesAvoid selected member)
  have framesWritten := RelationalRuntimeCallFramesHold.afterWrites context
    beforeOriginal beforeCandidate (frame :: frames)
    (continuation :: continuations) originalWrites candidateWrites
    stackFacts.2.2.2.1 framesAvoidProp
  have framesAfter := RelationalRuntimeCallFramesHold.of_memory_eq context
    { beforeOriginal with memory :=
        applyConcreteWrites beforeOriginal.memory originalWrites }
    { beforeCandidate with memory :=
        applyConcreteWrites beforeCandidate.memory candidateWrites }
    afterOriginal afterCandidate (frame :: frames)
    (continuation :: continuations) framesWritten originalMemory candidateMemory
  have linksWritten := RelationalRuntimeCallFrameLinksHold.afterWritesChecked
    beforeOriginal.memory beforeCandidate.memory (frame :: frames) links
    originalWrites candidateWrites stackFacts.2.2.2.2 linksAvoid
  have linksAfter := RelationalRuntimeCallFrameLinksHold.of_memory_eq
    (applyConcreteWrites beforeOriginal.memory originalWrites)
    (applyConcreteWrites beforeCandidate.memory candidateWrites)
    afterOriginal.memory afterCandidate.memory (frame :: frames) links
    linksWritten originalMemory candidateMemory
  exact ⟨targetChecked, targetHolds, targetWordsAfter, framesAfter, linksAfter⟩

/-- An ordinary affine frame transition whose decoded behavior performs an
exact, nonempty paired write list. -/
structure ReturnSlotAffineLinkedMemoryTransitionBinding where
  sourceShape : ReturnSlotAffineInventoryShape
  targetShape : ReturnSlotAffineInventoryShape
  claim : ReturnSlotAffineFrameSemanticTransitionClaim
  writes : PairedDecodedWritesClaim
  stackOffsets : List PairedStackRelativeWordWrite
deriving Repr, DecidableEq

def ReturnSlotAffineLinkedMemoryTransitionBinding.checked
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  match binding.sourceShape.locations, binding.targetShape.locations with
  | .affineFamily sourceStateIndex, .affineFamily targetStateIndex =>
      profile.checked graph && binding.claim.checked context graph &&
        binding.claim.physicalStateOnly == false &&
        binding.writes.checked binding.claim.originalNormalized
          binding.claim.candidateNormalized &&
        binding.writes.stackOffsetsChecked binding.stackOffsets &&
        binding.sourceShape.exactWords == binding.targetShape.exactWords &&
        binding.sourceShape.preservedImports ==
          binding.targetShape.preservedImports &&
        binding.sourceShape.preservedRelations ==
          binding.targetShape.preservedRelations &&
        binding.sourceShape.factsPreservedAcross context
          binding.claim.originalNormalized binding.claim.candidateNormalized &&
        binding.sourceShape.checked profile
          binding.claim.transition.source.nodeId &&
        binding.targetShape.checked profile
          binding.claim.transition.target.nodeId &&
        profile.states[sourceStateIndex]? == some binding.claim.transition.source &&
        profile.states[targetStateIndex]? == some binding.claim.transition.target
  | _, _ => false

theorem ReturnSlotAffineLinkedMemoryTransitionBinding.facts_checked_of_checked
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context profile graph = true) :
    binding.sourceShape.factsPreservedAcross context
      binding.claim.originalNormalized binding.claim.candidateNormalized = true := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations, Bool.and_eq_true, beq_iff_eq]
            at checked
          rcases checked with ⟨checked, _targetStateFound⟩
          rcases checked with ⟨checked, _sourceStateFound⟩
          rcases checked with ⟨checked, _targetShapeChecked⟩
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          exact checked.2

theorem ReturnSlotAffineLinkedMemoryTransitionBinding.stackOffsets_checked_of_checked
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context profile graph = true) :
    binding.writes.stackOffsetsChecked binding.stackOffsets = true := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations, Bool.and_eq_true, beq_iff_eq]
            at checked
          rcases checked with ⟨checked, _targetStateFound⟩
          rcases checked with ⟨checked, _sourceStateFound⟩
          rcases checked with ⟨checked, _targetShapeChecked⟩
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          rcases checked with ⟨checked, _factsPreserved⟩
          rcases checked with ⟨checked, _relationsExact⟩
          rcases checked with ⟨checked, _importsExact⟩
          rcases checked with ⟨checked, _wordsExact⟩
          exact checked.2

theorem ReturnSlotAffineLinkedMemoryTransitionBinding.payload_eq_of_checked
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context profile graph = true) :
    binding.sourceShape.exactWords = binding.targetShape.exactWords ∧
      binding.sourceShape.preservedImports =
        binding.targetShape.preservedImports ∧
      binding.sourceShape.preservedRelations =
        binding.targetShape.preservedRelations := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations, Bool.and_eq_true, beq_iff_eq]
            at checked
          rcases checked with ⟨checked, _targetStateFound⟩
          rcases checked with ⟨checked, _sourceStateFound⟩
          rcases checked with ⟨checked, _targetShapeChecked⟩
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          rcases checked with ⟨checked, _factsPreserved⟩
          rcases checked with ⟨checked, relationsExact⟩
          rcases checked with ⟨checked, importsExact⟩
          exact ⟨checked.2, importsExact, relationsExact⟩

/-- Transfer the concrete affine member and all register facts.  Memory is
left to the paired linked-footprint theorem below. -/
theorem ReturnSlotAffineLinkedMemoryTransitionBinding.transferActive
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context profile graph = true)
    (sourceRealizes : binding.sourceShape.Realizes profile
      binding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links) :
    ∃ targetInventory,
      binding.targetShape.Realizes profile
          binding.claim.transition.target.nodeId targetInventory ∧
        targetInventory.checked = true ∧
        targetInventory.holds frame
          (binding.claim.originalNormalized.eval originalState).registers
          (binding.claim.candidateNormalized.eval candidateState).registers ∧
        targetInventory.exactWords = sourceInventory.exactWords ∧
        binding.writes.ConcreteWritesExact
          binding.claim.originalNormalized binding.claim.candidateNormalized
          originalState candidateState := by
  cases sourceLocations : binding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
        sourceLocations] at checked
  | affineFamily sourceStateIndex =>
      cases targetLocations : binding.targetShape.locations with
      | exact locations =>
          simp [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
      | affineFamily targetStateIndex =>
          simp only [ReturnSlotAffineLinkedMemoryTransitionBinding.checked,
            sourceLocations, targetLocations] at checked
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, targetStateFoundChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, sourceStateFoundChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, targetShapeChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _sourceShapeChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _payloadFactsPreserved⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _payloadRelations⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _payloadImports⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, payloadWordsChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, _stackOffsetsChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, writesChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨checked, ordinaryChecked⟩
          rw [Bool.and_eq_true] at checked
          rcases checked with ⟨_profileChecked, claimChecked⟩
          have ordinary : binding.claim.physicalStateOnly = false := by
            simpa only [beq_iff_eq] using ordinaryChecked
          have payloadWords : binding.sourceShape.exactWords =
              binding.targetShape.exactWords := by
            simpa only [beq_iff_eq] using payloadWordsChecked
          have sourceStateFound : profile.states[sourceStateIndex]? =
              some binding.claim.transition.source := by
            simpa only [beq_iff_eq] using sourceStateFoundChecked
          have targetStateFound : profile.states[targetStateIndex]? =
              some binding.claim.transition.target := by
            simpa only [beq_iff_eq] using targetStateFoundChecked
          simp only [ReturnSlotAffineInventoryShape.Realizes,
            ReturnSlotAffineInventoryShape.PayloadMatches,
            sourceLocations] at sourceRealizes
          rcases sourceRealizes with
            ⟨⟨sourceWords, _sourceImports, _sourceRelations⟩,
              sourceState, sourceCoefficient, sourceLocation,
              profileSourceFound, _sourceNodeMatches, sourceContainsAt,
              sourceLocationsExact⟩
          have sourceStateExact :
              sourceState = binding.claim.transition.source := by
            rw [sourceStateFound] at profileSourceFound
            exact (Option.some.inj profileSourceFound).symm
          have sourceContains :
              binding.claim.transition.source.family.contains sourceLocation := by
            rw [← sourceStateExact]
            exact sourceContainsAt.contains
          have stackFacts := stackHolds
          simp only [RelationalLinkedRuntimeCallStackHolds] at stackFacts
          have sourceLocationHolds := stackFacts.2.1.2 sourceLocation (by
            rw [sourceLocationsExact]
            simp)
          obtain ⟨targetLocation, offsetsApplied⟩ :=
            binding.claim.apply_exists_of_checked context graph sourceLocation
              claimChecked sourceContains
          have transferred := binding.claim.holdsRuntimeFrame_of_checked
            context graph sourceLocation targetLocation (.internal frame)
            originalState candidateState ordinary claimChecked sourceContains
            offsetsApplied (by
              simpa [ReturnSlotOffsetPair.holdsRuntimeFrame_internal] using
                sourceLocationHolds)
          rcases transferred.1 with
            ⟨targetOriginalRegister, targetCandidateRegister, targetCoefficient,
              targetOriginalOffset, targetCandidateOffset⟩
          have targetContainsAt :
              binding.claim.transition.target.family.ContainsAt
                targetCoefficient targetLocation :=
            ⟨targetOriginalRegister, targetCandidateRegister,
              targetOriginalOffset, targetCandidateOffset⟩
          let targetInventory :=
            binding.targetShape.toInventory [targetLocation]
          have targetRealizes : binding.targetShape.Realizes profile
              binding.claim.transition.target.nodeId targetInventory := by
            simp only [ReturnSlotAffineInventoryShape.Realizes,
              ReturnSlotAffineInventoryShape.PayloadMatches, targetLocations]
            refine ⟨?_, binding.claim.transition.target, targetCoefficient,
              targetLocation, targetStateFound, rfl, targetContainsAt, ?_⟩
            · simp [targetInventory,
                ReturnSlotAffineInventoryShape.toInventory]
            · simp [targetInventory,
                ReturnSlotAffineInventoryShape.toInventory]
          have targetChecked : targetInventory.checked = true :=
            binding.targetShape.realizes_checked profile
              binding.claim.transition.target.nodeId targetInventory
              targetShapeChecked targetRealizes
          have targetLocationHolds : targetLocation.holds frame
              (binding.claim.originalNormalized.eval originalState).registers
              (binding.claim.candidateNormalized.eval candidateState).registers := by
            simpa [ReturnSlotOffsetPair.holdsRuntimeFrame_internal] using
              transferred.2
          have targetHolds : targetInventory.holds frame
              (binding.claim.originalNormalized.eval originalState).registers
              (binding.claim.candidateNormalized.eval candidateState).registers := by
            refine ⟨by simp [targetInventory,
              ReturnSlotAffineInventoryShape.toInventory], ?_⟩
            intro location member
            have locationExact : location = targetLocation := by
              simpa [targetInventory,
                ReturnSlotAffineInventoryShape.toInventory] using member
            subst location
            exact targetLocationHolds
          have inventoryWords :
              targetInventory.exactWords = sourceInventory.exactWords := by
            calc
              targetInventory.exactWords = binding.targetShape.exactWords := rfl
              _ = binding.sourceShape.exactWords := payloadWords.symm
              _ = sourceInventory.exactWords := sourceWords.symm
          exact ⟨targetInventory, targetRealizes, targetChecked, targetHolds,
            inventoryWords,
            binding.writes.concreteWritesExact_of_checked
              binding.claim.originalNormalized binding.claim.candidateNormalized
              originalState candidateState writesChecked⟩

/-- Execute one checked affine transition with exact paired writes while
preserving an arbitrary dormant frame/link tail. -/
theorem ReturnSlotAffineLinkedMemoryTransitionBinding.afterPairedWritesNested
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context profile graph = true)
    (sourceRealizes : binding.sourceShape.Realizes profile
      binding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (footprintChecked : relationalLinkedStackWritesAvoidChecked frame frames
      sourceInventory links
      (binding.writes.originalConcreteWrites originalState)
      (binding.writes.candidateConcreteWrites candidateState) = true) :
    ∃ targetInventory,
      binding.targetShape.Realizes profile
          binding.claim.transition.target.nodeId targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds context
          ((binding.claim.originalNormalized.eval originalState).nextMachineState
            originalState)
          ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
            candidateState)
          (frame :: frames) (continuation :: continuations)
          (some targetInventory) links := by
  obtain ⟨targetInventory, targetRealizes, targetChecked, targetHolds,
      targetWords, concreteExact⟩ :=
    binding.transferActive context profile graph originalState candidateState
      frame frames continuation continuations links sourceInventory checked
      sourceRealizes stackHolds
  let afterOriginal :=
    (binding.claim.originalNormalized.eval originalState).nextMachineState
      originalState
  let afterCandidate :=
    (binding.claim.candidateNormalized.eval candidateState).nextMachineState
      candidateState
  have originalMemory : afterOriginal.memory =
      applyConcreteWrites originalState.memory
        (binding.writes.originalConcreteWrites originalState) := by
    change applyConcreteWrites originalState.memory
        (evalNormalizedWrites originalState
          binding.claim.originalNormalized.writes) = _
    rw [concreteExact.1]
  have candidateMemory : afterCandidate.memory =
      applyConcreteWrites candidateState.memory
        (binding.writes.candidateConcreteWrites candidateState) := by
    change applyConcreteWrites candidateState.memory
        (evalNormalizedWrites candidateState
          binding.claim.candidateNormalized.writes) = _
    rw [concreteExact.2]
  have targetStack := RelationalLinkedRuntimeCallStackHolds.afterPairedWrites
    context originalState candidateState afterOriginal afterCandidate frame frames
    continuation continuations links sourceInventory targetInventory
    (binding.writes.originalConcreteWrites originalState)
    (binding.writes.candidateConcreteWrites candidateState)
    stackHolds targetChecked
    (by simpa [afterOriginal, afterCandidate] using targetHolds)
    targetWords footprintChecked originalMemory candidateMemory
  exact ⟨targetInventory, targetRealizes, targetStack⟩

theorem ReturnSlotAffineLinkedMemoryTransitionBinding.afterPairedWritesNestedWithFacts
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (context : StaticProofContext) (profile : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context profile graph = true)
    (sourceRealizes : binding.sourceShape.Realizes profile
      binding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some sourceInventory) originalState.registers candidateState.registers)
    (footprintChecked : relationalLinkedStackWritesAvoidChecked frame frames
      sourceInventory links
      (binding.writes.originalConcreteWrites originalState)
      (binding.writes.candidateConcreteWrites candidateState) = true) :
    ∃ targetInventory,
      binding.targetShape.Realizes profile
          binding.claim.transition.target.nodeId targetInventory ∧
        RelationalLinkedRuntimeCallStackHolds context
          ((binding.claim.originalNormalized.eval originalState).nextMachineState
            originalState)
          ((binding.claim.candidateNormalized.eval candidateState).nextMachineState
            candidateState)
          (frame :: frames) (continuation :: continuations)
          (some targetInventory) links ∧
        RelationalLinkedRuntimeCallFactsHold context world (some targetInventory)
          (binding.claim.originalNormalized.eval originalState).registers
          (binding.claim.candidateNormalized.eval candidateState).registers := by
  obtain ⟨targetInventory, targetRealizes, targetStack⟩ :=
    binding.afterPairedWritesNested context profile graph originalState
      candidateState frame frames continuation continuations links sourceInventory
      checked sourceRealizes stackHolds footprintChecked
  have payloadFacts := binding.facts_checked_of_checked context profile graph checked
  have payloadExact := binding.payload_eq_of_checked context profile graph checked
  have sourcePayload := binding.sourceShape.payload_eq_of_realizes profile
    binding.claim.transition.source.nodeId sourceInventory sourceRealizes
  have targetPayload := binding.targetShape.payload_eq_of_realizes profile
    binding.claim.transition.target.nodeId targetInventory targetRealizes
  have sourceStackFacts := stackHolds
  simp only [RelationalLinkedRuntimeCallStackHolds] at sourceStackFacts
  simp only [ReturnSlotAffineInventoryShape.factsPreservedAcross,
    Bool.and_eq_true] at payloadFacts
  rcases payloadFacts with
    ⟨⟨⟨importsPreserved, relationsUnambiguous⟩, relationsStatic⟩,
      relationsPreserved⟩
  have sourceImportsAcross : sourceInventory.preservesImportsAcross
      binding.claim.originalNormalized binding.claim.candidateNormalized = true := by
    simp only [ReturnSlotOffsetInventory.preservesImportsAcross,
      Bool.and_eq_true]
    refine ⟨sourceStackFacts.1, ?_⟩
    simpa only [sourcePayload.2.1] using importsPreserved
  have sourceRelationsAcross : sourceInventory.preservesRelationsAcross context
      binding.claim.originalNormalized binding.claim.candidateNormalized = true := by
    simp only [ReturnSlotOffsetInventory.preservesRelationsAcross,
      ReturnSlotOffsetInventory.preservedRelationsChecked, Bool.and_eq_true]
    refine ⟨⟨⟨sourceStackFacts.1, ?_⟩, ?_⟩, ?_⟩
    · unfold ReturnSlotOffsetInventory.preservedRelationsUnambiguous at relationsUnambiguous
      unfold ReturnSlotOffsetInventory.preservedRelationsUnambiguous
      simpa only [sourcePayload.2.2,
        ReturnSlotAffineInventoryShape.toInventory] using relationsUnambiguous
    · rw [sourcePayload.2.2]
      exact relationsStatic
    · rw [sourcePayload.2.2]
      exact relationsPreserved
  have importsAfter := sourceInventory.preservedImportsHold_after_of_checked
    world binding.claim.originalNormalized binding.claim.candidateNormalized
    originalState candidateState sourceImportsAcross factsHold.1
  have relationsAfter := sourceInventory.preservedRelationsHold_after_of_checked
    context world binding.claim.originalNormalized binding.claim.candidateNormalized
    originalState candidateState sourceRelationsAcross factsHold.2
  have targetImports : targetInventory.preservedImports =
      sourceInventory.preservedImports := by
    calc
      targetInventory.preservedImports = binding.targetShape.preservedImports :=
        targetPayload.2.1
      _ = binding.sourceShape.preservedImports := payloadExact.2.1.symm
      _ = sourceInventory.preservedImports := sourcePayload.2.1.symm
  have targetRelations : targetInventory.preservedRelations =
      sourceInventory.preservedRelations := by
    calc
      targetInventory.preservedRelations = binding.targetShape.preservedRelations :=
        targetPayload.2.2
      _ = binding.sourceShape.preservedRelations := payloadExact.2.2.symm
      _ = sourceInventory.preservedRelations := sourcePayload.2.2.symm
  refine ⟨targetInventory, targetRealizes, targetStack, ?_⟩
  simp only [RelationalLinkedRuntimeCallFactsHold]
  constructor
  · unfold ReturnSlotOffsetInventory.preservedImportsHold at importsAfter ⊢
    rw [targetImports]
    exact importsAfter
  · unfold ReturnSlotOffsetInventory.preservedRelationsHold at relationsAfter ⊢
    rw [targetRelations]
    exact relationsAfter

def StackRelativeWordOffset.insideWindowChecked
    (offset : StackRelativeWordOffset) (window : StackWindowPair) : Bool :=
  match offset with
  | .above amount => amount + 4 <= window.bytesAbove
  | .below amount => amount <= window.bytesBelow &&
      4 <= amount + window.bytesAbove

theorem StackRelativeWordOffset.addressNats_of_window
    (offset : StackRelativeWordOffset)
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (inside : offset.insideWindowChecked window = true) :
    (offset.address original).toNat = (match offset with
        | .above amount => original.esp.toNat + amount
        | .below amount => original.esp.toNat - amount) ∧
      (offset.address candidate).toNat = (match offset with
        | .above amount => candidate.esp.toNat + amount
        | .below amount => candidate.esp.toNat - amount) := by
  cases rangeResult : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none => simp [StackWindowPair.holds, rangeResult] at windowHolds
  | some range =>
      simp only [StackWindowPair.holds, rangeResult, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, candidateLower⟩,
          candidateUpper⟩, _pairedOffset⟩, _alignment⟩
      rw [windowRegisters.1] at originalLower originalUpper
      rw [windowRegisters.2] at candidateLower candidateUpper
      simp only [Registers.get] at originalLower originalUpper candidateLower candidateUpper
      have validRows := rangesValid
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at validRows
      have rangeMember := List.mem_of_find?_eq_some rangeResult
      have rangeValid := validRows.1.1.2 range rangeMember
      simp only [DynamicAddressRangePair.disjointFromImages, Bool.and_eq_true,
        Bool.or_eq_true, decide_eq_true_eq] at rangeValid
      rcases rangeValid with
        ⟨⟨⟨disjointFromImages, _originalAligned⟩,
          _candidateAligned⟩, _sizeAligned⟩
      rcases disjointFromImages with
        ⟨⟨⟨⟨_nonempty, originalNoWrap⟩, candidateNoWrap⟩,
          _originalDisjoint⟩, _candidateDisjoint⟩
      revert inside
      cases offset with
      | above amount =>
          intro inside
          simp only [StackRelativeWordOffset.insideWindowChecked,
            decide_eq_true_eq] at inside
          have amountSmall : amount < 2 ^ 32 := by omega
          have originalBefore : original.esp.toNat + amount < 2 ^ 32 := by
            omega
          have candidateBefore : candidate.esp.toNat + amount < 2 ^ 32 := by
            omega
          constructor <;>
            simp [StackRelativeWordOffset.address, StackRelativeWordOffset.word,
              BitVec.toNat_add, BitVec.toNat_ofNat,
              Nat.mod_eq_of_lt amountSmall,
              Nat.mod_eq_of_lt originalBefore,
              Nat.mod_eq_of_lt candidateBefore]
      | below amount =>
          intro inside
          simp only [StackRelativeWordOffset.insideWindowChecked,
            Bool.and_eq_true, decide_eq_true_eq] at inside
          have amountSmall : amount < 2 ^ 32 := by omega
          have originalEnough : amount <= original.esp.toNat := by omega
          have candidateEnough : amount <= candidate.esp.toNat := by omega
          constructor
          · simp only [StackRelativeWordOffset.address,
              StackRelativeWordOffset.word]
            rw [show original.esp + (0 - BitVec.ofNat 32 amount) =
                original.esp - BitVec.ofNat 32 amount by
              simp [BitVec.sub_eq_add_neg]]
            rw [BitVec.toNat_sub_of_le]
            · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
            · rw [BitVec.le_def]
              simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]

          · simp only [StackRelativeWordOffset.address,
              StackRelativeWordOffset.word]
            rw [show candidate.esp + (0 - BitVec.ofNat 32 amount) =
                candidate.esp - BitVec.ofNat 32 amount by
              simp [BitVec.sub_eq_add_neg]]
            rw [BitVec.toNat_sub_of_le]
            · simp [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]
            · rw [BitVec.le_def]
              simpa [BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall]

def StackRelativeWordOffset.endsBeforeOuterChecked
    (offset : StackRelativeWordOffset) (base : Word) (gap : Nat) : Bool :=
  base.toNat + gap < 2 ^ 32 &&
    match offset with
    | .above amount => amount + 4 <= base.toNat + gap
    | .below amount => 4 <= amount + base.toNat + gap

theorem StackRelativeWordOffset.addressEndBeforeOuter_of_natFacts
    (offset : StackRelativeWordOffset) (registers : PureState)
    (base : Word) (gap : Nat) (outerAddress : Word)
    (addressNat : (offset.address registers).toNat = match offset with
      | .above amount => registers.esp.toNat + amount
      | .below amount => registers.esp.toNat - amount)
    (belowEnough : match offset with
      | .above _ => True
      | .below amount => amount <= registers.esp.toNat)
    (endsBefore : offset.endsBeforeOuterChecked base gap = true)
    (outerNat : registers.esp.toNat + base.toNat + gap = outerAddress.toNat) :
    (offset.address registers).toNat + 4 <= outerAddress.toNat := by
  cases offset with
  | above amount =>
      simp only [StackRelativeWordOffset.endsBeforeOuterChecked,
        Bool.and_eq_true, decide_eq_true_eq] at endsBefore
      simp only at belowEnough
      simp only at addressNat
      omega
  | below amount =>
      simp only [StackRelativeWordOffset.endsBeforeOuterChecked,
        Bool.and_eq_true, decide_eq_true_eq] at endsBefore
      simp only at belowEnough
      simp only at addressNat
      omega

theorem StackRelativeWordOffset.addressEndBeforeOuter_of_window
    (offset : StackRelativeWordOffset)
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (base : Word) (gap : Nat)
    (originalOuter candidateOuter : Word)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (inside : offset.insideWindowChecked window = true)
    (endsBefore : offset.endsBeforeOuterChecked base gap = true)
    (originalOuterNat : original.esp.toNat + base.toNat + gap =
      originalOuter.toNat)
    (candidateOuterNat : candidate.esp.toNat + base.toNat + gap =
      candidateOuter.toNat) :
    (offset.address original).toNat + 4 <= originalOuter.toNat ∧
      (offset.address candidate).toNat + 4 <= candidateOuter.toNat := by
  cases offset with
  | above amount =>
      have addressNats := (StackRelativeWordOffset.above amount).addressNats_of_window
        context world window original candidate rangesValid windowHolds
        windowRegisters inside
      exact ⟨(StackRelativeWordOffset.above amount).addressEndBeforeOuter_of_natFacts
          original base gap originalOuter addressNats.1 trivial endsBefore
          originalOuterNat,
        (StackRelativeWordOffset.above amount).addressEndBeforeOuter_of_natFacts
          candidate base gap candidateOuter addressNats.2 trivial endsBefore
          candidateOuterNat⟩
  | below amount =>
      have addressNats := (StackRelativeWordOffset.below amount).addressNats_of_window
        context world window original candidate rangesValid windowHolds
        windowRegisters inside
      have enough := window.bytesBelow_le_registers_of_holds world original
        candidate windowHolds
      rw [windowRegisters.1, windowRegisters.2] at enough
      simp only [Registers.get] at enough
      simp only [StackRelativeWordOffset.insideWindowChecked, Bool.and_eq_true,
        decide_eq_true_eq] at inside
      exact ⟨(StackRelativeWordOffset.below amount).addressEndBeforeOuter_of_natFacts
          original base gap originalOuter addressNats.1
          (Nat.le_trans inside.1 enough.1) endsBefore originalOuterNat,
        (StackRelativeWordOffset.below amount).addressEndBeforeOuter_of_natFacts
          candidate base gap candidateOuter addressNats.2
          (Nat.le_trans inside.1 enough.2) endsBefore candidateOuterNat⟩

theorem StackRelativeWordOffset.originalAddressEndBeforeOuter_of_window
    (offset : StackRelativeWordOffset)
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (base : Word) (gap : Nat) (outer : Word)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (inside : offset.insideWindowChecked window = true)
    (endsBefore : offset.endsBeforeOuterChecked base gap = true)
    (outerNat : original.esp.toNat + base.toNat + gap = outer.toNat) :
    (offset.address original).toNat + 4 <= outer.toNat := by
  cases offset with
  | above amount =>
      have addressNat :=
        ((StackRelativeWordOffset.above amount).addressNats_of_window context
          world window original candidate rangesValid windowHolds windowRegisters
          inside).1
      exact (StackRelativeWordOffset.above amount).addressEndBeforeOuter_of_natFacts
        original base gap outer addressNat trivial endsBefore outerNat
  | below amount =>
      have addressNat :=
        ((StackRelativeWordOffset.below amount).addressNats_of_window context
          world window original candidate rangesValid windowHolds windowRegisters
          inside).1
      have enough := window.bytesBelow_le_registers_of_holds world original
        candidate windowHolds
      rw [windowRegisters.1] at enough
      simp only [Registers.get] at enough
      simp only [StackRelativeWordOffset.insideWindowChecked, Bool.and_eq_true,
        decide_eq_true_eq] at inside
      exact (StackRelativeWordOffset.below amount).addressEndBeforeOuter_of_natFacts
        original base gap outer addressNat (Nat.le_trans inside.1 enough.1)
        endsBefore outerNat

theorem StackRelativeWordOffset.candidateAddressEndBeforeOuter_of_window
    (offset : StackRelativeWordOffset)
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair) (original candidate : PureState)
    (base : Word) (gap : Nat) (outer : Word)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world original candidate = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (inside : offset.insideWindowChecked window = true)
    (endsBefore : offset.endsBeforeOuterChecked base gap = true)
    (outerNat : candidate.esp.toNat + base.toNat + gap = outer.toNat) :
    (offset.address candidate).toNat + 4 <= outer.toNat := by
  cases offset with
  | above amount =>
      have addressNat :=
        ((StackRelativeWordOffset.above amount).addressNats_of_window context
          world window original candidate rangesValid windowHolds windowRegisters
          inside).2
      exact (StackRelativeWordOffset.above amount).addressEndBeforeOuter_of_natFacts
        candidate base gap outer addressNat trivial endsBefore outerNat
  | below amount =>
      have addressNat :=
        ((StackRelativeWordOffset.below amount).addressNats_of_window context
          world window original candidate rangesValid windowHolds windowRegisters
          inside).2
      have enough := window.bytesBelow_le_registers_of_holds world original
        candidate windowHolds
      rw [windowRegisters.2] at enough
      simp only [Registers.get] at enough
      simp only [StackRelativeWordOffset.insideWindowChecked, Bool.and_eq_true,
        decide_eq_true_eq] at inside
      exact (StackRelativeWordOffset.below amount).addressEndBeforeOuter_of_natFacts
        candidate base gap outer addressNat (Nat.le_trans inside.1 enough.2)
        endsBefore outerNat

def PairedStackRelativeWordWrite.insideWindowChecked
    (write : PairedStackRelativeWordWrite) (window : StackWindowPair) : Bool :=
  write.original.offset.insideWindowChecked window &&
    write.candidate.offset.insideWindowChecked window

def PairedStackRelativeWordWrite.avoidsActiveChecked
    (write : PairedStackRelativeWordWrite) (family : ReturnSlotAffineFamily) : Bool :=
  wordOffsetsDisjoint family.originalBase write.original.offset.word &&
    wordOffsetsDisjoint family.candidateBase write.candidate.offset.word

def PairedStackRelativeWordWrite.avoidsExactWordChecked
    (write : PairedStackRelativeWordWrite) (family : ReturnSlotAffineFamily)
    (word : ReturnSlotExactWordPair) : Bool :=
  wordOffsetsDisjoint
      (family.originalBase + BitVec.ofNat 32 word.originalOffset)
      write.original.offset.word &&
    wordOffsetsDisjoint
      (family.candidateBase + BitVec.ofNat 32 word.candidateOffset)
      write.candidate.offset.word

def PairedStackRelativeWordWrite.beforeLinkShapeChecked
    (write : PairedStackRelativeWordWrite) (family : ReturnSlotAffineFamily)
    (shape : RelationalRuntimeCallFrameAffineLinkShape) : Bool :=
    write.original.offset.endsBeforeOuterChecked family.originalBase
      shape.originalGap &&
    write.candidate.offset.endsBeforeOuterChecked family.candidateBase
      shape.candidateGap

theorem PairedDecodedWritesClaim.concreteWritesBeforeOuter_of_stackOffsetsChecked
    (claim : PairedDecodedWritesClaim)
    (offsets : List PairedStackRelativeWordWrite)
    (context : StaticProofContext) (world : RelationalWorld)
    (window : StackWindowPair)
    (originalState candidateState : MachineState)
    (family : ReturnSlotAffineFamily)
    (shape : RelationalRuntimeCallFrameAffineLinkShape)
    (originalOuter candidateOuter : Word)
    (checked : claim.stackOffsetsChecked offsets = true)
    (rangesValid : world.stackRangesValid context = true)
    (windowHolds : window.holds world originalState.registers
      candidateState.registers = true)
    (windowRegisters : window.originalRegister = .esp ∧
      window.candidateRegister = .esp)
    (insideRows : (offsets.all fun write =>
      write.insideWindowChecked window) = true)
    (beforeRows : (offsets.all fun write =>
      write.beforeLinkShapeChecked family shape) = true)
    (originalOuterNat : originalState.registers.esp.toNat +
      family.originalBase.toNat + shape.originalGap = originalOuter.toNat)
    (candidateOuterNat : candidateState.registers.esp.toNat +
      family.candidateBase.toNat + shape.candidateGap = candidateOuter.toNat) :
    concreteWritesBeforeChecked originalOuter
        (claim.originalConcreteWrites originalState) = true ∧
      concreteWritesBeforeChecked candidateOuter
        (claim.candidateConcreteWrites candidateState) = true := by
  cases claim with
  | mk writes =>
      induction writes generalizing offsets with
      | nil =>
          cases offsets <;>
            simp [PairedDecodedWritesClaim.originalConcreteWrites,
              PairedDecodedWritesClaim.candidateConcreteWrites,
              concreteWritesBeforeChecked]
      | cons write writes induction =>
          cases offsets with
          | nil =>
              simp [PairedDecodedWritesClaim.stackOffsetsChecked] at checked
          | cons offset offsets =>
              simp only [PairedDecodedWritesClaim.stackOffsetsChecked,
                List.length_cons, List.zip_cons_cons, List.all_cons,
                Bool.and_eq_true, beq_iff_eq] at checked
              simp only [List.all_cons, Bool.and_eq_true] at insideRows beforeRows
              have tailChecked :
                  PairedDecodedWritesClaim.stackOffsetsChecked
                    ({ writes := writes } : PairedDecodedWritesClaim)
                    offsets = true := by
                change (writes.length == offsets.length &&
                  (writes.zip offsets).all fun row =>
                    row.1.stackOffsetChecked row.2) = true
                simp only [Bool.and_eq_true, beq_iff_eq]
                exact ⟨Nat.succ.inj checked.1, checked.2.2⟩
              have tail := induction offsets insideRows.2 beforeRows.2 tailChecked
              have addresses := write.concreteAddresses_of_stackOffsetChecked
                offset originalState candidateState checked.2.1
              simp only [PairedStackRelativeWordWrite.insideWindowChecked,
                PairedStackRelativeWordWrite.beforeLinkShapeChecked,
                Bool.and_eq_true] at insideRows beforeRows
              have originalBefore :=
                offset.original.offset.originalAddressEndBeforeOuter_of_window
                  context world window originalState.registers
                  candidateState.registers family.originalBase shape.originalGap
                  originalOuter rangesValid windowHolds windowRegisters
                  insideRows.1.1 beforeRows.1.1 originalOuterNat
              have candidateBefore :=
                offset.candidate.offset.candidateAddressEndBeforeOuter_of_window
                  context world window originalState.registers
                  candidateState.registers family.candidateBase shape.candidateGap
                  candidateOuter rangesValid windowHolds windowRegisters
                  insideRows.1.2 beforeRows.1.2 candidateOuterNat
              simp only [PairedDecodedWritesClaim.originalConcreteWrites,
                PairedDecodedWritesClaim.candidateConcreteWrites, List.map_cons,
                concreteWritesBeforeChecked, List.all_cons, Bool.and_eq_true,
                decide_eq_true_eq]
              exact ⟨⟨by simpa [addresses.1] using originalBefore, tail.1⟩,
                ⟨by simpa [addresses.2] using candidateBefore, tail.2⟩⟩

/-- Static, executable footprint certificate for arbitrary linked stack depth.
The selected stack window rules out modular wraparound, exact modular checks
protect the active inventory, and every permitted first-link shape supplies a
barrier before the dormant stack. -/
def ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked
    (binding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile) : Bool :=
  match binding.sourceShape.locations with
  | .exact _ => false
  | .affineFamily sourceStateIndex =>
      match affine.states[sourceStateIndex]? with
      | none => false
      | some state =>
          state.nodeId == binding.claim.transition.source.nodeId &&
            state.family.originalRegister == .esp &&
            state.family.candidateRegister == .esp &&
            state.family.translationStride == 2 ^ 32 &&
            binding.claim.region.stackWindows.any fun window =>
              window.originalRegister == .esp &&
                window.candidateRegister == .esp &&
                state.family.originalBase.toNat + 4 <= window.bytesAbove &&
                state.family.candidateBase.toNat + 4 <= window.bytesAbove &&
                binding.stackOffsets.all fun write =>
                  write.insideWindowChecked window &&
                    write.avoidsActiveChecked state.family &&
                    (binding.sourceShape.exactWords.all fun word =>
                      write.avoidsExactWordChecked state.family word) &&
                    (control.linkShapes.all fun shape =>
                      write.beforeLinkShapeChecked state.family shape)

theorem ReturnSlotAffineFamily.containsAt_offsets_eq_base_of_full_stride
    (family : ReturnSlotAffineFamily) (coefficient : Word)
    (location : ReturnSlotOffsetPair)
    (contains : family.ContainsAt coefficient location)
    (fullStride : family.translationStride = 2 ^ 32) :
    location.originalRegister = family.originalRegister ∧
      location.candidateRegister = family.candidateRegister ∧
      location.originalOffset = family.originalBase ∧
      location.candidateOffset = family.candidateBase := by
  have strideWord : BitVec.ofNat 32 family.translationStride = 0 := by
    rw [fullStride]
    decide
  rcases contains with
    ⟨originalRegister, candidateRegister, originalOffset, candidateOffset⟩
  exact ⟨originalRegister, candidateRegister,
    by simpa [strideWord] using originalOffset,
    by simpa [strideWord] using candidateOffset⟩

/-- Finite ordinary-control binding for a paired-memory affine transition. -/
structure AffineLinkedOrdinaryMemoryTransitionBinding where
  sourceControlStateIndex : Nat
  targetControlStateIndex : Nat
  edgeId : Nat
  continuationTargetId : Nat
  frameBinding : ReturnSlotAffineLinkedMemoryTransitionBinding
deriving Repr, DecidableEq

def AffineLinkedOrdinaryMemoryTransitionBinding.checked
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) : Bool :=
  control.checked affine graph &&
    binding.frameBinding.checked context affine graph &&
    binding.frameBinding.stackFootprintChecked control affine &&
    binding.edgeId == binding.frameBinding.claim.transition.edgeId &&
    match control.states[binding.sourceControlStateIndex]?,
        control.states[binding.targetControlStateIndex]? with
    | some source, some target =>
        source.nodeId == binding.frameBinding.claim.transition.source.nodeId &&
          target.nodeId == binding.frameBinding.claim.transition.target.nodeId &&
          source.continuation == some binding.continuationTargetId &&
          target.continuation == some binding.continuationTargetId &&
          source.activeShape == some binding.frameBinding.sourceShape &&
          target.activeShape == some binding.frameBinding.targetShape &&
          source.minimumDepth == 1 && target.minimumDepth == 1
    | _, _ => false

theorem AffineLinkedOrdinaryMemoryTransitionBinding.frame_checked_of_checked
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context control affine graph = true) :
    binding.frameBinding.checked context affine graph = true := by
  simp only [AffineLinkedOrdinaryMemoryTransitionBinding.checked,
    Bool.and_eq_true] at checked
  exact checked.1.1.1.2

theorem AffineLinkedOrdinaryMemoryTransitionBinding.stackFootprint_checked_of_checked
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (checked : binding.checked context control affine graph = true) :
    binding.frameBinding.stackFootprintChecked control affine = true := by
  simp only [AffineLinkedOrdinaryMemoryTransitionBinding.checked,
    Bool.and_eq_true] at checked
  exact checked.1.1.2

theorem AffineLinkedOrdinaryMemoryTransitionBinding.activeInventoryWritesAvoidChecked
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context control affine graph = true)
    (sourceRealizes : binding.frameBinding.sourceShape.Realizes affine
      binding.frameBinding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links) :
    frame.writesAvoidChecked
        (binding.frameBinding.writes.originalConcreteWrites originalState)
        (binding.frameBinding.writes.candidateConcreteWrites candidateState) = true ∧
      sourceInventory.writesAvoidChecked frame
        (binding.frameBinding.writes.originalConcreteWrites originalState)
        (binding.frameBinding.writes.candidateConcreteWrites candidateState) = true := by
  have footprint := binding.stackFootprint_checked_of_checked context control
    affine graph checked
  have frameChecked := binding.frame_checked_of_checked context control affine
    graph checked
  have offsetsChecked :=
    binding.frameBinding.stackOffsets_checked_of_checked context affine graph
      frameChecked
  cases sourceLocations : binding.frameBinding.sourceShape.locations with
  | exact locations =>
      simp [ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked,
        sourceLocations] at footprint
  | affineFamily sourceStateIndex =>
      cases stateFound : affine.states[sourceStateIndex]? with
      | none =>
          simp [ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked,
            sourceLocations, stateFound] at footprint
      | some state =>
          simp only [ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked,
            sourceLocations, stateFound, Bool.and_eq_true, beq_iff_eq] at footprint
          rcases footprint with
            ⟨⟨⟨⟨stateNode, originalEsp⟩, candidateEsp⟩, fullStride⟩,
              windowsChecked⟩
          rcases List.any_eq_true.mp windowsChecked with
            ⟨window, windowMember, windowChecked⟩
          simp only [Bool.and_eq_true] at windowChecked
          rcases windowChecked with
            ⟨⟨⟨⟨_windowOriginalEsp, _windowCandidateEsp⟩,
              _originalBaseFits⟩, _candidateBaseFits⟩, offsetRows⟩
          have activeRows : (binding.frameBinding.stackOffsets.all fun offset =>
              wordOffsetsDisjoint state.family.originalBase
                  offset.original.offset.word &&
                wordOffsetsDisjoint state.family.candidateBase
                  offset.candidate.offset.word) = true := by
            simp only [List.all_eq_true, Bool.and_eq_true]
            intro offset member
            have row := List.all_eq_true.mp offsetRows offset member
            simp only [PairedStackRelativeWordWrite.avoidsActiveChecked,
              Bool.and_eq_true] at row
            exact row.1.1.2
          simp only [ReturnSlotAffineInventoryShape.Realizes,
            ReturnSlotAffineInventoryShape.PayloadMatches, sourceLocations]
            at sourceRealizes
          have sourceWords := sourceRealizes.1.1
          rcases sourceRealizes.2 with
            ⟨realizedState, coefficient, location, realizedStateFound,
              _realizedNode, containsAt, locationsExact⟩
          have realizedStateExact : realizedState = state := by
            rw [stateFound] at realizedStateFound
            exact (Option.some.inj realizedStateFound).symm
          subst realizedState
          have locationFacts :=
            state.family.containsAt_offsets_eq_base_of_full_stride coefficient
              location containsAt fullStride
          have stackFacts := stackHolds
          simp only [RelationalLinkedRuntimeCallStackHolds] at stackFacts
          have locationHolds := stackFacts.2.1.2 location (by
            rw [locationsExact]
            simp)
          have originalFrame :
              originalState.registers.esp + state.family.originalBase =
                frame.originalStackAddress := by
            simpa [locationFacts.1, locationFacts.2.2.1, originalEsp,
              Registers.get] using locationHolds.1
          have candidateFrame :
              candidateState.registers.esp + state.family.candidateBase =
                frame.candidateStackAddress := by
            simpa [locationFacts.2.1, locationFacts.2.2.2, candidateEsp,
              Registers.get] using locationHolds.2
          have avoids :=
            binding.frameBinding.writes.concreteWritesAvoid_of_stackOffsetsChecked
              binding.frameBinding.stackOffsets originalState candidateState
              state.family.originalBase state.family.candidateBase offsetsChecked
              activeRows
          have activeChecked : frame.writesAvoidChecked
              (binding.frameBinding.writes.originalConcreteWrites originalState)
              (binding.frameBinding.writes.candidateConcreteWrites candidateState) =
                true := by
            simp only [RelationalRuntimeCallFrame.writesAvoidChecked,
              Bool.and_eq_true]
            constructor
            · apply concreteWritesAvoidWordChecked_of_avoids
              simpa [originalFrame] using avoids.1
            · apply concreteWritesAvoidWordChecked_of_avoids
              simpa [candidateFrame] using avoids.2
          have exactChecked : sourceInventory.writesAvoidChecked frame
              (binding.frameBinding.writes.originalConcreteWrites originalState)
              (binding.frameBinding.writes.candidateConcreteWrites candidateState) =
                true := by
            simp only [ReturnSlotOffsetInventory.writesAvoidChecked,
              List.all_eq_true, Bool.and_eq_true]
            intro word wordMember
            have shapeWordMember : word ∈
                binding.frameBinding.sourceShape.exactWords := by
              rw [← sourceWords]
              exact wordMember
            have exactRows : (binding.frameBinding.stackOffsets.all fun offset =>
                wordOffsetsDisjoint
                    (state.family.originalBase +
                      BitVec.ofNat 32 word.originalOffset)
                    offset.original.offset.word &&
                  wordOffsetsDisjoint
                    (state.family.candidateBase +
                      BitVec.ofNat 32 word.candidateOffset)
                    offset.candidate.offset.word) = true := by
              simp only [List.all_eq_true, Bool.and_eq_true]
              intro offset offsetMember
              have row := List.all_eq_true.mp offsetRows offset offsetMember
              simp only [PairedStackRelativeWordWrite.avoidsExactWordChecked,
                Bool.and_eq_true] at row
              have exactRow :=
                List.all_eq_true.mp row.1.2 word shapeWordMember
              simp only [Bool.and_eq_true] at exactRow
              exact exactRow
            have wordAvoids :=
              PairedDecodedWritesClaim.concreteWritesAvoid_of_stackOffsetsChecked
                binding.frameBinding.writes binding.frameBinding.stackOffsets
                originalState candidateState
                (state.family.originalBase +
                  BitVec.ofNat 32 word.originalOffset)
                (state.family.candidateBase +
                  BitVec.ofNat 32 word.candidateOffset)
                offsetsChecked exactRows
            have originalWordFrame :
                originalState.registers.esp +
                    (state.family.originalBase +
                      BitVec.ofNat 32 word.originalOffset) =
                  frame.originalStackAddress +
                    BitVec.ofNat 32 word.originalOffset := by
              simpa only [BitVec.add_assoc] using congrArg
                (fun address => address + BitVec.ofNat 32 word.originalOffset)
                originalFrame
            have candidateWordFrame :
                candidateState.registers.esp +
                    (state.family.candidateBase +
                      BitVec.ofNat 32 word.candidateOffset) =
                  frame.candidateStackAddress +
                    BitVec.ofNat 32 word.candidateOffset := by
              simpa only [BitVec.add_assoc] using congrArg
                (fun address => address + BitVec.ofNat 32 word.candidateOffset)
                candidateFrame
            constructor
            · apply concreteWritesAvoidWordChecked_of_avoids
              simpa [originalWordFrame] using wordAvoids.1
            · apply concreteWritesAvoidWordChecked_of_avoids
              simpa [candidateWordFrame] using wordAvoids.2
          exact ⟨activeChecked, exactChecked⟩

/-- The static stack-footprint certificate, source `StateRel`, concrete affine
inventory realization, and checked runtime links jointly discharge the entire
arbitrary-depth framed-memory side condition. -/
theorem AffineLinkedOrdinaryMemoryTransitionBinding.linkedStackWritesAvoidChecked
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) (world : RelationalWorld)
    (originalState candidateState : MachineState)
    (frame : RelationalRuntimeCallFrame)
    (frames : List RelationalRuntimeCallFrame)
    (continuation : Nat) (continuations : List Nat)
    (links : List RelationalRuntimeCallFrameLink)
    (sourceInventory : ReturnSlotOffsetInventory)
    (checked : binding.checked context control affine graph = true)
    (sourceRealizes : binding.frameBinding.sourceShape.Realizes affine
      binding.frameBinding.claim.transition.source.nodeId sourceInventory)
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (linksAllowed : control.LinksAllowed affine graph links)
    (sourceRelated : StateRel context world
      binding.frameBinding.claim.region.inputInvariant originalState
      candidateState) :
    relationalLinkedStackWritesAvoidChecked frame frames sourceInventory links
      (binding.frameBinding.writes.originalConcreteWrites originalState)
      (binding.frameBinding.writes.candidateConcreteWrites candidateState) = true := by
  have active := binding.activeInventoryWritesAvoidChecked context control affine
    graph originalState candidateState frame frames continuation continuations
    links sourceInventory checked sourceRealizes stackHolds
  have footprint := binding.stackFootprint_checked_of_checked context control
    affine graph checked
  have frameChecked := binding.frame_checked_of_checked context control affine
    graph checked
  have offsetsChecked :=
    binding.frameBinding.stackOffsets_checked_of_checked context affine graph
      frameChecked
  have stackFacts := stackHolds
  simp only [RelationalLinkedRuntimeCallStackHolds] at stackFacts
  cases frames with
  | nil =>
      cases links with
      | nil =>
          have framesAll : [frame].all (fun selected =>
              selected.writesAvoidChecked
                (binding.frameBinding.writes.originalConcreteWrites originalState)
                (binding.frameBinding.writes.candidateConcreteWrites candidateState)) =
                true := by simp [active.1]
          simp only [relationalLinkedStackWritesAvoidChecked, Bool.and_eq_true]
          exact ⟨⟨active.2, framesAll⟩, rfl⟩
      | cons link links =>
          simp [RelationalRuntimeCallFrameLinksHold] at stackFacts
  | cons outer frames =>
      cases continuations with
      | nil =>
          simp [RelationalRuntimeCallFramesHold] at stackFacts
      | cons outerContinuation continuations =>
          cases links with
          | nil =>
              simp [RelationalRuntimeCallFrameLinksHold] at stackFacts
          | cons link links =>
              have linksHold := stackFacts.2.2.2.2
              simp only [RelationalRuntimeCallFrameLinksHold] at linksHold
              obtain ⟨shape, shapeMember, shapeRealizes⟩ :=
                linksAllowed.2 link (by simp)
              cases sourceLocations : binding.frameBinding.sourceShape.locations with
              | exact locations =>
                  simp [ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked,
                    sourceLocations] at footprint
              | affineFamily sourceStateIndex =>
                  cases stateFound : affine.states[sourceStateIndex]? with
                  | none =>
                      simp [ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked,
                        sourceLocations, stateFound] at footprint
                  | some state =>
                      simp only [ReturnSlotAffineLinkedMemoryTransitionBinding.stackFootprintChecked,
                        sourceLocations, stateFound, Bool.and_eq_true, beq_iff_eq]
                          at footprint
                      rcases footprint with
                        ⟨⟨⟨⟨_stateNode, originalEsp⟩, candidateEsp⟩,
                          fullStride⟩, windowsChecked⟩
                      rcases List.any_eq_true.mp windowsChecked with
                        ⟨window, windowMember, windowChecked⟩
                      simp only [Bool.and_eq_true] at windowChecked
                      rcases windowChecked with
                        ⟨⟨⟨⟨windowOriginalEsp, windowCandidateEsp⟩,
                          originalBaseFits⟩, candidateBaseFits⟩, offsetRows⟩
                      have insideRows : (binding.frameBinding.stackOffsets.all
                          fun write => write.insideWindowChecked window) = true := by
                        simp only [List.all_eq_true]
                        intro write member
                        have row := List.all_eq_true.mp offsetRows write member
                        simp only [Bool.and_eq_true] at row
                        exact row.1.1.1
                      have beforeRows : (binding.frameBinding.stackOffsets.all
                          fun write => write.beforeLinkShapeChecked state.family
                            shape) = true := by
                        simp only [List.all_eq_true]
                        intro write member
                        have row := List.all_eq_true.mp offsetRows write member
                        simp only [Bool.and_eq_true] at row
                        exact List.all_eq_true.mp row.2 shape shapeMember
                      have windowsHold := sourceRelated.stackWindowsHold context
                        world binding.frameBinding.claim.region.inputInvariant
                        originalState candidateState
                      simp only [stackWindowsRelated, List.all_eq_true]
                        at windowsHold
                      have windowHolds : window.holds world
                          originalState.registers candidateState.registers = true := by
                        exact windowsHold window (by
                          simpa [RegionRelation.inputInvariant] using windowMember)
                      simp only [ReturnSlotAffineInventoryShape.Realizes,
                        ReturnSlotAffineInventoryShape.PayloadMatches,
                        sourceLocations] at sourceRealizes
                      rcases sourceRealizes.2 with
                        ⟨realizedState, coefficient, location,
                          realizedStateFound, _realizedNode, containsAt,
                          locationsExact⟩
                      have realizedStateExact : realizedState = state := by
                        rw [stateFound] at realizedStateFound
                        exact (Option.some.inj realizedStateFound).symm
                      subst realizedState
                      have locationFacts :=
                        state.family.containsAt_offsets_eq_base_of_full_stride
                          coefficient location containsAt fullStride
                      have locationHolds := stackFacts.2.1.2 location (by
                        rw [locationsExact]
                        simp)
                      have originalFrame :
                          originalState.registers.esp + state.family.originalBase =
                            frame.originalStackAddress := by
                        simpa [locationFacts.1, locationFacts.2.2.1, originalEsp,
                          Registers.get] using locationHolds.1
                      have candidateFrame :
                          candidateState.registers.esp + state.family.candidateBase =
                            frame.candidateStackAddress := by
                        simpa [locationFacts.2.1, locationFacts.2.2.2,
                          candidateEsp, Registers.get] using locationHolds.2
                      have baseAddressNats :=
                        (StackRelativeWordOffset.above
                          state.family.originalBase.toNat).addressNats_of_window
                            context world window originalState.registers
                            candidateState.registers
                            (sourceRelated.stackRangesValid context world
                              binding.frameBinding.claim.region.inputInvariant
                              originalState candidateState)
                            windowHolds
                            ⟨beq_iff_eq.mp windowOriginalEsp,
                              beq_iff_eq.mp windowCandidateEsp⟩
                            (by
                              simp [StackRelativeWordOffset.insideWindowChecked]
                              exact of_decide_eq_true originalBaseFits)
                      have candidateBaseAddressNats :=
                        (StackRelativeWordOffset.above
                          state.family.candidateBase.toNat).addressNats_of_window
                            context world window originalState.registers
                            candidateState.registers
                            (sourceRelated.stackRangesValid context world
                              binding.frameBinding.claim.region.inputInvariant
                              originalState candidateState)
                            windowHolds
                            ⟨beq_iff_eq.mp windowOriginalEsp,
                              beq_iff_eq.mp windowCandidateEsp⟩
                            (by
                              simp [StackRelativeWordOffset.insideWindowChecked]
                              exact of_decide_eq_true candidateBaseFits)
                      have originalFrameNat :
                          originalState.registers.esp.toNat +
                              state.family.originalBase.toNat =
                            frame.originalStackAddress.toNat := by
                        calc
                          originalState.registers.esp.toNat +
                              state.family.originalBase.toNat =
                            ((StackRelativeWordOffset.above
                              state.family.originalBase.toNat).address
                                originalState.registers).toNat :=
                                  baseAddressNats.1.symm
                          _ = frame.originalStackAddress.toNat := by
                            simpa [StackRelativeWordOffset.address,
                              StackRelativeWordOffset.word,
                              BitVec.ofNat_toNat] using congrArg BitVec.toNat
                                originalFrame
                      have candidateFrameNat :
                          candidateState.registers.esp.toNat +
                              state.family.candidateBase.toNat =
                            frame.candidateStackAddress.toNat := by
                        calc
                          candidateState.registers.esp.toNat +
                              state.family.candidateBase.toNat =
                            ((StackRelativeWordOffset.above
                              state.family.candidateBase.toNat).address
                                candidateState.registers).toNat :=
                                  candidateBaseAddressNats.2.symm
                          _ = frame.candidateStackAddress.toNat := by
                            simpa [StackRelativeWordOffset.address,
                              StackRelativeWordOffset.word,
                              BitVec.ofNat_toNat] using congrArg BitVec.toNat
                                candidateFrame
                      have originalOuterNat :
                          originalState.registers.esp.toNat +
                              state.family.originalBase.toNat +
                              shape.originalGap = outer.originalStackAddress.toNat := by
                        rw [originalFrameNat, ← shapeRealizes.originalGapExact]
                        exact linksHold.1.2.2.2.2.2.2.2.2.1
                      have candidateOuterNat :
                          candidateState.registers.esp.toNat +
                              state.family.candidateBase.toNat +
                              shape.candidateGap = outer.candidateStackAddress.toNat := by
                        rw [candidateFrameNat, ← shapeRealizes.candidateGapExact]
                        exact linksHold.1.2.2.2.2.2.2.2.2.2.1
                      have beforeOuter :=
                        binding.frameBinding.writes.concreteWritesBeforeOuter_of_stackOffsetsChecked
                          binding.frameBinding.stackOffsets context world window
                          originalState candidateState state.family shape
                          outer.originalStackAddress outer.candidateStackAddress
                          offsetsChecked
                          (sourceRelated.stackRangesValid context world
                            binding.frameBinding.claim.region.inputInvariant
                            originalState candidateState)
                          windowHolds
                          ⟨beq_iff_eq.mp windowOriginalEsp,
                            beq_iff_eq.mp windowCandidateEsp⟩
                          insideRows beforeRows originalOuterNat candidateOuterNat
                      have framesHold := stackFacts.2.2.2.1
                      simp only [RelationalRuntimeCallFramesHold] at framesHold
                      have tail :=
                        relationalLinkedStackTailWritesAvoidChecked_of_beforeOuter
                          context originalState candidateState frame outer frames
                          outerContinuation continuations link links
                          (binding.frameBinding.writes.originalConcreteWrites
                            originalState)
                          (binding.frameBinding.writes.candidateConcreteWrites
                            candidateState)
                          framesHold.2.2.2.2 linksHold beforeOuter.1
                          beforeOuter.2
                      have framesAll : (frame :: outer :: frames).all
                          (fun selected => selected.writesAvoidChecked
                            (binding.frameBinding.writes.originalConcreteWrites
                              originalState)
                            (binding.frameBinding.writes.candidateConcreteWrites
                              candidateState)) = true := by
                        simp only [List.all_cons, active.1, tail.1,
                          Bool.true_and]
                      simp only [relationalLinkedStackWritesAvoidChecked,
                        Bool.and_eq_true]
                      exact ⟨⟨active.2, framesAll⟩, tail.2⟩

/-- A finite paired-memory inventory covers one product-node exit only when
every active affine control state at that node names the exact submitted
semantic/write binding. -/
def affineMemoryBindingsCoverActiveNodeEdge
    (bindings : List AffineLinkedOrdinaryMemoryTransitionBinding)
    (control : AffineLinkedProductControlProfile)
    (nodeId edgeId : Nat)
    (frameBinding : ReturnSlotAffineLinkedMemoryTransitionBinding) : Bool :=
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

theorem affineMemoryBindingsCoverActiveNodeEdge.mono
    (source target : List AffineLinkedOrdinaryMemoryTransitionBinding)
    (control : AffineLinkedProductControlProfile)
    (nodeId edgeId : Nat)
    (frameBinding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (covered : affineMemoryBindingsCoverActiveNodeEdge source control nodeId
      edgeId frameBinding = true)
    (subset : ∀ binding ∈ source, binding ∈ target) :
    affineMemoryBindingsCoverActiveNodeEdge target control nodeId edgeId
      frameBinding = true := by
  simp only [affineMemoryBindingsCoverActiveNodeEdge, List.all_eq_true]
    at covered ⊢
  intro state stateMember
  have row := covered state stateMember
  by_cases active : state.nodeId == nodeId && state.activeShape.isSome
  · simp only [active, if_true] at row ⊢
    rcases List.any_eq_true.mp row with ⟨binding, bindingMember, bindingChecked⟩
    exact List.any_eq_true.mpr
      ⟨binding, subset binding bindingMember, bindingChecked⟩
  · cases inactive : (state.nodeId == nodeId && state.activeShape.isSome) with
    | false => simp [inactive]
    | true => exact False.elim (active inactive)

/-- Select the exact checked paired-memory binding applicable to a concrete
active affine state.  Neither list position nor Python-side uniqueness is in
the trusted path. -/
theorem affineMemoryBinding_of_allowed
    (bindings : List AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
    (frameBinding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (nodeId edgeId continuation : Nat)
    (continuations : List Nat)
    (inventory : ReturnSlotOffsetInventory)
    (bindingsChecked : bindings.all (fun binding =>
      binding.checked context control affine graph) = true)
    (covered : affineMemoryBindingsCoverActiveNodeEdge bindings control
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

theorem AffineLinkedOrdinaryMemoryTransitionBinding.afterPairedWritesNested
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph)
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
    (footprintChecked : relationalLinkedStackWritesAvoidChecked frame frames
      sourceInventory links
      (binding.frameBinding.writes.originalConcreteWrites originalState)
      (binding.frameBinding.writes.candidateConcreteWrites candidateState) = true) :
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
          (continuation :: continuations) (some targetInventory) := by
  have transferred := binding.frameBinding.afterPairedWritesNested context affine
    graph originalState candidateState frame frames continuation continuations
    links sourceInventory
    (binding.frame_checked_of_checked context control affine graph checked)
    sourceRealizes stackHolds footprintChecked
  rcases transferred with ⟨targetInventory, targetRealizes, targetStack⟩
  have checkedFacts := checked
  unfold AffineLinkedOrdinaryMemoryTransitionBinding.checked at checkedFacts
  cases sourceFound : control.states[binding.sourceControlStateIndex]? with
  | none => simp [sourceFound] at checkedFacts
  | some source =>
      cases targetFound : control.states[binding.targetControlStateIndex]? with
      | none => simp [sourceFound, targetFound] at checkedFacts
      | some target =>
          simp only [sourceFound, targetFound, Bool.and_eq_true, beq_iff_eq]
            at checkedFacts
          refine ⟨targetInventory, targetRealizes, targetStack,
            checkedFacts.1.1.1.1, target,
            List.mem_of_getElem? targetFound, ?_, ?_⟩
          · exact ⟨checkedFacts.2.1.1.1.1.1.1.2,
              by simpa [continuationExact] using checkedFacts.2.1.1.1.1.2,
              by simpa [checkedFacts.2.1.1.2] using targetRealizes⟩
          · simp [checkedFacts.2.2]

theorem AffineLinkedOrdinaryMemoryTransitionBinding.afterPairedWritesNestedWithFacts
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
    (context : StaticProofContext)
    (control : AffineLinkedProductControlProfile)
    (affine : ReturnSlotAffineFrameProfile)
    (graph : RelationalProductGraph) (world : RelationalWorld)
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
    (footprintChecked : relationalLinkedStackWritesAvoidChecked frame frames
      sourceInventory links
      (binding.frameBinding.writes.originalConcreteWrites originalState)
      (binding.frameBinding.writes.candidateConcreteWrites candidateState) = true) :
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
  have frameChecked := binding.frame_checked_of_checked context control affine graph
    checked
  obtain ⟨targetInventory, targetRealizes, targetStack, targetFacts⟩ :=
    binding.frameBinding.afterPairedWritesNestedWithFacts context affine graph world
      originalState candidateState frame frames continuation continuations links
      sourceInventory frameChecked sourceRealizes stackHolds factsHold
      footprintChecked
  have checkedFacts := checked
  unfold AffineLinkedOrdinaryMemoryTransitionBinding.checked at checkedFacts
  cases sourceFound : control.states[binding.sourceControlStateIndex]? with
  | none => simp [sourceFound] at checkedFacts
  | some source =>
      cases targetFound : control.states[binding.targetControlStateIndex]? with
      | none => simp [sourceFound, targetFound] at checkedFacts
      | some target =>
          simp only [sourceFound, targetFound, Bool.and_eq_true, beq_iff_eq]
            at checkedFacts
          have targetControl : control.Allows affine graph
              binding.frameBinding.claim.transition.target.nodeId
              (continuation :: continuations) (some targetInventory) := by
            refine ⟨checkedFacts.1.1.1.1, target,
              List.mem_of_getElem? targetFound, ?_, ?_⟩
            · exact ⟨checkedFacts.2.1.1.1.1.1.1.2,
                by simpa [continuationExact] using checkedFacts.2.1.1.1.1.2,
                by simpa [checkedFacts.2.1.1.2] using targetRealizes⟩
            · simp [checkedFacts.2.2]
          exact ⟨targetInventory, targetRealizes, targetStack,
            targetControl, targetFacts⟩

theorem AffineLinkedOrdinaryMemoryTransitionBinding.nextRunningRelated
    (binding : AffineLinkedOrdinaryMemoryTransitionBinding)
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
    (sourceStatesRelated : StateRel context world
      binding.frameBinding.claim.region.inputInvariant originalState
      candidateState)
    (nextStatesRelated : StateRel context world targetInvariant
      ((binding.frameBinding.claim.originalNormalized.eval
        originalState).nextMachineState originalState)
      ((binding.frameBinding.claim.candidateNormalized.eval
        candidateState).nextMachineState candidateState)) :
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
    binding.afterPairedWritesNestedWithFacts context control affine graph world
      originalState candidateState frame frames continuation continuations links
      sourceInventory checked sourceRealizes continuationExact stackHolds factsHold
      (binding.linkedStackWritesAvoidChecked context control affine graph world
        originalState candidateState frame frames continuation continuations links
        sourceInventory checked sourceRealizes stackHolds linksAllowed
        sourceStatesRelated)
  refine ⟨rfl, rfl, rfl, rfl,
    binding.frameBinding.claim.transition.target.nodeId, targetNode,
    targetInvariant, frame :: frames, some targetInventory, links,
    targetNodeFound, rfl, targetReachable, targetInvariantFound, ?_, targetStack,
    linksAllowed, targetFacts, stackTargetsMapped, nextStatesRelated⟩
  change control.Allows affine graph
    binding.frameBinding.claim.transition.target.nodeId
    (continuation :: continuations) (some targetInventory)
  exact targetControl

/-- Dispatch one paired-write successor from the finite checked inventory.
The submitted active affine state selects a binding by proof, so generated
acceptance code does not branch on list position or trust Python dispatch. -/
theorem affineMemoryBindingsNextRunningRelated_of_allowed
    (bindings : List AffineLinkedOrdinaryMemoryTransitionBinding)
    (frameBinding : ReturnSlotAffineLinkedMemoryTransitionBinding)
    (edgeId : Nat)
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
    (bindingsChecked : bindings.all (fun binding =>
      binding.checked context control affine graph) = true)
    (covered : affineMemoryBindingsCoverActiveNodeEdge bindings control
      frameBinding.claim.transition.source.nodeId edgeId frameBinding = true)
    (controlAllowed : control.Allows affine graph
      frameBinding.claim.transition.source.nodeId
      (continuation :: continuations) (some sourceInventory))
    (stackHolds : RelationalLinkedRuntimeCallStackHolds context originalState
      candidateState (frame :: frames) (continuation :: continuations)
      (some sourceInventory) links)
    (linksAllowed : control.LinksAllowed affine graph links)
    (factsHold : RelationalLinkedRuntimeCallFactsHold context world
      (some sourceInventory) originalState.registers candidateState.registers)
    (targetNodeFound : graph.getNode?
      frameBinding.claim.transition.target.nodeId = some targetNode)
    (targetInvariantFound : invariants.nodeInvariants[
      frameBinding.claim.transition.target.nodeId]? = some targetInvariant)
    (targetReachable : reachability.contains
      frameBinding.claim.transition.target.nodeId = true)
    (stackTargetsMapped : RelationalRuntimeCallTargetsMapped graph reachability
      (continuation :: continuations))
    (sourceStatesRelated : StateRel context world
      frameBinding.claim.region.inputInvariant originalState candidateState)
    (nextStatesRelated : StateRel context world targetInvariant
      ((frameBinding.claim.originalNormalized.eval originalState).nextMachineState
        originalState)
      ((frameBinding.claim.candidateNormalized.eval candidateState).nextMachineState
        candidateState)) :
    LinkedWorldExecutionsRelated context graph invariants reachability
      (control.authority affine graph) callbackTargets sites
      (.running targetNode.targetId
        ((frameBinding.claim.originalNormalized.eval originalState).nextMachineState
          originalState)
        (continuation :: continuations) eventIndex world)
      (.running targetNode.targetId
        ((frameBinding.claim.candidateNormalized.eval candidateState).nextMachineState
          candidateState)
        (continuation :: continuations) eventIndex world) := by
  obtain ⟨binding, _bindingMember, bindingChecked, _edgeExact, _sourceNode,
      frameBindingExact, continuationExact, sourceRealizes⟩ :=
    affineMemoryBinding_of_allowed bindings context control affine graph
      frameBinding frameBinding.claim.transition.source.nodeId edgeId continuation
      continuations sourceInventory bindingsChecked covered controlAllowed
  have result := binding.nextRunningRelated context control affine graph
    invariants reachability callbackTargets sites world originalState candidateState
    frame frames continuation continuations links sourceInventory eventIndex
    targetNode targetInvariant bindingChecked sourceRealizes continuationExact
    stackHolds linksAllowed factsHold
    (by simpa [frameBindingExact] using targetNodeFound)
    (by simpa [frameBindingExact] using targetInvariantFound)
    (by simpa [frameBindingExact] using targetReachable)
    stackTargetsMapped
    (by simpa [frameBindingExact] using sourceStatesRelated)
    (by simpa [frameBindingExact] using nextStatesRelated)
  simpa [frameBindingExact] using result

end StageA.Relational
