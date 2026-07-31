import StageA.RelationalInterpreterKernelOperationTraceChecker

namespace StageA.Relational.InterpreterKernelOperationProjection

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Compact projections of exact symbolic instruction transitions

Exact operation replay stores complete `MachineState` successors.  Most
downstream certificates observe only a few registers, memory, or flag bits.
These lemmas expose those fields without reducing unrelated x87 state,
undefined values, full flag expressions, or outcomes.
-/

/-- The exact instruction fields used by downstream state projection proofs.
The omitted x87, comparison, flag-update, and outcome fields remain present
in `SymbolicBehavior`; a generated equality to this compact view cannot
authorize claims about them. -/
structure CompactBehaviorProjection where
  eax : Expr
  ebx : Expr
  ecx : Expr
  edx : Expr
  esi : Expr
  edi : Expr
  ebp : Expr
  esp : Expr
  writes : List (Expr × Expr)
  flagsBase : Option Expr
deriving Repr, DecidableEq

def SymbolicBehavior.compactProjection
    (behavior : SymbolicBehavior) : CompactBehaviorProjection := {
  eax := behavior.registers.eax
  ebx := behavior.registers.ebx
  ecx := behavior.registers.ecx
  edx := behavior.registers.edx
  esi := behavior.registers.esi
  edi := behavior.registers.edi
  ebp := behavior.registers.ebp
  esp := behavior.registers.esp
  writes := behavior.writes
  flagsBase := behavior.flagsBase
}

@[simp] theorem SymbolicBehavior.eval_register
    (behavior : SymbolicBehavior) (state : MachineState) (register : Reg) :
    (behavior.eval state).registers.get register =
      (behavior.registers.get register).eval state := by
  cases register <;> rfl

@[simp] theorem SymbolicBehavior.eval_memory
    (behavior : SymbolicBehavior) (state : MachineState) :
    (behavior.eval state).memory = applyWrites state behavior.writes := by
  rfl

/-- Symbolic writes are evaluated once against the input state, then applied
in their original order.  This public bridge lets compact projection
certificates reuse the generic concrete-memory frame theorems. -/
theorem applyWrites_eq_applyConcreteWrites
    (state : MachineState) (writes : List (Expr × Expr)) :
    applyWrites state writes =
      applyConcreteWrites state.memory (evalNormalizedWrites state writes) := by
  have foldExact : ∀ (memory : Memory),
      List.foldl
          (fun current write =>
            Memory.write32 current (write.1.eval state) (write.2.eval state))
          memory writes =
        List.foldl (fun current write =>
          Memory.write32 current write.1 write.2)
          memory
          (writes.map fun write => (write.1.eval state, write.2.eval state)) := by
    intro memory
    induction writes generalizing memory with
    | nil => rfl
    | cons write tail induction =>
        simp only [List.map_cons, List.foldl_cons]
        exact induction _
  simpa [applyWrites, applyConcreteWrites, evalNormalizedWrites] using
    foldExact state.memory

/-- Executable disjointness for one protected word and a symbolic write list.
The expressions are evaluated in the exact instruction input state. -/
def symbolicWritesAvoidWordChecked (wordAddress : Word)
    (state : MachineState) (writes : List (Expr × Expr)) : Bool :=
  (evalNormalizedWrites state writes).all fun write =>
    wordOffsetsDisjoint wordAddress write.1

@[simp] theorem symbolicWritesAvoidWordChecked_nil (wordAddress : Word)
    (state : MachineState) :
    symbolicWritesAvoidWordChecked wordAddress state [] = true := by
  rfl

/-- Transport a checked footprint through an exact write-list witness.  This
avoids simplifying the complete instruction behavior at every consumer. -/
theorem symbolicWritesAvoidWordChecked_of_exact
    (wordAddress : Word) (state : MachineState)
    (actual expected : List (Expr × Expr))
    (writesExact : actual = expected)
    (checked :
      symbolicWritesAvoidWordChecked wordAddress state expected = true) :
    symbolicWritesAvoidWordChecked wordAddress state actual = true := by
  exact
    (congrArg
      (symbolicWritesAvoidWordChecked wordAddress state) writesExact).trans
        checked

/-- Reduce a one-write frame check to an address witness and a closed
four-byte disjointness check.  The written value is intentionally absent
from the premises because frame preservation depends only on the footprint. -/
theorem symbolicWritesAvoidWordChecked_singleton
    (wordAddress : Word) (state : MachineState)
    (address value : Expr) (concreteAddress : Word)
    (addressExact : address.eval state = concreteAddress)
    (disjoint :
      wordOffsetsDisjoint wordAddress concreteAddress = true) :
    symbolicWritesAvoidWordChecked wordAddress state [(address, value)] =
      true := by
  simp [symbolicWritesAvoidWordChecked, evalNormalizedWrites, addressExact,
    disjoint]

theorem write32AvoidsWord_of_wordOffsetsDisjoint
    {wordAddress writeAddress : Word}
    (checked : wordOffsetsDisjoint wordAddress writeAddress = true) :
    Write32AvoidsWord wordAddress writeAddress := by
  simp only [wordOffsetsDisjoint, List.all_eq_true] at checked
  intro wordByte wordByteBefore writeByte writeByteBefore
  have wordChecked := checked wordByte (by simpa using wordByteBefore)
  have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
  simpa only [decide_eq_true_eq] using writeChecked

/-- Four-byte disjointness is invariant under translation by a common flat
address base.  Generated frame proofs use this once with closed offsets rather
than repeatedly asking the bitvector prover to reason about an opaque base. -/
theorem wordOffsetsDisjoint_add_left
    (base left right : Word)
    (checked : wordOffsetsDisjoint left right = true) :
    wordOffsetsDisjoint (base + left) (base + right) = true := by
  simp only [wordOffsetsDisjoint, List.all_eq_true] at checked ⊢
  intro wordByte wordMember writeByte writeMember
  have separated := checked wordByte wordMember writeByte writeMember
  simp only [decide_eq_true_eq] at separated ⊢
  intro overlap
  apply separated
  have translated :
      base + (left + BitVec.ofNat 32 wordByte) =
        base + (right + BitVec.ofNat 32 writeByte) := by
    simpa only [BitVec.add_assoc] using overlap
  have cancelled := congrArg (fun value => value - base) translated
  simpa [BitVec.add_comm] using cancelled

theorem symbolicWritesAvoidWord_of_checked (wordAddress : Word)
    (state : MachineState) (writes : List (Expr × Expr))
    (checked : symbolicWritesAvoidWordChecked wordAddress state writes = true) :
    WritesAvoidWord wordAddress (evalNormalizedWrites state writes) := by
  simp only [symbolicWritesAvoidWordChecked, List.all_eq_true] at checked
  intro write member
  have disjoint := checked write member
  simp only [wordOffsetsDisjoint, List.all_eq_true] at disjoint
  intro wordByte wordByteBefore writeByte writeByteBefore
  have wordChecked := disjoint wordByte (by simpa using wordByteBefore)
  have writeChecked := wordChecked writeByte (by simpa using writeByteBefore)
  simpa only [decide_eq_true_eq] using writeChecked

theorem Memory.read32_applyWrites_of_checked
    (state : MachineState) (wordAddress : Word)
    (writes : List (Expr × Expr))
    (checked : symbolicWritesAvoidWordChecked wordAddress state writes = true) :
    Memory.read32 (applyWrites state writes) wordAddress =
      Memory.read32 state.memory wordAddress := by
  rw [applyWrites_eq_applyConcreteWrites]
  exact Memory.read32_applyConcreteWrites_of_avoids _ _ _
    (symbolicWritesAvoidWord_of_checked wordAddress state writes checked)

/-- A compact, composable checkpoint used by generated cdecl route proofs.
It records only the stack pointer, one protected word, and DF. -/
structure StackWordDirectionProjection
    (state : MachineState) (expectedEsp wordAddress wordValue : Word) :
    Prop where
  espExact : state.registers.esp = expectedEsp
  wordExact : Memory.read32 state.memory wordAddress = wordValue
  directionClear :
    state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0

/-- The corresponding checkpoint after EBP has become the cdecl frame base. -/
structure FrameWordDirectionProjection
    (state : MachineState)
    (expectedEsp expectedEbp wordAddress wordValue : Word) : Prop
    extends StackWordDirectionProjection state expectedEsp wordAddress wordValue
    where
  ebpExact : state.registers.ebp = expectedEbp

/-- A two-word cdecl checkpoint.  Multi-argument entry routes commonly need
more than one frame word to select their first branches; carrying both through
one checked projection avoids duplicating the instruction replay. -/
structure StackWordPairDirectionProjection
    (state : MachineState) (expectedEsp : Word)
    (firstAddress firstValue secondAddress secondValue : Word) : Prop
    extends StackWordDirectionProjection state expectedEsp firstAddress
      firstValue where
  secondWordExact : Memory.read32 state.memory secondAddress = secondValue

structure FrameWordPairDirectionProjection
    (state : MachineState) (expectedEsp expectedEbp : Word)
    (firstAddress firstValue secondAddress secondValue : Word) : Prop
    extends StackWordPairDirectionProjection state expectedEsp firstAddress
      firstValue secondAddress secondValue where
  ebpExact : state.registers.ebp = expectedEbp

/-- The REP direction expression is the architectural DF bit.  Keep this
bridge opaque so generated route certificates do not re-elaborate the full
32-bit initial EFLAGS expression. -/
theorem initialSymbolicDirectionBitEval_false
    (state : MachineState)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    BoolExpr.eval state (.bit initialSymbolic.eflagsExpression 10) = false := by
  change
    (initialSymbolic.eflagsExpression.eval state).toNat.testBit 10 = false
  calc
    (initialSymbolic.eflagsExpression.eval state).toNat.testBit 10 =
        (initialSymbolic.eflagsExpression.eval state)[10] :=
      (BitVec.getElem_eq_testBit_toNat
        (initialSymbolic.eflagsExpression.eval state) 10 (by omega)).symm
    _ =
        ((initialSymbolic.eflagsExpression.eval state).extractLsb' 10 1 ==
          BitVec.ofNat 1 1) :=
      (BitVec.getElem_eq_extractLsb'
        (initialSymbolic.eflagsExpression.eval state) 10 (by omega))
    _ = (state.eflags.extractLsb' 10 1 == BitVec.ofNat 1 1) := by
      rw [initialSymbolic_eflagsExpression_eval_extract_df]
    _ = false := by
      rw [directionClear]
      decide

/-- Evaluate the canonical forward REP operands from compact register and DF
facts.  Generated ABI modules pass an opaque checked operand equality into
this theorem instead of rewriting a binary-specific route expression. -/
theorem bulkCopyInputRegistersEval
    (copy : BulkCopyExpr) (state : MachineState)
    (source destination count : Word)
    (copyExact : copy = {
      destination := .inputReg .edi
      source := .inputReg .esi
      count := .inputReg .ecx
      direction := .bit initialSymbolic.eflagsExpression 10
    })
    (sourceExact : state.registers.esi = source)
    (destinationExact : state.registers.edi = destination)
    (countExact : state.registers.ecx = count)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    copy.source.eval state = source /\
      copy.destination.eval state = destination /\
      copy.count.eval state = count /\
      copy.direction.eval state = false := by
  subst copy
  exact And.intro sourceExact
    (And.intro destinationExact
      (And.intro countExact
        (initialSymbolicDirectionBitEval_false state directionClear)))

/-- Ordinary arithmetic flag updates preserve DF.  A nonempty `flagsBase`
remains explicit because instructions such as CLD, STD, and POPF may change
DF and must not pass through this preservation result. -/
@[simp] theorem SymbolicBehavior.eval_eflags_extract_df
    (behavior : SymbolicBehavior) (state : MachineState) :
    (behavior.eval state).eflags.extractLsb' 10 1 =
      ((behavior.flagsBase.getD inputEflagsExpression).eval state).extractLsb'
        10 1 := by
  cases baseExact : behavior.flagsBase <;>
    cases flagsExact : behavior.flags <;>
    simp [SymbolicBehavior.eval, baseExact, flagsExact]

@[simp] theorem symbolicBehaviorNextMachineState_register
    (behavior : SymbolicBehavior) (state : MachineState) (register : Reg) :
    (concreteBehaviorNextMachineState (behavior.eval state) state).registers.get
        register =
      (behavior.registers.get register).eval state := by
  cases register <;> rfl

@[simp] theorem symbolicBehaviorNextMachineState_memory
    (behavior : SymbolicBehavior) (state : MachineState) :
    (concreteBehaviorNextMachineState (behavior.eval state) state).memory =
      applyWrites state behavior.writes := by
  rfl

@[simp] theorem symbolicBehaviorNextMachineState_eflags_extract_df
    (behavior : SymbolicBehavior) (state : MachineState) :
    (concreteBehaviorNextMachineState
        (behavior.eval state) state).eflags.extractLsb' 10 1 =
      ((behavior.flagsBase.getD inputEflagsExpression).eval state).extractLsb'
        10 1 := by
  exact
    StageA.Relational.InterpreterKernelOperationProjection.SymbolicBehavior.eval_eflags_extract_df
      behavior state

@[simp] theorem CheckedNativeOperationRunningEdge.after_register
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (register : Reg) :
    (edge.after state).registers.get register =
      (edge.replay.behavior.registers.get register).eval state := by
  exact symbolicBehaviorNextMachineState_register
    edge.replay.behavior state register

/-- Project one register from an exact symbolic-expression witness without
rewriting the complete behavior or successor state.  Generated checkpoints
use this bridge so unrelated semantic fields remain opaque. -/
theorem CheckedNativeOperationRunningEdge.after_register_of_exact
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (register : Reg) (expression : Expr)
    (expressionExact :
      edge.replay.behavior.registers.get register = expression) :
    (edge.after state).registers.get register = expression.eval state := by
  exact
    (CheckedNativeOperationRunningEdge.after_register edge state register).trans
      (congrArg (fun current => current.eval state) expressionExact)

@[simp] theorem CheckedNativeOperationRunningEdge.after_memory
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) :
    (edge.after state).memory =
      applyWrites state edge.replay.behavior.writes := by
  exact symbolicBehaviorNextMachineState_memory edge.replay.behavior state

theorem CheckedNativeOperationRunningEdge.after_read32_of_checked
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (wordAddress : Word)
    (checked :
      symbolicWritesAvoidWordChecked wordAddress state
        edge.replay.behavior.writes = true) :
    Memory.read32 (edge.after state).memory wordAddress =
      Memory.read32 state.memory wordAddress := by
  rw [CheckedNativeOperationRunningEdge.after_memory]
  exact Memory.read32_applyWrites_of_checked state wordAddress
    edge.replay.behavior.writes checked

theorem CheckedNativeOperationRunningEdge.after_stackWordDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (expectedEsp wordAddress wordValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (wordChecked :
      symbolicWritesAvoidWordChecked wordAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (wordExact : Memory.read32 state.memory wordAddress = wordValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    StackWordDirectionProjection (edge.after state)
      expectedEsp wordAddress wordValue := by
  constructor
  · change (edge.after state).registers.get .esp = expectedEsp
    rw [CheckedNativeOperationRunningEdge.after_register]
    exact espExact
  · exact
      (StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationRunningEdge.after_read32_of_checked
        edge state wordAddress wordChecked).trans wordExact
  · rw [CheckedNativeOperationRunningEdge.after,
      symbolicBehaviorNextMachineState_eflags_extract_df,
      flagsBasePreserved]
    simpa only [Option.getD, inputEflagsExpression_eval] using directionClear

theorem CheckedNativeOperationRunningEdge.after_frameWordDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState)
    (expectedEsp expectedEbp wordAddress wordValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (ebpExact :
      (edge.replay.behavior.registers.get .ebp).eval state = expectedEbp)
    (wordChecked :
      symbolicWritesAvoidWordChecked wordAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (wordExact : Memory.read32 state.memory wordAddress = wordValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    FrameWordDirectionProjection (edge.after state)
      expectedEsp expectedEbp wordAddress wordValue := by
  constructor
  · exact
      StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationRunningEdge.after_stackWordDirectionProjection
        edge state expectedEsp wordAddress wordValue espExact wordChecked
        flagsBasePreserved wordExact directionClear
  · change (edge.after state).registers.get .ebp = expectedEbp
    rw [CheckedNativeOperationRunningEdge.after_register]
    exact ebpExact

theorem CheckedNativeOperationRunningEdge.after_stackWordPairDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (expectedEsp : Word)
    (firstAddress firstValue secondAddress secondValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (firstChecked :
      symbolicWritesAvoidWordChecked firstAddress state
        edge.replay.behavior.writes = true)
    (secondChecked :
      symbolicWritesAvoidWordChecked secondAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (firstExact : Memory.read32 state.memory firstAddress = firstValue)
    (secondExact : Memory.read32 state.memory secondAddress = secondValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    StackWordPairDirectionProjection (edge.after state) expectedEsp
      firstAddress firstValue secondAddress secondValue := by
  constructor
  · exact
      CheckedNativeOperationRunningEdge.after_stackWordDirectionProjection
        edge state expectedEsp firstAddress firstValue espExact firstChecked
        flagsBasePreserved firstExact directionClear
  · exact
      (CheckedNativeOperationRunningEdge.after_read32_of_checked edge state
        secondAddress secondChecked).trans secondExact

theorem CheckedNativeOperationRunningEdge.after_frameWordPairDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (expectedEsp expectedEbp : Word)
    (firstAddress firstValue secondAddress secondValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (ebpExact :
      (edge.replay.behavior.registers.get .ebp).eval state = expectedEbp)
    (firstChecked :
      symbolicWritesAvoidWordChecked firstAddress state
        edge.replay.behavior.writes = true)
    (secondChecked :
      symbolicWritesAvoidWordChecked secondAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (firstExact : Memory.read32 state.memory firstAddress = firstValue)
    (secondExact : Memory.read32 state.memory secondAddress = secondValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    FrameWordPairDirectionProjection (edge.after state) expectedEsp expectedEbp
      firstAddress firstValue secondAddress secondValue := by
  constructor
  · exact
      CheckedNativeOperationRunningEdge.after_stackWordPairDirectionProjection
        edge state expectedEsp firstAddress firstValue secondAddress secondValue
        espExact firstChecked secondChecked flagsBasePreserved firstExact
        secondExact directionClear
  · change (edge.after state).registers.get .ebp = expectedEbp
    rw [CheckedNativeOperationRunningEdge.after_register]
    exact ebpExact

@[simp] theorem CheckedNativeOperationRunningEdge.after_eflags_extract_df
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) :
    (edge.after state).eflags.extractLsb' 10 1 =
      ((edge.replay.behavior.flagsBase.getD inputEflagsExpression).eval
        state).extractLsb' 10 1 := by
  exact symbolicBehaviorNextMachineState_eflags_extract_df
    edge.replay.behavior state

/-- Project the architectural zero flag from one checked symbolic edge. -/
theorem CheckedNativeOperationRunningEdge.after_inputFlagSix_of_flags
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationRunningEdge candidate)
    (state : MachineState) (flags : FlagsExpr) (zero : BoolExpr)
    (baseExact : edge.replay.behavior.flagsBase = none)
    (flagsExact : edge.replay.behavior.flags = some flags)
    (zeroExact : flags.zero = some zero) :
    BoolExpr.eval (edge.after state) (.inputFlag 6) =
      BoolExpr.eval state zero := by
  unfold CheckedNativeOperationRunningEdge.after
    concreteBehaviorNextMachineState
  simp only [BoolExpr.eval, SymbolicBehavior.eval, baseExact, flagsExact,
    FlagsExpr.eval_extract_zf, zeroExact, evalFlagBit]
  cases evaluated : BoolExpr.eval state zero <;> simp [evaluated]

@[simp] theorem CheckedNativeOperationStoppedEdge.after_register
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) (register : Reg) :
    (edge.after state).registers.get register =
      (edge.replay.behavior.registers.get register).eval state := by
  exact symbolicBehaviorNextMachineState_register
    edge.replay.behavior state register

/-- Stopped edges use the same compact register projection as running edges. -/
theorem CheckedNativeOperationStoppedEdge.after_register_of_exact
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) (register : Reg) (expression : Expr)
    (expressionExact :
      edge.replay.behavior.registers.get register = expression) :
    (edge.after state).registers.get register = expression.eval state := by
  exact
    (CheckedNativeOperationStoppedEdge.after_register edge state register).trans
      (congrArg (fun current => current.eval state) expressionExact)

@[simp] theorem CheckedNativeOperationStoppedEdge.after_memory
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) :
    (edge.after state).memory =
      applyWrites state edge.replay.behavior.writes := by
  exact symbolicBehaviorNextMachineState_memory edge.replay.behavior state

theorem CheckedNativeOperationStoppedEdge.after_read32_of_checked
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) (wordAddress : Word)
    (checked :
      symbolicWritesAvoidWordChecked wordAddress state
        edge.replay.behavior.writes = true) :
    Memory.read32 (edge.after state).memory wordAddress =
      Memory.read32 state.memory wordAddress := by
  rw [CheckedNativeOperationStoppedEdge.after_memory]
  exact Memory.read32_applyWrites_of_checked state wordAddress
    edge.replay.behavior.writes checked

theorem CheckedNativeOperationStoppedEdge.after_stackWordDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) (expectedEsp wordAddress wordValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (wordChecked :
      symbolicWritesAvoidWordChecked wordAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (wordExact : Memory.read32 state.memory wordAddress = wordValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    StackWordDirectionProjection (edge.after state)
      expectedEsp wordAddress wordValue := by
  constructor
  · change (edge.after state).registers.get .esp = expectedEsp
    rw [CheckedNativeOperationStoppedEdge.after_register]
    exact espExact
  · exact
      (StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationStoppedEdge.after_read32_of_checked
        edge state wordAddress wordChecked).trans wordExact
  · rw [CheckedNativeOperationStoppedEdge.after,
      symbolicBehaviorNextMachineState_eflags_extract_df,
      flagsBasePreserved]
    simpa only [Option.getD, inputEflagsExpression_eval] using directionClear

theorem CheckedNativeOperationStoppedEdge.after_frameWordDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState)
    (expectedEsp expectedEbp wordAddress wordValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (ebpExact :
      (edge.replay.behavior.registers.get .ebp).eval state = expectedEbp)
    (wordChecked :
      symbolicWritesAvoidWordChecked wordAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (wordExact : Memory.read32 state.memory wordAddress = wordValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    FrameWordDirectionProjection (edge.after state)
      expectedEsp expectedEbp wordAddress wordValue := by
  constructor
  · exact
      StageA.Relational.InterpreterKernelOperationProjection.CheckedNativeOperationStoppedEdge.after_stackWordDirectionProjection
        edge state expectedEsp wordAddress wordValue espExact wordChecked
        flagsBasePreserved wordExact directionClear
  · change (edge.after state).registers.get .ebp = expectedEbp
    rw [CheckedNativeOperationStoppedEdge.after_register]
    exact ebpExact

theorem CheckedNativeOperationStoppedEdge.after_stackWordPairDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) (expectedEsp : Word)
    (firstAddress firstValue secondAddress secondValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (firstChecked :
      symbolicWritesAvoidWordChecked firstAddress state
        edge.replay.behavior.writes = true)
    (secondChecked :
      symbolicWritesAvoidWordChecked secondAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (firstExact : Memory.read32 state.memory firstAddress = firstValue)
    (secondExact : Memory.read32 state.memory secondAddress = secondValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    StackWordPairDirectionProjection (edge.after state) expectedEsp
      firstAddress firstValue secondAddress secondValue := by
  constructor
  · exact
      CheckedNativeOperationStoppedEdge.after_stackWordDirectionProjection
        edge state expectedEsp firstAddress firstValue espExact firstChecked
        flagsBasePreserved firstExact directionClear
  · exact
      (CheckedNativeOperationStoppedEdge.after_read32_of_checked edge state
        secondAddress secondChecked).trans secondExact

theorem CheckedNativeOperationStoppedEdge.after_frameWordPairDirectionProjection
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) (expectedEsp expectedEbp : Word)
    (firstAddress firstValue secondAddress secondValue : Word)
    (espExact :
      (edge.replay.behavior.registers.get .esp).eval state = expectedEsp)
    (ebpExact :
      (edge.replay.behavior.registers.get .ebp).eval state = expectedEbp)
    (firstChecked :
      symbolicWritesAvoidWordChecked firstAddress state
        edge.replay.behavior.writes = true)
    (secondChecked :
      symbolicWritesAvoidWordChecked secondAddress state
        edge.replay.behavior.writes = true)
    (flagsBasePreserved : edge.replay.behavior.flagsBase = none)
    (firstExact : Memory.read32 state.memory firstAddress = firstValue)
    (secondExact : Memory.read32 state.memory secondAddress = secondValue)
    (directionClear :
      state.eflags.extractLsb' 10 1 = BitVec.ofNat 1 0) :
    FrameWordPairDirectionProjection (edge.after state) expectedEsp expectedEbp
      firstAddress firstValue secondAddress secondValue := by
  constructor
  · exact
      CheckedNativeOperationStoppedEdge.after_stackWordPairDirectionProjection
        edge state expectedEsp firstAddress firstValue secondAddress secondValue
        espExact firstChecked secondChecked flagsBasePreserved firstExact
        secondExact directionClear
  · change (edge.after state).registers.get .ebp = expectedEbp
    rw [CheckedNativeOperationStoppedEdge.after_register]
    exact ebpExact

@[simp] theorem CheckedNativeOperationStoppedEdge.after_eflags_extract_df
    {candidate : ExactNativeWorldProgram}
    (edge : CheckedNativeOperationStoppedEdge candidate)
    (state : MachineState) :
    (edge.after state).eflags.extractLsb' 10 1 =
      ((edge.replay.behavior.flagsBase.getD inputEflagsExpression).eval
        state).extractLsb' 10 1 := by
  exact symbolicBehaviorNextMachineState_eflags_extract_df
    edge.replay.behavior state

#print axioms SymbolicBehavior.eval_register
#print axioms SymbolicBehavior.eval_memory
#print axioms CompactBehaviorProjection
#print axioms SymbolicBehavior.compactProjection
#print axioms applyWrites_eq_applyConcreteWrites
#print axioms symbolicWritesAvoidWordChecked_of_exact
#print axioms write32AvoidsWord_of_wordOffsetsDisjoint
#print axioms wordOffsetsDisjoint_add_left
#print axioms symbolicWritesAvoidWord_of_checked
#print axioms Memory.read32_applyWrites_of_checked
#print axioms StackWordDirectionProjection
#print axioms FrameWordDirectionProjection
#print axioms initialSymbolicDirectionBitEval_false
#print axioms bulkCopyInputRegistersEval
#print axioms SymbolicBehavior.eval_eflags_extract_df
#print axioms symbolicBehaviorNextMachineState_register
#print axioms symbolicBehaviorNextMachineState_memory
#print axioms symbolicBehaviorNextMachineState_eflags_extract_df
#print axioms CheckedNativeOperationRunningEdge.after_register
#print axioms CheckedNativeOperationRunningEdge.after_register_of_exact
#print axioms CheckedNativeOperationRunningEdge.after_memory
#print axioms CheckedNativeOperationRunningEdge.after_read32_of_checked
#print axioms CheckedNativeOperationRunningEdge.after_stackWordDirectionProjection
#print axioms CheckedNativeOperationRunningEdge.after_frameWordDirectionProjection
#print axioms CheckedNativeOperationRunningEdge.after_eflags_extract_df
#print axioms CheckedNativeOperationStoppedEdge.after_register
#print axioms CheckedNativeOperationStoppedEdge.after_register_of_exact
#print axioms CheckedNativeOperationStoppedEdge.after_memory
#print axioms CheckedNativeOperationStoppedEdge.after_read32_of_checked
#print axioms CheckedNativeOperationStoppedEdge.after_stackWordDirectionProjection
#print axioms CheckedNativeOperationStoppedEdge.after_frameWordDirectionProjection
#print axioms CheckedNativeOperationStoppedEdge.after_eflags_extract_df

end StageA.Relational.InterpreterKernelOperationProjection
