import StageA.RelationalInterpreterKernelCdeclEpilogueSymbolicClosure
import StageA.RelationalInterpreterKernelOperationReplay

namespace StageA.Relational.InterpreterKernelOperationPostcondition

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterKernelOperationReplay

/-!
# Checked operation postconditions

This module factors the common endpoint proof used by Step, Run, and Invoke.
A symbolic behavior is the sole source of register values, writes, flags, and
control outcome.  The checker only compares compact symbolic data.  The
soundness theorem evaluates those checked expressions at the concrete replay
input and derives the concrete endpoint and memory frame.
-/

structure NativeOperationRegisterPostcondition where
  eax : Option Expr := none
  ebx : Option Expr := none
  ecx : Option Expr := none
  edx : Option Expr := none
  esi : Option Expr := none
  edi : Option Expr := none
  ebp : Option Expr := none
  esp : Option Expr := none
deriving Repr, DecidableEq

def optionExprMatches (observed : Expr) : Option Expr -> Bool
  | none => true
  | some expected => observed == expected

def NativeOperationRegisterPostcondition.checked
    (postcondition : NativeOperationRegisterPostcondition)
    (behavior : SymbolicBehavior) : Bool :=
  optionExprMatches behavior.registers.eax postcondition.eax &&
    optionExprMatches behavior.registers.ebx postcondition.ebx &&
    optionExprMatches behavior.registers.ecx postcondition.ecx &&
    optionExprMatches behavior.registers.edx postcondition.edx &&
    optionExprMatches behavior.registers.esi postcondition.esi &&
    optionExprMatches behavior.registers.edi postcondition.edi &&
    optionExprMatches behavior.registers.ebp postcondition.ebp &&
    optionExprMatches behavior.registers.esp postcondition.esp

def NativeOperationRegisterPostcondition.Holds
    (postcondition : NativeOperationRegisterPostcondition)
    (input after : MachineState) : Prop :=
  (∀ expected, postcondition.eax = some expected ->
      after.registers.eax = expected.eval input) ∧
  (∀ expected, postcondition.ebx = some expected ->
      after.registers.ebx = expected.eval input) ∧
  (∀ expected, postcondition.ecx = some expected ->
      after.registers.ecx = expected.eval input) ∧
  (∀ expected, postcondition.edx = some expected ->
      after.registers.edx = expected.eval input) ∧
  (∀ expected, postcondition.esi = some expected ->
      after.registers.esi = expected.eval input) ∧
  (∀ expected, postcondition.edi = some expected ->
      after.registers.edi = expected.eval input) ∧
  (∀ expected, postcondition.ebp = some expected ->
      after.registers.ebp = expected.eval input) ∧
  (∀ expected, postcondition.esp = some expected ->
      after.registers.esp = expected.eval input)

private theorem optionExprMatches_sound
    (observed : Expr) (expected : Option Expr)
    (checked : optionExprMatches observed expected = true) :
    ∀ expression, expected = some expression ->
      observed = expression := by
  cases expected with
  | none =>
      intro expression impossible
      contradiction
  | some expected =>
      simp only [optionExprMatches, beq_iff_eq] at checked
      intro expression exact
      injection exact with exact
      simpa [exact] using checked

theorem NativeOperationRegisterPostcondition.holds_of_checked
    (postcondition : NativeOperationRegisterPostcondition)
    (behavior : SymbolicBehavior) (input after : MachineState)
    (checked : postcondition.checked behavior = true)
    (afterExact :
      after = concreteBehaviorNextMachineState (behavior.eval input) input) :
    postcondition.Holds input after := by
  simp only [NativeOperationRegisterPostcondition.checked,
    Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨eax, ebx⟩, ecx⟩, edx⟩, esi⟩, edi⟩, ebp⟩, esp⟩
  subst after
  change
    (∀ expected, postcondition.eax = some expected ->
      behavior.registers.eax.eval input = expected.eval input) ∧
    (∀ expected, postcondition.ebx = some expected ->
      behavior.registers.ebx.eval input = expected.eval input) ∧
    (∀ expected, postcondition.ecx = some expected ->
      behavior.registers.ecx.eval input = expected.eval input) ∧
    (∀ expected, postcondition.edx = some expected ->
      behavior.registers.edx.eval input = expected.eval input) ∧
    (∀ expected, postcondition.esi = some expected ->
      behavior.registers.esi.eval input = expected.eval input) ∧
    (∀ expected, postcondition.edi = some expected ->
      behavior.registers.edi.eval input = expected.eval input) ∧
    (∀ expected, postcondition.ebp = some expected ->
      behavior.registers.ebp.eval input = expected.eval input) ∧
    (∀ expected, postcondition.esp = some expected ->
      behavior.registers.esp.eval input = expected.eval input)
  exact ⟨fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ eax expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ ebx expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ ecx expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ edx expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ esi expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ edi expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ ebp expected exact),
    fun expected exact =>
      congrArg (Expr.eval input)
        (optionExprMatches_sound _ _ esp expected exact)⟩

inductive NativeOperationOutcomePostcondition where
  | running
  | returned (target : Expr)
  | jumped (targetRva : Nat)
  | branched (condition : BoolExpr) (trueTarget falseTarget : Nat)
  | called (targetRva continuationRva returnAddress : Nat)
  | indirectCall (target : Expr) (continuationRva returnAddress : Nat)
  | indirectJump (target : Expr)
  | externalCall (imported : PEImport) (arguments : List Expr)
      (continuationRva : Nat)
  | externalJump (imported : PEImport) (arguments : List Expr)
  | bulkCopy (copy : BulkCopyExpr) (continuationRva : Nat)
  | bulkFill (fill : BulkFillExpr) (continuationRva : Nat)
  | bulkScan (scan : BulkScanExpr) (continuationRva : Nat)
  | checkedContinue (valid : BoolExpr) (continuationRva : Nat)
  | atomicCompareExchange (address expected replacement : Expr)
      (continuationRva : Nat)
deriving Repr, DecidableEq

def NativeOperationOutcomePostcondition.expected :
    NativeOperationOutcomePostcondition -> Option OutcomeExpr
  | .running => none
  | .returned target => some (.returned target)
  | .jumped targetRva => some (.jump targetRva)
  | .branched condition trueTarget falseTarget =>
      some (.branch condition trueTarget falseTarget)
  | .called targetRva continuationRva returnAddress =>
      some (.call targetRva continuationRva returnAddress)
  | .indirectCall target continuationRva returnAddress =>
      some (.indirectCall target continuationRva returnAddress)
  | .indirectJump target => some (.indirectJump target)
  | .externalCall imported arguments continuationRva =>
      some (.externalCall imported arguments continuationRva)
  | .externalJump imported arguments =>
      some (.externalJump imported arguments)
  | .bulkCopy copy continuationRva =>
      some (.bulkCopy copy continuationRva)
  | .bulkFill fill continuationRva =>
      some (.bulkFill fill continuationRva)
  | .bulkScan scan continuationRva =>
      some (.bulkScan scan continuationRva)
  | .checkedContinue valid continuationRva =>
      some (.checkedContinue valid continuationRva)
  | .atomicCompareExchange address expected replacement continuationRva =>
      some (.atomicCompareExchange address expected replacement
        continuationRva)

def NativeOperationOutcomePostcondition.ofExpr :
    OutcomeExpr -> NativeOperationOutcomePostcondition
  | .returned target => .returned target
  | .jump targetRva => .jumped targetRva
  | .branch condition trueTarget falseTarget =>
      .branched condition trueTarget falseTarget
  | .call targetRva continuationRva returnAddress =>
      .called targetRva continuationRva returnAddress
  | .indirectCall target continuationRva returnAddress =>
      .indirectCall target continuationRva returnAddress
  | .indirectJump target => .indirectJump target
  | .externalCall imported arguments continuationRva =>
      .externalCall imported arguments continuationRva
  | .externalJump imported arguments =>
      .externalJump imported arguments
  | .bulkCopy copy continuationRva => .bulkCopy copy continuationRva
  | .bulkFill fill continuationRva => .bulkFill fill continuationRva
  | .bulkScan scan continuationRva => .bulkScan scan continuationRva
  | .checkedContinue valid continuationRva =>
      .checkedContinue valid continuationRva
  | .atomicCompareExchange address expected replacement continuationRva =>
      .atomicCompareExchange address expected replacement continuationRva

@[simp] theorem NativeOperationOutcomePostcondition.expected_ofExpr
    (outcome : OutcomeExpr) :
    (NativeOperationOutcomePostcondition.ofExpr outcome).expected =
      some outcome := by
  cases outcome <;> rfl

def evalNativeOperationOutcomeExpr
    (state : MachineState) : OutcomeExpr -> ConcreteOutcome
  | .returned target => .returned (target.eval state)
  | .jump targetRva => .jump targetRva
  | .branch condition trueTargetRva falseTargetRva =>
      .branch (condition.eval state) trueTargetRva falseTargetRva
  | .call targetRva returnRva returnAddress =>
      .call targetRva returnRva returnAddress
  | .externalCall imported arguments returnRva =>
      .externalCall imported (arguments.map (Expr.eval state)) returnRva
  | .externalJump imported arguments =>
      .externalJump imported (arguments.map (Expr.eval state))
  | .bulkCopy copy continuationRva =>
      .bulkCopy (copy.destination.eval state) (copy.source.eval state)
        (copy.count.eval state) (copy.direction.eval state) continuationRva
  | .bulkFill fill continuationRva =>
      .bulkFill (fill.destination.eval state) (fill.value.eval state)
        (fill.count.eval state) (fill.direction.eval state) continuationRva
  | .bulkScan scan continuationRva =>
      .bulkScan (scan.accumulator.eval state) (scan.destination.eval state)
        (scan.count.eval state) (scan.direction.eval state) continuationRva
  | .indirectCall target continuationRva returnAddress =>
      .indirectCall (target.eval state) continuationRva returnAddress
  | .indirectJump target => .indirectJump (target.eval state)
  | .checkedContinue valid continuationRva =>
      .checkedContinue (valid.eval state) continuationRva
  | .atomicCompareExchange address expected replacement continuationRva =>
      .atomicCompareExchange (address.eval state) (expected.eval state)
        (replacement.eval state) continuationRva

def NativeOperationOutcomePostcondition.checked
    (postcondition : NativeOperationOutcomePostcondition)
    (behavior : SymbolicBehavior) : Bool :=
  behavior.outcome == postcondition.expected

theorem NativeOperationOutcomePostcondition.exact_of_checked
    (postcondition : NativeOperationOutcomePostcondition)
    (behavior : SymbolicBehavior)
    (checked : postcondition.checked behavior = true) :
    behavior.outcome = postcondition.expected :=
  beq_iff_eq.mp checked

/-- A compact postcondition checked against one exact symbolic replay summary.
The write footprint is always projected from the summary and cannot be
independently widened by generated data. -/
structure CheckedNativeOperationPostcondition
    (behavior : SymbolicBehavior) where
  registers : NativeOperationRegisterPostcondition
  outcome : NativeOperationOutcomePostcondition
  registersChecked : registers.checked behavior = true
  outcomeChecked : outcome.checked behavior = true

def CheckedNativeOperationPostcondition.ofStoppedReplay
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot) :
    CheckedNativeOperationPostcondition replay.behavior := {
  registers := {}
  outcome := NativeOperationOutcomePostcondition.ofExpr
    (replay.behavior.outcome.getD (.jump 0))
  registersChecked := by
    simp [NativeOperationRegisterPostcondition.checked, optionExprMatches]
  outcomeChecked := by
    have some := replay.resultFacts.2
    cases exact : replay.behavior.outcome with
    | none =>
        simp [exact] at some
    | some outcome =>
        simp [NativeOperationOutcomePostcondition.checked, exact]
}

def CheckedNativeOperationPostcondition.writeFootprint
    {behavior : SymbolicBehavior}
    (_postcondition : CheckedNativeOperationPostcondition behavior)
    (input : MachineState) : CheckedCDeclWriteFootprint :=
  symbolicWriteFootprint behavior input

theorem CheckedNativeOperationPostcondition.memoryFrame
    {behavior : SymbolicBehavior}
    (postcondition : CheckedNativeOperationPostcondition behavior)
    (input : MachineState) :
    MemoryAgreesOutside (postcondition.writeFootprint input).contains
      (concreteBehaviorNextMachineState (behavior.eval input) input).memory
      input.memory := by
  exact symbolicWriteFootprint.memoryFrame behavior input

theorem CheckedNativeOperationPostcondition.registersHold
    {behavior : SymbolicBehavior}
    (postcondition : CheckedNativeOperationPostcondition behavior)
    (input after : MachineState)
    (afterExact :
      after = concreteBehaviorNextMachineState (behavior.eval input) input) :
    postcondition.registers.Holds input after :=
  postcondition.registers.holds_of_checked behavior input after
    postcondition.registersChecked afterExact

theorem CheckedNativeOperationPostcondition.outcomeExact
    {behavior : SymbolicBehavior}
    (postcondition : CheckedNativeOperationPostcondition behavior) :
    behavior.outcome = postcondition.outcome.expected :=
  postcondition.outcome.exact_of_checked behavior postcondition.outcomeChecked

theorem CheckedNativeOperationPostcondition.evaluatedOutcomeExact
    {behavior : SymbolicBehavior}
    (postcondition : CheckedNativeOperationPostcondition behavior)
    (state : MachineState) :
    (behavior.eval state).outcome =
      postcondition.outcome.expected.map
        (evalNativeOperationOutcomeExpr state) := by
  change behavior.outcome.map (evalNativeOperationOutcomeExpr state) =
    postcondition.outcome.expected.map
      (evalNativeOperationOutcomeExpr state)
  rw [postcondition.outcomeExact]

theorem CheckedNativeOperationPostcondition.evaluatedOutcomeGetDExact
    {behavior : SymbolicBehavior}
    (postcondition : CheckedNativeOperationPostcondition behavior)
    (state : MachineState) :
    (behavior.eval state).outcome.getD (.jump 0) =
      (postcondition.outcome.expected.map
        (evalNativeOperationOutcomeExpr state)).getD (.jump 0) :=
  congrArg (fun outcome => outcome.getD (.jump 0))
    (postcondition.evaluatedOutcomeExact state)

/-! ## Exact-instruction adapters

These adapters connect a compact checked postcondition to the exact
single-instruction replay leaf.  Their successor state is definitionally the
state computed by reviewed symbolic semantics; no post-state equality is a
certificate field.
-/

theorem CheckedNativeOperationPostcondition.runningRegistersHold
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot)
    (postcondition :
      CheckedNativeOperationPostcondition replay.behavior)
    (input : MachineState) :
    postcondition.registers.Holds input
      (concreteBehaviorNextMachineState (replay.behavior.eval input) input) :=
  postcondition.registersHold input _ rfl

theorem CheckedNativeOperationPostcondition.runningMemoryFrame
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot)
    (postcondition :
      CheckedNativeOperationPostcondition replay.behavior)
    (input : MachineState) :
    MemoryAgreesOutside (postcondition.writeFootprint input).contains
      (concreteBehaviorNextMachineState
        (replay.behavior.eval input) input).memory
      input.memory :=
  postcondition.memoryFrame input

theorem CheckedNativeOperationPostcondition.stoppedRegistersHold
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (postcondition :
      CheckedNativeOperationPostcondition replay.behavior)
    (input : MachineState) :
    postcondition.registers.Holds input
      (concreteBehaviorNextMachineState (replay.behavior.eval input) input) :=
  postcondition.registersHold input _ rfl

theorem CheckedNativeOperationPostcondition.stoppedMemoryFrame
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (postcondition :
      CheckedNativeOperationPostcondition replay.behavior)
    (input : MachineState) :
    MemoryAgreesOutside (postcondition.writeFootprint input).contains
      (concreteBehaviorNextMachineState
        (replay.behavior.eval input) input).memory
      input.memory :=
  postcondition.memoryFrame input

/-- Frame two sequential updates.  The protected predicate is stable when each
leaf preserves it; storage class is irrelevant. -/
theorem MemoryAgreesOutside.trans
    {footprint : Word -> Prop} {before middle after : Memory}
    (first : MemoryAgreesOutside footprint middle before)
    (second : MemoryAgreesOutside footprint after middle) :
    MemoryAgreesOutside footprint after before := by
  intro address outside
  rw [second address outside, first address outside]

#print axioms NativeOperationRegisterPostcondition.holds_of_checked
#print axioms NativeOperationOutcomePostcondition.exact_of_checked
#print axioms CheckedNativeOperationPostcondition.memoryFrame
#print axioms CheckedNativeOperationPostcondition.registersHold
#print axioms CheckedNativeOperationPostcondition.outcomeExact
#print axioms CheckedNativeOperationPostcondition.evaluatedOutcomeExact
#print axioms CheckedNativeOperationPostcondition.evaluatedOutcomeGetDExact
#print axioms CheckedNativeOperationPostcondition.runningRegistersHold
#print axioms CheckedNativeOperationPostcondition.runningMemoryFrame
#print axioms CheckedNativeOperationPostcondition.stoppedRegistersHold
#print axioms CheckedNativeOperationPostcondition.stoppedMemoryFrame
#print axioms MemoryAgreesOutside.trans

end StageA.Relational.InterpreterKernelOperationPostcondition
