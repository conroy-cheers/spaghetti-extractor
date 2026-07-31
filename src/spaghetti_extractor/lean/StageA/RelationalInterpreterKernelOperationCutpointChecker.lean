import StageA.RelationalInvariant
import StageA.RelationalInterpreterKernelOperationPostcondition

namespace StageA.Relational.InterpreterKernelOperationCutpointChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationReplay
open StageA.Relational.InterpreterNativeWorld

/-!
# Reflective operation cutpoint checking

Operation proofs retain instruction-granular execution.  This module checks
Hoare-style cutpoint invariants by pulling every target predicate backwards
through the exact symbolic effect of one checked instruction.  Generated data
cannot submit an endpoint state or execution equation.
-/

structure NativeOperationInvariant where
  predicates : List BoolExpr
deriving Repr, DecidableEq

def NativeOperationInvariant.Holds
    (invariant : NativeOperationInvariant) (state : MachineState) : Prop :=
  invariant.predicates.all (fun predicate => predicate.eval state) = true

/-- Project the state effect represented by `SymbolicBehavior` into the
normalized effect language used by the reviewed invariant pullback checker.
`flagsBase` is rejected until its explicit flag-bit pullback is represented. -/
def operationInvariantEffect? (behavior : SymbolicBehavior) :
    Option NormalizedSymbolicBehavior :=
  if behavior.flagsBase.isNone then
    some {
      registers := behavior.registers
      x87 := behavior.x87
      writes := behavior.writes
      flags := behavior.flags
      outcome := .jump 0
    }
  else
    none

private theorem evaluatedWrites_foldl
    (state : MachineState) (writes : List (Expr × Expr))
    (memory : Memory) :
    List.foldl (fun current write => current.write32 write.1 write.2) memory
        (writes.map fun write => (write.1.eval state, write.2.eval state)) =
      List.foldl
        (fun current write =>
          current.write32 (write.1.eval state) (write.2.eval state))
        memory writes := by
  induction writes generalizing memory with
  | nil => rfl
  | cons write tail induction =>
      simp only [List.map_cons, List.foldl_cons]
      exact induction _

theorem operationInvariantEffect?_nextMachineState
    (behavior : SymbolicBehavior) (effect : NormalizedSymbolicBehavior)
    (checked : operationInvariantEffect? behavior = some effect)
    (state : MachineState) :
    (effect.eval state).nextMachineState state =
      concreteBehaviorNextMachineState (behavior.eval state) state := by
  rcases behavior with
    ⟨registers, x87, writes, comparison, flagsBase, flags, outcome⟩
  cases flagsBase with
  | none =>
      simp only [operationInvariantEffect?, Option.isNone_none, if_true,
        Option.some.injEq] at checked
      subst effect
      simp [NormalizedSymbolicBehavior.eval, SymbolicBehavior.eval,
        RelationalBehavior.nextMachineState, concreteBehaviorNextMachineState,
        evalNormalizedRegisters, evalNormalizedX87, evalNormalizedWrites,
        evalNormalizedFlags, applyConcreteWrites, applyWrites]
      constructor
      · exact evaluatedWrites_foldl state writes state.memory
      · cases flags <;> rfl
  | some base =>
      simp [operationInvariantEffect?] at checked

def nativeOperationInvariantEdgeChecked
    (source target : NativeOperationInvariant)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  target.predicates.all fun predicate =>
    match predicate.edgePullbackExpression behavior with
    | some pulled => source.predicates.contains pulled
    | none => false

def NativeOperationInvariant.pullback?
    (target : NativeOperationInvariant)
    (behavior : NormalizedSymbolicBehavior) :
    Option NativeOperationInvariant := do
  let predicates <- target.predicates.mapM
    (fun predicate => predicate.edgePullbackExpression behavior)
  pure { predicates }

private theorem mapM_eq_some_of_mem
    (transform : α -> Option β) :
    ∀ (input : List α) (output : List β),
      input.mapM transform = some output ->
      ∀ item, item ∈ input ->
        ∃ mapped, mapped ∈ output ∧ transform item = some mapped := by
  intro input
  induction input with
  | nil =>
      intro output exact item member
      simp at member
  | cons head tail induction =>
      intro output exact item member
      cases headExact : transform head with
      | none =>
          simp [List.mapM_cons, headExact] at exact
      | some mappedHead =>
          cases tailExact : tail.mapM transform with
          | none =>
              simp [List.mapM_cons, headExact, tailExact] at exact
          | some mappedTail =>
              simp [List.mapM_cons, headExact, tailExact] at exact
              subst output
              simp only [List.mem_cons] at member
              cases member with
              | inl itemExact =>
                  subst item
                  exact ⟨mappedHead, by simp, headExact⟩
              | inr tailMember =>
                  obtain ⟨mapped, mappedMember, mappedExact⟩ :=
                    induction mappedTail tailExact item tailMember
                  exact ⟨mapped, by simp [mappedMember], mappedExact⟩

theorem NativeOperationInvariant.pullback?_sound
    (target source : NativeOperationInvariant)
    (behavior : NormalizedSymbolicBehavior)
    (checked : target.pullback? behavior = some source)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds ((behavior.eval state).nextMachineState state) := by
  simp only [NativeOperationInvariant.pullback?] at checked
  cases pulledExact : target.predicates.mapM
      (fun predicate => predicate.edgePullbackExpression behavior) with
  | none =>
      simp [pulledExact] at checked
  | some predicates =>
      simp [pulledExact] at checked
      subst source
      simp only [NativeOperationInvariant.Holds, List.all_eq_true] at sourceHolds ⊢
      intro predicate member
      obtain ⟨pulled, pulledMember, pullbackExact⟩ :=
        mapM_eq_some_of_mem
          (fun item => item.edgePullbackExpression behavior)
          target.predicates predicates pulledExact predicate member
      rw [← predicate.eval_edgePullbackExpression behavior state pulled
        pullbackExact]
      exact sourceHolds pulled pulledMember

theorem nativeOperationInvariantEdgeChecked_of_pullback
    (source target : NativeOperationInvariant)
    (behavior : NormalizedSymbolicBehavior)
    (pullbackExact : target.pullback? behavior = some source) :
    nativeOperationInvariantEdgeChecked source target behavior = true := by
  simp only [nativeOperationInvariantEdgeChecked, List.all_eq_true]
  intro predicate member
  simp only [NativeOperationInvariant.pullback?] at pullbackExact
  cases mappedExact : target.predicates.mapM
      (fun item => item.edgePullbackExpression behavior) with
  | none => simp [mappedExact] at pullbackExact
  | some predicates =>
      simp [mappedExact] at pullbackExact
      subst source
      obtain ⟨pulled, pulledMember, exact⟩ :=
        mapM_eq_some_of_mem
          (fun item => item.edgePullbackExpression behavior)
          target.predicates predicates mappedExact predicate member
      simpa [exact] using pulledMember

theorem nativeOperationInvariantEdgeChecked_sound
    (source target : NativeOperationInvariant)
    (behavior : NormalizedSymbolicBehavior)
    (checked :
      nativeOperationInvariantEdgeChecked source target behavior = true)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds ((behavior.eval state).nextMachineState state) := by
  simp only [NativeOperationInvariant.Holds, List.all_eq_true] at sourceHolds ⊢
  intro predicate member
  simp only [nativeOperationInvariantEdgeChecked, List.all_eq_true] at checked
  have row := checked predicate member
  cases pulledExact :
      predicate.edgePullbackExpression behavior with
  | none =>
      simp [pulledExact] at row
  | some pulled =>
      have pulledMember : pulled ∈ source.predicates := by
        simpa [pulledExact] using row
      rw [← predicate.eval_edgePullbackExpression behavior state pulled
        pulledExact]
      exact sourceHolds pulled pulledMember

def trivialNativeOperationInvariant : NativeOperationInvariant := {
  predicates := []
}

@[simp] theorem trivialNativeOperationInvariant_holds
    (state : MachineState) :
    trivialNativeOperationInvariant.Holds state := by
  rfl

/-- Checked invariant transport. The trivial arm is exact: both invariants are
literally empty and therefore hold for every concrete state. -/
inductive CheckedNativeOperationInvariantTransfer
    (behavior : SymbolicBehavior) :
    NativeOperationInvariant -> NativeOperationInvariant -> Type
  | normalized
      (source target : NativeOperationInvariant)
      (effect : NormalizedSymbolicBehavior)
      (effectExact : operationInvariantEffect? behavior = some effect)
      (invariantChecked :
        nativeOperationInvariantEdgeChecked source target effect = true) :
      CheckedNativeOperationInvariantTransfer behavior source target
  | trivial :
      CheckedNativeOperationInvariantTransfer behavior
        trivialNativeOperationInvariant trivialNativeOperationInvariant

theorem CheckedNativeOperationInvariantTransfer.sound
    {behavior : SymbolicBehavior}
    {source target : NativeOperationInvariant}
    (transfer :
      CheckedNativeOperationInvariantTransfer behavior source target)
    (state : MachineState) (sourceHolds : source.Holds state) :
    target.Holds
      (concreteBehaviorNextMachineState (behavior.eval state) state) := by
  cases transfer with
  | normalized source target effect effectExact invariantChecked =>
      rw [← operationInvariantEffect?_nextMachineState behavior effect
        effectExact state]
      exact nativeOperationInvariantEdgeChecked_sound source target effect
        invariantChecked state sourceHolds
  | trivial =>
      exact trivialNativeOperationInvariant_holds _

/-- A checked one-instruction cutpoint edge. Exact bytes and symbolic
semantics come from `replay`; invariant preservation comes from one of the
checked transfer constructors above. -/
structure CheckedNativeOperationRunningCutpoint
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot) where
  source : NativeOperationInvariant
  target : NativeOperationInvariant
  transfer :
    CheckedNativeOperationInvariantTransfer replay.behavior source target

def CheckedNativeOperationRunningCutpoint.ofCanonicalPullback
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot)
    (target source : NativeOperationInvariant)
    (effect : NormalizedSymbolicBehavior)
    (effectExact : operationInvariantEffect? replay.behavior = some effect)
    (pullbackExact : target.pullback? effect = some source) :
    CheckedNativeOperationRunningCutpoint replay := {
  source
  target
  transfer := .normalized source target effect effectExact
    (nativeOperationInvariantEdgeChecked_of_pullback source target effect
      pullbackExact)
}

def CheckedNativeOperationRunningCutpoint.ofTrivial
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot) :
    CheckedNativeOperationRunningCutpoint replay := {
  source := trivialNativeOperationInvariant
  target := trivialNativeOperationInvariant
  transfer := .trivial
}

theorem CheckedNativeOperationRunningCutpoint.replayTargetHolds
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    {replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot}
    (cutpoint : CheckedNativeOperationRunningCutpoint replay)
    (state : MachineState) (sourceHolds : cutpoint.source.Holds state) :
    cutpoint.target.Holds
      (concreteBehaviorNextMachineState (replay.behavior.eval state) state) :=
  cutpoint.transfer.sound state sourceHolds

theorem CheckedNativeOperationRunningCutpoint.targetHolds
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    {replay : CheckedNativeOperationRunningInstruction candidate instruction
      undefinedSlot}
    (cutpoint : CheckedNativeOperationRunningCutpoint replay)
    (state : MachineState) (sourceHolds : cutpoint.source.Holds state) :
    cutpoint.target.Holds
      (concreteBehaviorNextMachineState (replay.behavior.eval state) state) :=
  cutpoint.replayTargetHolds state sourceHolds

/-- Stopped control is checked against the same exact symbolic behavior. -/
structure CheckedNativeOperationStoppedCutpoint
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot) where
  source : NativeOperationInvariant
  target : NativeOperationInvariant
  transfer :
    CheckedNativeOperationInvariantTransfer replay.behavior source target
  postcondition : CheckedNativeOperationPostcondition replay.behavior

def CheckedNativeOperationStoppedCutpoint.ofCanonicalPullback
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (target source : NativeOperationInvariant)
    (effect : NormalizedSymbolicBehavior)
    (effectExact : operationInvariantEffect? replay.behavior = some effect)
    (pullbackExact : target.pullback? effect = some source)
    (postcondition : CheckedNativeOperationPostcondition replay.behavior) :
    CheckedNativeOperationStoppedCutpoint replay := {
  source
  target
  transfer := .normalized source target effect effectExact
    (nativeOperationInvariantEdgeChecked_of_pullback source target effect
      pullbackExact)
  postcondition
}

def CheckedNativeOperationStoppedCutpoint.ofTrivial
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    (replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot)
    (postcondition : CheckedNativeOperationPostcondition replay.behavior) :
    CheckedNativeOperationStoppedCutpoint replay := {
  source := trivialNativeOperationInvariant
  target := trivialNativeOperationInvariant
  transfer := .trivial
  postcondition
}

theorem CheckedNativeOperationStoppedCutpoint.replayTargetHolds
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    {replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot}
    (cutpoint : CheckedNativeOperationStoppedCutpoint replay)
    (state : MachineState) (sourceHolds : cutpoint.source.Holds state) :
    cutpoint.target.Holds
      (concreteBehaviorNextMachineState (replay.behavior.eval state) state) :=
  cutpoint.transfer.sound state sourceHolds

theorem CheckedNativeOperationStoppedCutpoint.outcomeExact
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    {replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot}
    (cutpoint : CheckedNativeOperationStoppedCutpoint replay) :
    replay.behavior.outcome = cutpoint.postcondition.outcome.expected :=
  cutpoint.postcondition.outcomeExact

theorem CheckedNativeOperationStoppedCutpoint.worldStepExpected
    {candidate : ExactNativeWorldProgram}
    {instruction : KernelInstruction} {undefinedSlot : Nat}
    {replay : CheckedNativeOperationStoppedInstruction candidate instruction
      undefinedSlot}
    (cutpoint : CheckedNativeOperationStoppedCutpoint replay)
    (input : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    candidate.transitionSystem.step
        (.running instruction.rva undefinedSlot input calls eventIndex events
          world) =
      transitionFromNativeWorldOutcome candidate.pe candidate.environment
        candidate.callableExternal candidate.indirectTargets instruction.rva
        (concreteBehaviorNextMachineState (replay.behavior.eval input) input)
        calls eventIndex events world
        ((cutpoint.postcondition.outcome.expected.map
          (evalNativeOperationOutcomeExpr input)).getD (.jump 0)) := by
  rw [replay.worldStepExact]
  rw [cutpoint.postcondition.evaluatedOutcomeGetDExact]

#print axioms operationInvariantEffect?_nextMachineState
#print axioms nativeOperationInvariantEdgeChecked_sound
#print axioms nativeOperationInvariantEdgeChecked_of_pullback
#print axioms CheckedNativeOperationInvariantTransfer.sound
#print axioms CheckedNativeOperationRunningCutpoint.targetHolds
#print axioms CheckedNativeOperationRunningCutpoint.replayTargetHolds
#print axioms CheckedNativeOperationStoppedCutpoint.replayTargetHolds
#print axioms CheckedNativeOperationStoppedCutpoint.outcomeExact
#print axioms CheckedNativeOperationStoppedCutpoint.worldStepExpected

end StageA.Relational.InterpreterKernelOperationCutpointChecker
