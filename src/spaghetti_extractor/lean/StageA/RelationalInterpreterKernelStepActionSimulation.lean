import StageA.RelationalInterpreterKernelStepOperationClosure

namespace StageA.Relational.InterpreterKernelStepActionSimulation

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelClosedCallTree
open StageA.Relational.InterpreterKernelStepNative
open StageA.Relational.InterpreterKernelStepOperation
open StageA.Relational.InterpreterKernelStepOperationClosure
open StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
open StageA.Relational.InterpreterNativeWorld

/-!
# Composable native simulation of a checked Step action list

The compiled Stage B interpreter executes one semantic action at a time.  Its
native loop may use many blocks and helper calls for one action, but the
semantic derivation is already a finite, ordered list.  This module makes that
list the induction boundary.

Generated proofs establish only:

* the native cursor invariant at the current action;
* one exact candidate path for an unavailable, halted, or continuing action;
* the cursor invariant at the next action; and
* the exact empty-list exit.

The recursive composition below is stable proof logic.  It prevents a binary
specific module from replaying or concatenating an entire action list as one
large theorem, and it keeps the semantic call derivation in every action
witness.
-/

/-- Exact native execution of a complete remaining semantic body.  The result
relation is supplied by the concrete compiled-interpreter proof and must bind
the computed native endpoint to the checked semantic body result.  This is a
predicate rather than data so the proof never extracts a machine endpoint from
the `Prop`-valued semantic derivation. -/
def CheckedInterpreterNativeBodyExecution
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (ResultRelated :
      Option (Sum MacroResult RuntimeState) -> NativeWorldExecution -> Prop)
    (result : Option (Sum MacroResult RuntimeState))
    (before : NativeWorldExecution) : Prop :=
  ∃ after observations,
    ExactComputedInterpreterStepPath template candidate before observations
      after ∧
    ResultRelated result after

/-- One continuing native action iteration.  The exact path ends at a cursor
for the semantic tail; its endpoint is not supplied independently. -/
def CheckedInterpreterNativeActionAdvance
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (CursorRelated :
      RuntimeState -> List SemanticAction -> NativeWorldExecution -> Prop)
    (next : RuntimeState) (tail : List SemanticAction)
    (before : NativeWorldExecution) : Prop :=
  ∃ after observations,
    ExactComputedInterpreterStepPath template candidate before observations
      after ∧
    CursorRelated next tail after

/-- Exact action-phase execution without a submitted endpoint.  This is the
Prop-valued construction surface used by generated derivation proofs before
the existing Type-valued Step certificate selects its checked witnesses. -/
def CheckedInterpreterNativeActionExecution
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    {records : List ProgramRecord} {sourceRva : Nat}
    {before : MachineState} {world : RelationalWorld}
    (lookupPhase :
      InterpreterStepNativeLookupPhase template candidate records sourceRva
        before world) : Prop :=
  ∃ after observations,
    ExactComputedInterpreterStepPath template candidate lookupPhase.afterLookup
      observations after

/-- Four proof families are sufficient for the semantic body constructors.
Each action field is indexed by the exact checked action derivation, so call
actions retain their nested Invoke derivation rather than entering through a
mnemonic or opcode-only rule. -/
structure InterpreterStepNativeBodySimulationAuthority
    (template : InterpreterStepNativeTemplate)
    (candidate : ExactNativeWorldProgram)
    (records : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : StageA.Formal.Word -> Option Nat)
    (transfer : SemanticTransfer)
    (CursorRelated :
      RuntimeState -> List SemanticAction -> NativeWorldExecution -> Prop)
    (ResultRelated :
      Option (Sum MacroResult RuntimeState) -> NativeWorldExecution -> Prop)
    : Prop where
  done : forall runtime before,
    CursorRelated runtime [] before ->
      CheckedInterpreterNativeBodyExecution template candidate ResultRelated
        (some (.inr runtime)) before
  unavailable : forall runtime action tail
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action none)
      before,
    CursorRelated runtime (action :: tail) before ->
      CheckedInterpreterNativeBodyExecution template candidate ResultRelated
        none before
  halted : forall runtime action tail result
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action (some (.inl result)))
      before,
    CursorRelated runtime (action :: tail) before ->
      CheckedInterpreterNativeBodyExecution template candidate ResultRelated
        (some (.inl result)) before
  next : forall runtime action tail next
      (head : CheckedInterpreterActionDerivation records environment
        resolveCodeTarget transfer runtime action (some (.inr next)))
      before,
    CursorRelated runtime (action :: tail) before ->
      CheckedInterpreterNativeActionAdvance template candidate CursorRelated
        next tail before

/-- Compose independently checked native action iterations by structural
induction over the authoritative semantic derivation. -/
theorem InterpreterStepNativeBodySimulationAuthority.simulate
    (authority : InterpreterStepNativeBodySimulationAuthority template
      candidate records environment resolveCodeTarget transfer CursorRelated
      ResultRelated)
    (derivation : CheckedInterpreterBodyDerivation records environment
      resolveCodeTarget transfer runtime actions result)
    (before : NativeWorldExecution)
    (cursorRelated : CursorRelated runtime actions before) :
    CheckedInterpreterNativeBodyExecution template candidate ResultRelated
      result before := by
  cases actions with
  | nil =>
      cases derivation with
      | done runtime =>
          exact authority.done runtime before cursorRelated
  | cons action tail =>
      cases derivation with
      | actionUnavailable runtime action tail head =>
          exact authority.unavailable runtime action tail head before
            cursorRelated
      | actionHalted runtime action tail result head =>
          exact authority.halted runtime action tail result head before
            cursorRelated
      | actionNext runtime action tail next result head rest =>
          obtain ⟨middle, firstObservations, firstPath, middleRelated⟩ :=
            authority.next runtime action tail next head before cursorRelated
          obtain
              ⟨after, remainingObservations, remainingPath, resultRelated⟩ :=
            authority.simulate rest middle middleRelated
          exact ⟨after, firstObservations ++ remainingObservations,
            .trans firstPath remainingPath, resultRelated⟩
termination_by actions.length
decreasing_by simp_all

/-- The composed body execution remains an exact candidate path. -/
theorem CheckedInterpreterNativeBodyExecution.nativePath
    (execution : CheckedInterpreterNativeBodyExecution template candidate
      ResultRelated result before) :
    ∃ after observations,
      InterpreterStepNativePath template candidate before observations after ∧
        ResultRelated result after := by
  obtain ⟨after, observations, path, related⟩ := execution
  exact ⟨after, observations, path.toNativePath, related⟩

/-- Extract the exact computed action execution expected by the existing Step
certificate.  Choice selects only witnesses already constrained by an exact
candidate path; it cannot introduce a path endpoint or transition fact. -/
noncomputable def CheckedInterpreterNativeBodyExecution.toExactActionExecution
    {records : List ProgramRecord} {sourceRva : Nat}
    {before : MachineState} {world : RelationalWorld}
    {lookupPhase :
      InterpreterStepNativeLookupPhase template candidate records sourceRva
        before world}
    (execution : CheckedInterpreterNativeBodyExecution template candidate
      ResultRelated result lookupPhase.afterLookup) :
    InterpreterStepExactActionExecution template candidate lookupPhase := by
  classical
  let after := Classical.choose execution
  have afterWitness := Classical.choose_spec execution
  let observations := Classical.choose afterWitness
  have facts := Classical.choose_spec afterWitness
  exact {
    after
    observations
    path := facts.1
  }

/-- Select the witnesses of a checked Prop-valued action execution.  The
selected path still consists only of exact candidate chunks and subroutines. -/
noncomputable def CheckedInterpreterNativeActionExecution.toExact
    (execution :
      CheckedInterpreterNativeActionExecution template candidate lookupPhase) :
    InterpreterStepExactActionExecution template candidate lookupPhase := by
  classical
  let after := Classical.choose execution
  have afterWitness := Classical.choose_spec execution
  let observations := Classical.choose afterWitness
  have path := Classical.choose_spec afterWitness
  exact {
    after
    observations
    path
  }

#print axioms InterpreterStepNativeBodySimulationAuthority.simulate
#print axioms CheckedInterpreterNativeBodyExecution.nativePath
#print axioms
  CheckedInterpreterNativeBodyExecution.toExactActionExecution
#print axioms CheckedInterpreterNativeActionExecution.toExact

end StageA.Relational.InterpreterKernelStepActionSimulation
