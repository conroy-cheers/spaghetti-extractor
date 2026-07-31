import StageA.RelationalInterpreterKernelOperationBoundaryChecker

namespace StageA.Relational.InterpreterKernelOperationGraphChecker

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Checked native-operation block graph

Generated operation artifacts provide exact `CheckedNativeOperationBlock`
certificates.  This module resolves a computed running transition back into
that finite inventory.  The successor RVA, slot, state, frame stack, event
state, and world are obtained by pattern matching on the exact transition;
none is accepted as an endpoint premise.

The target invariant is checked against the source block's exact terminal
invariant.  Consequently a successful result can be composed immediately with
the checked target block.
-/

structure CheckedNativeOperationBlockLookup
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate))
    (entryRva entrySlot : Nat) where
  block : CheckedNativeOperationBlock candidate
  member : block ∈ blocks
  entryRvaExact : block.entryRva = entryRva
  entrySlotExact : block.entrySlot = entrySlot

def checkedNativeOperationBlockLookup?
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate))
    (entryRva entrySlot : Nat) :
    Option (CheckedNativeOperationBlockLookup candidate blocks entryRva
      entrySlot) :=
  match blocks with
  | [] => none
  | block :: tail =>
      if entryRvaExact : block.entryRva = entryRva then
        if entrySlotExact : block.entrySlot = entrySlot then
          some {
            block
            member := .head _
            entryRvaExact
            entrySlotExact
          }
        else
          match checkedNativeOperationBlockLookup? candidate tail entryRva
              entrySlot with
          | none => none
          | some found =>
              some {
                block := found.block
                member := .tail _ found.member
                entryRvaExact := found.entryRvaExact
                entrySlotExact := found.entrySlotExact
              }
      else
        match checkedNativeOperationBlockLookup? candidate tail entryRva
            entrySlot with
        | none => none
        | some found =>
            some {
              block := found.block
              member := .tail _ found.member
              entryRvaExact := found.entryRvaExact
              entrySlotExact := found.entrySlotExact
            }

def nativeOperationOutcomeStatePreserving :
    NativeOperationOutcomePostcondition -> Bool
  | .returned _ | .jumped _ | .branched .. | .called ..
  | .checkedContinue _ _ => true
  | _ => false

def checkedNativeOperationInvariantLink
    (source target : CheckedNativeOperationBlock candidate) : Bool :=
  checkedNativeOperationBlockSourceInvariant target ==
      trivialNativeOperationInvariant ||
    (source.terminal.cutpoint.target ==
        checkedNativeOperationBlockSourceInvariant target &&
      nativeOperationOutcomeStatePreserving
        source.terminal.cutpoint.postcondition.outcome)

def nativeOperationOutcomeLocalTargets :
    NativeOperationOutcomePostcondition -> List Nat
  | .jumped targetRva => [targetRva]
  | .branched _ trueTarget falseTarget =>
      if trueTarget == falseTarget then [trueTarget]
      else [trueTarget, falseTarget]
  | .called targetRva _ _ => [targetRva]
  | .bulkCopy _ continuationRva
  | .bulkFill _ continuationRva
  | .checkedContinue _ continuationRva
  | .atomicCompareExchange _ _ _ continuationRva => [continuationRva]
  | .running | .returned _ | .indirectCall .. | .indirectJump _
  | .externalCall .. | .externalJump .. => []

def checkedNativeOperationGraphTargetCovered
    (blocks : List (CheckedNativeOperationBlock candidate))
    (source : CheckedNativeOperationBlock candidate)
    (targetRva : Nat) : Bool :=
  blocks.any fun target =>
    target.entryRva == targetRva &&
      target.entrySlot == 0 &&
      checkedNativeOperationInvariantLink source target

/-- Reflective direct-control closure. Indirect and external boundaries are
deliberately excluded and must be discharged by their typed boundary
certificates. -/
def checkedNativeOperationGraphClosed
    (blocks : List (CheckedNativeOperationBlock candidate)) : Bool :=
  blocks.all fun source =>
    (nativeOperationOutcomeLocalTargets
      source.terminal.cutpoint.postcondition.outcome).all
      (checkedNativeOperationGraphTargetCovered blocks source)

/-- Direct-control closure with explicit typed boundaries. A boundary target is
not treated as locally executed code: its separate bridge/callback/import
certificate must discharge the continuation before composition can proceed. -/
def checkedNativeOperationGraphTargetCoveredOrBoundary
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaryTargets : List Nat)
    (source : CheckedNativeOperationBlock candidate)
    (targetRva : Nat) : Bool :=
  checkedNativeOperationGraphTargetCovered blocks source targetRva ||
    boundaryTargets.contains targetRva

def checkedNativeOperationGraphClosedWithBoundaries
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaryTargets : List Nat) : Bool :=
  blocks.all fun source =>
    (nativeOperationOutcomeLocalTargets
      source.terminal.cutpoint.postcondition.outcome).all fun targetRva =>
        checkedNativeOperationGraphTargetCoveredOrBoundary blocks
          boundaryTargets source targetRva

structure CheckedNativeOperationGraphTarget
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (source : CheckedNativeOperationBlock candidate)
    (targetRva : Nat) where
  target : CheckedNativeOperationBlock candidate
  member : target ∈ blocks
  entryRvaExact : target.entryRva = targetRva
  entrySlotExact : target.entrySlot = 0
  invariantChecked :
    checkedNativeOperationInvariantLink source target = true

inductive CheckedNativeOperationGraphDestination
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaryTargets : List Nat)
    (source : CheckedNativeOperationBlock candidate)
    (targetRva : Nat) : Type where
  | local (target : CheckedNativeOperationGraphTarget blocks source targetRva)
  | boundary (member : targetRva ∈ boundaryTargets)

theorem checkedNativeOperationGraphTargetCovered_sound
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (source : CheckedNativeOperationBlock candidate)
    (targetRva : Nat)
    (checked :
      checkedNativeOperationGraphTargetCovered blocks source targetRva = true) :
    Nonempty (CheckedNativeOperationGraphTarget blocks source targetRva) := by
  simp only [checkedNativeOperationGraphTargetCovered, List.any_eq_true]
    at checked
  obtain ⟨target, member, targetChecked⟩ := checked
  simp only [Bool.and_eq_true, beq_iff_eq] at targetChecked
  exact ⟨{
    target
    member
    entryRvaExact := targetChecked.1.1
    entrySlotExact := targetChecked.1.2
    invariantChecked := targetChecked.2
  }⟩

theorem checkedNativeOperationGraphClosed_target
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (checked : checkedNativeOperationGraphClosed blocks = true)
    (source : CheckedNativeOperationBlock candidate)
    (sourceMember : source ∈ blocks)
    (targetRva : Nat)
    (targetMember :
      targetRva ∈
        nativeOperationOutcomeLocalTargets
          source.terminal.cutpoint.postcondition.outcome) :
    Nonempty (CheckedNativeOperationGraphTarget blocks source targetRva) := by
  simp only [checkedNativeOperationGraphClosed, List.all_eq_true] at checked
  have sourceChecked := checked source sourceMember
  simp only [List.all_eq_true] at sourceChecked
  exact checkedNativeOperationGraphTargetCovered_sound blocks source targetRva
    (sourceChecked targetRva targetMember)

theorem checkedNativeOperationGraphClosedWithBoundaries_target
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (boundaryTargets : List Nat)
    (checked :
      checkedNativeOperationGraphClosedWithBoundaries blocks boundaryTargets =
        true)
    (source : CheckedNativeOperationBlock candidate)
    (sourceMember : source ∈ blocks)
    (targetRva : Nat)
    (targetMember :
      targetRva ∈
        nativeOperationOutcomeLocalTargets
          source.terminal.cutpoint.postcondition.outcome) :
    Nonempty (CheckedNativeOperationGraphDestination blocks boundaryTargets
      source targetRva) := by
  simp only [checkedNativeOperationGraphClosedWithBoundaries,
    List.all_eq_true] at checked
  have sourceChecked := checked source sourceMember
  simp only [List.all_eq_true] at sourceChecked
  have targetChecked := sourceChecked targetRva targetMember
  simp only [checkedNativeOperationGraphTargetCoveredOrBoundary,
    Bool.or_eq_true] at targetChecked
  cases targetChecked with
  | inl localChecked =>
      obtain ⟨target⟩ :=
        checkedNativeOperationGraphTargetCovered_sound blocks source targetRva
          localChecked
      exact ⟨.local target⟩
  | inr boundaryChecked =>
      exact ⟨.boundary (by simpa using boundaryChecked)⟩

private theorem checkedNativeOperationInvariantLink_target
    {candidate : ExactNativeWorldProgram}
    (source target : CheckedNativeOperationBlock candidate)
    (checked : checkedNativeOperationInvariantLink source target = true) :
    checkedNativeOperationBlockSourceInvariant target =
        trivialNativeOperationInvariant ∨
      (source.terminal.cutpoint.target =
          checkedNativeOperationBlockSourceInvariant target ∧
        nativeOperationOutcomeStatePreserving
          source.terminal.cutpoint.postcondition.outcome = true) := by
  simpa [checkedNativeOperationInvariantLink, Bool.or_eq_true,
    Bool.and_eq_true, beq_iff_eq] using checked

private theorem checkedNativeOperationInvariantLink_machineState
    {candidate : ExactNativeWorldProgram}
    (source : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (targetRva targetSlot : Nat) (targetState : MachineState)
    (targetCalls : List NativeCallFrame) (targetEventIndex : Nat)
    (targetEvents : List NativeExternalEvent)
    (targetWorld : RelationalWorld)
    (preserving :
      nativeOperationOutcomeStatePreserving
        source.terminal.cutpoint.postcondition.outcome = true)
    (afterExact :
      source.after state calls eventIndex events world =
        .running targetRva targetSlot targetState targetCalls targetEventIndex
          targetEvents targetWorld) :
    source.terminal.after (source.terminalState state) = targetState := by
  rw [source.afterExpected] at afterExact
  cases outcomeExact :
      source.terminal.cutpoint.postcondition.outcome <;>
    simp [nativeOperationOutcomeStatePreserving, outcomeExact] at preserving
  case returned =>
    cases calls with
    | nil =>
        simp [CheckedNativeOperationBlock.expectedTerminalTransition,
          outcomeExact, NativeOperationOutcomePostcondition.expected,
          transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr]
          at afterExact
    | cons frame tail =>
        simp [CheckedNativeOperationBlock.expectedTerminalTransition,
          outcomeExact, NativeOperationOutcomePostcondition.expected,
          transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr]
          at afterExact
        split at afterExact
        · cases afterExact
          rfl
        · cases afterExact
  case jumped | branched | called =>
    simp [CheckedNativeOperationBlock.expectedTerminalTransition, outcomeExact,
      NativeOperationOutcomePostcondition.expected,
      transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr] at afterExact
    simpa [CheckedNativeOperationStoppedEdge.after] using afterExact.2.2.1
  case checkedContinue =>
    simp [CheckedNativeOperationBlock.expectedTerminalTransition, outcomeExact,
      NativeOperationOutcomePostcondition.expected,
      transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr] at afterExact
    split at afterExact <;>
      simp_all [CheckedNativeOperationStoppedEdge.after]

structure CheckedNativeOperationGraphSuccessor
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (source : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) where
  target : CheckedNativeOperationBlock candidate
  targetMember : target ∈ blocks
  targetState : MachineState
  targetCalls : List NativeCallFrame
  targetEventIndex : Nat
  targetEvents : List NativeExternalEvent
  targetWorld : RelationalWorld
  afterExact :
    source.after state calls eventIndex events world =
      .running target.entryRva target.entrySlot targetState targetCalls
        targetEventIndex targetEvents targetWorld
  invariantChecked :
    checkedNativeOperationInvariantLink source target = true

def checkedNativeOperationGraphSuccessor?
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (source : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld) :
    Option (CheckedNativeOperationGraphSuccessor blocks source state calls
      eventIndex events world) :=
  match afterExact : source.after state calls eventIndex events world with
  | .running entryRva entrySlot targetState targetCalls targetEventIndex
      targetEvents targetWorld =>
      match lookupExact :
          checkedNativeOperationBlockLookup? candidate blocks entryRva
            entrySlot with
      | none => none
      | some found =>
          if invariantChecked :
              checkedNativeOperationInvariantLink source found.block = true
          then
            some {
              target := found.block
              targetMember := found.member
              targetState
              targetCalls
              targetEventIndex
              targetEvents
              targetWorld
              afterExact := by
                rw [afterExact, found.entryRvaExact, found.entrySlotExact]
              invariantChecked
            }
          else none
  | .returned _ _ _
  | .terminated _ _
  | .fault _
  | .blocked _ => none

theorem CheckedNativeOperationGraphSuccessor.path
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {source : CheckedNativeOperationBlock candidate}
    {state : MachineState} {calls : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (successor : CheckedNativeOperationGraphSuccessor blocks source state calls
      eventIndex events world) :
    NonemptyRelatedPath candidate.transitionSystem
      (.running source.entryRva source.entrySlot state calls eventIndex events
        world)
      (source.observations state calls eventIndex events world)
      (.running successor.target.entryRva successor.target.entrySlot
        successor.targetState successor.targetCalls successor.targetEventIndex
        successor.targetEvents successor.targetWorld) := by
  have path := source.path state calls eventIndex events world
  rw [successor.afterExact] at path
  exact path

theorem CheckedNativeOperationGraphSuccessor.targetInvariantHolds
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {source : CheckedNativeOperationBlock candidate}
    {state : MachineState} {calls : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (successor : CheckedNativeOperationGraphSuccessor blocks source state calls
      eventIndex events world)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant source).Holds state) :
    (checkedNativeOperationBlockSourceInvariant successor.target).Holds
      successor.targetState := by
  have invariantExact := successor.invariantChecked
  rcases checkedNativeOperationInvariantLink_target source successor.target
      invariantExact with trivial | linked
  · rw [trivial]
    exact trivialNativeOperationInvariant_holds _
  · have sourceShape :=
      checkedNativeOperationBlockSourceInvariantHolds source state sourceHolds
    have terminalHolds := source.terminalInvariantHolds state sourceShape
    rw [linked.1] at terminalHolds
    have stateExact := checkedNativeOperationInvariantLink_machineState source
      state calls eventIndex events world successor.target.entryRva
      successor.target.entrySlot successor.targetState successor.targetCalls
      successor.targetEventIndex successor.targetEvents successor.targetWorld
      linked.2 successor.afterExact
    rw [← stateExact]
    exact terminalHolds

theorem CheckedNativeOperationGraphSuccessor.targetStateExact
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {source : CheckedNativeOperationBlock candidate}
    {state : MachineState} {calls : List NativeCallFrame}
    {eventIndex : Nat} {events : List NativeExternalEvent}
    {world : RelationalWorld}
    (successor : CheckedNativeOperationGraphSuccessor blocks source state calls
      eventIndex events world)
    (preserving :
      nativeOperationOutcomeStatePreserving
        source.terminal.cutpoint.postcondition.outcome = true) :
    source.terminal.after (source.terminalState state) =
      successor.targetState := by
  exact checkedNativeOperationInvariantLink_machineState source state calls
    eventIndex events world successor.target.entryRva
    successor.target.entrySlot successor.targetState successor.targetCalls
    successor.targetEventIndex successor.targetEvents successor.targetWorld
    preserving successor.afterExact

#print axioms CheckedNativeOperationGraphSuccessor.path
#print axioms CheckedNativeOperationGraphSuccessor.targetInvariantHolds
#print axioms CheckedNativeOperationGraphSuccessor.targetStateExact
#print axioms checkedNativeOperationGraphTargetCovered_sound
#print axioms checkedNativeOperationGraphClosed_target
#print axioms checkedNativeOperationGraphClosedWithBoundaries_target

end StageA.Relational.InterpreterKernelOperationGraphChecker
