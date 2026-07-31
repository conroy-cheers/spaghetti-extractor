import StageA.RelationalInterpreterKernelOperationStateRouteChecker

namespace StageA.Relational.InterpreterKernelOperationRankedStateRoute

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelOperationControlChecker
open StageA.Relational.InterpreterKernelOperationCutpointChecker
open StageA.Relational.InterpreterKernelOperationFrameChecker
open StageA.Relational.InterpreterKernelOperationGraphChecker
open StageA.Relational.InterpreterKernelOperationPostcondition
open StageA.Relational.InterpreterKernelOperationStateRouteChecker
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

/-!
# Ranked state-indexed native routes

Compiler-generated control flow commonly contains state-dependent branches but
is acyclic between semantic cutpoints.  The exact checked block computes each
branch; a generated rank certificate only proves that every possible local
successor makes progress.  This separates reusable execution reasoning from
binary-specific rank data.

Calls, returns, checked continuations, indirect control, and external events are
cutpoints.  Their stack, environment, and target obligations are discharged by
the typed boundary checker rather than hidden in a graph rank.
-/

theorem CheckedNativeOperationBlock.alwaysRunningLocalAfter
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (localChecked :
      nativeOperationOutcomeAlwaysRunningLocal
        block.terminal.cutpoint.postcondition.outcome = true) :
    ∃ targetRva targetState targetCalls targetEventIndex targetEvents
        targetWorld,
      targetRva ∈ nativeOperationOutcomeLocalTargets
        block.terminal.cutpoint.postcondition.outcome ∧
      block.after state calls eventIndex events world =
        .running targetRva 0 targetState targetCalls targetEventIndex
          targetEvents targetWorld := by
  rw [block.afterExpected]
  cases outcomeExact :
      block.terminal.cutpoint.postcondition.outcome <;>
    simp_all [nativeOperationOutcomeAlwaysRunningLocal,
      nativeOperationOutcomeLocalTargets,
      CheckedNativeOperationBlock.expectedTerminalTransition,
      NativeOperationOutcomePostcondition.expected,
      transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr]
  case branched condition trueTarget falseTarget =>
    by_cases sameTarget : trueTarget = falseTarget
    · subst falseTarget
      cases evaluated : condition.eval (block.terminalState state) <;> simp_all
    · cases evaluated : condition.eval (block.terminalState state) <;> simp_all

theorem CheckedNativeOperationBlock.alwaysRunningLocalTarget
    {candidate : ExactNativeWorldProgram}
    (block : CheckedNativeOperationBlock candidate)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (targetRva targetSlot : Nat) (targetState : MachineState)
    (targetCalls : List NativeCallFrame) (targetEventIndex : Nat)
    (targetEvents : List NativeExternalEvent)
    (targetWorld : RelationalWorld)
    (localChecked :
      nativeOperationOutcomeAlwaysRunningLocal
        block.terminal.cutpoint.postcondition.outcome = true)
    (afterExact :
      block.after state calls eventIndex events world =
        .running targetRva targetSlot targetState targetCalls targetEventIndex
          targetEvents targetWorld) :
    targetRva ∈ nativeOperationOutcomeLocalTargets
      block.terminal.cutpoint.postcondition.outcome := by
  rw [block.afterExpected] at afterExact
  cases outcomeExact :
      block.terminal.cutpoint.postcondition.outcome <;>
    simp_all [nativeOperationOutcomeAlwaysRunningLocal,
      nativeOperationOutcomeLocalTargets,
      CheckedNativeOperationBlock.expectedTerminalTransition,
      NativeOperationOutcomePostcondition.expected,
      transitionFromNativeWorldOutcome, evalNativeOperationOutcomeExpr]
  case branched condition trueTarget falseTarget =>
    by_cases sameTarget : trueTarget = falseTarget
    · subst falseTarget
      cases evaluated : condition.eval (block.terminalState state) <;> simp_all
    · cases evaluated : condition.eval (block.terminalState state) <;> simp_all

structure CheckedNativeOperationRankedRouteCertificate where
  stopRvas : List Nat
  rank : Nat -> Nat

def checkedNativeOperationRankedRouteCertificate
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (certificate : CheckedNativeOperationRankedRouteCertificate) : Bool :=
  blocks.all fun source =>
    if certificate.stopRvas.contains source.entryRva then
      true
    else
      nativeOperationOutcomeAlwaysRunningLocal
          source.terminal.cutpoint.postcondition.outcome &&
        (nativeOperationOutcomeLocalTargets
          source.terminal.cutpoint.postcondition.outcome).all fun targetRva =>
            checkedNativeOperationGraphTargetCovered blocks source targetRva &&
              decide (certificate.rank targetRva <
                certificate.rank source.entryRva)

structure CheckedNativeOperationRankedRoutePolicy
    (candidate : ExactNativeWorldProgram)
    (blocks : List (CheckedNativeOperationBlock candidate)) where
  stop : Nat -> Bool
  rank : Nat -> Nat
  continueLocal : ∀ block, block ∈ blocks -> stop block.entryRva = false ->
    nativeOperationOutcomeAlwaysRunningLocal
      block.terminal.cutpoint.postcondition.outcome = true
  targetCovered : ∀ source, source ∈ blocks ->
    stop source.entryRva = false -> ∀ targetRva,
      targetRva ∈ nativeOperationOutcomeLocalTargets
        source.terminal.cutpoint.postcondition.outcome ->
      checkedNativeOperationGraphTargetCovered blocks source targetRva = true
  rankDecreases : ∀ source, source ∈ blocks ->
    stop source.entryRva = false -> ∀ targetRva,
      targetRva ∈ nativeOperationOutcomeLocalTargets
        source.terminal.cutpoint.postcondition.outcome ->
      rank targetRva < rank source.entryRva

def checkedNativeOperationRankedRouteCertificate_sound
    {candidate : ExactNativeWorldProgram}
    (blocks : List (CheckedNativeOperationBlock candidate))
    (certificate : CheckedNativeOperationRankedRouteCertificate)
    (checked :
      checkedNativeOperationRankedRouteCertificate blocks certificate = true) :
    CheckedNativeOperationRankedRoutePolicy candidate blocks := by
  have sourceChecked : ∀ source, source ∈ blocks ->
      (if certificate.stopRvas.contains source.entryRva then
        true
      else
        nativeOperationOutcomeAlwaysRunningLocal
            source.terminal.cutpoint.postcondition.outcome &&
          (nativeOperationOutcomeLocalTargets
            source.terminal.cutpoint.postcondition.outcome).all
              (fun targetRva =>
                checkedNativeOperationGraphTargetCovered blocks source
                    targetRva &&
                  decide (certificate.rank targetRva <
                    certificate.rank source.entryRva))) = true := by
    simpa [checkedNativeOperationRankedRouteCertificate,
      List.all_eq_true] using checked
  refine {
    stop := fun entryRva => certificate.stopRvas.contains entryRva
    rank := certificate.rank
    continueLocal := ?_
    targetCovered := ?_
    rankDecreases := ?_
  }
  · intro source sourceMember continues
    have sourceResult := sourceChecked source sourceMember
    rw [continues] at sourceResult
    simp only [Bool.false_eq_true, if_false, Bool.and_eq_true] at sourceResult
    exact sourceResult.1
  · intro source sourceMember continues targetRva targetMember
    have sourceResult := sourceChecked source sourceMember
    rw [continues] at sourceResult
    simp only [Bool.false_eq_true, if_false, Bool.and_eq_true] at sourceResult
    have targetsChecked := sourceResult.2
    rw [List.all_eq_true] at targetsChecked
    have targetChecked := targetsChecked targetRva targetMember
    simp only [Bool.and_eq_true] at targetChecked
    exact targetChecked.1
  · intro source sourceMember continues targetRva targetMember
    have sourceResult := sourceChecked source sourceMember
    rw [continues] at sourceResult
    simp only [Bool.false_eq_true, if_false, Bool.and_eq_true] at sourceResult
    have targetsChecked := sourceResult.2
    rw [List.all_eq_true] at targetsChecked
    have targetChecked := targetsChecked targetRva targetMember
    simp only [Bool.and_eq_true] at targetChecked
    exact of_decide_eq_true targetChecked.2

theorem checkedNativeOperationGraphSuccessor_of_policy
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (policy : CheckedNativeOperationRankedRoutePolicy candidate blocks)
    (source : CheckedNativeOperationBlock candidate)
    (sourceMember : source ∈ blocks)
    (state : MachineState) (calls : List NativeCallFrame)
    (eventIndex : Nat) (events : List NativeExternalEvent)
    (world : RelationalWorld)
    (continues : policy.stop source.entryRva = false) :
    Nonempty (CheckedNativeOperationGraphSuccessor blocks source state calls
      eventIndex events world) := by
  have localChecked :=
    policy.continueLocal source sourceMember continues
  obtain ⟨targetRva, targetState, targetCalls, targetEventIndex, targetEvents,
      targetWorld, targetMember, afterExact⟩ :=
    CheckedNativeOperationBlock.alwaysRunningLocalAfter source state calls
      eventIndex events world localChecked
  obtain ⟨target⟩ := checkedNativeOperationGraphTargetCovered_sound blocks
    source targetRva
    (policy.targetCovered source sourceMember continues targetRva targetMember)
  refine ⟨{
    target := target.target
    targetMember := target.member
    targetState
    targetCalls
    targetEventIndex
    targetEvents
    targetWorld
    afterExact := ?_
    invariantChecked := target.invariantChecked
  }⟩
  simpa [target.entryRvaExact, target.entrySlotExact] using afterExact

structure CheckedNativeOperationStateRouteToStop
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (policy : CheckedNativeOperationRankedRoutePolicy candidate blocks)
    (sourceBlock : CheckedNativeOperationBlock candidate)
    (sourceState : MachineState) (sourceCalls : List NativeCallFrame)
    (sourceEventIndex : Nat) (sourceEvents : List NativeExternalEvent)
    (sourceWorld : RelationalWorld) where
  finalBlock : CheckedNativeOperationBlock candidate
  finalState : MachineState
  finalCalls : List NativeCallFrame
  finalEventIndex : Nat
  finalEvents : List NativeExternalEvent
  finalWorld : RelationalWorld
  route : CheckedNativeOperationStateRoute candidate blocks sourceBlock
    sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld
    finalBlock finalState finalCalls finalEventIndex finalEvents finalWorld
  stopped : policy.stop finalBlock.entryRva = true

noncomputable def checkedNativeOperationStateRouteToStop
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    (policy : CheckedNativeOperationRankedRoutePolicy candidate blocks)
    (sourceBlock : CheckedNativeOperationBlock candidate)
    (sourceMember : sourceBlock ∈ blocks)
    (sourceState : MachineState) (sourceCalls : List NativeCallFrame)
    (sourceEventIndex : Nat) (sourceEvents : List NativeExternalEvent)
    (sourceWorld : RelationalWorld)
    (sourceHolds :
      (checkedNativeOperationBlockSourceInvariant sourceBlock).Holds
        sourceState) :
    CheckedNativeOperationStateRouteToStop policy sourceBlock sourceState
      sourceCalls sourceEventIndex sourceEvents sourceWorld :=
  if stopped : policy.stop sourceBlock.entryRva = true then
    {
      finalBlock := sourceBlock
      finalState := sourceState
      finalCalls := sourceCalls
      finalEventIndex := sourceEventIndex
      finalEvents := sourceEvents
      finalWorld := sourceWorld
      route := .final sourceBlock sourceState sourceCalls sourceEventIndex
        sourceEvents sourceWorld sourceMember sourceHolds
      stopped
    }
  else
    let stoppedFalse : policy.stop sourceBlock.entryRva = false := by
      cases exact : policy.stop sourceBlock.entryRva with
      | false => exact rfl
      | true => exact False.elim (stopped exact)
    let successor := Classical.choice
      (checkedNativeOperationGraphSuccessor_of_policy policy sourceBlock
        sourceMember sourceState sourceCalls sourceEventIndex sourceEvents
        sourceWorld stoppedFalse)
    let tail := checkedNativeOperationStateRouteToStop policy successor.target
      successor.targetMember successor.targetState successor.targetCalls
      successor.targetEventIndex successor.targetEvents successor.targetWorld
      (successor.targetInvariantHolds sourceHolds)
    {
      finalBlock := tail.finalBlock
      finalState := tail.finalState
      finalCalls := tail.finalCalls
      finalEventIndex := tail.finalEventIndex
      finalEvents := tail.finalEvents
      finalWorld := tail.finalWorld
      route := .step sourceBlock sourceState sourceCalls sourceEventIndex
        sourceEvents sourceWorld sourceMember sourceHolds
        (policy.continueLocal sourceBlock sourceMember stoppedFalse)
        successor tail.route
      stopped := tail.stopped
    }
termination_by policy.rank sourceBlock.entryRva
decreasing_by
  have targetMember :=
    CheckedNativeOperationBlock.alwaysRunningLocalTarget sourceBlock sourceState
      sourceCalls sourceEventIndex sourceEvents sourceWorld
      successor.target.entryRva successor.target.entrySlot
      successor.targetState successor.targetCalls successor.targetEventIndex
      successor.targetEvents successor.targetWorld
      (policy.continueLocal sourceBlock sourceMember stoppedFalse)
      successor.afterExact
  exact policy.rankDecreases sourceBlock sourceMember stoppedFalse
    successor.target.entryRva targetMember

theorem CheckedNativeOperationStateRouteToStop.path
    {candidate : ExactNativeWorldProgram}
    {blocks : List (CheckedNativeOperationBlock candidate)}
    {policy : CheckedNativeOperationRankedRoutePolicy candidate blocks}
    {sourceBlock : CheckedNativeOperationBlock candidate}
    {sourceState : MachineState} {sourceCalls : List NativeCallFrame}
    {sourceEventIndex : Nat} {sourceEvents : List NativeExternalEvent}
    {sourceWorld : RelationalWorld}
    (result : CheckedNativeOperationStateRouteToStop policy sourceBlock
      sourceState sourceCalls sourceEventIndex sourceEvents sourceWorld) :
    NonemptyRelatedPath candidate.transitionSystem result.route.before
      result.route.observations result.route.after :=
  result.route.path

#print axioms CheckedNativeOperationBlock.alwaysRunningLocalAfter
#print axioms CheckedNativeOperationBlock.alwaysRunningLocalTarget
#print axioms checkedNativeOperationRankedRouteCertificate_sound
#print axioms checkedNativeOperationGraphSuccessor_of_policy
#print axioms checkedNativeOperationStateRouteToStop
#print axioms CheckedNativeOperationStateRouteToStop.path

end StageA.Relational.InterpreterKernelOperationRankedStateRoute
