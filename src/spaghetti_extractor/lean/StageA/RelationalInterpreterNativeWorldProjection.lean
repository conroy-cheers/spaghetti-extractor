import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterNativeWorldProjection

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeWorld

/-!
# Callback-free native-world projection

The callback-capable executor extends the ordinary native executor with an
external suspension state and a callback-frame stack.  Internal execution does
not observe those additions.  This module checks that boundary once: a nested
step from an ordinary state that emits no observation has an ordinary successor
and is exactly the corresponding base-program step.

The finite-path theorem composes that fact.  It cannot erase an external call,
callback, fault, return event, or blocked transition because each such frontier
emits an observation before it can leave the ordinary carrier.
-/

def liftNativeWorldExecution : NativeWorldExecution -> NestedNativeWorldExecution
  | .running rva undefinedSlot state calls eventIndex events world =>
      .running rva undefinedSlot state calls eventIndex events world []
  | .returned state events world => .returned state events world
  | .terminated events world => .terminated events world
  | .fault cause => .fault cause
  | .blocked reason => .blocked reason

@[simp] theorem liftNativeWorldExecution_rva
    (execution : NativeWorldExecution) :
    (liftNativeWorldExecution execution).rva? = execution.rva? := by
  cases execution <;> rfl

theorem liftNativeWorldExecution_injective :
    Function.Injective liftNativeWorldExecution := by
  intro left right equal
  cases left <;> cases right <;> simp_all [liftNativeWorldExecution]

/-- A silent nested step from the ordinary carrier is exactly one base-program
step.  The proof exhausts the decoded outcome, indirect-target resolution, and
external action rather than assuming that the two transition functions agree. -/
theorem silentNestedStepFromLift_projects
    (program : ExactNestedNativeWorldProgram)
    (before : NativeWorldExecution)
    (silent :
      (program.transitionSystem.step
        (liftNativeWorldExecution before)).observation = none) :
    exists after,
      program.transitionSystem.step (liftNativeWorldExecution before) = {
        next := liftNativeWorldExecution after
        observation := none
      } /\
      program.base.transitionSystem.step before = {
        next := after
        observation := none
      } := by
  cases before with
  | running rva undefinedSlot state calls eventIndex events world =>
      cases decoded :
          stepKernelPE32Instruction program.pe program.imports
            (.running rva undefinedSlot state) with
      | running nextRva nextSlot nextState =>
          refine ⟨.running nextRva nextSlot nextState calls eventIndex events
            world, ?_, ?_⟩ <;>
            simp [ExactNestedNativeWorldProgram.transitionSystem,
              ExactNativeWorldProgram.transitionSystem,
              ExactNestedNativeWorldProgram.base, liftNativeWorldExecution,
              stepPE32NestedNativeWorldExecution,
              stepPE32NativeWorldExecution, decoded]
      | fault =>
          simp [ExactNestedNativeWorldProgram.transitionSystem,
            liftNativeWorldExecution, stepPE32NestedNativeWorldExecution,
            decoded, blockedNestedNativeWorldTransition] at silent
      | stopped outcome nextState =>
          cases outcome with
          | returned target =>
              cases calls with
              | nil =>
                  simp [ExactNestedNativeWorldProgram.transitionSystem,
                    liftNativeWorldExecution,
                    stepPE32NestedNativeWorldExecution, decoded,
                    transitionFromNestedNativeWorldOutcome] at silent
              | cons frame tail =>
                  by_cases returned :
                      target = frame.returnAddress
                  · refine ⟨.running frame.continuationRva 0 nextState tail
                      eventIndex events world, ?_, ?_⟩ <;>
                      simp [ExactNestedNativeWorldProgram.transitionSystem,
                        ExactNativeWorldProgram.transitionSystem,
                        ExactNestedNativeWorldProgram.base,
                        liftNativeWorldExecution,
                        stepPE32NestedNativeWorldExecution,
                        stepPE32NativeWorldExecution, decoded,
                        transitionFromNestedNativeWorldOutcome,
                        transitionFromNativeWorldOutcome, returned]
                  · simp [ExactNestedNativeWorldProgram.transitionSystem,
                      liftNativeWorldExecution,
                      stepPE32NestedNativeWorldExecution, decoded,
                      transitionFromNestedNativeWorldOutcome, returned,
                      blockedNestedNativeWorldTransition] at silent
          | jump targetRva =>
              refine ⟨.running targetRva 0 nextState calls eventIndex events
                world, ?_, ?_⟩ <;>
                simp [ExactNestedNativeWorldProgram.transitionSystem,
                  ExactNativeWorldProgram.transitionSystem,
                  ExactNestedNativeWorldProgram.base,
                  liftNativeWorldExecution,
                  stepPE32NestedNativeWorldExecution,
                  stepPE32NativeWorldExecution, decoded,
                  transitionFromNestedNativeWorldOutcome,
                  transitionFromNativeWorldOutcome]
          | branch condition taken fallthrough =>
              refine ⟨.running (if condition then taken else fallthrough) 0
                nextState calls eventIndex events world, ?_, ?_⟩ <;>
                simp [ExactNestedNativeWorldProgram.transitionSystem,
                  ExactNativeWorldProgram.transitionSystem,
                  ExactNestedNativeWorldProgram.base,
                  liftNativeWorldExecution,
                  stepPE32NestedNativeWorldExecution,
                  stepPE32NativeWorldExecution, decoded,
                  transitionFromNestedNativeWorldOutcome,
                  transitionFromNativeWorldOutcome]
          | call targetRva continuationRva returnAddress =>
              refine ⟨.running targetRva 0 nextState
                ({ continuationRva, returnAddress := BitVec.ofNat 32 returnAddress } ::
                  calls) eventIndex events world, ?_, ?_⟩ <;>
                simp [ExactNestedNativeWorldProgram.transitionSystem,
                  ExactNativeWorldProgram.transitionSystem,
                  ExactNestedNativeWorldProgram.base,
                  liftNativeWorldExecution,
                  stepPE32NestedNativeWorldExecution,
                  stepPE32NativeWorldExecution, decoded,
                  transitionFromNestedNativeWorldOutcome,
                  transitionFromNativeWorldOutcome]
          | externalCall imported arguments continuationRva =>
              simp [ExactNestedNativeWorldProgram.transitionSystem,
                liftNativeWorldExecution, stepPE32NestedNativeWorldExecution,
                decoded, transitionFromNestedNativeWorldOutcome,
                suspendNestedNativeWorldExternalCall] at silent
          | externalJump imported arguments =>
              cases calls with
              | nil =>
                  simp [ExactNestedNativeWorldProgram.transitionSystem,
                    liftNativeWorldExecution,
                    stepPE32NestedNativeWorldExecution, decoded,
                    transitionFromNestedNativeWorldOutcome,
                    suspendNestedNativeWorldExternalTailCall,
                    blockedNestedNativeWorldTransition] at silent
              | cons frame tail =>
                  simp [ExactNestedNativeWorldProgram.transitionSystem,
                    liftNativeWorldExecution,
                    stepPE32NestedNativeWorldExecution, decoded,
                    transitionFromNestedNativeWorldOutcome,
                    suspendNestedNativeWorldExternalTailCall,
                    suspendNestedNativeWorldExternalCall] at silent
          | bulkCopy destination source count direction continuationRva =>
              refine ⟨.running continuationRva 0
                { nextState with
                  memory := Memory.bulkCopyDwords nextState.memory destination
                    source direction count.toNat }
                calls eventIndex events world, ?_, ?_⟩ <;>
                simp [ExactNestedNativeWorldProgram.transitionSystem,
                  ExactNativeWorldProgram.transitionSystem,
                  ExactNestedNativeWorldProgram.base,
                  liftNativeWorldExecution,
                  stepPE32NestedNativeWorldExecution,
                  stepPE32NativeWorldExecution, decoded,
                  transitionFromNestedNativeWorldOutcome,
                  transitionFromNativeWorldOutcome]
          | bulkFill destination value count direction continuationRva =>
              refine ⟨.running continuationRva 0
                { nextState with
                  memory := Memory.bulkFillDwords nextState.memory destination
                    value direction count.toNat }
                calls eventIndex events world, ?_, ?_⟩ <;>
                simp [ExactNestedNativeWorldProgram.transitionSystem,
                  ExactNativeWorldProgram.transitionSystem,
                  ExactNestedNativeWorldProgram.base,
                  liftNativeWorldExecution,
                  stepPE32NestedNativeWorldExecution,
                  stepPE32NativeWorldExecution, decoded,
                  transitionFromNestedNativeWorldOutcome,
                  transitionFromNativeWorldOutcome]
          | checkedContinue valid continuationRva =>
              cases valid with
              | false =>
                  simp [ExactNestedNativeWorldProgram.transitionSystem,
                    liftNativeWorldExecution,
                    stepPE32NestedNativeWorldExecution, decoded,
                    transitionFromNestedNativeWorldOutcome] at silent
              | true =>
                  refine ⟨.running continuationRva 0 nextState calls eventIndex
                    events world, ?_, ?_⟩ <;>
                    simp [ExactNestedNativeWorldProgram.transitionSystem,
                      ExactNativeWorldProgram.transitionSystem,
                      ExactNestedNativeWorldProgram.base,
                      liftNativeWorldExecution,
                      stepPE32NestedNativeWorldExecution,
                      stepPE32NativeWorldExecution, decoded,
                      transitionFromNestedNativeWorldOutcome,
                      transitionFromNativeWorldOutcome]
          | atomicCompareExchange address expected replacement continuationRva =>
              refine ⟨.running continuationRva 0
                { nextState with
                  memory := Memory.atomicCompareExchange nextState.memory address
                    expected replacement }
                calls eventIndex events world, ?_, ?_⟩ <;>
                simp [ExactNestedNativeWorldProgram.transitionSystem,
                  ExactNativeWorldProgram.transitionSystem,
                  ExactNestedNativeWorldProgram.base,
                  liftNativeWorldExecution,
                  stepPE32NestedNativeWorldExecution,
                  stepPE32NativeWorldExecution, decoded,
                  transitionFromNestedNativeWorldOutcome,
                  transitionFromNativeWorldOutcome]
          | indirectCall target continuationRva returnAddress =>
              simp only [ExactNestedNativeWorldProgram.transitionSystem,
                liftNativeWorldExecution, stepPE32NestedNativeWorldExecution,
                decoded, transitionFromNestedNativeWorldOutcome] at silent
              split at silent
              · simp [blockedNestedNativeWorldTransition] at silent
              · rename_i targetRva resolution
                refine ⟨.running targetRva 0 nextState
                    ({ continuationRva,
                       returnAddress := BitVec.ofNat 32 returnAddress } :: calls)
                    eventIndex events world, ?_, ?_⟩ <;>
                  simp_all [ExactNestedNativeWorldProgram.transitionSystem,
                    ExactNativeWorldProgram.transitionSystem,
                    ExactNestedNativeWorldProgram.base,
                    liftNativeWorldExecution,
                    stepPE32NestedNativeWorldExecution,
                    stepPE32NativeWorldExecution,
                    transitionFromNestedNativeWorldOutcome,
                    transitionFromNativeWorldOutcome]
              · rename_i bindingId resolution
                cases callable : program.callableExternal with
                | none =>
                    simp [callable, blockedNestedNativeWorldTransition] at silent
                | some config =>
                    cases resolved :
                        resolveNativeImportBindingCall? config world bindingId
                          target nextState with
                    | none =>
                        simp [callable, resolved,
                          blockedNestedNativeWorldTransition] at silent
                    | some result =>
                        rcases result with ⟨binding, arguments⟩
                        simp [callable, resolved,
                          suspendNestedNativeWorldExternalCall] at silent
              · rename_i resourceId resolution
                cases callable : program.callableExternal with
                | none =>
                    simp [callable, blockedNestedNativeWorldTransition] at silent
                | some config =>
                    cases resolved :
                        resolveNativeCallableResource config world resourceId
                          target .call <;>
                      simp [callable, resolved,
                        blockedNestedNativeWorldTransition,
                        applyNestedNativeResolvedCallableCall] at silent
          | indirectJump target =>
              simp only [ExactNestedNativeWorldProgram.transitionSystem,
                liftNativeWorldExecution, stepPE32NestedNativeWorldExecution,
                decoded, transitionFromNestedNativeWorldOutcome] at silent
              split at silent
              · simp [blockedNestedNativeWorldTransition] at silent
              · rename_i targetRva resolution
                refine ⟨.running targetRva 0 nextState calls eventIndex events
                    world,
                    ?_, ?_⟩ <;>
                  simp_all [ExactNestedNativeWorldProgram.transitionSystem,
                    ExactNativeWorldProgram.transitionSystem,
                    ExactNestedNativeWorldProgram.base,
                    liftNativeWorldExecution,
                    stepPE32NestedNativeWorldExecution,
                    stepPE32NativeWorldExecution,
                    transitionFromNestedNativeWorldOutcome,
                    transitionFromNativeWorldOutcome]
              · rename_i bindingId resolution
                cases callable : program.callableExternal with
                | none =>
                    simp [callable, blockedNestedNativeWorldTransition] at silent
                | some config =>
                    cases resolved :
                        resolveNativeImportBindingCall? config world bindingId
                          target nextState with
                    | none =>
                        simp [callable, resolved,
                          blockedNestedNativeWorldTransition] at silent
                    | some result =>
                        rcases result with ⟨binding, arguments⟩
                        cases calls <;>
                          simp [callable, resolved,
                            suspendNestedNativeWorldExternalTailCall,
                            suspendNestedNativeWorldExternalCall,
                            blockedNestedNativeWorldTransition] at silent
              · rename_i resourceId resolution
                cases callable : program.callableExternal with
                | none =>
                    simp [callable, blockedNestedNativeWorldTransition] at silent
                | some config =>
                    cases resolved :
                        resolveNativeCallableResource config world resourceId
                          target .jump <;>
                      cases calls <;>
                      simp [callable, resolved,
                        blockedNestedNativeWorldTransition,
                        applyNestedNativeResolvedCallableTail] at silent
  | returned state events world =>
      exact ⟨.returned state events world, rfl, rfl⟩
  | terminated events world =>
      exact ⟨.terminated events world, rfl, rfl⟩
  | fault cause =>
      exact ⟨.fault cause, rfl, rfl⟩
  | blocked reason =>
      exact ⟨.blocked reason, rfl, rfl⟩

/-- A callback-free, observation-free nested replay projects to the exact base
native replay with the same fuel and endpoint. -/
theorem runRelatedSteps_nestedLift_silent_projects
    (program : ExactNestedNativeWorldProgram)
    (fuel : Nat) (before after : NativeWorldExecution)
    (executed :
      runRelatedSteps program.transitionSystem fuel
          (liftNativeWorldExecution before) =
        (liftNativeWorldExecution after, [])) :
    runRelatedSteps program.base.transitionSystem fuel before = (after, []) := by
  induction fuel generalizing before with
  | zero =>
      simp only [runRelatedSteps] at executed |-
      have equal :=
        liftNativeWorldExecution_injective (congrArg Prod.fst executed)
      simpa [equal]
  | succ fuel induction =>
      simp only [runRelatedSteps] at executed |-
      let transition :=
        program.transitionSystem.step (liftNativeWorldExecution before)
      let tail := runRelatedSteps program.transitionSystem fuel transition.next
      have observationsEmpty :
          transition.observation.toList ++ tail.2 = [] :=
        congrArg Prod.snd executed
      have transitionSilent : transition.observation = none := by
        cases observed : transition.observation <;>
          simp_all [transition]
      obtain ⟨middle, nestedStep, baseStep⟩ :=
        silentNestedStepFromLift_projects program before transitionSilent
      have tailExecuted :
          runRelatedSteps program.transitionSystem fuel
              (liftNativeWorldExecution middle) =
            (liftNativeWorldExecution after, []) := by
        have endpointExact : tail.1 = liftNativeWorldExecution after :=
          congrArg Prod.fst executed
        have tailSilent : tail.2 = [] := by
          simpa [transitionSilent] using observationsEmpty
        have tailPair :
            tail = (liftNativeWorldExecution after, []) := by
          apply Prod.ext
          · exact endpointExact
          · exact tailSilent
        simpa [tail, transition, nestedStep] using tailPair
      have projected := induction middle tailExecuted
      simp [baseStep, projected]

#print axioms silentNestedStepFromLift_projects
#print axioms runRelatedSteps_nestedLift_silent_projects

end StageA.Relational.InterpreterNativeWorldProjection
