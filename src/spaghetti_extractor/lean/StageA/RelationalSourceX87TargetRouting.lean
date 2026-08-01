import StageA.RelationalSourceInterpreterKernel

namespace StageA.Relational.SourceWorld.InterpreterKernel

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterX87

/-!
Checked x87 target routing for the source-equivalence lane.

This module does not introduce another x87 semantics.  It factors the
post-processing already performed by `x87Step?` so that a checked exact-schedule
witness, its exact source provider, and the independently decoded world-region
carrier can be composed once.  Missing target lookup, provider execution,
decoded carrier, or local effect equality leaves the adapter unconstructible.
-/

/-- Pure post-processing of one exact x87 schedule result.  This is the body of
`x87Step?` after provider selection and exists only to expose a compact proof
boundary for generated schedule certificates. -/
def routeX87ScheduleResult? (program : Program) (result : ScheduleResult) :
    Option EvaluatedStep := do
  let macroResult <- scheduleMacroResult? result
  if !result.trace.calls.isEmpty then none else
  match result.trace.faults with
  | [] => do
      let control <- lastControl? result
      let rawOutcome <- match control with
        | .fallthrough target => some (.jump target)
        | .stop outcome => some outcome
      let outcome <- mapScheduleOutcome? program rawOutcome
      pure {
        effect := .outcome result.state outcome
        macroResult := some macroResult
      }
  | [.x87 .floatingPoint] =>
      pure {
        effect := .fault .x87FloatingPoint
        macroResult := some macroResult
      }
  | _ => none

theorem x87Step?_eq_routeX87ScheduleResult?
    (program : Program) (sourceRva : Nat) (state : MachineState) :
    x87Step? program sourceRva state = (do
      let result <- program.x87Provider.execute sourceRva state
      routeX87ScheduleResult? program result) := by
  rfl

/-- Exact decoding plus a checked continuation lookup suffices for every
machine state.  The substantial x87 validity proof is reused from the existing
singleton theorem; changing the target inventory changes only the normalized
continuation stored in the resulting behavior. -/
theorem executeSingletonCommand_isSome_of_decoded_and_continuation
    (candidate : Bool) (pe : PE32) (span : Span)
    (targets : List CodeTargetPair) (continuation : Nat)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (decoded : StageA.Relational.X87.decodeSingletonCommand pe span =
      some descriptor)
    (continuationExact : normalizeCodeTarget candidate targets span.stop =
      some continuation)
    (state : MachineState)
    (inputValid :
      (StageA.Relational.X87.commandStepInput pe span.start descriptor state).validFor
        descriptor.command) :
    (StageA.Relational.X87.executeSingletonCommand candidate pe span targets
      state).isSome = true := by
  let input := StageA.Relational.X87.commandStepInput pe span.start descriptor state
  let response := state.x87Semantics.execute descriptor.command
    descriptor.waitMode state.x87Physical input
  have inputChecked : input.checkedFor descriptor.command = true :=
    StageA.X87.StepInput.checkedFor_of_valid input descriptor.command (by
      simpa [input] using inputValid)
  have waitValid := StageA.Relational.X87.decodeSingletonCommand_waitModeValid
    pe span descriptor decoded
  have waitChecked : descriptor.command.waitModeChecked descriptor.waitMode = true :=
    StageA.X87.Command.waitModeChecked_of_valid descriptor.command
      descriptor.waitMode waitValid
  have responseValid : response.structurallyValid descriptor.command
      descriptor.waitMode := by
    exact state.x87Semantics.execute_structurallyValid
      state.x87Semantics.complies descriptor.command descriptor.waitMode
      state.x87Physical input waitValid (by simpa [input] using inputValid)
  have responseChecked :
      response.checkedFor descriptor.command descriptor.waitMode = true :=
    StageA.X87.Response.checkedFor_of_structurallyValid response
      descriptor.command descriptor.waitMode responseValid
  have inputCheckedExact :
      (StageA.Relational.X87.commandStepInput pe span.start descriptor state).checkedFor
        descriptor.command = true := by
    simpa [input] using inputChecked
  have responseCheckedExact :
      (state.x87Semantics.execute descriptor.command descriptor.waitMode
        state.x87Physical
        (StageA.Relational.X87.commandStepInput pe span.start descriptor state)).checkedFor
          descriptor.command descriptor.waitMode = true := by
    simpa [response, input] using responseChecked
  unfold StageA.Relational.X87.executeSingletonCommand
  rw [decoded, continuationExact]
  cases storeExact : response.store with
  | none =>
      have storeExact' :
          (state.x87Semantics.execute descriptor.command descriptor.waitMode
            state.x87Physical
            (StageA.Relational.X87.commandStepInput pe span.start descriptor
              state)).store = none := by
        simpa [response, input] using storeExact
      simp [inputCheckedExact, waitChecked, responseCheckedExact, storeExact']
  | some store =>
      have usesMemory : descriptor.command.usesMemoryOperand = true := by
        apply StageA.X87.Command.usesMemoryOperand_of_expectedStoreKind
          descriptor.command store.kind
        simpa [storeExact] using responseValid.1.symm
      have operandSome : descriptor.memoryOperand.isSome = true := by
        rw [← StageA.Relational.X87.decodeSingletonCommand_memoryOperand pe span
          descriptor decoded]
        exact usesMemory
      cases operandExact : descriptor.memoryOperand with
      | none => simp [operandExact] at operandSome
      | some addressing =>
          have storeExact' :
              (state.x87Semantics.execute descriptor.command descriptor.waitMode
                state.x87Physical
                (StageA.Relational.X87.commandStepInput pe span.start descriptor
                  state)).store = some store := by
            simpa [response, input] using storeExact
          simp [inputCheckedExact, waitChecked, responseCheckedExact, storeExact',
            StageA.Relational.X87.commandDataAddress, operandExact]

/-- Two successful executions of the same decoded x87 command differ only in
the continuation selected from their target inventories. -/
theorem executeSingletonCommand_eq_with_outcome_of_continuations
    (candidate : Bool) (pe : PE32) (span : Span)
    (leftTargets rightTargets : List CodeTargetPair)
    (leftContinuation rightContinuation : Nat)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (decoded : StageA.Relational.X87.decodeSingletonCommand pe span =
      some descriptor)
    (leftContinuationExact :
      normalizeCodeTarget candidate leftTargets span.stop =
        some leftContinuation)
    (rightContinuationExact :
      normalizeCodeTarget candidate rightTargets span.stop =
        some rightContinuation)
    (state : MachineState) (leftBehavior rightBehavior : RelationalBehavior)
    (leftExecuted :
      StageA.Relational.X87.executeSingletonCommand candidate pe span leftTargets
        state = some leftBehavior)
    (rightExecuted :
      StageA.Relational.X87.executeSingletonCommand candidate pe span rightTargets
        state = some rightBehavior) :
    rightBehavior = { leftBehavior with outcome := .jump rightContinuation } := by
  unfold StageA.Relational.X87.executeSingletonCommand at leftExecuted rightExecuted
  rw [decoded, leftContinuationExact] at leftExecuted
  rw [decoded, rightContinuationExact] at rightExecuted
  simp at leftExecuted rightExecuted
  cases storeExact :
      (state.x87Semantics.execute descriptor.command descriptor.waitMode
        state.x87Physical
        (StageA.Relational.X87.commandStepInput pe span.start descriptor
          state)).store with
  | none =>
      simp only [storeExact, Option.bind_some, Option.some.injEq,
        StageA.Relational.X87.singletonBehavior] at leftExecuted rightExecuted
      rcases leftExecuted with ⟨_, _, _, leftExecuted⟩
      rcases rightExecuted with ⟨_, _, _, rightExecuted⟩
      subst leftBehavior
      subst rightBehavior
      rfl
  | some store =>
      cases addressExact :
          StageA.Relational.X87.commandDataAddress descriptor state with
      | none => simp [storeExact, addressExact] at leftExecuted
      | some address =>
          simp only [storeExact, addressExact, Option.map_some, Option.bind_some,
            Option.some.injEq, StageA.Relational.X87.singletonBehavior]
            at leftExecuted rightExecuted
          rcases leftExecuted with ⟨_, _, _, leftExecuted⟩
          rcases rightExecuted with ⟨_, _, _, rightExecuted⟩
          subst leftBehavior
          subst rightBehavior
          rfl

def exactX87SingletonStepResult (record : RawInstructionRecord)
    (descriptor : StageA.Relational.X87.DecodedCommand) (state : MachineState)
    (behavior : RelationalBehavior) (effect : StageA.X87.MachineEffect) :
    StepResult := {
  state := behavior.nextMachineState state
  memoryEffects := x87ReadEffects descriptor state ++ x87WriteEffects effect
  faults := behavior.x87Fault.toList.map .x87
  control := .fallthrough record.span.stop
  calls := []
  x87Response := some effect.response
}

theorem executeX87Singleton_eq_exactStepResult
    (pe : PE32) (record : RawInstructionRecord) (state : MachineState)
    (descriptor : StageA.Relational.X87.DecodedCommand)
    (behavior : RelationalBehavior) (effect : StageA.X87.MachineEffect)
    (recordClass : record.decodeClass = some .x87Singleton)
    (decoded : StageA.Relational.X87.decodeSingletonCommand pe record.span =
      some descriptor)
    (executed : StageA.Relational.X87.executeSingletonCommand false pe
      record.span [singletonTarget record.span] state = some behavior)
    (effectExact : behavior.x87Effect = some effect)
    (outcomeExact : behavior.outcome = .jump record.span.stop) :
    executeX87Singleton pe record state = some
      (exactX87SingletonStepResult record descriptor state behavior effect) := by
  simp [executeX87Singleton, recordClass, decoded, executed, effectExact,
    outcomeExact, exactX87SingletonStepResult]

/-! ## Static target assembly

These are the target-specific inputs.  They are finite lookup equalities, list
membership, and the checked binding partition.  Provider execution is derived
from the partition rather than accepted as another universal field. -/

structure ExactX87SingletonTargetFacts
    (pe : PE32) (program : Program) (targetId : Nat)
    (witness : ExactInterpreterX87ScheduleWitness pe)
    (schedule : ExactX87SingletonScheduleFacts pe witness) where
  originalSide : program.worldProgram.candidate = false
  originalPeExact : program.worldProgram.context.originalPe = pe
  sourceRvaExact :
    sourceRvaForTarget? program targetId = some witness.schedule.sourceRva
  classificationExact :
    x87Classified program witness.schedule.sourceRva = some true
  classified : witness.schedule.sourceRva ∈ program.x87SourceRvas
  partition : ExactBindingPartition pe program
  witnessMember : witness ∈ partition.x87Witnesses
  region : RegionRelation
  regionExact : regionById program.worldProgram.regions targetId = some region
  regionSpanExact : region.original = schedule.record.span
  continuationTargetId : Nat
  sourceContinuationExact :
    targetIdForRva? program schedule.record.span.stop = some continuationTargetId
  decodedContinuationExact :
    normalizeCodeTarget false region.targets schedule.record.span.stop =
      some continuationTargetId

theorem ExactX87SingletonTargetFacts.providerExact
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule)
    (state : MachineState) :
    program.x87Provider.execute witness.schedule.sourceRva state =
      runExactInterpreter pe witness.schedule state :=
  facts.partition.x87ProviderExact witness.schedule.sourceRva facts.classified
    witness facts.witnessMember rfl state

def ExactX87SingletonTargetFacts.toBoundTargetSelection
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    BoundTargetSelection program targetId :=
  .x87 witness.schedule.sourceRva facts.sourceRvaExact
    facts.classificationExact facts.classified

theorem ExactX87SingletonTargetFacts.decodedBehaviorExact
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule)
    (state : MachineState) (calls : List Nat) :
    decodedWorldRegionBehaviorWithCalls program.worldProgram targetId state calls =
      StageA.Relational.X87.executeSingletonCommand false pe
        schedule.record.span facts.region.targets state := by
  simp [decodedWorldRegionBehaviorWithCalls, facts.regionExact,
    facts.originalSide, facts.originalPeExact, facts.regionSpanExact,
    StageA.Relational.X87.spanStartsWithX87Command, schedule.decoded]

/-- Static singleton schedule and target facts close the complete target-local
effect equation.  The proof executes the checked schedule and decoded carrier
symbolically for an arbitrary state, but no caller supplies a universal
execution or effect theorem. -/
private def ExactX87SingletonTargetFacts.toLocalEffectExactCore
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    TargetLocalEffectExact program targetId where
  effect := by
    intro state calls
    have singletonCommandSome :=
      executeSingletonCommand_isSome_of_decoded_and_continuation false pe
        schedule.record.span [singletonTarget schedule.record.span]
        schedule.record.span.stop schedule.descriptor schedule.decoded
        (by simp [normalizeCodeTarget, singletonTarget]) state
        (schedule.inputValid state)
    cases singletonCommandExact :
        StageA.Relational.X87.executeSingletonCommand false pe
          schedule.record.span [singletonTarget schedule.record.span] state with
    | none => simp [singletonCommandExact] at singletonCommandSome
    | some singletonBehavior =>
        have singletonOutcome :=
          StageA.Relational.X87.executeSingletonCommand_outcome_of_continuation
            false pe schedule.record.span
            [singletonTarget schedule.record.span] state singletonBehavior
            schedule.record.span.stop
            (by simp [normalizeCodeTarget, singletonTarget])
            singletonCommandExact
        have singletonEffectSome :=
          StageA.Relational.X87.executeSingletonCommand_effect_isSome
            false pe schedule.record.span
            [singletonTarget schedule.record.span] state singletonBehavior
            singletonCommandExact
        cases singletonEffectExact : singletonBehavior.x87Effect with
        | none => simp [singletonEffectExact] at singletonEffectSome
        | some singletonEffect =>
            let sourceResult := exactX87SingletonStepResult schedule.record
              schedule.descriptor state singletonBehavior singletonEffect
            have sourceResultExact :
                executeX87Singleton pe schedule.record state =
                  some sourceResult := by
              simpa [sourceResult] using executeX87Singleton_eq_exactStepResult
                pe schedule.record state schedule.descriptor singletonBehavior
                singletonEffect schedule.recordClass schedule.decoded
                singletonCommandExact singletonEffectExact singletonOutcome
            have runExact := schedule.runExactInterpreter_of_step state
              sourceResult sourceResultExact
            have decodedSome :=
              executeSingletonCommand_isSome_of_decoded_and_continuation false
                pe schedule.record.span facts.region.targets
                facts.continuationTargetId schedule.descriptor schedule.decoded
                facts.decodedContinuationExact state (schedule.inputValid state)
            cases decodedExact :
                StageA.Relational.X87.executeSingletonCommand false pe
                  schedule.record.span facts.region.targets state with
            | none => simp [decodedExact] at decodedSome
            | some decodedBehavior =>
                have decodedFromSingleton :=
                  executeSingletonCommand_eq_with_outcome_of_continuations false
                    pe schedule.record.span
                    [singletonTarget schedule.record.span] facts.region.targets
                    schedule.record.span.stop facts.continuationTargetId
                    schedule.descriptor schedule.decoded
                    (by simp [normalizeCodeTarget, singletonTarget])
                    facts.decodedContinuationExact state singletonBehavior
                    decodedBehavior singletonCommandExact decodedExact
                rw [show targetStepWithCalls? program targetId state calls =
                    x87Step? program witness.schedule.sourceRva state by
                  simp [targetStepWithCalls?, facts.sourceRvaExact,
                    facts.classificationExact]]
                rw [x87Step?_eq_routeX87ScheduleResult?,
                  facts.providerExact state, runExact]
                rw [facts.decodedBehaviorExact state calls, decodedExact]
                subst decodedBehavior
                cases faultExact : singletonBehavior.x87Fault with
                | none =>
                    simp [sourceResult, exactX87SingletonStepResult,
                      routeX87ScheduleResult?,
                      scheduleMacroResult?, lastControl?,
                      ExecutionTrace.appendStep, mapScheduleOutcome?,
                      facts.sourceContinuationExact, evaluatedEffectOfBehavior,
                      RelationalBehavior.nextMachineState, faultExact]
                | some fault =>
                    cases fault
                    simp [sourceResult, exactX87SingletonStepResult,
                      routeX87ScheduleResult?,
                      scheduleMacroResult?, lastControl?,
                      ExecutionTrace.appendStep, evaluatedEffectOfBehavior,
                      faultExact]

theorem ExactX87SingletonTargetFacts.decodedBehaviorIsSome
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule)
    (state : MachineState) (calls : List Nat) :
    (decodedWorldRegionBehaviorWithCalls program.worldProgram targetId state
      calls).isSome := by
  have executed := executeSingletonCommand_isSome_of_decoded_and_continuation
    false pe schedule.record.span facts.region.targets
    facts.continuationTargetId schedule.descriptor schedule.decoded
    facts.decodedContinuationExact state (schedule.inputValid state)
  rw [facts.decodedBehaviorExact state calls]
  simpa using executed

theorem ExactX87SingletonTargetFacts.targetStepIsSome
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule)
    (state : MachineState) (calls : List Nat) :
    (targetStepWithCalls? program targetId state calls).isSome := by
  have localEffect := facts.toLocalEffectExactCore.effect state calls
  have decodedSome := facts.decodedBehaviorIsSome state calls
  cases sourceExact : targetStepWithCalls? program targetId state calls with
  | none =>
      cases decodedExact : decodedWorldRegionBehaviorWithCalls
          program.worldProgram targetId state calls with
      | none => simp [decodedExact] at decodedSome
      | some behavior => simp [sourceExact, decodedExact] at localEffect
  | some sourceStep => simp

/-- Retain the successful source and decoded evaluator results needed by later
preservation proofs.  The values are `Option.get` projections justified by the
checked totality proofs above, not generated functions or choice axioms. -/
def ExactX87SingletonTargetFacts.toSuccessfulTargetEffectComponents
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    SuccessfulTargetEffectComponents program targetId where
  sourceStep := fun state =>
    fun calls => (targetStepWithCalls? program targetId state calls).get
      (facts.targetStepIsSome state calls)
  decodedBehavior := fun state calls =>
    (decodedWorldRegionBehaviorWithCalls program.worldProgram targetId state
      calls).get (facts.decodedBehaviorIsSome state calls)
  sourceStepExact := by
    intro state calls
    exact (Option.some_get (facts.targetStepIsSome state calls)).symm
  decodedBehaviorExact := by
    intro state calls
    exact (Option.some_get (facts.decodedBehaviorIsSome state calls)).symm
  effectsExact := by
    intro state calls
    have localEffect := facts.toLocalEffectExactCore.effect state calls
    rw [← Option.some_get (facts.targetStepIsSome state calls),
      ← Option.some_get (facts.decodedBehaviorIsSome state calls)] at localEffect
    exact localEffect

def ExactX87SingletonTargetFacts.toLocalEffectExact
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    TargetLocalEffectExact program targetId :=
  facts.toSuccessfulTargetEffectComponents.toLocalEffectExact

def ExactX87SingletonTargetFacts.toWorldRoutingExact
    {pe : PE32} {program : Program} {targetId : Nat}
    {witness : ExactInterpreterX87ScheduleWitness pe}
    {schedule : ExactX87SingletonScheduleFacts pe witness}
    (facts : ExactX87SingletonTargetFacts pe program targetId witness schedule) :
    TargetWorldRoutingExact program targetId :=
  facts.toLocalEffectExact.toWorldRoutingExact

end StageA.Relational.SourceWorld.InterpreterKernel
