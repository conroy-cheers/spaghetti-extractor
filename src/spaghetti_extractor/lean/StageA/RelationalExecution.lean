import StageA.RelationalInvariant

namespace StageA.Relational

open StageA.Formal

def PureOutcome.relationalObservation : PureOutcome -> Option RelationalObservable
  | .externalCall imported arguments _ => some (.external imported arguments)
  | .externalJump imported arguments => some (.external imported arguments)
  | .returned _ => some .returned
  | .checkedContinue valid _ => if valid then none else some .fault
  | _ => none

def relationalObservationsRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair) :
    Option RelationalObservable -> Option RelationalObservable -> Bool
  | none, none => true
  | some (.external originalImport originalArguments),
      some (.external candidateImport candidateArguments) =>
      originalImport == candidateImport &&
        wordsRelated originalImageBase candidateImageBase targets values
          originalArguments candidateArguments
  | some .returned, some .returned => true
  | some .fault, some .fault => true
  | _, _ => false

theorem relationalObservationsRelated_self (imageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (observation : Option RelationalObservable) :
    relationalObservationsRelated imageBase imageBase targets values
      observation observation = true := by
  cases observation with
  | none => rfl
  | some observation =>
      cases observation <;>
        simp [relationalObservationsRelated, wordsRelated_self]

theorem outcomesRelated_observation_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    original.observation = candidate.observation := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.observation]

theorem outcomesRelated_nextLogicalTarget_eq
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    original.nextLogicalTarget = candidate.nextLogicalTarget := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.nextLogicalTarget]

theorem outcomesRelated_relationalObservation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : PureOutcome)
    (related : outcomesRelated originalImageBase candidateImageBase targets values
      original candidate = true) :
    relationalObservationsRelated originalImageBase candidateImageBase targets values
      original.relationalObservation candidate.relationalObservation = true := by
  cases original <;> cases candidate <;>
    simp_all [outcomesRelated, PureOutcome.relationalObservation,
      relationalObservationsRelated]
  all_goals split <;> simp_all

structure Transition (state : Type) where
  next : state
  observation : Option Observable

structure TransitionSystem (state : Type) where
  step : state -> Transition state

def WeakBisimulation {originalState candidateState : Type}
    (original : TransitionSystem originalState) (candidate : TransitionSystem candidateState)
    (relation : originalState -> candidateState -> Prop) : Prop :=
  ∀ originalValue candidateValue,
    relation originalValue candidateValue ->
    (original.step originalValue).observation = (candidate.step candidateValue).observation ∧
    relation (original.step originalValue).next (candidate.step candidateValue).next

def trace {state : Type} (system : TransitionSystem state) : Nat -> state -> List Observable
  | 0, _ => []
  | fuel + 1, state =>
      let transition := system.step state
      transition.observation.toList ++ trace system fuel transition.next

theorem weakBisimulation_trace {originalState candidateState : Type}
    (original : TransitionSystem originalState) (candidate : TransitionSystem candidateState)
    (relation : originalState -> candidateState -> Prop)
    (bisimulation : WeakBisimulation original candidate relation) :
    ∀ fuel originalState candidateState,
      relation originalState candidateState ->
      trace original fuel originalState = trace candidate fuel candidateState := by
  intro fuel
  induction fuel with
  | zero => intro _ _ _; rfl
  | succ fuel ih =>
      intro originalState candidateState related
      have step := bisimulation originalState candidateState related
      change
        (original.step originalState).observation.toList ++
            trace original fuel (original.step originalState).next =
          (candidate.step candidateState).observation.toList ++
            trace candidate fuel (candidate.step candidateState).next
      rw [step.1]
      exact congrArg ((candidate.step candidateState).observation.toList ++ ·)
        (ih (original.step originalState).next (candidate.step candidateState).next step.2)

structure RelatedTransition (state observation : Type) where
  next : state
  observation : Option observation

structure RelatedTransitionSystem (state observation : Type) where
  step : state -> RelatedTransition state observation

def RelationalWeakBisimulation
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop) : Prop :=
  ∀ originalValue candidateValue,
    stateRelation originalValue candidateValue ->
    observationRelation (original.step originalValue).observation
      (candidate.step candidateValue).observation ∧
    stateRelation (original.step originalValue).next (candidate.step candidateValue).next

def RelatedTrace
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop) :
    Nat -> originalState -> candidateState -> Prop
  | 0, originalState, candidateState => stateRelation originalState candidateState
  | fuel + 1, originalState, candidateState =>
      observationRelation (original.step originalState).observation
          (candidate.step candidateState).observation ∧
        RelatedTrace original candidate stateRelation observationRelation fuel
          (original.step originalState).next (candidate.step candidateState).next

theorem relationalWeakBisimulation_trace
    {originalState candidateState originalObservation candidateObservation : Type}
    (original : RelatedTransitionSystem originalState originalObservation)
    (candidate : RelatedTransitionSystem candidateState candidateObservation)
    (stateRelation : originalState -> candidateState -> Prop)
    (observationRelation : Option originalObservation -> Option candidateObservation -> Prop)
    (bisimulation : RelationalWeakBisimulation original candidate stateRelation
      observationRelation) :
    ∀ fuel originalState candidateState,
      stateRelation originalState candidateState ->
      RelatedTrace original candidate stateRelation observationRelation fuel
        originalState candidateState := by
  intro fuel
  induction fuel with
  | zero =>
      intro originalState candidateState related
      exact related
  | succ fuel ih =>
      intro originalState candidateState related
      have step := bisimulation originalState candidateState related
      exact ⟨step.1, ih _ _ step.2⟩

def Memory.bulkCopyDwords (memory : Memory) (destination source : Word)
    (direction : Bool) : Nat -> Memory
  | 0 => memory
  | count + 1 =>
      let value := Memory.read32 memory source
      let nextMemory := memory.write32 destination value
      let distance := BitVec.ofNat 32 4
      let nextDestination := if direction then destination - distance else destination + distance
      let nextSource := if direction then source - distance else source + distance
      Memory.bulkCopyDwords nextMemory nextDestination nextSource direction count

def Memory.atomicCompareExchange (memory : Memory) (address expected replacement : Word) :
    Memory :=
  if Memory.read32 memory address == expected then
    memory.write32 address replacement
  else
    memory

structure RelationalExternalEvent where
  imported : ExternalTarget
  arguments : List Word
  state : MachineState

structure RelationalEnvironment where
  result : Nat -> RelationalExternalEvent -> MachineState

def RelationalEnvironmentsRegisterCompatible
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (regions : List RegionRelation)
    (original candidate : RelationalEnvironment) : Prop :=
  ∀ source target contract originalBehavior candidateBehavior eventIndex originalEvent
      candidateEvent,
    source ∈ regions → target ∈ regions →
    InvariantWP.ExternalRegisterPolicyEdgeClosed source target
      contract originalBehavior candidateBehavior →
    originalEvent.imported = candidateEvent.imported →
    wordsRelated originalImageBase candidateImageBase targets values
      originalEvent.arguments candidateEvent.arguments = true →
    registerRelationsHold originalImageBase candidateImageBase targets values
      target.inputRelations
      (original.result eventIndex originalEvent).registers
      (candidate.result eventIndex candidateEvent).registers = true

structure RelationalProgramSemantics where
  behavior : Nat -> MachineState -> Option RelationalBehavior
  resolveTarget : Word -> Option Nat
  resolveImportCall : Word -> MachineState -> Option (ExternalTarget × List Word)
  environment : RelationalEnvironment

def ImportAddressResolutionsValid (candidate : Bool) (world : RelationalWorld)
    (program : RelationalProgramSemantics) : Prop :=
  ∀ binding, binding ∈ world.importAddresses → ∀ state,
    ∃ arguments,
      program.resolveImportCall
        (if candidate then binding.candidateAddress else binding.originalAddress)
        state = some (binding.imported, arguments)

inductive RelationalExecution where
  | running (region : Nat) (state : MachineState) (calls : List Nat) (eventIndex : Nat)
  | returned (state : MachineState)
  | fault

def transitionFromOutcome (program : RelationalProgramSemantics)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat) :
    PureOutcome -> RelatedTransition RelationalExecution RelationalObservable
  | .returned target =>
      match calls with
      | [] => { next := .returned state, observation := some .returned }
      | continuation :: tail =>
          match program.resolveTarget target with
          | some resolved =>
              if resolved == continuation then
                { next := .running continuation state tail eventIndex, observation := none }
              else
                { next := .fault, observation := some .fault }
          | none => { next := .fault, observation := some .fault }
  | .jump target =>
      { next := .running target state calls eventIndex, observation := none }
  | .branch condition taken fallthrough =>
      { next := .running (if condition then taken else fallthrough) state calls eventIndex,
        observation := none }
  | .call target continuation =>
      { next := .running target state (continuation :: calls) eventIndex, observation := none }
  | .callUnmappedReturn _ =>
      { next := .fault, observation := some .fault }
  | .externalCall imported arguments continuation =>
      let event := { imported, arguments, state : RelationalExternalEvent }
      let result := program.environment.result eventIndex event
      { next := .running continuation result calls (eventIndex + 1),
        observation := some (.external imported arguments) }
  | .externalJump imported arguments =>
      let event := { imported, arguments, state : RelationalExternalEvent }
      let result := program.environment.result eventIndex event
      let next := match calls with
        | [] => RelationalExecution.returned result
        | continuation :: tail =>
            RelationalExecution.running continuation result tail (eventIndex + 1)
      { next, observation := some (.external imported arguments) }
  | .bulkCopy destination source count direction continuation =>
      let memory := Memory.bulkCopyDwords state.memory destination source direction count.toNat
      { next := .running continuation { state with memory } calls eventIndex,
        observation := none }
  | .indirectCall target continuation =>
      match program.resolveTarget target with
      | some resolved =>
          { next := .running resolved state (continuation :: calls) eventIndex,
            observation := none }
      | none =>
          match program.resolveImportCall target state with
          | some (imported, arguments) =>
              let event := { imported, arguments, state : RelationalExternalEvent }
              let result := program.environment.result eventIndex event
              { next := .running continuation result calls (eventIndex + 1),
                observation := some (.external imported arguments) }
          | none => { next := .fault, observation := some .fault }
  | .indirectJump target =>
      match program.resolveTarget target with
      | some resolved =>
          { next := .running resolved state calls eventIndex, observation := none }
      | none =>
          match program.resolveImportCall target state with
          | some (imported, arguments) =>
              let event := { imported, arguments, state : RelationalExternalEvent }
              let result := program.environment.result eventIndex event
              let next := match calls with
                | [] => RelationalExecution.returned result
                | continuation :: tail =>
                    RelationalExecution.running continuation result tail (eventIndex + 1)
              { next, observation := some (.external imported arguments) }
          | none => { next := .fault, observation := some .fault }
  | .checkedContinue valid continuation =>
      if valid then
        { next := .running continuation state calls eventIndex, observation := none }
      else
        { next := .fault, observation := some .fault }
  | .atomicCompareExchange address expected replacement continuation =>
      let memory := Memory.atomicCompareExchange state.memory address expected replacement
      { next := .running continuation { state with memory } calls eventIndex,
        observation := none }

def stepRelationalExecution (program : RelationalProgramSemantics) :
    RelationalExecution -> RelatedTransition RelationalExecution RelationalObservable
  | .running region state calls eventIndex =>
      match program.behavior region state with
      | none => { next := .fault, observation := some .fault }
      | some behavior =>
          transitionFromOutcome program (behavior.nextMachineState state) calls eventIndex
            behavior.outcome
  | .returned state => { next := .returned state, observation := none }
  | .fault => { next := .fault, observation := none }

def RelationalProgramSemantics.transitionSystem (program : RelationalProgramSemantics) :
    RelatedTransitionSystem RelationalExecution RelationalObservable := {
  step := stepRelationalExecution program
}

def decodedProgramSemantics (candidate : Bool) (pe : PE32) (imports : List PEImport)
    (regions : List RegionRelation) (environment : RelationalEnvironment) :
    RelationalProgramSemantics := {
  behavior := decodedRegionBehavior candidate pe imports regions
  resolveTarget := resolveMappedCodeTarget candidate pe.imageBase (allCodeTargets regions)
  resolveImportCall := fun _ _ => none
  environment
}

def regionMachineStatesRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (regions : List RegionRelation) (id : Nat)
    (original candidate : MachineState) : Prop :=
  match regionById regions id with
  | some region =>
      composableStatesRelated originalImageBase candidateImageBase targets
        region.flagInputs region.bounds region.addressSeparations values
        region.inputRelations original candidate
  | none => False

def executionsRelated (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (regions : List RegionRelation)
    (terminalRelation : MachineState -> MachineState -> Prop) :
    RelationalExecution -> RelationalExecution -> Prop
  | .running originalRegion originalState originalCalls originalEventIndex,
      .running candidateRegion candidateState candidateCalls candidateEventIndex =>
      originalRegion = candidateRegion ∧ originalCalls = candidateCalls ∧
        originalEventIndex = candidateEventIndex ∧
        regionMachineStatesRelated originalImageBase candidateImageBase targets values regions
          originalRegion originalState candidateState
  | .returned originalState, .returned candidateState =>
      terminalRelation originalState candidateState
  | .fault, .fault => True
  | _, _ => False

def AllRunningTransitionsRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∀ region originalState candidateState calls eventIndex,
    regionMachineStatesRelated originalImageBase candidateImageBase targets values regions region
      originalState candidateState ->
    relationalObservationsRelated originalImageBase candidateImageBase targets values
        (stepRelationalExecution original
          (.running region originalState calls eventIndex)).observation
        (stepRelationalExecution candidate
          (.running region candidateState calls eventIndex)).observation = true ∧
      executionsRelated originalImageBase candidateImageBase targets values regions terminalRelation
        (stepRelationalExecution original
          (.running region originalState calls eventIndex)).next
        (stepRelationalExecution candidate
          (.running region candidateState calls eventIndex)).next

def RegionRunningTransitionRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (region : RegionRelation) : Prop :=
  ∀ originalState candidateState calls eventIndex,
    composableStatesRelated originalImageBase candidateImageBase targets
      region.flagInputs region.bounds region.addressSeparations values
      region.inputRelations
      originalState candidateState ->
    relationalObservationsRelated originalImageBase candidateImageBase targets values
        (stepRelationalExecution original
          (.running region.id originalState calls eventIndex)).observation
        (stepRelationalExecution candidate
          (.running region.id candidateState calls eventIndex)).observation = true ∧
      executionsRelated originalImageBase candidateImageBase targets values regions terminalRelation
        (stepRelationalExecution original
          (.running region.id originalState calls eventIndex)).next
        (stepRelationalExecution candidate
          (.running region.id candidateState calls eventIndex)).next

def AllRegionRunningTransitionsRelated
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∀ region, region ∈ regions ->
    RegionRunningTransitionRelated originalImageBase candidateImageBase regions targets values
      original candidate terminalRelation region

theorem allRunningTransitionsRelated_of_regions
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (checked : AllRegionRunningTransitionsRelated originalImageBase candidateImageBase
      regions targets values original candidate terminalRelation) :
    AllRunningTransitionsRelated originalImageBase candidateImageBase regions targets values
      original candidate terminalRelation := by
  intro id originalState candidateState calls eventIndex related
  unfold regionMachineStatesRelated at related
  cases found : regionById regions id with
  | none => simp [found] at related
  | some region =>
      have member : region ∈ regions := by
        unfold regionById at found
        exact List.mem_of_find?_eq_some found
      have idMatch : region.id = id := by
        unfold regionById at found
        have matched := List.find?_some found
        simpa only [beq_iff_eq] using matched
      subst id
      exact checked region member originalState candidateState calls eventIndex (by
        simpa [found] using related)

def WholeProgramBisimulation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (executionRelation : RelationalExecution -> RelationalExecution -> Prop) : Prop :=
  RelationalWeakBisimulation original.transitionSystem candidate.transitionSystem
    executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)

theorem wholeProgramBisimulation_of_runningTransitions
    (originalImageBase candidateImageBase : Nat)
    (regions : List RegionRelation) (targets : List CodeTargetPair)
    (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (terminalRelation : MachineState -> MachineState -> Prop)
    (running : AllRunningTransitionsRelated originalImageBase candidateImageBase regions
      targets values original candidate terminalRelation) :
    WholeProgramBisimulation originalImageBase candidateImageBase targets values
      original candidate
      (executionsRelated originalImageBase candidateImageBase targets values regions
        terminalRelation) := by
  intro originalExecution candidateExecution related
  cases originalExecution <;> cases candidateExecution <;>
    simp [executionsRelated] at related
  case running.running originalRegion originalState originalCalls originalEventIndex
      candidateRegion candidateState candidateCalls candidateEventIndex =>
    rcases related with ⟨regionEqual, callsEqual, eventIndexEqual, stateRelated⟩
    subst candidateRegion
    subst candidateCalls
    subst candidateEventIndex
    exact running originalRegion originalState candidateState originalCalls originalEventIndex
      stateRelated
  case returned.returned originalState candidateState =>
    exact ⟨rfl, related⟩
  case fault.fault =>
    exact ⟨rfl, trivial⟩

def WholeProgramTraceRelation
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (executionRelation : RelationalExecution -> RelationalExecution -> Prop) :
    Nat -> RelationalExecution -> RelationalExecution -> Prop :=
  RelatedTrace original.transitionSystem candidate.transitionSystem executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)

def WholeProgramObservationalEquivalence
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (initialRelation : MachineState -> MachineState -> Prop) : Prop :=
  ∃ executionRelation : RelationalExecution -> RelationalExecution -> Prop,
    (∀ entry originalState candidateState,
      initialRelation originalState candidateState ->
      executionRelation (.running entry originalState [] 0)
        (.running entry candidateState [] 0)) ∧
    WholeProgramBisimulation originalImageBase candidateImageBase targets values
      original candidate executionRelation

theorem wholeProgramObservationalEquivalence_self (imageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (program : RelationalProgramSemantics) :
    WholeProgramObservationalEquivalence imageBase imageBase targets values program program
      (fun original candidate => original = candidate) := by
  refine ⟨fun original candidate => original = candidate, ?_, ?_⟩
  · intro entry originalState candidateState related
    subst candidateState
    rfl
  · intro originalExecution candidateExecution related
    subst candidateExecution
    exact ⟨relationalObservationsRelated_self imageBase targets values _, rfl⟩

theorem wholeProgramObservationalEquivalence_trace
    (originalImageBase candidateImageBase : Nat)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (original candidate : RelationalProgramSemantics)
    (initialRelation : MachineState -> MachineState -> Prop)
    (equivalent : WholeProgramObservationalEquivalence originalImageBase candidateImageBase
      targets values original candidate initialRelation) :
    ∀ fuel entry originalState candidateState,
      initialRelation originalState candidateState ->
      ∃ executionRelation : RelationalExecution -> RelationalExecution -> Prop,
        WholeProgramTraceRelation originalImageBase candidateImageBase targets values
          original candidate executionRelation fuel
          (.running entry originalState [] 0) (.running entry candidateState [] 0) := by
  rcases equivalent with ⟨executionRelation, initial, bisimulation⟩
  intro fuel entry originalState candidateState related
  refine ⟨executionRelation, ?_⟩
  exact relationalWeakBisimulation_trace original.transitionSystem candidate.transitionSystem
    executionRelation
    (fun originalObservation candidateObservation =>
      relationalObservationsRelated originalImageBase candidateImageBase targets values
        originalObservation candidateObservation = true)
    bisimulation fuel _ _ (initial entry originalState candidateState related)

end StageA.Relational
