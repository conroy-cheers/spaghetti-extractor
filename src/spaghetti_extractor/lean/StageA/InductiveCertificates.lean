import Std

namespace StageA.InductiveCertificates

/- Reachability is deliberately defined over finite execution prefixes.  A
   game loop need not terminate for an inductive invariant to cover every state
   reached after any finite number of iterations. -/
inductive Reachable {State : Type} (initial : State -> Prop)
    (step : State -> State -> Prop) : State -> Prop where
  | initial {state} : initial state -> Reachable initial step state
  | next {source target} :
      Reachable initial step source ->
      step source target ->
      Reachable initial step target

structure InductiveInvariant {State : Type} (initial : State -> Prop)
    (step : State -> State -> Prop) where
  predicate : State -> Prop
  initiation : forall state, initial state -> predicate state
  preservation : forall source target,
    predicate source -> step source target -> predicate target

theorem reachable_satisfies {State : Type} {initial : State -> Prop}
    {step : State -> State -> Prop}
    (certificate : InductiveInvariant initial step) :
    forall state, Reachable initial step state -> certificate.predicate state := by
  intro state reachable
  induction reachable with
  | initial hypothesis => exact certificate.initiation _ hypothesis
  | next _ transition sourceHolds =>
      exact certificate.preservation _ _ sourceHolds transition

/- Binary certificates are indexed by cutpoint as well as concrete machine
   state.  The state space may be infinite; only the submitted cutpoint and
   transition inventories are finite. -/
inductive CutpointReachable {Cutpoint State : Type}
    (root : Cutpoint -> State -> Prop)
    (step : Cutpoint -> State -> Cutpoint -> State -> Prop) :
    Cutpoint -> State -> Prop where
  | root {cutpoint state} :
      root cutpoint state -> CutpointReachable root step cutpoint state
  | next {source sourceState target targetState} :
      CutpointReachable root step source sourceState ->
      step source sourceState target targetState ->
      CutpointReachable root step target targetState

structure CutpointInvariantCertificate {Cutpoint State : Type}
    (root : Cutpoint -> State -> Prop)
    (step : Cutpoint -> State -> Cutpoint -> State -> Prop) where
  invariant : Cutpoint -> State -> Prop
  initiation : forall cutpoint state,
    root cutpoint state -> invariant cutpoint state
  preservation : forall source sourceState target targetState,
    invariant source sourceState ->
    step source sourceState target targetState ->
    invariant target targetState

theorem cutpoint_reachable_satisfies {Cutpoint State : Type}
    {root : Cutpoint -> State -> Prop}
    {step : Cutpoint -> State -> Cutpoint -> State -> Prop}
    (certificate : CutpointInvariantCertificate root step) :
    forall cutpoint state,
      CutpointReachable root step cutpoint state ->
      certificate.invariant cutpoint state := by
  intro cutpoint state reachable
  induction reachable with
  | root hypothesis => exact certificate.initiation _ _ hypothesis
  | next _ transition sourceHolds =>
      exact certificate.preservation _ _ _ _ sourceHolds transition

/- The finite checker is intentionally independent of binary-specific data.
   Exact machine-IR checking supplies the inventory-completeness fields; a
   generated certificate supplies only the proposed invariant. -/
structure FiniteTransitionSystem (State : Type) where
  states : List State
  transitions : List (Prod State State)
  initial : State -> Bool
  step : State -> State -> Bool
  initialComplete : forall state, initial state = true -> state ∈ states
  transitionExact : forall source target,
    step source target = true <-> (source, target) ∈ transitions

structure FiniteInvariantCertificate (State : Type) where
  invariant : State -> Bool

def boolImplies (premise conclusion : Bool) : Bool :=
  !premise || conclusion

def checkFiniteCertificate {State : Type}
    (system : FiniteTransitionSystem State)
    (certificate : FiniteInvariantCertificate State) : Bool :=
  system.states.all (fun state =>
    boolImplies (system.initial state) (certificate.invariant state)) &&
  system.transitions.all (fun edge =>
    boolImplies (certificate.invariant edge.1)
      (certificate.invariant edge.2))

theorem boolImplies_elim {premise conclusion : Bool}
    (checked : boolImplies premise conclusion = true)
    (holds : premise = true) : conclusion = true := by
  simp [boolImplies, holds] at checked
  exact checked

theorem checkFiniteCertificate_sound {State : Type}
    (system : FiniteTransitionSystem State)
    (certificate : FiniteInvariantCertificate State)
    (checked : checkFiniteCertificate system certificate = true) :
    forall state,
      Reachable (fun value => system.initial value = true)
        (fun source target => system.step source target = true) state ->
      certificate.invariant state = true := by
  have checks :
      (system.states.all (fun state =>
        boolImplies (system.initial state) (certificate.invariant state)) = true) ∧
      (system.transitions.all (fun edge =>
        boolImplies (certificate.invariant edge.1)
          (certificate.invariant edge.2)) = true) := by
    simpa [checkFiniteCertificate] using checked
  have initiationChecks := List.all_eq_true.mp checks.1
  have preservationChecks := List.all_eq_true.mp checks.2
  intro state reachable
  apply reachable_satisfies {
    predicate := fun value => certificate.invariant value = true
    initiation := by
      intro value initial
      exact boolImplies_elim
        (initiationChecks value (system.initialComplete value initial)) initial
    preservation := by
      intro source target sourceHolds transition
      exact boolImplies_elim
        (preservationChecks (source, target)
          ((system.transitionExact source target).mp transition)) sourceHolds
  } state reachable

end StageA.InductiveCertificates
