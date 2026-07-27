import StageA.RelationalInterpreterMixedContext

namespace StageA.Relational.RuntimeValueCarry

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext

/-!
# Checked runtime value-carry routes

This module is a stable checker for compact cutpoint invariants. Generated
modules provide only data plus semantic authorities derived from exact decoded
transitions. A route status or Python analysis result has no proof meaning.
-/

inductive Location where
  | inRegister (register : Reg)
  | inFrameWord (register : Reg) (adjustment : StackAdjustment)
deriving Repr, DecidableEq

def Location.read (location : Location) (state : MachineState) : Word :=
  match location with
  | .inRegister register => state.registers.get register
  | .inFrameWord register adjustment =>
      Memory.read32 state.memory
        ((adjustment.expression register).eval state)

structure Fact where
  targetId : Nat
  locationId : Nat
deriving Repr, DecidableEq

structure CutpointEdge where
  edgeId : Nat
  sourceTargetId : Nat
  targetTargetId : Nat
deriving Repr, DecidableEq

structure CutpointGraph where
  targetIds : List Nat
  edges : List CutpointEdge
deriving Repr, DecidableEq

inductive TransferKind where
  | finiteOriginCallResult
  | directCallRegisterPreserve
  | decodedPreserve
  | decodedRegisterToFrame
  | callFrameWordPreserve
deriving Repr, DecidableEq

structure Transfer where
  edgeId : Nat
  sourceTargetId : Nat
  targetTargetId : Nat
  kind : TransferKind
  sourceLocationId : Option Nat
  targetLocationId : Nat
deriving Repr, DecidableEq

structure Route where
  originTargetId : Nat
  locations : List Location
  facts : List Fact
  transfers : List Transfer
  targetFact : Fact
deriving Repr, DecidableEq

def noDuplicates [BEq α] (items : List α) : Bool :=
  items.length == items.eraseDups.length

def CutpointGraph.checked (graph : CutpointGraph) : Bool :=
  !graph.targetIds.isEmpty &&
    noDuplicates graph.targetIds &&
    noDuplicates (graph.edges.map (·.edgeId)) &&
    graph.edges.all fun edge =>
      graph.targetIds.contains edge.sourceTargetId &&
        graph.targetIds.contains edge.targetTargetId

def Route.location? (route : Route) (locationId : Nat) : Option Location :=
  route.locations[locationId]?

def Route.fact? (route : Route) (targetId : Nat) : Option Fact :=
  route.facts.find? fun fact => fact.targetId == targetId

def Route.edge? (graph : CutpointGraph) (edgeId : Nat) :
    Option CutpointEdge :=
  graph.edges.find? fun edge => edge.edgeId == edgeId

def Route.transfer? (route : Route) (edgeId : Nat) : Option Transfer :=
  route.transfers.find? fun transfer => transfer.edgeId == edgeId

def Route.factKnown (route : Route) (fact : Fact) : Bool :=
  route.facts.contains fact && (route.location? fact.locationId).isSome

def Transfer.edgeChecked
    (graph : CutpointGraph) (transfer : Transfer) : Bool :=
  match graph.edges.find? fun edge => edge.edgeId == transfer.edgeId with
  | none => false
  | some edge =>
      edge.sourceTargetId == transfer.sourceTargetId &&
        edge.targetTargetId == transfer.targetTargetId

def Transfer.locationsChecked (route : Route) (transfer : Transfer) : Bool :=
  match route.location? transfer.targetLocationId with
  | none => false
  | some target =>
      route.facts.contains {
        targetId := transfer.targetTargetId
        locationId := transfer.targetLocationId
      } &&
      match transfer.kind, transfer.sourceLocationId with
      | .finiteOriginCallResult, none =>
          match target with
          | .inRegister _ => true
          | _ => false
      | .directCallRegisterPreserve, some sourceId =>
          match route.location? sourceId, target with
          | some (.inRegister source), .inRegister target =>
              source == target &&
                route.facts.contains {
                  targetId := transfer.sourceTargetId
                  locationId := sourceId
                }
          | _, _ => false
      | .decodedPreserve, some sourceId =>
          match route.location? sourceId with
          | some source =>
              source == target &&
                route.facts.contains {
                  targetId := transfer.sourceTargetId
                  locationId := sourceId
                }
          | none => false
      | .decodedRegisterToFrame, some sourceId =>
          match route.location? sourceId, target with
          | some (.inRegister _), .inFrameWord _ _ =>
              route.facts.contains {
                targetId := transfer.sourceTargetId
                locationId := sourceId
              }
          | _, _ => false
      | .callFrameWordPreserve, some sourceId =>
          match route.location? sourceId, target with
          | some (.inFrameWord sourceRegister sourceAdjustment),
              .inFrameWord targetRegister targetAdjustment =>
              sourceRegister == targetRegister &&
                sourceAdjustment == targetAdjustment &&
                route.facts.contains {
                  targetId := transfer.sourceTargetId
                  locationId := sourceId
                }
          | _, _ => false
      | _, _ => false

def Route.incomingCovered
    (route : Route) (graph : CutpointGraph) : Bool :=
  graph.edges.all fun edge =>
    if (route.fact? edge.targetTargetId).isSome then
      route.transfers.any fun transfer =>
        transfer.edgeId == edge.edgeId &&
          transfer.sourceTargetId == edge.sourceTargetId &&
          transfer.targetTargetId == edge.targetTargetId
    else
      true

def Route.inventoryChecked
    (graph : CutpointGraph) (route : Route) : Bool :=
    !route.locations.isEmpty &&
    !route.facts.isEmpty &&
    noDuplicates route.facts &&
    noDuplicates (route.facts.map (·.targetId)) &&
    route.facts.all (fun fact =>
      graph.targetIds.contains fact.targetId &&
        (route.location? fact.locationId).isSome) &&
    !route.transfers.isEmpty &&
    noDuplicates (route.transfers.map (·.edgeId)) &&
    route.transfers.all (fun transfer =>
        transfer.edgeChecked graph &&
        transfer.locationsChecked route)

def Route.structureChecked
    (graph : CutpointGraph) (route : Route) : Bool :=
  ((graph.checked &&
      route.inventoryChecked graph) &&
    route.factKnown route.targetFact) &&
    route.incomingCovered graph

def Route.originChecked
    (context : OriginalDecodedStaticContext) (route : Route) : Bool :=
  (context.codeMap.get? route.originTargetId).isSome

def Route.checked
    (context : OriginalDecodedStaticContext) (graph : CutpointGraph)
    (route : Route) : Bool :=
  route.structureChecked graph && route.originChecked context

theorem Route.incomingCovered_of_structureChecked
    (graph : CutpointGraph) (route : Route)
    (checked : route.structureChecked graph = true) :
    route.incomingCovered graph = true := by
  rw [Route.structureChecked] at checked
  simp only [Bool.and_eq_true] at checked
  exact checked.2

theorem Route.targetFactKnown_of_structureChecked
    (graph : CutpointGraph) (route : Route)
    (checked : route.structureChecked graph = true) :
    route.factKnown route.targetFact = true := by
  rw [Route.structureChecked] at checked
  simp only [Bool.and_eq_true] at checked
  exact checked.1.2

theorem Route.structureChecked_of_checked
    (context : OriginalDecodedStaticContext) (graph : CutpointGraph)
    (route : Route) (checked : route.checked context graph = true) :
    route.structureChecked graph = true := by
  rw [Route.checked] at checked
  simp only [Bool.and_eq_true] at checked
  exact checked.1

theorem Route.originKnown_of_checked
    (context : OriginalDecodedStaticContext) (graph : CutpointGraph)
    (route : Route) (checked : route.checked context graph = true) :
    (context.codeMap.get? route.originTargetId).isSome = true := by
  rw [Route.checked] at checked
  simp only [Bool.and_eq_true] at checked
  simpa only [Route.originChecked] using checked.2

theorem Route.transfer_exists_for_incoming
    (context : OriginalDecodedStaticContext) (graph : CutpointGraph)
    (route : Route) (checked : route.checked context graph = true)
    (edge : CutpointEdge) (edgeMember : edge ∈ graph.edges)
    (targetTracked : (route.fact? edge.targetTargetId).isSome = true) :
    ∃ transfer, transfer ∈ route.transfers ∧
      transfer.edgeId = edge.edgeId ∧
      transfer.sourceTargetId = edge.sourceTargetId ∧
      transfer.targetTargetId = edge.targetTargetId := by
  have covered := List.all_eq_true.mp
    (route.incomingCovered_of_structureChecked graph
      (route.structureChecked_of_checked context graph checked))
    edge edgeMember
  simp only [targetTracked, if_true, List.any_eq_true] at covered
  rcases covered with ⟨transfer, transferMember, matchTrue⟩
  have matched :
      transfer.edgeId = edge.edgeId ∧
        transfer.sourceTargetId = edge.sourceTargetId ∧
        transfer.targetTargetId = edge.targetTargetId := by
    simp only [Bool.and_eq_true, beq_iff_eq] at matchTrue
    exact ⟨matchTrue.1.1, matchTrue.1.2, matchTrue.2⟩
  exact ⟨transfer, transferMember, matched.1, matched.2.1, matched.2.2⟩

/-- The concrete original-side meaning of the route's static code origin.
Generated semantic authorities establish this predicate from decoded register
and memory effects. -/
def Route.FactHolds
    (context : OriginalDecodedStaticContext) (route : Route)
    (fact : Fact) (state : MachineState) : Prop :=
  ∃ location target,
    route.location? fact.locationId = some location ∧
      context.codeMap.get? route.originTargetId = some target ∧
      codeAddressMatches context.pe.imageBase target.rva
        target.aliases (location.read state) = true

end StageA.Relational.RuntimeValueCarry
