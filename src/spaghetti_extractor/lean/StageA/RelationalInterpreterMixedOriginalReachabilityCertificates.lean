import StageA.RelationalIndexedCertificateComposition
import StageA.RelationalInterpreterMixedOriginal
import StageA.RelationalInterpreterMixedWorldBridge

namespace StageA.Relational.InterpreterMixedOriginal

open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge

/-- Indexable form of one rooted reachability row.  Unlike the legacy list
fold, this predicate can be checked in independent bounded shards. -/
def originalReachabilityInventoryAt
    (context : OriginalDecodedStaticContext) (targetIds : List Nat)
    (index : Nat) : Bool :=
  match targetIds[index]? with
  | none => false
  | some targetId =>
      match context.source? targetId with
      | none => false
      | some source => source.region.targets.all targetIds.contains

theorem originalReachabilityInventoryValid_of_indexed_holds
    (checked : forall index, index < targetIds.length ->
      originalReachabilityInventoryAt context targetIds index = true) :
    originalReachabilityInventoryValid context targetIds = true := by
  simp only [originalReachabilityInventoryValid, List.all_eq_true]
  intro targetId member
  rcases List.mem_iff_getElem?.mp member with ⟨index, found⟩
  have before := List.getElem?_eq_some_iff.mp found |>.1
  have row := checked index before
  simpa [originalReachabilityInventoryAt, found] using row

/-- Construct the static rooted-reachability certificate from the checked
inventory.  This certificate closes decoded direct successors only.  Runtime
indirect-control closure remains an independent premise of mixed component
composition and cannot be discharged by this constructor. -/
def exactOriginalDecodedReachabilityOfCheckedStaticInventory
    (context : OriginalDecodedStaticContext)
    (authority : ExactOriginalDecodedAuthority context)
    (launch : PE32ConsoleLaunchV2)
    (root : DirectExactOriginalDecodedLaunchRoot context launch)
    (targetIds : List Nat)
    (unique : targetIds.Nodup)
    (entryReachable : launch.entryTargetId ∈ targetIds)
    (tlsReachable : forall targetId, targetId ∈ launch.tlsCallbackTargetIds ->
      targetId ∈ targetIds)
    (checked : originalReachabilityInventoryValid context targetIds = true) :
    ExactOriginalDecodedReachability context authority launch root := {
  targetIds
  unique
  entryReachable
  tlsReachable
  sourcesExist := by
    intro targetId member
    exact originalReachabilityInventoryValid_sources checked member
  successorsClosed := by
    intro targetId source member found successor successorMember
    exact originalReachabilityInventoryValid_successors checked member found
      successorMember
}

#print axioms exactOriginalDecodedReachabilityOfCheckedStaticInventory

end StageA.Relational.InterpreterMixedOriginal
