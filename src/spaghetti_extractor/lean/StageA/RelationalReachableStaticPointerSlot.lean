import StageA.RelationalInterpreterMixedOriginal
import StageA.RelationalInterpreterNormalization

namespace StageA.Relational.ReachableStaticPointerSlot

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterNormalization

/-! # Reachable writable static pointer slots

This module checks finite proposals against an exact decoded-original context.
It re-decodes scalar write widths and REP outcomes, then separates immutable
facts from runtime footprint premises. A non-constant scalar write classified
as `runtimeSeparated`, or each exact REP destination, must be proved disjoint
from the slot in the concrete source state. Such a classification is never
itself an acceptance fact.

`Certificate.regions` is sparse. A missing row is accepted only when Lean
replays the normalized behavior and proves every write to be an absolute
width-aware write disjoint from the slot. Thus artifacts scale with may-touch
regions, although the current `ExactOriginalDecodedAuthority` does not expose a
shared normalized-behavior inventory: kernel reduction still re-decodes each
reachable region for each slot certificate. A future authority-level behavior
object can remove that compute without changing the certificate semantics.
Reachable external outcomes additionally resolve to a unique validated
footprint-bounded machine-call contract.
-/

inductive Knowledge (alpha : Type) where
  | unknown
  | exact (value : alpha)
deriving Repr, DecidableEq

inductive WriteClassification where
  | absoluteDisjoint (width : MemoryWidth)
  | slotZero
  | slotCodeTarget (targetId : Nat)
  | runtimeSeparated (width : MemoryWidth)
deriving Repr, DecidableEq, BEq

def WriteClassification.width : WriteClassification -> MemoryWidth
  | .absoluteDisjoint width | .runtimeSeparated width => width
  | .slotZero | .slotCodeTarget _ => .dword

structure RegionBinding where
  targetId : Nat
  writes : Knowledge (List WriteClassification)
deriving Repr, DecidableEq

structure GuardedNonzeroEdge where
  sourceTargetId : Nat
  nonzeroTargetId : Nat
deriving Repr, DecidableEq, BEq

structure IndirectSlotSite where
  sourceTargetId : Nat
deriving Repr, DecidableEq, BEq

/-- All inventories are explicit. `unknown` cannot pass `checked`. -/
structure Certificate where
  slotRva : Nat
  reachableTargetIds : Knowledge (List Nat)
  allowedTargetIds : Knowledge (List Nat)
  regions : Knowledge (List RegionBinding)
  guardedNonzeroEdges : Knowledge (List GuardedNonzeroEdge)
  indirectSlotSites : Knowledge (List IndirectSlotSite)
  aliases : Knowledge (List Nat)
deriving Repr, DecidableEq

def noDuplicates [BEq alpha] (items : List alpha) : Bool :=
  items.length == items.eraseDups.length

def sameFiniteSet [BEq alpha] (left right : List alpha) : Bool :=
  noDuplicates left && noDuplicates right &&
    left.all right.contains && right.all left.contains

def slotAddress (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : Nat :=
  context.pe.imageBase + certificate.slotRva

def relocationOverlapsSlot (slotRva : Nat) (relocation : BaseRelocation) : Bool :=
  slotRva < relocation.rva + 4 && relocation.rva < slotRva + 4

def initialZeroChecked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : Bool :=
  let absolute := slotAddress context certificate
  certificate.slotRva % 4 == 0 &&
    absolute + 4 <= 2 ^ 32 &&
    writableStaticWordInPe context.pe (BitVec.ofNat 32 absolute) &&
    !staticWordOverlapsImportIat context.pe context.imports
      (BitVec.ofNat 32 absolute) &&
    readRvaU32 context.pe certificate.slotRva == some 0 &&
    context.relocations.all fun relocation =>
      !relocationOverlapsSlot certificate.slotRva relocation

def originalTargetPair? (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option CodeTargetPair := do
  let target <- context.codeMap.get? targetId
  pure {
    id := target.id
    regionIndex := target.regionIndex
    originalRva := target.rva
    candidateRva := target.rva
    originalAliases := target.aliases
    candidateAliases := target.aliases
  }

def originalTargetPairs? (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : Option (List CodeTargetPair) :=
  targetIds.mapM (originalTargetPair? context)

def normalizedRegionBehavior? (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option NormalizedSymbolicBehavior := do
  let source <- context.source? targetId
  let behavior <- regionBehaviorWithMachineCallContracts context.pe context.imports
    context.machineImportCallContracts source.region.span
  let targets <- originalTargetPairs? context source.region.targets
  normalizeSymbolicBehavior false targets behavior

structure DecodedWriteInventory where
  scalarWidths : List MemoryWidth
  repMovsdCount : Nat
  repStosdCount : Nat
deriving Repr, DecidableEq

def DecodedWriteInventory.append
    (left right : DecodedWriteInventory) : DecodedWriteInventory := {
  scalarWidths := left.scalarWidths ++ right.scalarWidths
  repMovsdCount := left.repMovsdCount + right.repMovsdCount
  repStosdCount := left.repStosdCount + right.repStosdCount
}

def orderedEffectsWriteInventory
    (effects : List OrderedEffectKind) : DecodedWriteInventory :=
  effects.foldl (fun inventory effect =>
    match effect with
    | .write width =>
        { inventory with scalarWidths := inventory.scalarWidths ++ [width] }
    | .repMovsd =>
        { inventory with repMovsdCount := inventory.repMovsdCount + 1 }
    | .repStosd =>
        { inventory with repStosdCount := inventory.repStosdCount + 1 }
    | .repMovs _ =>
        { inventory with repMovsdCount := inventory.repMovsdCount + 1 }
    | .repStos _ =>
        { inventory with repStosdCount := inventory.repStosdCount + 1 }
    | .read _ | .call _ | .divideGuard => inventory) {
      scalarWidths := []
      repMovsdCount := 0
      repStosdCount := 0
    }

/-- Re-decode one exact region and recover its complete ordered write-width
inventory from the reviewed architectural effect table. The submitted state
machine is not consulted. -/
def decodedRegionWriteInventoryFrom :
    PE32 -> List PEImport -> Nat -> Nat -> Bytes ->
      Option DecodedWriteInventory
  | _, _, 0, _, [] => some {
      scalarWidths := []
      repMovsdCount := 0
      repStosdCount := 0
    }
  | _, _, 0, _, _ :: _ => none
  | pe, imports, fuel + 1, rva, bytes =>
      if bytes.isEmpty then
        some {
          scalarWidths := []
          repMovsdCount := 0
          repStosdCount := 0
        }
      else do
        let decoded : DecodedInstruction <- decodeInstructionExact bytes
        if decoded.size = 0 || decoded.size > bytes.length then none else
        let instruction : ExactDecodedInstruction := {
          rva
          bytes := bytes.take decoded.size
        }
        let exact <- instruction.decode? pe
        let effects <- decodedOrderedEffects? pe imports instruction exact
        let tail <- decodedRegionWriteInventoryFrom pe imports fuel
          (rva + decoded.size) decoded.trailing
        pure ((orderedEffectsWriteInventory effects).append tail)

def decodedRegionWriteInventory? (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option DecodedWriteInventory := do
  let source : OriginalDecodedSource <- context.source? targetId
  let bytes : Bytes <- spanBytes context.pe source.region.span
  decodedRegionWriteInventoryFrom context.pe context.imports
    (bytes.length + 1) source.region.span.start bytes

def nonScalarWriteInventoryChecked
    (inventory : DecodedWriteInventory)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  match behavior.outcome with
  | .bulkCopy .. => inventory.repMovsdCount == 1 && inventory.repStosdCount == 0
  | .bulkFill .. => inventory.repMovsdCount == 0 && inventory.repStosdCount == 1
  | _ => inventory.repMovsdCount == 0 && inventory.repStosdCount == 0

def normalizedRegionWriteInventory?
    (context : OriginalDecodedStaticContext) (targetId : Nat) :
    Option (NormalizedSymbolicBehavior × DecodedWriteInventory) := do
  let behavior <- normalizedRegionBehavior? context targetId
  let inventory <- decodedRegionWriteInventory? context targetId
  if inventory.scalarWidths.length != behavior.writes.length ||
      !nonScalarWriteInventoryChecked inventory behavior then
    none
  else
    some (behavior, inventory)

def sourceTargets (context : OriginalDecodedStaticContext)
    (targetId : Nat) : List Nat :=
  match context.source? targetId with
  | none => []
  | some source => source.region.targets

def rootTargetIds (context : OriginalDecodedStaticContext) : List Nat :=
  (List.range context.codeMap.entries.size).filter fun targetId =>
    match context.source? targetId with
    | some source => source.region.root
    | none => false

def reachabilityStep (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : List Nat :=
  (targetIds ++ targetIds.flatMap (sourceTargets context)).eraseDups

def reachabilityClosureAux (context : OriginalDecodedStaticContext) :
    Nat -> List Nat -> List Nat
  | 0, targetIds => targetIds
  | fuel + 1, targetIds =>
      reachabilityClosureAux context fuel (reachabilityStep context targetIds)

def reachabilityClosure (context : OriginalDecodedStaticContext) : List Nat :=
  reachabilityClosureAux context (context.codeMap.entries.size + 1)
    (rootTargetIds context)

def normalizedDirectTargets : NormalizedOutcomeExpr -> List Nat
  | .returned _ => []
  | .jump target => [target]
  | .branch _ taken fallthrough => [taken, fallthrough].eraseDups
  | .call target continuation => [target, continuation].eraseDups
  | .callUnmappedReturn target => [target]
  | .externalCall _ _ continuation => [continuation]
  | .externalJump _ _ => []
  | .bulkCopy _ _ _ _ continuation => [continuation]
  | .bulkFill _ _ _ _ continuation => [continuation]
  | .indirectCall _ continuation => [continuation]
  | .indirectJump _ => []
  | .checkedContinue _ continuation => [continuation]
  | .atomicCompareExchange _ _ _ continuation => [continuation]

def directTargetsIncluded (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Bool :=
  match context.source? targetId, normalizedRegionBehavior? context targetId with
  | some source, some behavior =>
      (normalizedDirectTargets behavior.outcome).all source.region.targets.contains
  | _, _ => false

def reachableInventoryChecked (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : Bool :=
  !targetIds.isEmpty && sameFiniteSet targetIds (reachabilityClosure context) &&
    sameFiniteSet (reachabilityStep context targetIds) targetIds &&
    targetIds.all fun targetId =>
      (context.source? targetId).isSome && directTargetsIncluded context targetId

def targetCanonicalWord? (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option Nat := do
  let target <- context.codeMap.get? targetId
  if target.id != targetId || !target.aliases.isEmpty ||
      !rvaInExecutableSection context.pe target.rva ||
      context.pe.imageBase + target.rva >= 2 ^ 32 then
    none
  else
    pure (context.pe.imageBase + target.rva)

def allowedTargetsChecked (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : Bool :=
  noDuplicates targetIds && targetIds.all fun targetId =>
    (targetCanonicalWord? context targetId).isSome

def allowedWords (context : OriginalDecodedStaticContext)
    (targetIds : List Nat) : List Word :=
  0 :: (targetIds.filterMap (targetCanonicalWord? context)).map
    (BitVec.ofNat 32)

def natWriteSpanDisjoint (slot address : Nat) (width : MemoryWidth) : Bool :=
  slot + 4 <= address || address + width.bytes <= slot

def WriteClassification.checked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (allowedTargetIds : List Nat)
    (classification : WriteClassification) (write : Expr × Expr) : Bool :=
  let slot := slotAddress context certificate
  match classification with
  | .absoluteDisjoint width =>
      match write.1 with
      | .constant address =>
          address + width.bytes <= 2 ^ 32 &&
            natWriteSpanDisjoint slot address width
      | _ => false
  | .slotZero =>
      write.1 == .constant slot && write.2 == .constant 0
  | .slotCodeTarget targetId =>
      allowedTargetIds.contains targetId &&
        match targetCanonicalWord? context targetId with
        | some value => write.1 == .constant slot && write.2 == .constant value
        | none => false
  | .runtimeSeparated _ =>
      match write.1 with
      | .constant _ => false
      | _ => true

def classificationsChecked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (allowedTargetIds : List Nat) :
    List WriteClassification -> List MemoryWidth -> List (Expr × Expr) -> Bool
  | [], [], [] => true
  | classification :: classifications, width :: widths, write :: writes =>
      decide (classification.width = width) &&
        classification.checked context certificate allowedTargetIds write &&
        classificationsChecked context certificate allowedTargetIds
          classifications widths writes
  | _, _, _ => false

def RegionBinding.checked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds allowedTargetIds : List Nat)
    (binding : RegionBinding) : Bool :=
  reachableTargetIds.contains binding.targetId &&
    match binding.writes, normalizedRegionWriteInventory? context binding.targetId with
    | .exact classifications, some (behavior, inventory) =>
        classificationsChecked context certificate allowedTargetIds
          classifications inventory.scalarWidths behavior.writes
    | _, _ => false

def defaultDisjointClassifications
    (widths : List MemoryWidth) : List WriteClassification :=
  widths.map .absoluteDisjoint

/-- A missing sparse row means that every write must independently replay as
an absolute write disjoint from this slot. Unknown submitted rows still reject.
-/
def regionClassifications? (bindings : List RegionBinding) (targetId : Nat)
    (inventory : DecodedWriteInventory) : Option (List WriteClassification) :=
  match bindings.find? fun binding => binding.targetId == targetId with
  | some binding =>
      match binding.writes with
      | .exact classifications => some classifications
      | .unknown => none
  | none => some (defaultDisjointClassifications inventory.scalarWidths)

def sparseBindingsChecked (reachableTargetIds : List Nat)
    (bindings : List RegionBinding) : Bool :=
  noDuplicates (bindings.map (·.targetId)) &&
    bindings.all fun binding => reachableTargetIds.contains binding.targetId

def regionInventoryChecked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds allowedTargetIds : List Nat)
    (bindings : List RegionBinding) : Bool :=
  sparseBindingsChecked reachableTargetIds bindings &&
    reachableTargetIds.all fun targetId =>
      match normalizedRegionWriteInventory? context targetId with
      | some (behavior, inventory) =>
          match regionClassifications? bindings targetId inventory with
          | some classifications =>
              classificationsChecked context certificate allowedTargetIds
                classifications inventory.scalarWidths behavior.writes
          | none => false
      | none => false

def slotReadExpression (slot : Nat) : Expr :=
  .read32 (.constant slot)

/-- `some true` means that the condition is precisely `slot == 0`; `some
false` means precisely `slot != 0`. -/
def slotZeroCondition? (slot : Nat) : BoolExpr -> Option Bool
  | .equal left right =>
      if (left == slotReadExpression slot && right == .constant 0) ||
          (right == slotReadExpression slot && left == .constant 0) then
        some true
      else
        none
  | .not condition => (slotZeroCondition? slot condition).map (!·)
  | _ => none

def GuardedNonzeroEdge.checked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds : List Nat)
    (edge : GuardedNonzeroEdge) : Bool :=
  reachableTargetIds.contains edge.sourceTargetId &&
    reachableTargetIds.contains edge.nonzeroTargetId &&
    match normalizedRegionBehavior? context edge.sourceTargetId with
    | some behavior =>
        match behavior.outcome with
        | .branch condition taken fallthrough =>
            match slotZeroCondition? (slotAddress context certificate) condition with
            | some conditionMeansZero =>
                if conditionMeansZero then
                  edge.nonzeroTargetId == fallthrough && taken != fallthrough
                else
                  edge.nonzeroTargetId == taken && taken != fallthrough
            | none => false
        | _ => false
    | none => false

def IndirectSlotSite.checked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds allowedTargetIds : List Nat)
    (site : IndirectSlotSite) : Bool :=
  reachableTargetIds.contains site.sourceTargetId &&
    match context.source? site.sourceTargetId,
        normalizedRegionBehavior? context site.sourceTargetId with
    | some source, some behavior =>
        allowedTargetIds.all source.region.targets.contains &&
          match behavior.outcome with
          | .indirectCall target _ | .indirectJump target =>
              target == slotReadExpression (slotAddress context certificate)
          | _ => false
    | _, _ => false

def reachableSlotIndirectSourceTargetIds
    (context : OriginalDecodedStaticContext) (certificate : Certificate)
    (reachableTargetIds : List Nat) : List Nat :=
  reachableTargetIds.filter fun targetId =>
    match normalizedRegionBehavior? context targetId with
    | some behavior =>
        match behavior.outcome with
        | .indirectCall target _ | .indirectJump target =>
            target == slotReadExpression (slotAddress context certificate)
        | _ => false
    | none => false

def indirectInventoryChecked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds allowedTargetIds : List Nat)
    (sites : List IndirectSlotSite) : Bool :=
  sameFiniteSet (sites.map (·.sourceTargetId))
      (reachableSlotIndirectSourceTargetIds context certificate
        reachableTargetIds) &&
    sites.all (IndirectSlotSite.checked context certificate reachableTargetIds
      allowedTargetIds)

def machineCallMemoryEffectFootprintBoundedChecked :
    MachineCallMemoryEffect -> Bool
  | .none | .readOnly | .argumentRanges => true
  | .newDynamicRanges | .relationalState => false

def footprintBoundedContract? (contract : MachineImportCallContract) :
    Option MachineImportCallContract :=
  if machineCallMemoryEffectFootprintBoundedChecked contract.memoryEffect
  then some contract else none

theorem footprintBoundedContract?_sound
    {source result : MachineImportCallContract}
    (found : footprintBoundedContract? source = some result) :
    machineCallMemoryEffectFootprintBoundedChecked result.memoryEffect = true := by
  unfold footprintBoundedContract? at found
  split at found
  case isTrue bounded =>
    have exact := Option.some.inj found
    subst result
    exact bounded
  case isFalse => simp at found

def checkedExternalOutcomeContract?
    (context : OriginalDecodedStaticContext)
    (behavior : NormalizedSymbolicBehavior) :
    Option MachineImportCallContract :=
  match behavior.outcome with
  | .externalCall imported _ _ | .externalJump imported _ =>
      match context.machineImportCallContracts.filter
          (fun contract => contract.imported == imported) with
      | [contract] => footprintBoundedContract? contract
      | _ => none
  | _ => none

def externalOutcomeFootprintChecked
    (context : OriginalDecodedStaticContext)
    (behavior : NormalizedSymbolicBehavior) : Bool :=
  match behavior.outcome with
  | .externalCall .. | .externalJump .. =>
      (checkedExternalOutcomeContract? context behavior).isSome
  | _ => true

theorem checkedExternalOutcomeContract?_bounded
    {context : OriginalDecodedStaticContext}
    {behavior : NormalizedSymbolicBehavior}
    {contract : MachineImportCallContract}
    (found :
      checkedExternalOutcomeContract? context behavior = some contract) :
    machineCallMemoryEffectFootprintBoundedChecked contract.memoryEffect = true := by
  unfold checkedExternalOutcomeContract? at found
  generalize outcomeExact : behavior.outcome = outcome at found
  cases outcome <;> try simp at found
  all_goals
    generalize contractsExact :
      context.machineImportCallContracts.filter
        (fun candidate => candidate.imported == ‹ExternalTarget›) = contracts at found
    cases contracts with
    | nil => simp at found
    | cons head tail =>
        cases tail with
        | nil => exact footprintBoundedContract?_sound found
        | cons second rest => simp at found

/-- Every reachable external transition resolves to one exact, validated
machine-call contract whose complete write effect is represented by its
footprints. Effects with non-footprint relational memory authority fail closed.
-/
def externalWriteInventoryChecked (context : OriginalDecodedStaticContext)
    (reachableTargetIds : List Nat) : Bool :=
  machineImportCallContractsValid context.imports
      context.machineImportCallContracts &&
    reachableTargetIds.all fun targetId =>
      match normalizedRegionWriteInventory? context targetId with
      | some (behavior, _) => externalOutcomeFootprintChecked context behavior
      | none => false

def Certificate.checked (certificate : Certificate)
    (context : OriginalDecodedStaticContext) : Bool :=
  match certificate.reachableTargetIds, certificate.allowedTargetIds,
      certificate.regions, certificate.guardedNonzeroEdges,
      certificate.indirectSlotSites, certificate.aliases with
  | .exact reachableTargetIds, .exact allowedTargetIds, .exact regions,
      .exact guardedEdges, .exact indirectSites, .exact aliases =>
      aliases.isEmpty && initialZeroChecked context certificate &&
        reachableInventoryChecked context reachableTargetIds &&
        allowedTargetsChecked context allowedTargetIds &&
        regionInventoryChecked context certificate reachableTargetIds
          allowedTargetIds regions &&
        noDuplicates guardedEdges && guardedEdges.all
          (GuardedNonzeroEdge.checked context certificate reachableTargetIds) &&
        externalWriteInventoryChecked context reachableTargetIds &&
        indirectInventoryChecked context certificate reachableTargetIds
          allowedTargetIds indirectSites
  | _, _, _, _, _, _ => false

/-- The acceptance-facing object binds the Boolean replay to the exact PE,
imports, relocations, code map, and region index already checked by the decoded
original authority. -/
structure KernelEvidence (context : OriginalDecodedStaticContext)
    (certificate : Certificate) where
  authority : ExactOriginalDecodedAuthority context
  checked : certificate.checked context = true

structure Certificate.CheckedFacts (certificate : Certificate)
    (context : OriginalDecodedStaticContext) where
  reachableTargetIds : List Nat
  allowedTargetIds : List Nat
  regions : List RegionBinding
  guardedEdges : List GuardedNonzeroEdge
  indirectSites : List IndirectSlotSite
  reachableExact : certificate.reachableTargetIds = .exact reachableTargetIds
  allowedExact : certificate.allowedTargetIds = .exact allowedTargetIds
  regionsExact : certificate.regions = .exact regions
  guardedExact : certificate.guardedNonzeroEdges = .exact guardedEdges
  indirectExact : certificate.indirectSlotSites = .exact indirectSites
  aliasesExact : certificate.aliases = .exact []
  initialZero : initialZeroChecked context certificate = true
  reachableChecked : reachableInventoryChecked context reachableTargetIds = true
  targetsChecked : allowedTargetsChecked context allowedTargetIds = true
  regionChecked : regionInventoryChecked context certificate reachableTargetIds
    allowedTargetIds regions = true
  guardedChecked : guardedEdges.all
    (GuardedNonzeroEdge.checked context certificate reachableTargetIds) = true
  externalChecked :
    externalWriteInventoryChecked context reachableTargetIds = true
  indirectChecked : indirectInventoryChecked context certificate
    reachableTargetIds allowedTargetIds indirectSites = true

def Certificate.checkedFactsOfChecked
    {certificate : Certificate} {context : OriginalDecodedStaticContext}
    (checked : certificate.checked context = true) :
    certificate.CheckedFacts context := by
  cases reachableEq : certificate.reachableTargetIds with
  | unknown => simp [Certificate.checked, reachableEq] at checked
  | exact reachableTargetIds =>
    cases allowedEq : certificate.allowedTargetIds with
    | unknown => simp [Certificate.checked, reachableEq, allowedEq] at checked
    | exact allowedTargetIds =>
      cases regionsEq : certificate.regions with
      | unknown =>
          simp [Certificate.checked, reachableEq, allowedEq, regionsEq] at checked
      | exact regions =>
        cases guardedEq : certificate.guardedNonzeroEdges with
        | unknown =>
            simp [Certificate.checked, reachableEq, allowedEq, regionsEq,
              guardedEq] at checked
        | exact guardedEdges =>
          cases indirectEq : certificate.indirectSlotSites with
          | unknown =>
              simp [Certificate.checked, reachableEq, allowedEq, regionsEq,
                guardedEq, indirectEq] at checked
          | exact indirectSites =>
            cases aliasesEq : certificate.aliases with
            | unknown =>
                simp [Certificate.checked, reachableEq, allowedEq, regionsEq,
                  guardedEq, indirectEq, aliasesEq] at checked
            | exact aliases =>
              simp only [Certificate.checked, reachableEq, allowedEq, regionsEq,
                guardedEq, indirectEq, aliasesEq, Bool.and_eq_true] at checked
              rcases checked with ⟨checked, indirectChecked⟩
              rcases checked with ⟨checked, externalChecked⟩
              rcases checked with ⟨checked, guardedChecked⟩
              rcases checked with ⟨checked, _guardedNodup⟩
              rcases checked with ⟨checked, regionChecked⟩
              rcases checked with ⟨checked, targetsChecked⟩
              rcases checked with ⟨checked, reachableChecked⟩
              rcases checked with ⟨aliasesEmptyChecked, initialZero⟩
              have aliasesEmpty : aliases = [] := by
                simpa using aliasesEmptyChecked
              subst aliases
              refine {
                reachableTargetIds
                allowedTargetIds
                regions
                guardedEdges
                indirectSites
                reachableExact := reachableEq
                allowedExact := allowedEq
                regionsExact := regionsEq
                guardedExact := guardedEq
                indirectExact := indirectEq
                aliasesExact := aliasesEq
                initialZero
                reachableChecked
                targetsChecked
                regionChecked
                guardedChecked
                externalChecked
                indirectChecked
              }

def SlotValueAllowed (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (memory : Memory) : Prop :=
  match certificate.allowedTargetIds with
  | .unknown => False
  | .exact targetIds =>
      Memory.read32 memory (BitVec.ofNat 32 (slotAddress context certificate)) ∈
        allowedWords context targetIds

/-- Concrete launch-memory bridge for this word. The PE loader proof supplies
this fact from its checked image construction. -/
def LaunchSlotInitialized (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (memory : Memory) : Prop :=
  Memory.read32 memory (BitVec.ofNat 32 (slotAddress context certificate)) =
    BitVec.ofNat 32 ((readRvaU32 context.pe certificate.slotRva).getD 0)

theorem Certificate.launch_slot_allowed
    {certificate : Certificate} {context : OriginalDecodedStaticContext}
    (checked : certificate.checked context = true) (memory : Memory)
    (initialized : LaunchSlotInitialized context certificate memory) :
    SlotValueAllowed context certificate memory := by
  let facts := certificate.checkedFactsOfChecked checked
  have initial := facts.initialZero
  unfold initialZeroChecked at initial
  simp only [Bool.and_eq_true, beq_iff_eq] at initial
  have readZero : readRvaU32 context.pe certificate.slotRva = some 0 := by
    simpa using initial.1.2
  unfold LaunchSlotInitialized at initialized
  rw [readZero] at initialized
  unfold SlotValueAllowed
  rw [facts.allowedExact]
  simp only [initialized]
  simp [allowedWords]

theorem initialZeroChecked_slot_fits
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    (checked : initialZeroChecked context certificate = true) :
    (BitVec.ofNat 32 (slotAddress context certificate)).toNat + 4 <= 2 ^ 32 := by
  unfold initialZeroChecked at checked
  simp only [Bool.and_eq_true] at checked
  have writable := checked.1.1.1.2
  exact (writableStaticWordInPe_bounds context.pe
    (BitVec.ofNat 32 (slotAddress context certificate)) writable).2.2

theorem initialZeroChecked_slot_nat_fits
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    (checked : initialZeroChecked context certificate = true) :
    slotAddress context certificate + 4 <= 2 ^ 32 := by
  unfold initialZeroChecked at checked
  simp only [Bool.and_eq_true] at checked
  exact of_decide_eq_true checked.1.1.1.1.2

def WriteSpanAvoidsWord
    (slotAddress writeAddress : Word) (width : MemoryWidth) : Prop :=
  forall slotOffset, slotOffset < 4 ->
    forall writeOffset, writeOffset < width.bytes ->
      ¬slotAddress + BitVec.ofNat 32 slotOffset =
        writeAddress + BitVec.ofNat 32 writeOffset

theorem writeSpanAvoidsWord_of_nat_disjoint
    (slotAddress writeAddress : Word) (width : MemoryWidth)
    (slotFits : slotAddress.toNat + 4 <= 2 ^ 32)
    (writeFits : writeAddress.toNat + width.bytes <= 2 ^ 32)
    (disjoint : slotAddress.toNat + 4 <= writeAddress.toNat ∨
      writeAddress.toNat + width.bytes <= slotAddress.toNat) :
    WriteSpanAvoidsWord slotAddress writeAddress width := by
  intro slotOffset slotBefore writeOffset writeBefore overlap
  have overlapNat := congrArg BitVec.toNat overlap
  have slotOffsetSmall : slotOffset < 2 ^ 32 := by omega
  have writeOffsetSmall : writeOffset < 2 ^ 32 := by
    cases width <;> simp [MemoryWidth.bytes] at writeBefore <;> omega
  have slotAddressBefore : slotAddress.toNat + slotOffset < 2 ^ 32 := by
    omega
  have writeAddressBefore :
      writeAddress.toNat + writeOffset < 2 ^ 32 := by
    omega
  simp [BitVec.toNat_add, BitVec.toNat_ofNat,
    Nat.mod_eq_of_lt slotOffsetSmall, Nat.mod_eq_of_lt writeOffsetSmall,
    Nat.mod_eq_of_lt slotAddressBefore,
    Nat.mod_eq_of_lt writeAddressBefore] at overlapNat
  omega

theorem Memory.read32_writeMemory_of_avoids
    (memory : Memory) (slotAddress writeAddress value : Word)
    (width : MemoryWidth)
    (avoids : WriteSpanAvoidsWord slotAddress writeAddress width) :
    Memory.read32 (writeMemory memory writeAddress value width) slotAddress =
      Memory.read32 memory slotAddress := by
  have avoid (slotOffset writeOffset : Nat)
      (slotBefore : slotOffset < 4) (writeBefore : writeOffset < width.bytes) :
      ¬(slotAddress + BitVec.ofNat 32 slotOffset =
        writeAddress + BitVec.ofNat 32 writeOffset) :=
    avoids slotOffset slotBefore writeOffset writeBefore
  cases width with
  | byte =>
      have h00 : slotAddress ≠ writeAddress := by
        simpa using avoid 0 0 (by decide) (by decide)
      have h10 : slotAddress + BitVec.ofNat 32 1 ≠ writeAddress := by
        simpa using avoid 1 0 (by decide) (by decide)
      have h20 : slotAddress + BitVec.ofNat 32 2 ≠ writeAddress := by
        simpa using avoid 2 0 (by decide) (by decide)
      have h30 : slotAddress + BitVec.ofNat 32 3 ≠ writeAddress := by
        simpa using avoid 3 0 (by decide) (by decide)
      simp [Memory.read32, writeMemory, writeMemoryByte, h00, h10, h20, h30]
  | word =>
      have h00 : slotAddress ≠ writeAddress := by
        simpa using avoid 0 0 (by decide) (by decide)
      have h01 : slotAddress ≠ writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 0 1 (by decide) (by decide)
      have h10 : slotAddress + BitVec.ofNat 32 1 ≠ writeAddress := by
        simpa using avoid 1 0 (by decide) (by decide)
      have h11 : slotAddress + BitVec.ofNat 32 1 ≠
          writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 1 1 (by decide) (by decide)
      have h20 : slotAddress + BitVec.ofNat 32 2 ≠ writeAddress := by
        simpa using avoid 2 0 (by decide) (by decide)
      have h21 : slotAddress + BitVec.ofNat 32 2 ≠
          writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 2 1 (by decide) (by decide)
      have h30 : slotAddress + BitVec.ofNat 32 3 ≠ writeAddress := by
        simpa using avoid 3 0 (by decide) (by decide)
      have h31 : slotAddress + BitVec.ofNat 32 3 ≠
          writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 3 1 (by decide) (by decide)
      simp [Memory.read32, writeMemory, writeMemoryByte, h00, h01, h10, h11,
        h20, h21, h30, h31]
  | dword =>
      have h00 : slotAddress ≠ writeAddress := by
        simpa using avoid 0 0 (by decide) (by decide)
      have h01 : slotAddress ≠ writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 0 1 (by decide) (by decide)
      have h02 : slotAddress ≠ writeAddress + BitVec.ofNat 32 2 := by
        simpa using avoid 0 2 (by decide) (by decide)
      have h03 : slotAddress ≠ writeAddress + BitVec.ofNat 32 3 := by
        simpa using avoid 0 3 (by decide) (by decide)
      have h10 : slotAddress + BitVec.ofNat 32 1 ≠ writeAddress := by
        simpa using avoid 1 0 (by decide) (by decide)
      have h11 : slotAddress + BitVec.ofNat 32 1 ≠
          writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 1 1 (by decide) (by decide)
      have h12 : slotAddress + BitVec.ofNat 32 1 ≠
          writeAddress + BitVec.ofNat 32 2 := by
        simpa using avoid 1 2 (by decide) (by decide)
      have h13 : slotAddress + BitVec.ofNat 32 1 ≠
          writeAddress + BitVec.ofNat 32 3 := by
        simpa using avoid 1 3 (by decide) (by decide)
      have h20 : slotAddress + BitVec.ofNat 32 2 ≠ writeAddress := by
        simpa using avoid 2 0 (by decide) (by decide)
      have h21 : slotAddress + BitVec.ofNat 32 2 ≠
          writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 2 1 (by decide) (by decide)
      have h22 : slotAddress + BitVec.ofNat 32 2 ≠
          writeAddress + BitVec.ofNat 32 2 := by
        simpa using avoid 2 2 (by decide) (by decide)
      have h23 : slotAddress + BitVec.ofNat 32 2 ≠
          writeAddress + BitVec.ofNat 32 3 := by
        simpa using avoid 2 3 (by decide) (by decide)
      have h30 : slotAddress + BitVec.ofNat 32 3 ≠ writeAddress := by
        simpa using avoid 3 0 (by decide) (by decide)
      have h31 : slotAddress + BitVec.ofNat 32 3 ≠
          writeAddress + BitVec.ofNat 32 1 := by
        simpa using avoid 3 1 (by decide) (by decide)
      have h32 : slotAddress + BitVec.ofNat 32 3 ≠
          writeAddress + BitVec.ofNat 32 2 := by
        simpa using avoid 3 2 (by decide) (by decide)
      have h33 : slotAddress + BitVec.ofNat 32 3 ≠
          writeAddress + BitVec.ofNat 32 3 := by
        simpa using avoid 3 3 (by decide) (by decide)
      simp [Memory.read32, writeMemory, writeMemoryByte, h00, h01, h02, h03,
        h10, h11, h12, h13, h20, h21, h22, h23, h30, h31, h32, h33]

theorem Memory.read32_writeMemory_dword_same_of_fits
    (memory : Memory) (address value : Word)
    (fits : address.toNat + 4 <= 2 ^ 32) :
    Memory.read32 (writeMemory memory address value .dword) address = value := by
  have memoryExact :
      writeMemory memory address value .dword = memory.write32 address value := by
    funext query
    by_cases q0 : query = address
    · subst query
      simp [writeMemory, writeMemoryByte, Memory.write32]
    by_cases q1 : query = address + BitVec.ofNat 32 1
    · subst query
      simp [writeMemory, writeMemoryByte, Memory.write32]
    by_cases q2 : query = address + BitVec.ofNat 32 2
    · subst query
      simp [writeMemory, writeMemoryByte, Memory.write32]
    by_cases q3 : query = address + BitVec.ofNat 32 3
    · subst query
      simp [writeMemory, writeMemoryByte, Memory.write32]
    simp [writeMemory, writeMemoryByte, Memory.write32, q0, q1, q2, q3]
  rw [memoryExact]
  exact Memory.read32_write32_same_of_fits memory address value fits

def RuntimeSeparation (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (state : MachineState)
    (classification : WriteClassification) (write : Expr × Expr) : Prop :=
  match classification with
  | .runtimeSeparated width =>
      WriteSpanAvoidsWord
        (BitVec.ofNat 32 (slotAddress context certificate))
        (write.1.eval state) width
  | _ => True

def RuntimeSeparations (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (state : MachineState) :
    List WriteClassification -> List (Expr × Expr) -> Prop
  | [], [] => True
  | classification :: classifications, write :: writes =>
      RuntimeSeparation context certificate state classification write /\
        RuntimeSeparations context certificate state classifications writes
  | _, _ => False

theorem RuntimeSeparations.head
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    {state : MachineState} {classification : WriteClassification}
    {classifications : List WriteClassification} {write : Expr × Expr}
    {writes : List (Expr × Expr)}
    (runtime : RuntimeSeparations context certificate state
      (classification :: classifications) (write :: writes)) :
    RuntimeSeparation context certificate state classification write := by
  simpa only [RuntimeSeparations] using runtime.1

def widthWriteAdmissible (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (allowedTargetIds : List Nat)
    (state : MachineState) (width : MemoryWidth) (write : Expr × Expr) : Prop :=
  let slot := BitVec.ofNat 32 (slotAddress context certificate)
  (width = .dword /\ write.1.eval state = slot /\
      write.2.eval state ∈ allowedWords context allowedTargetIds) \/
    WriteSpanAvoidsWord slot (write.1.eval state) width

theorem WriteClassification.width_admissible_of_checked
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    {allowedTargetIds : List Nat} {classification : WriteClassification}
    {width : MemoryWidth} {write : Expr × Expr} {state : MachineState}
    (widthExact : classification.width = width)
    (checked : classification.checked context certificate allowedTargetIds write = true)
    (slotFits : (BitVec.ofNat 32 (slotAddress context certificate)).toNat + 4 <=
      2 ^ 32)
    (slotNatFits : slotAddress context certificate + 4 <= 2 ^ 32)
    (runtime : RuntimeSeparation context certificate state classification write) :
    widthWriteAdmissible context certificate allowedTargetIds state width write := by
  cases classification with
  | absoluteDisjoint classificationWidth =>
      simp only [WriteClassification.width] at widthExact
      subst width
      rcases write with ⟨address, value⟩
      cases address <;> simp [WriteClassification.checked] at checked
      rename_i address
      have widthPositive : 0 < classificationWidth.bytes := by
        cases classificationWidth <;> decide
      have addressBefore : address < 2 ^ 32 := by
        omega
      right
      apply writeSpanAvoidsWord_of_nat_disjoint
        (BitVec.ofNat 32 (slotAddress context certificate))
        (BitVec.ofNat 32 address) classificationWidth
      · exact slotFits
      · simp only [Expr.eval, BitVec.toNat_ofNat]
        simpa [Nat.mod_eq_of_lt addressBefore] using checked.1
      · have slotBefore : slotAddress context certificate < 2 ^ 32 := by
          omega
        simpa [Expr.eval, BitVec.toNat_ofNat, Nat.mod_eq_of_lt slotBefore,
          Nat.mod_eq_of_lt addressBefore, natWriteSpanDisjoint] using checked.2
  | slotZero =>
      simp only [WriteClassification.width] at widthExact
      subst width
      rcases write with ⟨address, value⟩
      simp only [WriteClassification.checked, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨rfl, rfl⟩
      left
      simp [allowedWords, Expr.eval]
  | slotCodeTarget targetId =>
      simp only [WriteClassification.width] at widthExact
      subst width
      rcases write with ⟨address, value⟩
      simp only [WriteClassification.checked, Bool.and_eq_true] at checked
      rcases checked with ⟨member, targetChecked⟩
      cases found : targetCanonicalWord? context targetId with
      | none => simp [found] at targetChecked
      | some targetWord =>
          simp only [found, Bool.and_eq_true, beq_iff_eq] at targetChecked
          rcases targetChecked with ⟨rfl, rfl⟩
          left
          constructor
          · simp
          · simp only [Expr.eval, allowedWords, List.mem_cons]
            constructor
            · trivial
            right
            apply List.mem_map.mpr
            refine ⟨targetWord, ?_, rfl⟩
            apply List.mem_filterMap.mpr
            exact ⟨targetId, by simpa using member, found⟩
  | runtimeSeparated runtimeWidth =>
      simp only [WriteClassification.width] at widthExact
      subst width
      exact Or.inr runtime

def applyWidthWrites (memory : Memory) (state : MachineState) :
    List MemoryWidth -> List (Expr × Expr) -> Memory
  | width :: widths, write :: writes =>
      applyWidthWrites
        (writeMemory memory (write.1.eval state) (write.2.eval state) width)
        state widths writes
  | _, _ => memory

theorem apply_classified_width_writes_preserves_allowed
    (context : OriginalDecodedStaticContext) (certificate : Certificate)
    (allowedTargetIds : List Nat) (state : MachineState)
    (memory : Memory)
    (slotFits : (BitVec.ofNat 32 (slotAddress context certificate)).toNat + 4 <=
      2 ^ 32)
    (slotNatFits : slotAddress context certificate + 4 <= 2 ^ 32) :
    forall (classifications : List WriteClassification)
      (widths : List MemoryWidth) (writes : List (Expr × Expr)),
      classificationsChecked context certificate allowedTargetIds
        classifications widths writes = true ->
      RuntimeSeparations context certificate state classifications writes ->
      Memory.read32 memory
          (BitVec.ofNat 32 (slotAddress context certificate)) ∈
            allowedWords context allowedTargetIds ->
      Memory.read32 (applyWidthWrites memory state widths writes)
          (BitVec.ofNat 32 (slotAddress context certificate)) ∈
            allowedWords context allowedTargetIds := by
  intro classifications
  induction classifications generalizing memory with
  | nil =>
      intro widths writes checked runtime prior
      cases widths <;> cases writes <;>
        simp [classificationsChecked, applyWidthWrites] at checked ⊢
      exact prior
  | cons classification classifications induction =>
      intro widths writes checked runtime prior
      cases widths with
      | nil => simp [classificationsChecked] at checked
      | cons width widthTail =>
        cases writes with
        | nil => simp [classificationsChecked] at checked
        | cons head tail =>
          simp only [classificationsChecked, Bool.and_eq_true] at checked
          have tailChecked := checked.2
          have widthExact : classification.width = width :=
            of_decide_eq_true checked.1.1
          have headRuntime :
              RuntimeSeparation context certificate state classification head :=
            RuntimeSeparations.head runtime
          have headAdmissible :=
            WriteClassification.width_admissible_of_checked
              (classification := classification) (width := width)
              (write := head) (state := state) widthExact checked.1.2
              slotFits slotNatFits headRuntime
          have nextAllowed :
              Memory.read32
                  (writeMemory memory (head.1.eval state) (head.2.eval state) width)
                  (BitVec.ofNat 32 (slotAddress context certificate)) ∈
                allowedWords context allowedTargetIds := by
            rcases headAdmissible with ⟨widthExact, addressExact, valueAllowed⟩ |
                avoids
            · rw [widthExact, addressExact]
              rw [Memory.read32_writeMemory_dword_same_of_fits _ _ _ slotFits]
              exact valueAllowed
            · rw [Memory.read32_writeMemory_of_avoids _ _ _ _ width avoids]
              exact prior
          cases classification with
          | absoluteDisjoint classificationWidth =>
              simp only [RuntimeSeparations] at runtime
              exact induction
                (writeMemory memory (head.1.eval state) (head.2.eval state) width)
                widthTail tail tailChecked runtime.2 nextAllowed
          | slotZero =>
              simp only [RuntimeSeparations] at runtime
              exact induction
                (writeMemory memory (head.1.eval state) (head.2.eval state) width)
                widthTail tail tailChecked runtime.2 nextAllowed
          | slotCodeTarget targetId =>
              simp only [RuntimeSeparations] at runtime
              exact induction
                (writeMemory memory (head.1.eval state) (head.2.eval state) width)
                widthTail tail tailChecked runtime.2 nextAllowed
          | runtimeSeparated classificationWidth =>
              simp only [RuntimeSeparations] at runtime
              exact induction
                (writeMemory memory (head.1.eval state) (head.2.eval state) width)
                widthTail tail tailChecked runtime.2 nextAllowed

def nextBulkWriteAddress (address : Word) (direction : Bool) : Word :=
  if direction then address - BitVec.ofNat 32 4
  else address + BitVec.ofNat 32 4

/-- Exact finite destination footprint of a decoded REP MOVSD/STOSD outcome. -/
def BulkWritesAvoidWord (slotAddress : Word) (direction : Bool) :
    Word -> Nat -> Prop
  | _, 0 => True
  | writeAddress, count + 1 =>
      Write32AvoidsWord slotAddress writeAddress /\
        BulkWritesAvoidWord slotAddress direction
          (nextBulkWriteAddress writeAddress direction) count

theorem Memory.read32_bulkFillDwords_of_avoids
    (slotAddress destination value : Word) (direction : Bool) :
    forall (count : Nat) (memory : Memory),
      BulkWritesAvoidWord slotAddress direction destination count ->
      Memory.read32
          (Memory.bulkFillDwords memory destination value direction count)
          slotAddress =
        Memory.read32 memory slotAddress := by
  intro count
  induction count generalizing destination with
  | zero =>
      intro memory avoids
      rfl
  | succ count induction =>
      intro memory avoids
      simp only [BulkWritesAvoidWord] at avoids
      unfold nextBulkWriteAddress at avoids
      simp only [Memory.bulkFillDwords]
      rw [induction _ (memory.write32 destination value) avoids.2]
      exact Memory.read32_write32_of_avoids memory slotAddress destination value
        avoids.1

theorem Memory.read32_bulkCopyDwords_of_avoids
    (slotAddress destination source : Word) (direction : Bool) :
    forall (count : Nat) (memory : Memory),
      BulkWritesAvoidWord slotAddress direction destination count ->
      Memory.read32
          (Memory.bulkCopyDwords memory destination source direction count)
          slotAddress =
        Memory.read32 memory slotAddress := by
  intro count
  induction count generalizing destination source with
  | zero =>
      intro memory avoids
      rfl
  | succ count induction =>
      intro memory avoids
      simp only [BulkWritesAvoidWord] at avoids
      unfold nextBulkWriteAddress at avoids
      simp only [Memory.bulkCopyDwords]
      rw [induction _ _
        (memory.write32 destination (Memory.read32 memory source)) avoids.2]
      exact Memory.read32_write32_of_avoids memory slotAddress destination
        (Memory.read32 memory source) avoids.1

def OutcomeWriteSeparations (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (state : MachineState) :
    NormalizedOutcomeExpr -> Prop
  | .bulkCopy destination _ count direction _ |
      .bulkFill destination _ count direction _ =>
      BulkWritesAvoidWord
        (BitVec.ofNat 32 (slotAddress context certificate))
        (direction.eval state) (destination.eval state) (count.eval state).toNat
  | _ => True

def applyOutcomeWrites (memory : Memory) (state : MachineState) :
    NormalizedOutcomeExpr -> Memory
  | .bulkCopy destination source count direction _ =>
      Memory.bulkCopyDwords memory (destination.eval state) (source.eval state)
        (direction.eval state) (count.eval state).toNat
  | .bulkFill destination value count direction _ =>
      Memory.bulkFillDwords memory (destination.eval state) (value.eval state)
        (direction.eval state) (count.eval state).toNat
  | _ => memory

theorem applyOutcomeWrites_preserves_word
    (context : OriginalDecodedStaticContext) (certificate : Certificate)
    (state : MachineState) (memory : Memory) (outcome : NormalizedOutcomeExpr)
    (separated : OutcomeWriteSeparations context certificate state outcome) :
    Memory.read32 (applyOutcomeWrites memory state outcome)
        (BitVec.ofNat 32 (slotAddress context certificate)) =
      Memory.read32 memory
        (BitVec.ofNat 32 (slotAddress context certificate)) := by
  cases outcome <;> try rfl
  case bulkCopy destination source count direction continuation =>
    exact Memory.read32_bulkCopyDwords_of_avoids
      (BitVec.ofNat 32 (slotAddress context certificate))
      (destination.eval state) (source.eval state) (direction.eval state)
      (count.eval state).toNat memory separated
  case bulkFill destination value count direction continuation =>
    exact Memory.read32_bulkFillDwords_of_avoids
      (BitVec.ofNat 32 (slotAddress context certificate))
      (destination.eval state) (value.eval state) (direction.eval state)
      (count.eval state).toNat memory separated

def RegionTransition (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (before after : Memory) : Prop :=
  exists (reachableTargetIds allowedTargetIds : List Nat)
      (bindings : List RegionBinding) (targetId : Nat)
      (behavior : NormalizedSymbolicBehavior) (inventory : DecodedWriteInventory)
      (state : MachineState) (classifications : List WriteClassification),
    certificate.reachableTargetIds = .exact reachableTargetIds /\
    certificate.allowedTargetIds = .exact allowedTargetIds /\
    certificate.regions = .exact bindings /\
    targetId ∈ reachableTargetIds /\
    normalizedRegionWriteInventory? context targetId = some (behavior, inventory) /\
    regionClassifications? bindings targetId inventory = some classifications /\
    state.memory = before /\
    RuntimeSeparations context certificate state classifications behavior.writes /\
    OutcomeWriteSeparations context certificate state behavior.outcome /\
    after = applyOutcomeWrites
      (applyWidthWrites before state inventory.scalarWidths behavior.writes)
      state behavior.outcome

theorem Certificate.transition_preserves
    {certificate : Certificate} {context : OriginalDecodedStaticContext}
    (checked : certificate.checked context = true) {before after : Memory}
    (prior : SlotValueAllowed context certificate before)
    (transition : RegionTransition context certificate before after) :
    SlotValueAllowed context certificate after := by
  rcases transition with
    ⟨reachableTargetIds, allowedTargetIds, bindings, targetId, behavior, inventory,
      state, classifications, reachableExact, allowedExact, regionsExact, targetMember,
      normalized, classificationsFound, stateMemory, runtime, outcomeRuntime, rfl⟩
  let facts := certificate.checkedFactsOfChecked checked
  have reachableIds : facts.reachableTargetIds = reachableTargetIds := by
    rw [facts.reachableExact] at reachableExact
    exact Knowledge.exact.inj reachableExact
  have allowedIds : facts.allowedTargetIds = allowedTargetIds := by
    rw [facts.allowedExact] at allowedExact
    exact Knowledge.exact.inj allowedExact
  have regionRows : facts.regions = bindings := by
    rw [facts.regionsExact] at regionsExact
    exact Knowledge.exact.inj regionsExact
  subst reachableTargetIds
  subst allowedTargetIds
  subst bindings
  have regionChecked := facts.regionChecked
  unfold regionInventoryChecked at regionChecked
  simp only [Bool.and_eq_true] at regionChecked
  have rowsChecked := regionChecked.2
  rw [List.all_eq_true] at rowsChecked
  have rowChecked := rowsChecked targetId targetMember
  simp only [normalized, classificationsFound] at rowChecked
  have classificationsOk := rowChecked
  have slotFits := initialZeroChecked_slot_fits facts.initialZero
  have slotNatFits := initialZeroChecked_slot_nat_fits facts.initialZero
  unfold SlotValueAllowed at prior ⊢
  rw [facts.allowedExact] at prior ⊢
  have scalarAllowed := apply_classified_width_writes_preserves_allowed context certificate
    facts.allowedTargetIds state before slotFits slotNatFits classifications
      inventory.scalarWidths behavior.writes classificationsOk runtime prior
  rw [applyOutcomeWrites_preserves_word context certificate state
    (applyWidthWrites before state inventory.scalarWidths behavior.writes)
    behavior.outcome outcomeRuntime]
  exact scalarAllowed

inductive RegionTrace (context : OriginalDecodedStaticContext)
    (certificate : Certificate) : Memory -> Memory -> Prop where
  | refl (memory) : RegionTrace context certificate memory memory
  | step {start middle finish} :
      RegionTrace context certificate start middle ->
      RegionTransition context certificate middle finish ->
      RegionTrace context certificate start finish

theorem Certificate.trace_preserves
    {certificate : Certificate} {context : OriginalDecodedStaticContext}
    (checked : certificate.checked context = true) {start finish : Memory}
    (initial : SlotValueAllowed context certificate start)
    (trace : RegionTrace context certificate start finish) :
    SlotValueAllowed context certificate finish := by
  induction trace with
  | refl => exact initial
  | step trace transition traceIH =>
      exact certificate.transition_preserves checked traceIH transition

def hasSlotWriter : List RegionBinding -> Bool
  | [] => false
  | binding :: bindings =>
      match binding.writes with
      | .unknown => true
      | .exact classifications =>
          classifications.any fun classification =>
            match classification with
            | .slotZero | .slotCodeTarget _ => true
            | .absoluteDisjoint _ | .runtimeSeparated _ => false
      || hasSlotWriter bindings

theorem Certificate.no_writers_allowed_is_zero
    {certificate : Certificate} {context : OriginalDecodedStaticContext}
    (_checked : certificate.checked context = true)
    (noTargets : certificate.allowedTargetIds = .exact [])
    (memory : Memory) (allowed : SlotValueAllowed context certificate memory) :
    Memory.read32 memory (BitVec.ofNat 32 (slotAddress context certificate)) = 0 := by
  unfold SlotValueAllowed at allowed
  rw [noTargets] at allowed
  simpa [allowedWords] using allowed

def selectedBranchTarget (state : MachineState) :
    NormalizedOutcomeExpr -> Option Nat
  | .branch condition taken fallthrough =>
      some (if condition.eval state then taken else fallthrough)
  | _ => none

theorem slotZeroCondition_sound (slot : Nat) (condition : BoolExpr)
    (meansZero : slotZeroCondition? slot condition = some polarity)
    (state : MachineState)
    (zero : Memory.read32 state.memory (BitVec.ofNat 32 slot) = 0) :
    condition.eval state = polarity := by
  induction condition generalizing polarity with
  | equal left right =>
      simp only [slotZeroCondition?] at meansZero
      split at meansZero
      case isTrue shape =>
        have polarityTrue : polarity = true := Option.some.inj meansZero.symm
        subst polarity
        simp only [Bool.or_eq_true, Bool.and_eq_true, beq_iff_eq] at shape
        rcases shape with ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
        · simp only [BoolExpr.eval, slotReadExpression, Expr.eval]
          change decide (Memory.read32 state.memory (BitVec.ofNat 32 slot) = 0) = true
          rw [zero]
          decide
        · simp only [BoolExpr.eval, slotReadExpression, Expr.eval]
          change decide (0 = Memory.read32 state.memory (BitVec.ofNat 32 slot)) = true
          rw [zero]
          decide
      case isFalse => contradiction
  | not condition induction =>
      cases innerFound : slotZeroCondition? slot condition with
      | none => simp [slotZeroCondition?, innerFound] at meansZero
      | some innerPolarity =>
          have innerExact := induction innerFound
          simp [slotZeroCondition?, innerFound] at meansZero
          simp only [BoolExpr.eval]
          rw [innerExact, meansZero]
          cases polarity <;> rfl
  | and left right => simp [slotZeroCondition?] at meansZero
  | or left right => simp [slotZeroCondition?] at meansZero
  | xor left right => simp [slotZeroCondition?] at meansZero
  | unsignedLess left right => simp [slotZeroCondition?] at meansZero
  | msb value => simp [slotZeroCondition?] at meansZero
  | bit value index => simp [slotZeroCondition?] at meansZero
  | inputFlag index => simp [slotZeroCondition?] at meansZero
  | divisionValid high low divisor => simp [slotZeroCondition?] at meansZero

theorem GuardedNonzeroEdge.not_selected_when_zero
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    {reachableTargetIds : List Nat} {edge : GuardedNonzeroEdge}
    (checked : edge.checked context certificate reachableTargetIds = true)
    {behavior : NormalizedSymbolicBehavior}
    (normalized : normalizedRegionBehavior? context edge.sourceTargetId = some behavior)
    (state : MachineState)
    (zero : Memory.read32 state.memory
      (BitVec.ofNat 32 (slotAddress context certificate)) = 0) :
    selectedBranchTarget state behavior.outcome != some edge.nonzeroTargetId := by
  unfold GuardedNonzeroEdge.checked at checked
  simp only [normalized, Bool.and_eq_true] at checked
  rcases checked with ⟨_, shape⟩
  cases outcome : behavior.outcome <;> simp [outcome] at shape ⊢
  case branch condition taken fallthrough =>
    cases polarityFound : slotZeroCondition?
        (slotAddress context certificate) condition with
    | none => simp [polarityFound] at shape
    | some polarity =>
        simp [polarityFound] at shape
        have conditionExact := slotZeroCondition_sound
          (slotAddress context certificate) condition polarityFound state zero
        cases polarity with
        | false =>
            simp only [selectedBranchTarget, conditionExact,
              Option.some.injEq, ne_eq]
            intro same
            exact shape.2 (shape.1.symm.trans same.symm)
        | true =>
            simp only [selectedBranchTarget, conditionExact,
              Option.some.injEq, ne_eq]
            intro same
            exact shape.2 (same.trans shape.1)

theorem IndirectSlotSite.target_is_finite
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    {reachableTargetIds allowedTargetIds : List Nat} {site : IndirectSlotSite}
    (checked : site.checked context certificate reachableTargetIds
      allowedTargetIds = true)
    {behavior : NormalizedSymbolicBehavior}
    (normalized : normalizedRegionBehavior? context site.sourceTargetId = some behavior)
    (state : MachineState)
    (allowed : Memory.read32 state.memory
      (BitVec.ofNat 32 (slotAddress context certificate)) ∈
        allowedWords context allowedTargetIds) :
    match behavior.outcome with
    | .indirectCall target _ | .indirectJump target =>
        target.eval state ∈ allowedWords context allowedTargetIds
    | _ => False := by
  unfold IndirectSlotSite.checked at checked
  cases sourceFound : context.source? site.sourceTargetId with
  | none => simp [sourceFound] at checked
  | some source =>
      simp only [sourceFound, normalized, Bool.and_eq_true] at checked
      rcases checked with ⟨_, shape⟩
      cases outcome : behavior.outcome with
      | indirectCall target continuation =>
          have targetExact : target = slotReadExpression
              (slotAddress context certificate) := by
            simpa [outcome] using shape.2
          subst target
          simpa [slotReadExpression, Expr.eval] using allowed
      | indirectJump target =>
          have targetExact : target = slotReadExpression
              (slotAddress context certificate) := by
            simpa [outcome] using shape.2
          subst target
          simpa [slotReadExpression, Expr.eval] using allowed
      | returned target => simp [outcome] at shape
      | jump target => simp [outcome] at shape
      | branch condition taken fallthrough => simp [outcome] at shape
      | call target continuation => simp [outcome] at shape
      | callUnmappedReturn target => simp [outcome] at shape
      | externalCall imported arguments continuation => simp [outcome] at shape
      | externalJump imported arguments => simp [outcome] at shape
      | bulkCopy destination source count direction continuation => simp [outcome] at shape
      | bulkFill destination value count direction continuation =>
          simp [outcome] at shape
      | checkedContinue valid continuation => simp [outcome] at shape
      | atomicCompareExchange address expected replacement continuation =>
          simp [outcome] at shape

end StageA.Relational.ReachableStaticPointerSlot
