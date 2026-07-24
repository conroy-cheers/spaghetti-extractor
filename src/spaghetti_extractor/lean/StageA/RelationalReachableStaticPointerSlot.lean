import StageA.RelationalInterpreterMixedOriginal

namespace StageA.Relational.ReachableStaticPointerSlot

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal

/-! # Reachable writable static pointer slots

This module checks finite proposals against an exact decoded-original context.
It deliberately separates immutable facts from the one runtime premise which a
whole-program composition proof must provide: a non-constant write classified
as `runtimeSeparated` must be proved disjoint from the slot in the concrete
source state.  Such a classification is never itself an acceptance fact.

`Certificate.regions` is sparse. A missing row is accepted only when Lean
replays the normalized behavior and proves every write to be an absolute
four-byte write disjoint from the slot. Thus artifacts scale with may-touch
regions, although the current `ExactOriginalDecodedAuthority` does not expose a
shared normalized-behavior inventory: kernel reduction still re-decodes each
reachable region for each slot certificate. A future authority-level behavior
object can remove that compute without changing the certificate semantics.
-/

inductive Knowledge (alpha : Type) where
  | unknown
  | exact (value : alpha)
deriving Repr, DecidableEq

inductive WriteClassification where
  | absoluteDisjoint
  | slotZero
  | slotCodeTarget (targetId : Nat)
  | runtimeSeparated
deriving Repr, DecidableEq, BEq

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

def natWordsDisjoint (left right : Nat) : Bool :=
  left + 4 <= right || right + 4 <= left

def WriteClassification.checked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (allowedTargetIds : List Nat)
    (classification : WriteClassification) (write : Expr × Expr) : Bool :=
  let slot := slotAddress context certificate
  match classification with
  | .absoluteDisjoint =>
      match write.1 with
      | .constant address =>
          address + 4 <= 2 ^ 32 && natWordsDisjoint slot address
      | _ => false
  | .slotZero =>
      write.1 == .constant slot && write.2 == .constant 0
  | .slotCodeTarget targetId =>
      allowedTargetIds.contains targetId &&
        match targetCanonicalWord? context targetId with
        | some value => write.1 == .constant slot && write.2 == .constant value
        | none => false
  | .runtimeSeparated =>
      match write.1 with
      | .constant _ => false
      | _ => true

def classificationsChecked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (allowedTargetIds : List Nat) :
    List WriteClassification -> List (Expr × Expr) -> Bool
  | [], [] => true
  | classification :: classifications, write :: writes =>
      classification.checked context certificate allowedTargetIds write &&
        classificationsChecked context certificate allowedTargetIds
          classifications writes
  | _, _ => false

def RegionBinding.checked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds allowedTargetIds : List Nat)
    (binding : RegionBinding) : Bool :=
  reachableTargetIds.contains binding.targetId &&
    match binding.writes, normalizedRegionBehavior? context binding.targetId with
    | .exact classifications, some behavior =>
        classificationsChecked context certificate allowedTargetIds
          classifications behavior.writes
    | _, _ => false

def defaultDisjointClassifications
    (writes : List (Expr × Expr)) : List WriteClassification :=
  writes.map fun _ => .absoluteDisjoint

/-- A missing sparse row means that every write must independently replay as
an absolute write disjoint from this slot. Unknown submitted rows still reject.
-/
def regionClassifications? (bindings : List RegionBinding) (targetId : Nat)
    (behavior : NormalizedSymbolicBehavior) : Option (List WriteClassification) :=
  match bindings.find? fun binding => binding.targetId == targetId with
  | some binding =>
      match binding.writes with
      | .exact classifications => some classifications
      | .unknown => none
  | none => some (defaultDisjointClassifications behavior.writes)

def sparseBindingsChecked (reachableTargetIds : List Nat)
    (bindings : List RegionBinding) : Bool :=
  noDuplicates (bindings.map (·.targetId)) &&
    bindings.all fun binding => reachableTargetIds.contains binding.targetId

def regionInventoryChecked (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (reachableTargetIds allowedTargetIds : List Nat)
    (bindings : List RegionBinding) : Bool :=
  sparseBindingsChecked reachableTargetIds bindings &&
    reachableTargetIds.all fun targetId =>
      match normalizedRegionBehavior? context targetId with
      | some behavior =>
          match regionClassifications? bindings targetId behavior with
          | some classifications =>
              classificationsChecked context certificate allowedTargetIds
                classifications behavior.writes
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

def RuntimeSeparations (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (state : MachineState) :
    List WriteClassification -> List (Expr × Expr) -> Prop
  | [], [] => True
  | .runtimeSeparated :: classifications, write :: writes =>
      Write32AvoidsWord
          (BitVec.ofNat 32 (slotAddress context certificate))
          (write.1.eval state) /\
        RuntimeSeparations context certificate state classifications writes
  | _ :: classifications, _ :: writes =>
      RuntimeSeparations context certificate state classifications writes
  | _, _ => False

def writeAdmissible (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (allowedTargetIds : List Nat)
    (state : MachineState) (write : Expr × Expr) : Prop :=
  let slot := BitVec.ofNat 32 (slotAddress context certificate)
  (write.1.eval state = slot /\
      write.2.eval state ∈ allowedWords context allowedTargetIds) \/
    Write32AvoidsWord slot (write.1.eval state)

theorem WriteClassification.admissible_of_checked
    {context : OriginalDecodedStaticContext} {certificate : Certificate}
    {allowedTargetIds : List Nat} {classification : WriteClassification}
    {write : Expr × Expr} {state : MachineState}
    (checked : classification.checked context certificate allowedTargetIds write = true)
    (slotFits : (BitVec.ofNat 32 (slotAddress context certificate)).toNat + 4 <=
      2 ^ 32)
    (slotNatFits : slotAddress context certificate + 4 <= 2 ^ 32)
    (runtime : match classification with
      | .runtimeSeparated => Write32AvoidsWord
          (BitVec.ofNat 32 (slotAddress context certificate))
          (write.1.eval state)
      | _ => True) :
    writeAdmissible context certificate allowedTargetIds state write := by
  cases classification with
  | absoluteDisjoint =>
      rcases write with ⟨address, value⟩
      cases address <;> simp [WriteClassification.checked] at checked
      rename_i address
      right
      apply write32AvoidsWord_of_nat_disjoint
      · exact slotFits
      · simp only [Expr.eval, BitVec.toNat_ofNat]
        have addressBefore : address < 2 ^ 32 := by omega
        simpa [Nat.mod_eq_of_lt addressBefore] using checked.1
      · have slotBefore : slotAddress context certificate < 2 ^ 32 := by
          omega
        have addressBefore : address < 2 ^ 32 := by omega
        simpa [Expr.eval, BitVec.toNat_ofNat, Nat.mod_eq_of_lt slotBefore,
          Nat.mod_eq_of_lt addressBefore, natWordsDisjoint] using checked.2
  | slotZero =>
      rcases write with ⟨address, value⟩
      simp only [WriteClassification.checked, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨rfl, rfl⟩
      left
      simp [allowedWords, Expr.eval]
  | slotCodeTarget targetId =>
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
          · simp [Expr.eval]
          · simp only [Expr.eval, allowedWords, List.mem_cons]
            right
            apply List.mem_map.mpr
            refine ⟨targetWord, ?_, rfl⟩
            apply List.mem_filterMap.mpr
            exact ⟨targetId, by simpa using member, found⟩
  | runtimeSeparated =>
      exact Or.inr runtime

theorem classifications_admissible_of_checked
    (context : OriginalDecodedStaticContext) (certificate : Certificate)
    (allowedTargetIds : List Nat) (state : MachineState)
    (slotFits : (BitVec.ofNat 32 (slotAddress context certificate)).toNat + 4 <=
      2 ^ 32)
    (slotNatFits : slotAddress context certificate + 4 <= 2 ^ 32) :
    forall classifications writes,
      classificationsChecked context certificate allowedTargetIds
        classifications writes = true ->
      RuntimeSeparations context certificate state classifications writes ->
      forall candidate, candidate ∈ writes ->
        writeAdmissible context certificate allowedTargetIds state candidate := by
  intro classifications
  induction classifications with
  | nil =>
      intro writes checked runtime candidate member
      cases writes <;> simp [classificationsChecked] at checked member
  | cons classification classifications induction =>
      intro writes checked runtime candidate member
      cases writes with
      | nil => simp [classificationsChecked] at checked
      | cons head tail =>
          simp only [classificationsChecked, Bool.and_eq_true] at checked
          cases classification with
          | absoluteDisjoint =>
              simp only [RuntimeSeparations] at runtime
              rcases List.mem_cons.mp member with same | member
              · subst candidate
                exact WriteClassification.admissible_of_checked checked.1
                  slotFits slotNatFits trivial
              · exact induction tail checked.2 runtime candidate member
          | slotZero =>
              simp only [RuntimeSeparations] at runtime
              rcases List.mem_cons.mp member with same | member
              · subst candidate
                exact WriteClassification.admissible_of_checked checked.1
                  slotFits slotNatFits trivial
              · exact induction tail checked.2 runtime candidate member
          | slotCodeTarget targetId =>
              simp only [RuntimeSeparations] at runtime
              rcases List.mem_cons.mp member with same | member
              · subst candidate
                exact WriteClassification.admissible_of_checked checked.1
                  slotFits slotNatFits trivial
              · exact induction tail checked.2 runtime candidate member
          | runtimeSeparated =>
              simp only [RuntimeSeparations] at runtime
              rcases runtime with ⟨headSeparated, tailSeparated⟩
              rcases List.mem_cons.mp member with same | member
              · subst candidate
                exact WriteClassification.admissible_of_checked checked.1
                  slotFits slotNatFits headSeparated
              · exact induction tail checked.2 tailSeparated candidate member

theorem apply_writes_preserves_allowed
    (context : OriginalDecodedStaticContext) (certificate : Certificate)
    (allowedTargetIds : List Nat) (state : MachineState)
    (memory : Memory) (writes : List (Expr × Expr))
    (slotFits : (BitVec.ofNat 32 (slotAddress context certificate)).toNat + 4 <=
      2 ^ 32)
    (admissible : forall write, write ∈ writes ->
      writeAdmissible context certificate allowedTargetIds state write)
    (prior : Memory.read32 memory
      (BitVec.ofNat 32 (slotAddress context certificate)) ∈
        allowedWords context allowedTargetIds) :
    Memory.read32 (applyConcreteWrites memory (evalNormalizedWrites state writes))
      (BitVec.ofNat 32 (slotAddress context certificate)) ∈
        allowedWords context allowedTargetIds := by
  induction writes generalizing memory with
  | nil => simpa [applyConcreteWrites, evalNormalizedWrites] using prior
  | cons write writes induction =>
      have head := admissible write (by simp)
      have nextAllowed :
          Memory.read32 (memory.write32 (write.1.eval state) (write.2.eval state))
            (BitVec.ofNat 32 (slotAddress context certificate)) ∈
              allowedWords context allowedTargetIds := by
        rcases head with ⟨address, value⟩ | avoids
        · rw [address]
          rw [Memory.read32_write32_same_of_fits _ _ _ slotFits]
          exact value
        · rw [Memory.read32_write32_of_avoids _ _ _ _ avoids]
          exact prior
      simp only [evalNormalizedWrites, List.map_cons, applyConcreteWrites,
        List.foldl_cons]
      exact induction
        (memory.write32 (write.1.eval state) (write.2.eval state))
        (fun candidate candidateMember => admissible candidate (by
          simp [candidateMember])) nextAllowed

def RegionTransition (context : OriginalDecodedStaticContext)
    (certificate : Certificate) (before after : Memory) : Prop :=
  exists reachableTargetIds allowedTargetIds bindings targetId behavior state classifications,
    certificate.reachableTargetIds = .exact reachableTargetIds /\
    certificate.allowedTargetIds = .exact allowedTargetIds /\
    certificate.regions = .exact bindings /\
    targetId ∈ reachableTargetIds /\
    normalizedRegionBehavior? context targetId = some behavior /\
    regionClassifications? bindings targetId behavior = some classifications /\
    state.memory = before /\
    RuntimeSeparations context certificate state classifications behavior.writes /\
    after = applyConcreteWrites before (evalNormalizedWrites state behavior.writes)

theorem Certificate.transition_preserves
    {certificate : Certificate} {context : OriginalDecodedStaticContext}
    (checked : certificate.checked context = true) {before after : Memory}
    (prior : SlotValueAllowed context certificate before)
    (transition : RegionTransition context certificate before after) :
    SlotValueAllowed context certificate after := by
  rcases transition with
    ⟨reachableTargetIds, allowedTargetIds, bindings, targetId, behavior, state,
      classifications, reachableExact, allowedExact, regionsExact, targetMember,
      normalized, classificationsFound, stateMemory, runtime, rfl⟩
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
  have inventory := facts.regionChecked
  unfold regionInventoryChecked at inventory
  simp only [Bool.and_eq_true] at inventory
  have rowsChecked := inventory.2
  rw [List.all_eq_true] at rowsChecked
  have rowChecked := rowsChecked targetId targetMember
  simp only [normalized, classificationsFound] at rowChecked
  have classificationsOk := rowChecked
  have slotFits := initialZeroChecked_slot_fits facts.initialZero
  have slotNatFits := initialZeroChecked_slot_nat_fits facts.initialZero
  have admissible := classifications_admissible_of_checked context certificate
    facts.allowedTargetIds state slotFits slotNatFits classifications behavior.writes
      classificationsOk runtime
  unfold SlotValueAllowed at prior ⊢
  rw [facts.allowedExact] at prior ⊢
  exact apply_writes_preserves_allowed context certificate facts.allowedTargetIds
    state before behavior.writes slotFits admissible prior

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
            | _ => false
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
      | checkedContinue valid continuation => simp [outcome] at shape
      | atomicCompareExchange address expected replacement continuation =>
          simp [outcome] at shape

end StageA.Relational.ReachableStaticPointerSlot
