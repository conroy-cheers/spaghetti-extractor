import StageA.RelationalInterpreterMixedWorldBridge
import StageA.RelationalInterpreterTransfer
import StageA.RelationalStaticMachineImportContracts

namespace StageA.Relational.InterpreterMixedOriginal

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterTransfer
open StageA.Relational.StaticMachineImportContracts

/-! # Generated decoded-original support

This module contains only generic checks and proof plumbing.  Generated modules
provide exact PE bindings and finite state-machine inventories.  Import
identities are checked against the PE parser's result; diagnostic JSON status
never enters these definitions.
-/

structure OriginalImportIdentity where
  dll : Bytes
  name : ImportName
deriving Repr, DecidableEq

def OriginalImportIdentity.normalizedTarget
    (identity : OriginalImportIdentity) : ExternalTarget := {
  dll := normalizeDllName identity.dll
  name := identity.name
}

def OriginalImportIdentity.matches (identity : OriginalImportIdentity)
    (imported : PEImport) : Bool :=
  normalizeImport imported == identity.normalizedTarget

def originalImportIdentitiesValid (imports : List PEImport)
    (identities : List OriginalImportIdentity) : Bool :=
  identities.all fun identity => imports.any identity.matches

def machineImportContractsCoverIdentities
    (contracts : List MachineImportCallContract)
    (identities : List OriginalImportIdentity) : Bool :=
  identities.all fun identity =>
    contracts.any fun contract =>
      contract.imported == identity.normalizedTarget

/-- Checked provenance for an indirect call loaded through one exact PE IAT
slot.  This establishes source location and import-contract binding only.  The
decoded segment proof remains responsible for proving that the instruction's
target expression reads this slot. -/
structure OriginalIATCallSiteBinding where
  sourceTargetId : Nat
  instructionRva : Nat
  iatVa : Nat
  iatRva : Nat
  identity : OriginalImportIdentity
deriving Repr, DecidableEq

def originalIATCallSiteBindingValid
    (context : OriginalDecodedStaticContext)
    (binding : OriginalIATCallSiteBinding) : Bool :=
  match context.source? binding.sourceTargetId with
  | none => false
  | some source =>
      source.region.span.start <= binding.instructionRva &&
        binding.instructionRva <
          source.region.span.start + source.region.span.size &&
        context.pe.imageBase + binding.iatRva < 2^32 &&
        binding.iatVa == context.pe.imageBase + binding.iatRva &&
        context.imports.any (fun imported =>
          imported.iatRva == binding.iatRva &&
            binding.identity.matches imported) &&
        context.machineImportCallContracts.any (fun contract =>
          contract.imported == binding.identity.normalizedTarget)

def originalIATCallSiteBindingsValid
    (context : OriginalDecodedStaticContext)
    (bindings : List OriginalIATCallSiteBinding) : Bool :=
  bindings.all (originalIATCallSiteBindingValid context)

def originalTargetIdMatchesRva (mapping : OriginalCodeMap)
    (targetId rva : Nat) : Bool :=
  match mapping.get? targetId with
  | some target => target.rva == rva
  | none => false

theorem originalTargetIdMatchesRva_sound
    (checked : originalTargetIdMatchesRva mapping targetId rva = true) :
    exists target, mapping.get? targetId = some target /\ target.rva = rva := by
  cases found : mapping.get? targetId with
  | none => simp [originalTargetIdMatchesRva, found] at checked
  | some target =>
      refine ⟨target, rfl, ?_⟩
      simpa [originalTargetIdMatchesRva, found] using checked

def originalPE32WordBytes (value : Nat) : Bytes :=
  [value % 256, (value / 256) % 256, (value / 65536) % 256,
    (value / 16777216) % 256]

/-- Exact original-side PE binding shared by indirect calls and jumps through
a writable word. Runtime stability comes from `staticWordRelationSlots`; the
on-disk bytes and relocation bind only the initial loader value. -/
structure OriginalStaticWordSlotBindingCore where
  sourceTargetId : Nat
  instructionRva : Nat
  slotRva : Nat
  targetRva : Nat
  slotBytes : Bytes
deriving Repr, DecidableEq

def OriginalStaticWordSlotBindingCore.initialValueChecked
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (binding : OriginalStaticWordSlotBindingCore)
    (targetId : Nat) (slot : StaticWordRelationSlotPair) : Bool :=
  carrier.originalPe == context.pe &&
    carrier.candidatePe == context.pe &&
    carrier.originalImportCertificate == context.importCertificate &&
    carrier.candidateImportCertificate == context.importCertificate &&
    carrier.originalRelocations == context.relocations &&
    carrier.candidateRelocations == context.relocations &&
    staticWordRelationSlotsValid carrier &&
    exactRvaBytes context.pe binding.slotRva 4 == some binding.slotBytes &&
    binding.slotBytes ==
      originalPE32WordBytes (context.pe.imageBase + binding.targetRva) &&
    pe32RelocationWordAt context.relocations binding.slotRva &&
    rvaInExecutableSection context.pe binding.targetRva &&
    match context.source? binding.sourceTargetId,
        context.codeMap.get? targetId,
        carrier.codeMap.get? targetId with
    | some source, some originalTarget, some carrierTarget =>
        source.region.span.start <= binding.instructionRva &&
          binding.instructionRva <
            source.region.span.start + source.region.span.size &&
          originalTarget.rva == binding.targetRva &&
          carrierTarget.originalRva == binding.targetRva &&
          carrierTarget.candidateRva == binding.targetRva &&
          slot.originalAddress == BitVec.ofNat 32
            (context.pe.imageBase + binding.slotRva) &&
          slot.candidateAddress == BitVec.ofNat 32
            (context.pe.imageBase + binding.slotRva)
    | _, _, _ => false

def OriginalStaticWordSlotBindingCore.exactChecked
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (binding : OriginalStaticWordSlotBindingCore)
    (targetId : Nat) (slot : StaticWordRelationSlotPair) : Bool :=
  binding.initialValueChecked context carrier targetId slot &&
    slot.relation == .fixedCodePointer targetId

/-- Exact original-side evidence for an indirect call through a writable PE
word. -/
structure OriginalStaticWordSlotBinding extends
    OriginalStaticWordSlotBindingCore where
  claim : StaticWordSlotIndirectCallTargetClaim
deriving Repr, DecidableEq

def OriginalStaticWordSlotBinding.exactChecked
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (binding : OriginalStaticWordSlotBinding) : Bool :=
  binding.toOriginalStaticWordSlotBindingCore.exactChecked context carrier
    binding.claim.targetId binding.claim.slot

def OriginalStaticWordSlotBinding.valid
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (binding : OriginalStaticWordSlotBinding) : Bool :=
  binding.exactChecked context carrier &&
    binding.claim.checked carrier sourceInvariant originalBehavior
      candidateBehavior

theorem originalStaticWordSlotBinding_claimChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext}
    {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    {binding : OriginalStaticWordSlotBinding}
    (checked : binding.valid context carrier sourceInvariant originalBehavior
      candidateBehavior = true) :
    binding.claim.checked carrier sourceInvariant originalBehavior
      candidateBehavior = true := by
  simp only [OriginalStaticWordSlotBinding.valid, Bool.and_eq_true] at checked
  exact checked.2

/-- Exact original-side evidence for an indirect tail jump through the same
writable-word protocol. Calls and jumps have distinct normalized outcomes, but
share the PE, relocation, code-map, and runtime slot relation. -/
structure OriginalStaticWordJumpSlotBinding extends
    OriginalStaticWordSlotBindingCore where
  claim : StaticWordSlotIndirectJumpTargetClaim
deriving Repr, DecidableEq

def OriginalStaticWordJumpSlotBinding.exactChecked
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (binding : OriginalStaticWordJumpSlotBinding) : Bool :=
  binding.toOriginalStaticWordSlotBindingCore.exactChecked context carrier
    binding.claim.targetId binding.claim.slot

def OriginalStaticWordJumpSlotBinding.valid
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior)
    (binding : OriginalStaticWordJumpSlotBinding) : Bool :=
  binding.exactChecked context carrier &&
    binding.claim.checked carrier sourceInvariant originalBehavior
      candidateBehavior

theorem originalStaticWordJumpSlotBinding_claimChecked
    {context : OriginalDecodedStaticContext}
    {carrier : StaticProofContext}
    {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    {binding : OriginalStaticWordJumpSlotBinding}
    (checked : binding.valid context carrier sourceInvariant originalBehavior
      candidateBehavior = true) :
    binding.claim.checked carrier sourceInvariant originalBehavior
      candidateBehavior = true := by
  simp only [OriginalStaticWordJumpSlotBinding.valid, Bool.and_eq_true] at checked
  exact checked.2

def originalTargetIdsMatchRvasChecked (mapping : OriginalCodeMap) :
    List Nat -> List Nat -> Bool
  | [], [] => true
  | targetId :: targetIds, rva :: rvas =>
      originalTargetIdMatchesRva mapping targetId rva &&
        originalTargetIdsMatchRvasChecked mapping targetIds rvas
  | _, _ => false

theorem originalTargetIdsMatchRvasChecked_sound
    (checked : originalTargetIdsMatchRvasChecked mapping targetIds rvas = true) :
    OriginalTargetIdsMatchRvas mapping targetIds rvas := by
  induction targetIds generalizing rvas with
  | nil => cases rvas <;> simp_all [originalTargetIdsMatchRvasChecked,
      OriginalTargetIdsMatchRvas]
  | cons targetId targetIds ih =>
      cases rvas with
      | nil => simp [originalTargetIdsMatchRvasChecked] at checked
      | cons rva rvas =>
          simp only [originalTargetIdsMatchRvasChecked, Bool.and_eq_true] at checked
          exact ⟨originalTargetIdMatchesRva_sound checked.1, ih checked.2⟩

def originalSourceRoot (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Bool :=
  match context.source? targetId with
  | some source => source.region.root
  | none => false

def originalLaunchRootsDecoded (context : OriginalDecodedStaticContext)
    (launch : PE32ConsoleLaunchV2) : Bool :=
  originalSourceRoot context launch.entryTargetId &&
    launch.tlsCallbackTargetIds.all (originalSourceRoot context)

theorem originalLaunchRootsDecoded_sound
    (checked : originalLaunchRootsDecoded context launch = true) :
    forall targetId,
      targetId = launch.entryTargetId \/
        targetId ∈ launch.tlsCallbackTargetIds ->
      exists source, context.source? targetId = some source /\
        source.region.root = true := by
  simp only [originalLaunchRootsDecoded, Bool.and_eq_true,
    List.all_eq_true] at checked
  intro targetId member
  have rootChecked : originalSourceRoot context targetId = true := by
    cases member with
    | inl entry => simpa [entry] using checked.1
    | inr callback => exact checked.2 targetId callback
  cases found : context.source? targetId with
  | none => simp [originalSourceRoot, found] at rootChecked
  | some source =>
      exact ⟨source, rfl, by
        simpa [originalSourceRoot, found] using rootChecked⟩

def originalReachabilityInventoryValid
    (context : OriginalDecodedStaticContext) (targetIds : List Nat) : Bool :=
  targetIds.all fun targetId =>
    match context.source? targetId with
    | none => false
    | some source => source.region.targets.all targetIds.contains

theorem originalReachabilityInventoryValid_sources
    (checked : originalReachabilityInventoryValid context targetIds = true)
    (member : targetId ∈ targetIds) :
    exists source, context.source? targetId = some source := by
  simp only [originalReachabilityInventoryValid, List.all_eq_true] at checked
  have row := checked targetId member
  cases found : context.source? targetId with
  | none => simp [found] at row
  | some source => exact ⟨source, rfl⟩

theorem originalReachabilityInventoryValid_successors
    (checked : originalReachabilityInventoryValid context targetIds = true)
    (member : targetId ∈ targetIds)
    (found : context.source? targetId = some source)
    (successorMember : successor ∈ source.region.targets) :
    successor ∈ targetIds := by
  simp only [originalReachabilityInventoryValid, List.all_eq_true] at checked
  have row := checked targetId member
  simp only [found, List.all_eq_true] at row
  have contained := row successor successorMember
  simpa using contained

/-- A partial evaluator which succeeds only when an expression is independent
of every machine-state projection.  Unsupported operations fail closed. -/
def stateIndependentExprValue? : Expr -> Option Word
  | .constant value => some (BitVec.ofNat 32 value)
  | _ => none

theorem stateIndependentExprValue_sound
    (expression : Expr) (value : Word)
    (computed : stateIndependentExprValue? expression = some value)
    (state : MachineState) :
    expression.eval state = value := by
  cases expression <;> simp_all [stateIndependentExprValue?, Expr.eval]

def stateIndependentBoolValue? :
    BoolExpr -> Option Bool
  | .equal left right =>
      return decide ((← stateIndependentExprValue? left) =
        (← stateIndependentExprValue? right))
  | .unsignedLess left right =>
      return decide ((← stateIndependentExprValue? left) <
        (← stateIndependentExprValue? right))
  | _ => none

theorem stateIndependentBoolValue_sound
    (expression : BoolExpr) (value : Bool)
    (computed : stateIndependentBoolValue? expression = some value)
    (state : MachineState) :
    expression.eval state = value := by
  cases expression with
  | equal left right =>
      cases leftFound : stateIndependentExprValue? left with
      | none => simp [stateIndependentBoolValue?, leftFound] at computed
      | some leftValue =>
          cases rightFound : stateIndependentExprValue? right with
          | none =>
              simp [stateIndependentBoolValue?, leftFound, rightFound] at computed
          | some rightValue =>
              simp [stateIndependentBoolValue?, leftFound, rightFound] at computed
              subst value
              simp only [BoolExpr.eval]
              rw [stateIndependentExprValue_sound left leftValue leftFound state]
              rw [stateIndependentExprValue_sound right rightValue rightFound state]
  | unsignedLess left right =>
      cases leftFound : stateIndependentExprValue? left with
      | none => simp [stateIndependentBoolValue?, leftFound] at computed
      | some leftValue =>
          cases rightFound : stateIndependentExprValue? right with
          | none =>
              simp [stateIndependentBoolValue?, leftFound, rightFound] at computed
          | some rightValue =>
              simp [stateIndependentBoolValue?, leftFound, rightFound] at computed
              subst value
              simp only [BoolExpr.eval]
              rw [stateIndependentExprValue_sound left leftValue leftFound state]
              rw [stateIndependentExprValue_sound right rightValue rightFound state]
  | not expression => simp [stateIndependentBoolValue?] at computed
  | and left right => simp [stateIndependentBoolValue?] at computed
  | or left right => simp [stateIndependentBoolValue?] at computed
  | xor left right => simp [stateIndependentBoolValue?] at computed
  | msb expression => simp [stateIndependentBoolValue?] at computed
  | bit expression index => simp [stateIndependentBoolValue?] at computed
  | inputFlag index => simp [stateIndependentBoolValue?] at computed
  | divisionValid high low divisor =>
      simp [stateIndependentBoolValue?] at computed

def stateIndependentEdgeGuardValue?
    (outcome : OutcomeExpr) (edgeRva : Nat) : Option Bool :=
  match outcome with
  | .branch condition taken fallthrough =>
      if taken == edgeRva && fallthrough != edgeRva then
        stateIndependentBoolValue? condition
      else if fallthrough == edgeRva && taken != edgeRva then
        return !(← stateIndependentBoolValue? condition)
      else
        none
  | _ => none

def outcomeEdgeSelected
    (outcome : OutcomeExpr) (edgeRva : Nat) (state : MachineState) : Bool :=
  match outcome with
  | .branch condition taken fallthrough =>
      (if condition.eval state then taken else fallthrough) == edgeRva
  | _ => false

theorem stateIndependent_false_edge_not_selected
    (outcome : OutcomeExpr) (edgeRva : Nat)
    (computed : stateIndependentEdgeGuardValue? outcome edgeRva = some false)
    (state : MachineState) :
    outcomeEdgeSelected outcome edgeRva state = false := by
  cases outcome <;>
    simp_all only [stateIndependentEdgeGuardValue?, outcomeEdgeSelected]
  case branch condition taken fallthrough =>
    split at computed
    case isTrue selectedTaken =>
      have conditionFalse := stateIndependentBoolValue_sound
        condition false computed state
      simp at selectedTaken
      simp [conditionFalse, selectedTaken.2]
    case isFalse notSelectedTaken =>
      split at computed
      case isTrue selectedFallthrough =>
        cases conditionFound : stateIndependentBoolValue? condition with
        | none => simp [conditionFound] at computed
        | some conditionValue =>
            have conditionExact := stateIndependentBoolValue_sound
              condition conditionValue conditionFound state
            cases conditionValue <;>
              simp_all [conditionFound, conditionExact]
      case isFalse notSelectedFallthrough => simp at computed

/-- A proposed direct edge omitted from rooted closure.  Its checker binds the
source and destination through the exact original code map, re-decodes the
complete source span, and accepts only a state-independent false branch guard.
The other raw branch edge must remain in the source inventory. -/
structure OriginalStateIndependentFalseEdgeCut where
  sourceTargetId : Nat
  destinationTargetId : Nat
  edgeRva : Nat
deriving Repr, DecidableEq

def OriginalStateIndependentFalseEdgeCut.valid
    (cut : OriginalStateIndependentFalseEdgeCut)
    (context : OriginalDecodedStaticContext) : Bool :=
  match context.source? cut.sourceTargetId,
      context.codeMap.get? cut.destinationTargetId with
  | some source, some _ =>
      !source.region.targets.contains cut.destinationTargetId &&
        context.codeMap.resolveRawEip context.pe.imageBase
          (BitVec.ofNat 32 (context.pe.imageBase + cut.edgeRva)) ==
            some cut.destinationTargetId &&
        match regionBehaviorWithMachineCallContracts context.pe context.imports
            context.machineImportCallContracts source.region.span with
        | some behavior =>
            match behavior.outcome with
            | some outcome =>
                stateIndependentEdgeGuardValue? outcome cut.edgeRva == some false &&
                  match outcome with
                  | .branch _ taken fallthrough =>
                      let otherRva := if taken == cut.edgeRva then fallthrough else taken
                      match context.codeMap.resolveRawEip context.pe.imageBase
                          (BitVec.ofNat 32 (context.pe.imageBase + otherRva)) with
                      | some otherTargetId => source.region.targets.contains otherTargetId
                      | none => false
                  | _ => false
            | none => false
        | none => false
  | _, _ => false

def OriginalStateIndependentFalseEdgeCut.Impossible
    (cut : OriginalStateIndependentFalseEdgeCut)
    (context : OriginalDecodedStaticContext) : Prop :=
  forall source behavior outcome state,
    context.source? cut.sourceTargetId = some source ->
    regionBehaviorWithMachineCallContracts context.pe context.imports
      context.machineImportCallContracts source.region.span = some behavior ->
    behavior.outcome = some outcome ->
    outcomeEdgeSelected outcome cut.edgeRva state = false

theorem originalStateIndependentFalseEdgeCut_valid_impossible
    {cut : OriginalStateIndependentFalseEdgeCut}
    {context : OriginalDecodedStaticContext}
    (checked : cut.valid context = true) :
    cut.Impossible context := by
  intro source behavior outcome state sourceFound decoded outcomeFound
  simp only [OriginalStateIndependentFalseEdgeCut.valid, sourceFound] at checked
  cases destinationFound : context.codeMap.get? cut.destinationTargetId with
  | none => simp [destinationFound] at checked
  | some destination =>
      simp only [destinationFound] at checked
      simp only [Bool.and_eq_true] at checked
      rcases checked with ⟨⟨_, _⟩, decodedChecked⟩
      simp only [decoded] at decodedChecked
      simp only [outcomeFound, Bool.and_eq_true] at decodedChecked
      exact stateIndependent_false_edge_not_selected outcome
        cut.edgeRva (by simpa using decodedChecked.1) state

/-- One decoded call continuation omitted from syntactic reachability because
the exact imported-call route is checked to terminate.  The continuation still
has an exact code-map target: call-frame normalization must retain its concrete
return address even though execution cannot resume there. -/
structure OriginalTerminalSuccessorCut where
  sourceTargetId : Nat
  continuationTargetId : Nat
  binding : StaticMachineImportTerminalBoundaryBinding
  syntheticPadding : Bool := false
deriving Repr, DecidableEq

def OriginalTerminalSuccessorCut.valid
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (cut : OriginalTerminalSuccessorCut) : Bool :=
  carrier.originalPe == context.pe &&
    carrier.originalImports == context.imports &&
    carrier.machineImportCallContracts == context.machineImportCallContracts &&
    cut.binding.valid carrier signatures boundaries inventory &&
    match context.source? cut.sourceTargetId,
        context.source? cut.continuationTargetId with
    | some source, some continuation =>
        source.region.span == cut.binding.boundary.sourceSpan &&
          (context.codeMap.resolveRawEip context.pe.imageBase
            (BitVec.ofNat 32
              (context.pe.imageBase + cut.binding.boundary.sourceSpan.start)) ==
            some cut.sourceTargetId) &&
          (context.codeMap.resolveRawEip context.pe.imageBase
            (BitVec.ofNat 32
              (context.pe.imageBase +
                cut.binding.boundary.continuationRva)) ==
            some cut.continuationTargetId) &&
          !source.region.targets.contains cut.continuationTargetId &&
          (!cut.syntheticPadding ||
            match spanBytes context.pe continuation.region.span with
            | some bytes => paddingBytes bytes
            | none => false)
    | _, _ => false

def originalTerminalSuccessorCutsValid
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (cuts : List OriginalTerminalSuccessorCut)
    (expectedCount : Nat) : Bool :=
  cuts.length == expectedCount &&
    cuts.all fun cut =>
      (cuts.filter fun other =>
        other.sourceTargetId == cut.sourceTargetId &&
          other.continuationTargetId == cut.continuationTargetId).length == 1 &&
      cut.valid context carrier signatures boundaries inventory

/-- Finite carrier fields that generated data can prove independently from the
two universal lookup-algorithm equalities retained by the legacy carrier. -/
structure GeneratedOriginalFiniteCarrierBinding
    (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) : Prop where
  originalRole : original.candidate = false
  peBound : original.context.originalPe = context.pe
  importsBound : original.context.originalImports = context.imports
  machineContractsBound :
    original.context.machineImportCallContracts =
      context.machineImportCallContracts
  sourceRegionsBound : forall targetId source,
    context.source? targetId = some source ->
      exists region, regionById original.regions targetId = some region /\
        region.id = source.target.id /\
        region.original = source.region.span /\
        region.root = source.region.root /\
        region.targets.map (fun target => target.id) = source.region.targets
  regionsHaveSources : forall region, region ∈ original.regions ->
    exists source, context.source? region.id = some source /\
      region.original = source.region.span /\
      region.targets.map (fun target => target.id) = source.region.targets
  originalTargetsBound : forall region, region ∈ original.regions ->
    forall target, target ∈ region.targets ->
      exists originalTarget,
        context.codeMap.get? target.id = some originalTarget /\
        target.originalRva = originalTarget.rva /\
        target.originalAliases = originalTarget.aliases

def GeneratedOriginalFiniteCarrierBinding.toExact
    (binding : GeneratedOriginalFiniteCarrierBinding context original)
    (indexedResolution : forall address,
      original.context.codeMap.resolveRawEip false context.pe.imageBase address =
        context.codeMap.resolveRawEip context.pe.imageBase address)
    (returnResolution : forall address,
      resolveMappedCodeTarget false context.pe.imageBase
          original.context.codeMap.entries.toList address =
        context.codeMap.resolveRawEip context.pe.imageBase address) :
    ExactDecodedOriginalCarrierBinding context original := {
  originalRole := binding.originalRole
  peBound := binding.peBound
  importsBound := binding.importsBound
  machineContractsBound := binding.machineContractsBound
  sourceRegionsBound := binding.sourceRegionsBound
  regionsHaveSources := binding.regionsHaveSources
  originalTargetsBound := binding.originalTargetsBound
  indexedIndirectResolutionBound := indexedResolution
  concreteReturnResolutionBound := returnResolution
}

end StageA.Relational.InterpreterMixedOriginal
