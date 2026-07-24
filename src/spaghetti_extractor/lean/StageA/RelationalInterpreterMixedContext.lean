import StageA.RelationalInterpreterKernelData
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.InterpreterMixedContext

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData
open StageA.Relational.InterpreterNativeWorld

/-! # Static contexts for decoded-original/native-candidate proofs

The structurally paired `StaticProofContext` is useful when both binaries have
corresponding code addresses.  A compiled interpreter candidate does not have
that shape: its private native code is indexed directly by its own PE, while
the decoded original still needs a complete and unambiguous source index.

This module defines that split without changing the existing world bridge.
All certificates below contain checked facts about immutable artifacts.  No
Boolean verdict or caller-supplied status can stand in for those facts.
-/

structure OriginalCodeTarget where
  id : Nat
  regionIndex : Nat
  rva : Nat
  aliases : List CodeAlias := []
deriving Repr, DecidableEq

structure OriginalCodeAddress where
  targetId : Nat
  kind : StaticCodeAddressKind
deriving Repr, DecidableEq

structure OriginalCodeMap where
  entries : FiniteIndex OriginalCodeTarget
  addresses : FiniteIndex OriginalCodeAddress
deriving Repr, DecidableEq

def OriginalCodeMap.get? (mapping : OriginalCodeMap)
    (targetId : Nat) : Option OriginalCodeTarget :=
  mapping.entries.get? targetId

def originalCodeAddressRva (mapping : OriginalCodeMap)
    (address : OriginalCodeAddress) : Option Nat := do
  let target <- mapping.get? address.targetId
  match address.kind with
  | .canonical => pure target.rva
  | .alias index => pure (← target.aliases[index]?).rva

def OriginalCodeMap.findRvaAux (mapping : OriginalCodeMap) (needle : Nat) :
    Nat -> Nat -> Nat -> Option (Nat × OriginalCodeAddress)
  | 0, _, _ => none
  | fuel + 1, lower, upper =>
      if lower < upper then
        let middle := lower + (upper - lower) / 2
        match mapping.addresses.get? middle with
        | none => none
        | some address =>
            match originalCodeAddressRva mapping address with
            | none => none
            | some rva =>
                if needle < rva then
                  mapping.findRvaAux needle fuel lower middle
                else if rva < needle then
                  mapping.findRvaAux needle fuel (middle + 1) upper
                else
                  some (middle, address)
      else
        none

def OriginalCodeMap.findRva? (mapping : OriginalCodeMap)
    (needle : Nat) : Option (Nat × OriginalCodeAddress) :=
  mapping.findRvaAux needle (mapping.addresses.size + 1) 0
    mapping.addresses.size

def OriginalCodeMap.addressRvaAt? (mapping : OriginalCodeMap)
    (index : Nat) : Option Nat := do
  let address <- mapping.addresses.get? index
  originalCodeAddressRva mapping address

def OriginalCodeMap.rawEipMatches (imageBase : Nat)
    (mapping : OriginalCodeMap) (eip : Word) : List Nat :=
  let absolute := eip.toNat
  if imageBase <= absolute then
    let needle := absolute - imageBase
    match mapping.findRva? needle with
    | none => []
    | some (index, address) =>
        let priorMatches :=
          match index with
          | 0 => false
          | prior + 1 => mapping.addressRvaAt? prior == some needle
        let nextMatches := mapping.addressRvaAt? (index + 1) == some needle
        if priorMatches || nextMatches then
          [address.targetId, address.targetId]
        else
          [address.targetId]
  else
    []

def OriginalCodeMap.resolveRawEip (imageBase : Nat)
    (mapping : OriginalCodeMap) (eip : Word) : Option Nat :=
  match mapping.rawEipMatches imageBase eip with
  | [targetId] => some targetId
  | _ => none

def OriginalCodeMap.canonicalRawEip? (imageBase : Nat)
    (mapping : OriginalCodeMap) (targetId : Nat) : Option Word := do
  let target <- mapping.get? targetId
  pure (BitVec.ofNat 32 (imageBase + target.rva))

def OriginalCodeMap.entryAtValid (mapping : OriginalCodeMap)
    (index : Nat) : Bool :=
  match mapping.get? index with
  | some target => target.id == index
  | none => false

def OriginalCodeMap.addressContribution (mapping : OriginalCodeMap)
    (index : Nat) : Nat :=
  match mapping.get? index with
  | none => 0
  | some target => 1 + target.aliases.length

def OriginalCodeMap.expectedAddressCount (mapping : OriginalCodeMap) : Nat :=
  indexedNatFold mapping.addressContribution 0 mapping.entries.size 0

def OriginalCodeMap.addressAtValid (pe : PE32) (mapping : OriginalCodeMap)
    (index : Nat) : Bool :=
  match mapping.addresses.get? index with
  | none => false
  | some address =>
      match originalCodeAddressRva mapping address with
      | none => false
      | some rva =>
          rvaInExecutableSection pe rva &&
            match index with
            | 0 => true
            | prior + 1 =>
                match mapping.addresses.get? prior with
                | none => false
                | some priorAddress =>
                    match originalCodeAddressRva mapping priorAddress with
                    | some priorRva => priorRva < rva
                    | none => false

def OriginalCodeMap.targetRoundTripsAt (pe : PE32)
    (mapping : OriginalCodeMap) (targetId : Nat) : Bool :=
  match mapping.get? targetId with
  | none => false
  | some target =>
      mapping.resolveRawEip pe.imageBase
          (BitVec.ofNat 32 (pe.imageBase + target.rva)) == some targetId &&
        target.aliases.all fun alias =>
          mapping.resolveRawEip pe.imageBase
            (BitVec.ofNat 32 (pe.imageBase + alias.rva)) == some targetId

def OriginalCodeMap.aliasesSemanticallyValidAt (pe : PE32)
    (imports : List PEImport) (mapping : OriginalCodeMap)
    (targetId : Nat) : Bool :=
  match mapping.get? targetId with
  | none => false
  | some target =>
      target.aliases.all fun alias =>
        codeAliasBridgeBehavior pe imports alias.rva target.rva ==
          some { initialSymbolic with outcome := some (.jump target.rva) }

/-- Shardable checked evidence for the one-sided code target index. -/
structure OriginalCodeMapCertificate (pe : PE32) (imports : List PEImport)
    (mapping : OriginalCodeMap) where
  entriesStructurallyValid : mapping.entries.structurallyValid 16 = true
  addressesStructurallyValid : mapping.addresses.structurallyValid 16 = true
  entryChecks : IndexedBoolCertificate
  entryChecksValid :
    entryChecks.checked mapping.entryAtValid mapping.entries.size = true
  addressCountExact : mapping.addresses.size = mapping.expectedAddressCount
  addressChecks : IndexedBoolCertificate
  addressChecksValid :
    addressChecks.checked (mapping.addressAtValid pe) mapping.addresses.size = true
  roundTripChecks : IndexedBoolCertificate
  roundTripChecksValid :
    roundTripChecks.checked (mapping.targetRoundTripsAt pe)
      mapping.entries.size = true
  aliasChecks : IndexedBoolCertificate
  aliasChecksValid :
    aliasChecks.checked (mapping.aliasesSemanticallyValidAt pe imports)
      mapping.entries.size = true

theorem OriginalCodeMapCertificate.entry_valid
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (targetId : Nat) (before : targetId < mapping.entries.size) :
    mapping.entryAtValid targetId = true :=
  certificate.entryChecks.holds_of_checked mapping.entryAtValid
    mapping.entries.size certificate.entryChecksValid targetId before

theorem OriginalCodeMapCertificate.target_round_trips
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (targetId : Nat) (before : targetId < mapping.entries.size) :
    mapping.targetRoundTripsAt pe targetId = true :=
  certificate.roundTripChecks.holds_of_checked (mapping.targetRoundTripsAt pe)
    mapping.entries.size certificate.roundTripChecksValid targetId before

theorem OriginalCodeMapCertificate.target_id_eq
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (targetId : Nat) (target : OriginalCodeTarget)
    (found : mapping.get? targetId = some target) :
    target.id = targetId := by
  have before := FiniteIndex.get?_eq_some_implies_lt_size
    mapping.entries targetId target found
  have checked := certificate.entry_valid targetId before
  simpa [OriginalCodeMap.entryAtValid, found] using checked

structure OriginalDecodedRegion where
  id : Nat
  span : Span
  root : Bool
  targets : List Nat
deriving Repr, DecidableEq

structure OriginalDecodedSource where
  target : OriginalCodeTarget
  region : OriginalDecodedRegion
deriving Repr, DecidableEq

structure OriginalDecodedStaticContext where
  pe : PE32
  importCertificate : ImportTableCertificate
  relocations : List BaseRelocation
  codeMap : OriginalCodeMap
  regions : FiniteIndex OriginalDecodedRegion
  machineImportCallContracts : List MachineImportCallContract := []
deriving Repr, DecidableEq

def OriginalDecodedStaticContext.imports
    (context : OriginalDecodedStaticContext) : List PEImport :=
  context.importCertificate.imports

/-- Resolve one decoded source exclusively through original-side indices. -/
def OriginalDecodedStaticContext.source?
    (context : OriginalDecodedStaticContext)
    (targetId : Nat) : Option OriginalDecodedSource := do
  let target <- context.codeMap.get? targetId
  let region <- context.regions.get? target.regionIndex
  if region.id != target.id || region.span.start != target.rva ||
      region.span.size == 0 || (spanBytes context.pe region.span).isNone ||
      !region.targets.all (fun destination =>
        (context.codeMap.get? destination).isSome) then
    none
  else
    pure { target, region }

def OriginalDecodedStaticContext.sourceAtValid
    (context : OriginalDecodedStaticContext) (targetId : Nat) : Bool :=
  (context.source? targetId).isSome

/-- Exact static authority for the decoded original.  Its code inventory is
one-sided, and therefore cannot manufacture candidate addresses. -/
structure ExactOriginalDecodedAuthority
    (context : OriginalDecodedStaticContext) where
  peParsed : parsePE32Tree context.pe.bytes = some context.pe
  importsParsed : importTableValid context.pe context.importCertificate = true
  relocationsParsed : parseRelocations context.pe = some context.relocations
  loaderImageValid : preferredBaseLoaderImageValid context.pe = true
  codeMap : OriginalCodeMapCertificate context.pe context.imports context.codeMap
  regionsStructurallyValid : context.regions.structurallyValid 16 = true
  sourceChecks : IndexedBoolCertificate
  sourceChecksValid :
    sourceChecks.checked context.sourceAtValid context.codeMap.entries.size = true
  machineContractsValid :
    machineImportCallContractsValid context.imports
      context.machineImportCallContracts = true

theorem ExactOriginalDecodedAuthority.source_exists
    (authority : ExactOriginalDecodedAuthority context)
    (targetId : Nat) (before : targetId < context.codeMap.entries.size) :
    ∃ source, context.source? targetId = some source := by
  have checked := authority.sourceChecks.holds_of_checked
    context.sourceAtValid context.codeMap.entries.size
    authority.sourceChecksValid targetId before
  cases found : context.source? targetId with
  | none => simp [OriginalDecodedStaticContext.sourceAtValid, found] at checked
  | some source => exact ⟨source, rfl⟩

/-- Candidate authority is indexed directly by the exact native program.  In
particular, there is no candidate half of an original code map. -/
structure ExactNativeCandidateAuthority
    (candidate : ExactNativeWorldProgram) where
  importCertificate : ImportTableCertificate
  relocations : List BaseRelocation
  tableRva : Nat
  countRva : Nat
  semanticRecords : List StageA.Relational.Interpreter.ProgramRecord
  peParsed : parsePE32Tree candidate.pe.bytes = some candidate.pe
  importsBound : importCertificate.imports = candidate.imports
  importsParsed : importTableValid candidate.pe importCertificate = true
  relocationsParsed : parseRelocations candidate.pe = some relocations
  loaderImageValid : preferredBaseLoaderImageValid candidate.pe = true
  table : ProgramTableCertificate candidate.pe candidate.imports relocations
    tableRva countRva semanticRecords

structure NativeExternalBoundary where
  eventIndex : Nat
  event : NativeExternalEvent
  world : RelationalWorld

/-- Primitive relations chosen for one proof profile.  Event observations and
external boundaries are derived below, so proof-blocked observations and API
identity cannot be relaxed by supplying a permissive status field. -/
structure MixedRelationContract where
  worldsRelated : RelationalWorld -> RelationalWorld -> Prop
  launchStatesRelated : RelationalWorld -> RelationalWorld ->
    MachineState -> MachineState -> Prop
  runtimeStatesRelated : RelationalWorld -> RelationalWorld ->
    MachineState -> MachineState -> Prop
  valuesRelated : RelationalWorld -> RelationalWorld -> Word -> Word -> Prop
  callbackTargetsRelated : Nat -> Nat -> Prop

def mixedValuesRelated (relation : Word -> Word -> Prop) :
    List Word -> List Word -> Prop
  | [], [] => True
  | original :: originals, candidate :: candidates =>
      relation original candidate ∧
        mixedValuesRelated relation originals candidates
  | _, _ => False

def MixedRelationContract.eventObservationsRelated
    (contract : MixedRelationContract) :
    Option WorldRelationalObservable -> Option WorldRelationalObservable -> Prop
  | none, none => True
  | some (.external originalWorld originalImport originalArguments),
      some (.external candidateWorld candidateImport candidateArguments) =>
      contract.worldsRelated originalWorld candidateWorld ∧
        originalImport = candidateImport ∧
        mixedValuesRelated
          (contract.valuesRelated originalWorld candidateWorld)
          originalArguments candidateArguments
  | some (.callableExternal original), some (.callableExternal candidate) =>
      original.globalExternalIndex = candidate.globalExternalIndex ∧
        original.identity = candidate.identity ∧
        contract.worldsRelated original.world candidate.world ∧
        mixedValuesRelated
          (contract.valuesRelated original.world candidate.world)
          original.arguments candidate.arguments
  | some (.returned originalWorld originalResult),
      some (.returned candidateWorld candidateResult) =>
      contract.worldsRelated originalWorld candidateWorld ∧
        contract.valuesRelated originalWorld candidateWorld
          originalResult candidateResult
  | some (.callback originalWorld originalTarget),
      some (.callback candidateWorld candidateTarget) =>
      contract.worldsRelated originalWorld candidateWorld ∧
        contract.callbackTargetsRelated originalTarget candidateTarget
  | some (.fault originalCause), some (.fault candidateCause) =>
      originalCause = candidateCause
  | _, _ => False

/-- Pointwise lockstep boundary for one original external suspension and one
candidate native call.  The redundant original suspension fields are checked
against its immutable event before either side can be related. -/
def MixedRelationContract.externalBoundariesRelated
    (contract : MixedRelationContract) (original : WorldExternalSuspension)
    (candidate : NativeExternalBoundary) : Prop :=
  original.event.siteId = original.siteId ∧
    original.event.imported = original.imported ∧
    original.event.arguments = original.arguments ∧
    original.event.state = original.state ∧
    original.event.world = original.world ∧
    original.eventIndex = candidate.eventIndex ∧
    original.imported = normalizeImport candidate.event.imported ∧
    contract.worldsRelated original.world candidate.world ∧
    contract.runtimeStatesRelated original.world candidate.world
      original.state candidate.event.state ∧
    mixedValuesRelated (contract.valuesRelated original.world candidate.world)
      original.arguments candidate.event.arguments

theorem MixedRelationContract.external_boundaries_same_event_index
    (contract : MixedRelationContract)
    (original : WorldExternalSuspension) (candidate : NativeExternalBoundary)
    (related : contract.externalBoundariesRelated original candidate) :
    original.eventIndex = candidate.eventIndex := by
  rcases related with ⟨_, _, _, _, _, eventIndex, _⟩
  exact eventIndex

theorem MixedRelationContract.external_boundaries_same_import
    (contract : MixedRelationContract)
    (original : WorldExternalSuspension) (candidate : NativeExternalBoundary)
    (related : contract.externalBoundariesRelated original candidate) :
    original.imported = normalizeImport candidate.event.imported := by
  rcases related with ⟨_, _, _, _, _, _, imported, _⟩
  exact imported

theorem MixedRelationContract.external_boundary_arguments_related
    (contract : MixedRelationContract)
    (original : WorldExternalSuspension) (candidate : NativeExternalBoundary)
    (related : contract.externalBoundariesRelated original candidate) :
    mixedValuesRelated (contract.valuesRelated original.world candidate.world)
      original.arguments candidate.event.arguments := by
  rcases related with ⟨_, _, _, _, _, _, _, _, _, arguments⟩
  exact arguments

theorem MixedRelationContract.proofBlocked_left_is_unrelated
    (contract : MixedRelationContract) (reason : ExecutionBlock)
    (candidate : Option WorldRelationalObservable) :
    ¬ contract.eventObservationsRelated (some (.proofBlocked reason)) candidate := by
  cases candidate <;> simp [MixedRelationContract.eventObservationsRelated]

theorem MixedRelationContract.proofBlocked_right_is_unrelated
    (contract : MixedRelationContract) (reason : ExecutionBlock)
    (original : Option WorldRelationalObservable) :
    ¬ contract.eventObservationsRelated original (some (.proofBlocked reason)) := by
  cases original <;> simp [MixedRelationContract.eventObservationsRelated]

#print axioms OriginalCodeMapCertificate.entry_valid
#print axioms OriginalCodeMapCertificate.target_round_trips
#print axioms OriginalCodeMapCertificate.target_id_eq
#print axioms ExactOriginalDecodedAuthority.source_exists
#print axioms MixedRelationContract.external_boundaries_same_event_index
#print axioms MixedRelationContract.external_boundaries_same_import
#print axioms MixedRelationContract.external_boundary_arguments_related
#print axioms MixedRelationContract.proofBlocked_left_is_unrelated
#print axioms MixedRelationContract.proofBlocked_right_is_unrelated

end StageA.Relational.InterpreterMixedContext
