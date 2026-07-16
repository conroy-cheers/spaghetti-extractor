import StageA.RelationalDecode
import Lean.Elab.Tactic.Omega

namespace StageA.Relational

open StageA.Formal

def indexedBoolRangesValid (predicate : Nat -> Bool) (size : Nat) :
    Nat -> List Span -> Bool
  | cursor, [] => cursor == size
  | cursor, span :: spans =>
      span.size > 0 && span.start == cursor && span.stop <= size &&
        (List.range span.size).all (fun offset => predicate (span.start + offset)) &&
        indexedBoolRangesValid predicate size span.stop spans

structure IndexedBoolCertificate where
  ranges : List Span
deriving Repr, DecidableEq

def IndexedBoolCertificate.checked (predicate : Nat -> Bool) (size : Nat)
    (certificate : IndexedBoolCertificate) : Bool :=
  indexedBoolRangesValid predicate size 0 certificate.ranges

def IndexedBoolCertificate.Holds (_certificate : IndexedBoolCertificate)
    (predicate : Nat -> Bool) (size : Nat) : Prop :=
  ∀ index, index < size -> predicate index = true

def indexedRangesCover (size : Nat) : Nat -> List Span -> Bool
  | cursor, [] => cursor == size
  | cursor, span :: spans =>
      span.size > 0 && span.start == cursor && span.stop <= size &&
        indexedRangesCover size span.stop spans

def IndexedBoolRangeHolds (predicate : Nat -> Bool) (span : Span) : Prop :=
  ∀ offset, offset < span.size -> predicate (span.start + offset) = true

def indexedNatFold (value : Nat -> Nat) : Nat -> Nat -> Nat -> Nat
  | _, 0, total => total
  | start, size + 1, total =>
      indexedNatFold value (start + 1) size (total + value start)

def IndexedNatRangeFoldHolds (value : Nat -> Nat) (span : Span)
    (before after : Nat) : Prop :=
  indexedNatFold value span.start span.size before = after

def AllIndexedBoolRangesHold (predicate : Nat -> Bool) : List Span -> Prop
  | [] => True
  | span :: spans =>
      IndexedBoolRangeHolds predicate span ∧ AllIndexedBoolRangesHold predicate spans

def indexedBoolRangeChecked (predicate : Nat -> Bool) (span : Span) : Bool :=
  (List.range span.size).all fun offset => predicate (span.start + offset)

theorem indexedBoolRangeHolds_of_checked (predicate : Nat -> Bool) (span : Span)
    (checked : indexedBoolRangeChecked predicate span = true) :
    IndexedBoolRangeHolds predicate span := by
  intro offset before
  simp only [indexedBoolRangeChecked, List.all_eq_true] at checked
  exact checked offset (by simpa using before)

theorem allIndexedBoolRangesHold_sound (predicate : Nat -> Bool) (size : Nat) :
    ∀ cursor ranges,
      indexedRangesCover size cursor ranges = true ->
      AllIndexedBoolRangesHold predicate ranges ->
      ∀ index, cursor <= index -> index < size -> predicate index = true := by
  intro cursor ranges
  induction ranges generalizing cursor with
  | nil =>
      intro coverage _ index after before
      simp [indexedRangesCover] at coverage
      omega
  | cons span spans ih =>
      intro coverage rangesHold index after before
      simp only [indexedRangesCover, Bool.and_eq_true, beq_iff_eq] at coverage
      rcases coverage with ⟨⟨⟨nonempty, starts⟩, bounded⟩, tail⟩
      rcases rangesHold with ⟨head, rest⟩
      by_cases inside : index < span.stop
      · have offsetBound : index - span.start < span.size := by
          simp [Span.stop] at inside
          omega
        have value := head (index - span.start) offsetBound
        rw [← starts] at after
        have address : span.start + (index - span.start) = index :=
          Nat.add_sub_of_le after
        simpa [address] using value
      · apply ih span.stop tail rest index
        · exact Nat.le_of_not_gt inside
        · exact before

theorem IndexedBoolCertificate.holds_of_ranges
    (predicate : Nat -> Bool) (size : Nat) (certificate : IndexedBoolCertificate)
    (coverage : indexedRangesCover size 0 certificate.ranges = true)
    (rangesHold : AllIndexedBoolRangesHold predicate certificate.ranges) :
    certificate.Holds predicate size := by
  intro index before
  exact allIndexedBoolRangesHold_sound predicate size 0 certificate.ranges
    coverage rangesHold index (Nat.zero_le index) before

theorem indexedBoolRangesValid_sound (predicate : Nat -> Bool) (size : Nat) :
    ∀ cursor ranges,
      indexedBoolRangesValid predicate size cursor ranges = true ->
      ∀ index, cursor <= index -> index < size -> predicate index = true := by
  intro cursor ranges
  induction ranges generalizing cursor with
  | nil =>
      intro checked index after before
      simp [indexedBoolRangesValid] at checked
      omega
  | cons span spans ih =>
      intro checked index after before
      simp only [indexedBoolRangesValid, Bool.and_eq_true, beq_iff_eq] at checked
      rcases checked with ⟨⟨⟨⟨nonempty, starts⟩, bounded⟩, values⟩, tail⟩
      by_cases inside : index < span.stop
      · have offsetBound : index - span.start < span.size := by
          simp [Span.stop] at inside
          omega
        have member : index - span.start ∈ List.range span.size := by
          simpa using offsetBound
        simp only [List.all_eq_true] at values
        have value := values (index - span.start) member
        rw [← starts] at after
        have address : span.start + (index - span.start) = index :=
          Nat.add_sub_of_le after
        simpa [address] using value
      · apply ih span.stop tail index
        · exact Nat.le_of_not_gt inside
        · exact before

theorem IndexedBoolCertificate.holds_of_checked
    (predicate : Nat -> Bool) (size : Nat) (certificate : IndexedBoolCertificate)
    (checked : certificate.checked predicate size = true) :
    certificate.Holds predicate size := by
  intro index before
  exact indexedBoolRangesValid_sound predicate size 0 certificate.ranges checked
    index (Nat.zero_le index) before

inductive StaticCodeAddressKind where
  | canonical
  | alias (index : Nat)
deriving Repr, DecidableEq

structure StaticCodeAddress where
  targetId : Nat
  kind : StaticCodeAddressKind
deriving Repr, DecidableEq

structure StaticCodeMap where
  entries : Array CodeTargetPair
  originalAddresses : Array StaticCodeAddress
  candidateAddresses : Array StaticCodeAddress
deriving Repr, DecidableEq

def StaticCodeMap.get? (mapping : StaticCodeMap) (targetId : Nat) : Option CodeTargetPair :=
  mapping.entries[targetId]?

def StaticCodeMap.resolveIds (mapping : StaticCodeMap) :
    List Nat -> Option (List CodeTargetPair)
  | [] => some []
  | targetId :: targetIds => do
      let target <- mapping.get? targetId
      let targets <- mapping.resolveIds targetIds
      pure (target :: targets)

def staticCodeEntriesIndexedAux : Nat -> List CodeTargetPair -> Bool
  | _, [] => true
  | index, target :: targets =>
      target.id == index && staticCodeEntriesIndexedAux (index + 1) targets

def StaticCodeMap.entriesIndexed (mapping : StaticCodeMap) : Bool :=
  staticCodeEntriesIndexedAux 0 mapping.entries.toList

def staticCodeAddressRva (candidate : Bool) (mapping : StaticCodeMap)
    (address : StaticCodeAddress) : Option Nat := do
  let target <- mapping.get? address.targetId
  match address.kind with
  | .canonical => pure (if candidate then target.candidateRva else target.originalRva)
  | .alias index =>
      let aliases := if candidate then target.candidateAliases else target.originalAliases
      pure (← aliases[index]?).rva

def staticCodeAddressesValidAux (candidate : Bool) (mapping : StaticCodeMap) :
    Option Nat -> List StaticCodeAddress -> Bool
  | _, [] => true
  | previous, address :: addresses =>
      match staticCodeAddressRva candidate mapping address with
      | none => false
      | some rva =>
          previous.all (· < rva) &&
            staticCodeAddressesValidAux candidate mapping (some rva) addresses

def StaticCodeMap.addressContribution (candidate : Bool)
    (mapping : StaticCodeMap) (index : Nat) : Nat :=
  match mapping.get? index with
  | none => 0
  | some target =>
      1 + (if candidate then target.candidateAliases else target.originalAliases).length

def StaticCodeMap.expectedAddressCount (candidate : Bool)
    (mapping : StaticCodeMap) : Nat :=
  indexedNatFold (mapping.addressContribution candidate) 0 mapping.entries.size 0

def StaticCodeMap.addressesValid (candidate : Bool) (mapping : StaticCodeMap) : Bool :=
  let addresses := if candidate then mapping.candidateAddresses else mapping.originalAddresses
  addresses.size == mapping.expectedAddressCount candidate &&
    staticCodeAddressesValidAux candidate mapping none addresses.toList

def rvaInExecutableSection (pe : PE32) (rva : Nat) : Bool :=
  pe.sections.any fun sec =>
    sec.executable && sec.virtualAddress <= rva &&
      rva < sec.virtualAddress + sec.mappedSize

def StaticCodeMap.addressesInExecutableImage (candidate : Bool) (pe : PE32)
    (mapping : StaticCodeMap) : Bool :=
  let addresses := if candidate then mapping.candidateAddresses else mapping.originalAddresses
  addresses.toList.all fun address =>
    match staticCodeAddressRva candidate mapping address with
    | some rva => rvaInExecutableSection pe rva
    | none => false

def StaticCodeMap.valid (originalPe candidatePe : PE32) (mapping : StaticCodeMap) : Bool :=
  mapping.entriesIndexed &&
    mapping.addressesValid false && mapping.addressesValid true &&
    mapping.addressesInExecutableImage false originalPe &&
    mapping.addressesInExecutableImage true candidatePe

def StaticCodeMap.entryAtValid (mapping : StaticCodeMap) (index : Nat) : Bool :=
  match mapping.get? index with
  | some target => target.id == index
  | none => false

def StaticCodeMap.addressAtValid (candidate : Bool) (pe : PE32)
    (mapping : StaticCodeMap) (index : Nat) : Bool :=
  let addresses := if candidate then mapping.candidateAddresses else mapping.originalAddresses
  match addresses[index]? with
  | none => false
  | some address =>
      match staticCodeAddressRva candidate mapping address with
      | none => false
      | some rva =>
          rvaInExecutableSection pe rva &&
            match index with
            | 0 => true
            | prior + 1 =>
                match addresses[prior]? with
                | none => false
                | some priorAddress =>
                    match staticCodeAddressRva candidate mapping priorAddress with
                    | some priorRva => priorRva < rva
                    | none => false

def StaticCodeMap.IndexedValid (originalPe candidatePe : PE32)
    (mapping : StaticCodeMap) : Prop :=
  (∀ index, index < mapping.entries.size -> mapping.entryAtValid index = true) ∧
    mapping.originalAddresses.size = mapping.expectedAddressCount false ∧
    mapping.candidateAddresses.size = mapping.expectedAddressCount true ∧
    (∀ index, index < mapping.originalAddresses.size ->
      mapping.addressAtValid false originalPe index = true) ∧
    (∀ index, index < mapping.candidateAddresses.size ->
      mapping.addressAtValid true candidatePe index = true)

structure StaticDataMap where
  entries : Array ValueTargetPair
  originalOrder : List Nat
  candidateOrder : List Nat
deriving Repr, DecidableEq

def StaticDataMap.get? (mapping : StaticDataMap) (targetId : Nat) : Option ValueTargetPair :=
  mapping.entries[targetId]?

def StaticDataMap.resolveIds (mapping : StaticDataMap) :
    List Nat -> Option (List ValueTargetPair)
  | [] => some []
  | targetId :: targetIds => do
      let target <- mapping.get? targetId
      let targets <- mapping.resolveIds targetIds
      pure (target :: targets)

def staticDataEntriesIndexedAux : Nat -> List ValueTargetPair -> Bool
  | _, [] => true
  | index, target :: targets =>
      target.id == index && staticDataEntriesIndexedAux (index + 1) targets

def StaticDataMap.entriesIndexed (mapping : StaticDataMap) : Bool :=
  staticDataEntriesIndexedAux 0 mapping.entries.toList

def staticDataRange (candidate : Bool) (mapping : StaticDataMap)
    (targetId : Nat) : Option (Nat × Nat) := do
  let target <- mapping.get? targetId
  let start := if candidate then target.candidateValue else target.originalValue
  pure (start, start + target.mappedSize)

def staticDataOrderValidAux (candidate : Bool) (mapping : StaticDataMap) :
    Option Nat -> List Nat -> Bool
  | _, [] => true
  | previous, targetId :: targetIds =>
      match staticDataRange candidate mapping targetId with
      | none => false
      | some range =>
          previous.all (· <= range.1) &&
            staticDataOrderValidAux candidate mapping (some range.1) targetIds

def staticDataOrderIdsUnique (order : List Nat) : Bool :=
  order.all fun targetId =>
    (order.filter (· == targetId)).length == 1

def StaticDataMap.orderValid (candidate : Bool) (mapping : StaticDataMap) : Bool :=
  let order := if candidate then mapping.candidateOrder else mapping.originalOrder
  order.length == mapping.entries.size &&
    staticDataOrderIdsUnique order &&
    staticDataOrderValidAux candidate mapping none order

def staticDataEffectiveSize (target : ValueTargetPair) : Nat :=
  max 1 target.mappedSize

def staticDataTargetsCompatible (left right : ValueTargetPair) : Bool :=
  left.id == right.id ||
    left.originalValue + right.candidateValue ==
      right.originalValue + left.candidateValue ||
    ((left.originalValue + staticDataEffectiveSize left <= right.originalValue ||
        right.originalValue + staticDataEffectiveSize right <= left.originalValue) &&
      (left.candidateValue + staticDataEffectiveSize left <= right.candidateValue ||
        right.candidateValue + staticDataEffectiveSize right <= left.candidateValue))

def StaticDataMap.mappingsCompatible (mapping : StaticDataMap) : Bool :=
  mapping.entries.toList.all fun left =>
    mapping.entries.toList.all (staticDataTargetsCompatible left)

def mappedValueRangeInImage (candidate : Bool) (pe : PE32)
    (target : ValueTargetPair) : Bool :=
  if target.mappedSize == 0 then true else
    let value := if candidate then target.candidateValue else target.originalValue
    pe.imageBase <= value && pe.sections.any fun sec =>
      sec.virtualAddress <= value - pe.imageBase &&
        value - pe.imageBase + target.mappedSize <=
          sec.virtualAddress + sec.mappedSize

def StaticDataMap.rangesInImages (originalPe candidatePe : PE32)
    (mapping : StaticDataMap) : Bool :=
  mapping.entries.toList.all fun target =>
    mappedValueRangeInImage false originalPe target &&
      mappedValueRangeInImage true candidatePe target

def StaticDataMap.valid (originalPe candidatePe : PE32) (mapping : StaticDataMap) : Bool :=
  mapping.entriesIndexed && mapping.orderValid false && mapping.orderValid true &&
    mapping.mappingsCompatible && mapping.rangesInImages originalPe candidatePe

inductive CutpointKind where
  | entrypoint
  | exported
  | callback
  | tlsInitializer
deriving Repr, DecidableEq

structure CutpointPair where
  targetId : Nat
  kind : CutpointKind
deriving Repr, DecidableEq

structure ObservationModel where
  imports : Bool := true
  returns : Bool := true
  faults : Bool := true
  callbacks : Bool := false
  tls : Bool := false
  threads : Bool := false
  directSyscalls : Bool := false
  seh : Bool := false
  executableMemoryWrites : Bool := false
deriving Repr, DecidableEq

inductive DynamicWordRelationKind where
  | relatedWord
  | codePointer
  | dataPointer
  | nullableDynamicPointer
deriving Repr, DecidableEq

structure DynamicWordRelation where
  offset : Nat
  kind : DynamicWordRelationKind
deriving Repr, DecidableEq

structure StaticDynamicPointerSlotPair where
  id : Nat
  originalAddress : Word
  candidateAddress : Word
  requiredWords : List DynamicWordRelation
deriving Repr, DecidableEq

inductive StaticWordRelationKind where
  | exact
  | relatedWord
  | codePointer
  | fixedCodePointer (targetId : Nat)
  | dataPointer
deriving Repr, DecidableEq

structure StaticWordRelationSlotPair where
  id : Nat
  originalAddress : Word
  candidateAddress : Word
  relation : StaticWordRelationKind
deriving Repr, DecidableEq

structure DynamicAddressRangePair where
  id : Nat
  originalBase : Word
  candidateBase : Word
  size : Nat
  wordRelations : List DynamicWordRelation := []
deriving Repr, DecidableEq

structure OpaqueResourcePair where
  id : Nat
  original : Word
  candidate : Word
deriving Repr, DecidableEq

inductive RelationalTlsValueTarget where
  | exact (value : Word)
  | dynamicRange (rangeId offset : Nat)
  | opaqueResource (resourceId : Nat)
  | staticData (targetId offset : Nat)
deriving Repr, DecidableEq

structure RelationalTlsSlot where
  index : Nat
  target : RelationalTlsValueTarget
deriving Repr, DecidableEq

structure RelationalTlsState where
  slots : List RelationalTlsSlot := []
  lastError : Word := BitVec.ofNat 32 0
deriving Repr, DecidableEq

structure ImportAddressPair where
  id : Nat
  imported : ExternalTarget
  originalIatRva : Nat
  candidateIatRva : Nat
  originalAddress : Word
  candidateAddress : Word
deriving Repr, DecidableEq

structure RegisteredCallbackPair where
  targetId : Nat
  originalAddress : Word
  candidateAddress : Word
deriving Repr, DecidableEq

structure RelationalWorld where
  dynamicRanges : List DynamicAddressRangePair := []
  stackRanges : List DynamicAddressRangePair := []
  opaqueResources : List OpaqueResourcePair := []
  importAddresses : List ImportAddressPair := []
  registeredCallbacks : List RegisteredCallbackPair := []
  tlsState : RelationalTlsState := {}
deriving Repr, DecidableEq

def RelationalWorld.empty : RelationalWorld := {}

def RelationalWorld.staticOnly (world : RelationalWorld) : Bool :=
  world.dynamicRanges.isEmpty && world.opaqueResources.isEmpty &&
    world.registeredCallbacks.isEmpty && world.tlsState.slots.isEmpty &&
    world.tlsState.lastError == BitVec.ofNat 32 0

def dynamicAddressRangeIdsUnique (ranges : List DynamicAddressRangePair) : Bool :=
  ranges.all fun range =>
    (ranges.filter (fun other => other.id == range.id)).length == 1

theorem dynamicAddressRange_eq_of_same_id
    (ranges : List DynamicAddressRangePair)
    (unique : dynamicAddressRangeIdsUnique ranges = true)
    (left right : DynamicAddressRangePair)
    (leftMember : left ∈ ranges) (rightMember : right ∈ ranges)
    (sameId : left.id = right.id) :
    left = right := by
  simp only [dynamicAddressRangeIdsUnique, List.all_eq_true] at unique
  have singletonLength := unique left leftMember
  simp only [beq_iff_eq] at singletonLength
  have leftFiltered :
      left ∈ ranges.filter (fun other => other.id == left.id) := by
    exact List.mem_filter.mpr ⟨leftMember, by simp⟩
  have rightFiltered :
      right ∈ ranges.filter (fun other => other.id == left.id) := by
    exact List.mem_filter.mpr ⟨rightMember, by simp [sameId]⟩
  rcases List.length_eq_one_iff.mp singletonLength with ⟨only, filtered⟩
  rw [filtered] at leftFiltered rightFiltered
  simp only [List.mem_singleton] at leftFiltered rightFiltered
  exact leftFiltered.trans rightFiltered.symm

def opaqueResourceIdsUnique (resources : List OpaqueResourcePair) : Bool :=
  resources.all fun resource =>
    (resources.filter (fun other => other.id == resource.id)).length == 1

def opaqueResourceValuesUniqueOn (candidate : Bool)
    (resources : List OpaqueResourcePair) : Bool :=
  resources.all fun resource =>
    let value := if candidate then resource.candidate else resource.original
    (resources.filter (fun other =>
      (if candidate then other.candidate else other.original) == value)).length == 1

def RelationalWorld.opaqueResourcesValid (world : RelationalWorld) : Bool :=
  opaqueResourceIdsUnique world.opaqueResources &&
    opaqueResourceValuesUniqueOn false world.opaqueResources &&
    opaqueResourceValuesUniqueOn true world.opaqueResources &&
    world.opaqueResources.all fun resource =>
      resource.original != BitVec.ofNat 32 0 &&
        resource.candidate != BitVec.ofNat 32 0

def DynamicAddressRangePair.wordRelationsValid
    (range : DynamicAddressRangePair) : Bool :=
  range.wordRelations.all fun relation =>
      relation.offset + 4 <= range.size &&
        range.wordRelations.all fun other =>
          other == relation ||
            relation.offset + 4 <= other.offset || other.offset + 4 <= relation.offset

def dynamicAddressRangesDisjointOn
    (candidate : Bool) (ranges : List DynamicAddressRangePair) : Bool :=
  ranges.all fun range =>
    ranges.all fun other =>
      range.id == other.id ||
        let base := if candidate then range.candidateBase else range.originalBase
        let otherBase := if candidate then other.candidateBase else other.originalBase
        base.toNat + range.size <= otherBase.toNat ||
          otherBase.toNat + other.size <= base.toNat

def dynamicAddressRangesCrossDisjointOn
    (candidate : Bool) (left right : List DynamicAddressRangePair) : Bool :=
  left.all fun range =>
    right.all fun other =>
      let base := if candidate then range.candidateBase else range.originalBase
      let otherBase := if candidate then other.candidateBase else other.originalBase
      base.toNat + range.size <= otherBase.toNat ||
        otherBase.toNat + other.size <= base.toNat

structure StaticProofContext where
  originalPe : PE32
  candidatePe : PE32
  originalImportCertificate : ImportTableCertificate
  candidateImportCertificate : ImportTableCertificate
  originalRelocations : List BaseRelocation
  candidateRelocations : List BaseRelocation
  codeMap : StaticCodeMap
  dataMap : StaticDataMap
  roots : List CutpointPair
  observations : ObservationModel
  staticDynamicPointerSlots : List StaticDynamicPointerSlotPair := []
  staticWordRelationSlots : List StaticWordRelationSlotPair := []
  machineImportCallContracts : List MachineImportCallContract := []
deriving Repr, DecidableEq

def machineImportCallContractIdsUnique
    (contracts : List MachineImportCallContract) : Bool :=
  contracts.all fun contract =>
    (contracts.filter (fun other => other.id == contract.id)).length == 1

def machineImportCallTargetsUnique
    (contracts : List MachineImportCallContract) : Bool :=
  contracts.all fun contract =>
    (contracts.filter (fun other => other.imported == contract.imported)).length == 1

def machineImportCallContractsValid (imports : List PEImport)
    (contracts : List MachineImportCallContract) : Bool :=
  machineImportCallContractIdsUnique contracts &&
    machineImportCallTargetsUnique contracts &&
    contracts.all fun contract =>
      contract.shapeValid && imports.any fun imported =>
        contract.matchesImport imported

def dynamicWordRelationsShapeValid (relations : List DynamicWordRelation) : Bool :=
  !relations.isEmpty && relations.all fun relation =>
    (relations.filter (fun other => other.offset == relation.offset)).length == 1 &&
      relations.all fun other =>
        other.offset == relation.offset ||
          relation.offset + 4 <= other.offset || other.offset + 4 <= relation.offset

def writableStaticWordInPe (pe : PE32) (address : Word) : Bool :=
  let absolute := address.toNat
  pe.imageBase <= absolute && absolute + 4 <= 2^32 &&
    absolute + 4 <= pe.imageBase + pe.sizeOfImage &&
    pe.sections.any fun sec =>
      sec.writable && !sec.executable &&
        pe.imageBase + sec.virtualAddress <= absolute &&
        absolute + 4 <= pe.imageBase + sec.virtualAddress + sec.mappedSize

def staticWordOverlapsImportIat (pe : PE32) (imports : List PEImport)
    (address : Word) : Bool :=
  let start := address.toNat
  imports.any fun imported =>
    let iatStart := pe.imageBase + imported.iatRva
    start < iatStart + 4 && iatStart < start + 4

def staticWordOverlapsImmutableSection (pe : PE32) (address : Word) : Bool :=
  let start := address.toNat
  (start < pe.imageBase + pe.sizeOfHeaders && pe.imageBase < start + 4) ||
    pe.sections.any fun sec =>
      !sec.writable && start < pe.imageBase + sec.virtualAddress + sec.mappedSize &&
        pe.imageBase + sec.virtualAddress < start + 4

def StaticDynamicPointerSlotPair.valid (context : StaticProofContext)
    (slot : StaticDynamicPointerSlotPair) : Bool :=
  slot.originalAddress != BitVec.ofNat 32 0 &&
    slot.candidateAddress != BitVec.ofNat 32 0 &&
    writableStaticWordInPe context.originalPe slot.originalAddress &&
    writableStaticWordInPe context.candidatePe slot.candidateAddress &&
    !staticWordOverlapsImportIat context.originalPe
      context.originalImportCertificate.imports
      slot.originalAddress &&
    !staticWordOverlapsImportIat context.candidatePe
      context.candidateImportCertificate.imports
      slot.candidateAddress &&
    !staticWordOverlapsImmutableSection context.originalPe slot.originalAddress &&
    !staticWordOverlapsImmutableSection context.candidatePe slot.candidateAddress &&
    dynamicWordRelationsShapeValid slot.requiredWords

def staticDynamicPointerSlotIdsUnique
    (slots : List StaticDynamicPointerSlotPair) : Bool :=
  slots.all fun slot =>
    (slots.filter (fun other => other.id == slot.id)).length == 1

theorem staticDynamicPointerSlot_eq_of_same_id
    (slots : List StaticDynamicPointerSlotPair)
    (unique : staticDynamicPointerSlotIdsUnique slots = true)
    (left right : StaticDynamicPointerSlotPair)
    (leftMember : left ∈ slots) (rightMember : right ∈ slots)
    (sameId : left.id = right.id) :
    left = right := by
  simp only [staticDynamicPointerSlotIdsUnique, List.all_eq_true] at unique
  have singletonLength := unique left leftMember
  simp only [beq_iff_eq] at singletonLength
  have leftFiltered :
      left ∈ slots.filter (fun other => other.id == left.id) := by
    exact List.mem_filter.mpr ⟨leftMember, by simp⟩
  have rightFiltered :
      right ∈ slots.filter (fun other => other.id == left.id) := by
    exact List.mem_filter.mpr ⟨rightMember, by simp [sameId]⟩
  rcases List.length_eq_one_iff.mp singletonLength with ⟨only, filtered⟩
  rw [filtered] at leftFiltered rightFiltered
  simp only [List.mem_singleton] at leftFiltered rightFiltered
  exact leftFiltered.trans rightFiltered.symm

def staticDynamicPointerSlotsDisjointOn (candidate : Bool)
    (slots : List StaticDynamicPointerSlotPair) : Bool :=
  slots.all fun slot =>
    slots.all fun other =>
      slot.id == other.id ||
        let address := if candidate then slot.candidateAddress else slot.originalAddress
        let otherAddress :=
          if candidate then other.candidateAddress else other.originalAddress
        address.toNat + 4 <= otherAddress.toNat ||
          otherAddress.toNat + 4 <= address.toNat

def staticDynamicPointerSlotsValid (context : StaticProofContext) : Bool :=
  staticDynamicPointerSlotIdsUnique context.staticDynamicPointerSlots &&
    staticDynamicPointerSlotsDisjointOn false context.staticDynamicPointerSlots &&
    staticDynamicPointerSlotsDisjointOn true context.staticDynamicPointerSlots &&
    context.staticDynamicPointerSlots.all
      (StaticDynamicPointerSlotPair.valid context)

def StaticWordRelationSlotPair.valid (context : StaticProofContext)
    (slot : StaticWordRelationSlotPair) : Bool :=
  slot.originalAddress != BitVec.ofNat 32 0 &&
    slot.candidateAddress != BitVec.ofNat 32 0 &&
    writableStaticWordInPe context.originalPe slot.originalAddress &&
    writableStaticWordInPe context.candidatePe slot.candidateAddress &&
    !staticWordOverlapsImportIat context.originalPe
      context.originalImportCertificate.imports slot.originalAddress &&
    !staticWordOverlapsImportIat context.candidatePe
      context.candidateImportCertificate.imports slot.candidateAddress &&
    !staticWordOverlapsImmutableSection context.originalPe slot.originalAddress &&
    !staticWordOverlapsImmutableSection context.candidatePe slot.candidateAddress &&
    match slot.relation with
    | .fixedCodePointer targetId => (context.codeMap.get? targetId).isSome
    | _ => true

def staticWordRelationSlotIdsUnique
    (slots : List StaticWordRelationSlotPair) : Bool :=
  slots.all fun slot =>
    (slots.filter (fun other => other.id == slot.id)).length == 1

theorem staticWordRelationSlot_eq_of_same_id
    (slots : List StaticWordRelationSlotPair)
    (unique : staticWordRelationSlotIdsUnique slots = true)
    (left right : StaticWordRelationSlotPair)
    (leftMember : left ∈ slots) (rightMember : right ∈ slots)
    (sameId : left.id = right.id) :
    left = right := by
  simp only [staticWordRelationSlotIdsUnique, List.all_eq_true] at unique
  have singletonLength := unique left leftMember
  simp only [beq_iff_eq] at singletonLength
  have leftFiltered :
      left ∈ slots.filter (fun other => other.id == left.id) := by
    exact List.mem_filter.mpr ⟨leftMember, by simp⟩
  have rightFiltered :
      right ∈ slots.filter (fun other => other.id == left.id) := by
    exact List.mem_filter.mpr ⟨rightMember, by simp [sameId]⟩
  rcases List.length_eq_one_iff.mp singletonLength with ⟨only, filtered⟩
  rw [filtered] at leftFiltered rightFiltered
  simp only [List.mem_singleton] at leftFiltered rightFiltered
  exact leftFiltered.trans rightFiltered.symm

def staticWordRelationSlotsDisjointOn (candidate : Bool)
    (slots : List StaticWordRelationSlotPair) : Bool :=
  slots.all fun slot =>
    slots.all fun other =>
      slot.id == other.id ||
        let address := if candidate then slot.candidateAddress else slot.originalAddress
        let otherAddress :=
          if candidate then other.candidateAddress else other.originalAddress
        address.toNat + 4 <= otherAddress.toNat ||
          otherAddress.toNat + 4 <= address.toNat

def staticWordRelationSlotsCrossDisjointOn (candidate : Bool)
    (wordSlots : List StaticWordRelationSlotPair)
    (pointerSlots : List StaticDynamicPointerSlotPair) : Bool :=
  wordSlots.all fun slot =>
    pointerSlots.all fun other =>
      let address := if candidate then slot.candidateAddress else slot.originalAddress
      let otherAddress :=
        if candidate then other.candidateAddress else other.originalAddress
      address.toNat + 4 <= otherAddress.toNat ||
        otherAddress.toNat + 4 <= address.toNat

def staticWordRelationSlotsValid (context : StaticProofContext) : Bool :=
  staticWordRelationSlotIdsUnique context.staticWordRelationSlots &&
    staticWordRelationSlotsDisjointOn false context.staticWordRelationSlots &&
    staticWordRelationSlotsDisjointOn true context.staticWordRelationSlots &&
    staticWordRelationSlotsCrossDisjointOn false context.staticWordRelationSlots
      context.staticDynamicPointerSlots &&
    staticWordRelationSlotsCrossDisjointOn true context.staticWordRelationSlots
      context.staticDynamicPointerSlots &&
    context.staticWordRelationSlots.all (StaticWordRelationSlotPair.valid context)

def DynamicAddressRangePair.disjointFromImages (context : StaticProofContext)
    (range : DynamicAddressRangePair) : Bool :=
  let originalBase := range.originalBase.toNat
  let candidateBase := range.candidateBase.toNat
  let originalImageBase := context.originalPe.imageBase
  let candidateImageBase := context.candidatePe.imageBase
  range.size > 0 &&
    (!(range.originalBase == BitVec.ofNat 32 0)) &&
    (!(range.candidateBase == BitVec.ofNat 32 0)) &&
    originalBase + range.size < 2^32 &&
    candidateBase + range.size < 2^32 &&
    (originalBase + range.size <= originalImageBase ||
      originalImageBase + context.originalPe.sizeOfImage <= originalBase) &&
    (candidateBase + range.size <= candidateImageBase ||
      candidateImageBase + context.candidatePe.sizeOfImage <= candidateBase)

def RelationalWorld.stackRangesValid (context : StaticProofContext)
    (world : RelationalWorld) : Bool :=
  dynamicAddressRangeIdsUnique world.stackRanges &&
    world.stackRanges.all (fun range =>
      range.disjointFromImages context &&
        range.originalBase.toNat % 4 == 0 &&
        range.candidateBase.toNat % 4 == 0 && range.size % 4 == 0) &&
    dynamicAddressRangesDisjointOn false world.stackRanges &&
    dynamicAddressRangesDisjointOn true world.stackRanges

def RelationalWorld.dynamicRangesValid (context : StaticProofContext)
    (world : RelationalWorld) : Bool :=
  dynamicAddressRangeIdsUnique world.dynamicRanges &&
    world.dynamicRanges.all (DynamicAddressRangePair.disjointFromImages context) &&
    world.dynamicRanges.all DynamicAddressRangePair.wordRelationsValid &&
    dynamicAddressRangesDisjointOn false world.dynamicRanges &&
    dynamicAddressRangesDisjointOn true world.dynamicRanges &&
    dynamicAddressRangesCrossDisjointOn false world.dynamicRanges world.stackRanges &&
    dynamicAddressRangesCrossDisjointOn true world.dynamicRanges world.stackRanges

def RelationalTlsValueTarget.resolve (candidate : Bool)
    (context : StaticProofContext) (world : RelationalWorld) :
    RelationalTlsValueTarget -> Option Word
  | .exact value => some value
  | .dynamicRange rangeId offset => do
      let range <- world.dynamicRanges.find? (fun range => range.id == rangeId)
      if offset < range.size then
        some ((if candidate then range.candidateBase else range.originalBase) +
          BitVec.ofNat 32 offset)
      else none
  | .opaqueResource resourceId => do
      let resource <- world.opaqueResources.find? (fun resource => resource.id == resourceId)
      some (if candidate then resource.candidate else resource.original)
  | .staticData targetId offset => do
      let target <- context.dataMap.get? targetId
      if offset < max 1 target.mappedSize then
        some (BitVec.ofNat 32
          ((if candidate then target.candidateValue else target.originalValue) + offset))
      else none

def relationalTlsSlotIndicesUnique (slots : List RelationalTlsSlot) : Bool :=
  slots.all fun slot =>
    (slots.filter (fun other => other.index == slot.index)).length == 1

def RelationalWorld.tlsStateValid (context : StaticProofContext)
    (world : RelationalWorld) : Bool :=
  relationalTlsSlotIndicesUnique world.tlsState.slots &&
    world.tlsState.slots.all fun slot =>
      slot.index < 2^32 &&
        (slot.target.resolve false context world).isSome &&
        (slot.target.resolve true context world).isSome

def RegisteredCallbackPair.valid (context : StaticProofContext)
    (callback : RegisteredCallbackPair) : Bool :=
  match context.codeMap.get? callback.targetId with
  | none => false
  | some target =>
      (callback.originalAddress == BitVec.ofNat 32
          (context.originalPe.imageBase + target.originalRva) ||
        target.originalAliases.any fun alias =>
          callback.originalAddress == BitVec.ofNat 32
            (context.originalPe.imageBase + alias.rva)) &&
      (callback.candidateAddress == BitVec.ofNat 32
          (context.candidatePe.imageBase + target.candidateRva) ||
        target.candidateAliases.any fun alias =>
          callback.candidateAddress == BitVec.ofNat 32
            (context.candidatePe.imageBase + alias.rva))

def RelationalWorld.registeredCallbacksValid (context : StaticProofContext)
    (world : RelationalWorld) : Bool :=
  world.registeredCallbacks.all (RegisteredCallbackPair.valid context)

def RelationalWorld.valid (context : StaticProofContext)
    (world : RelationalWorld) : Bool :=
  world.dynamicRangesValid context && world.stackRangesValid context &&
    world.opaqueResourcesValid && world.registeredCallbacksValid context &&
    world.tlsStateValid context

def DynamicAddressRangePair.valueTarget
    (range : DynamicAddressRangePair) : ValueTargetPair := {
  id := range.id
  originalValue := range.originalBase.toNat
  candidateValue := range.candidateBase.toNat
  originalRelocationRva := 0
  candidateRelocationRva := 0
  mappedSize := range.size
  relocationOffsets := range.wordRelations.map (fun relation => relation.offset)
}

def RelationalWorld.dynamicValueTargets
    (world : RelationalWorld) : List ValueTargetPair :=
  world.dynamicRanges.map DynamicAddressRangePair.valueTarget

def RelationalWorld.stackValueTargets
    (world : RelationalWorld) : List ValueTargetPair :=
  world.stackRanges.map DynamicAddressRangePair.valueTarget

def RelationalWorld.runtimeValueTargets
    (world : RelationalWorld) : List ValueTargetPair :=
  world.dynamicValueTargets ++ world.stackValueTargets

def StaticProofContext.relationalValueTargets
    (context : StaticProofContext) (world : RelationalWorld) : List ValueTargetPair :=
  context.dataMap.entries.toList ++ world.runtimeValueTargets

def StaticProofContext.originalImports (context : StaticProofContext) : List PEImport :=
  context.originalImportCertificate.imports

def StaticProofContext.candidateImports (context : StaticProofContext) : List PEImport :=
  context.candidateImportCertificate.imports

def importAtIatRva (imports : List PEImport) (iatRva : Nat) : Option PEImport :=
  imports.find? (fun imported => imported.iatRva == iatRva)

def ImportAddressPair.staticValid (context : StaticProofContext)
    (binding : ImportAddressPair) : Bool :=
  match importAtIatRva context.originalImports binding.originalIatRva,
      importAtIatRva context.candidateImports binding.candidateIatRva with
  | some originalImport, some candidateImport =>
      normalizeImport originalImport == binding.imported &&
        normalizeImport candidateImport == binding.imported &&
        binding.originalIatRva + 4 <= context.originalPe.sizeOfImage &&
        binding.candidateIatRva + 4 <= context.candidatePe.sizeOfImage &&
        context.originalPe.imageBase + binding.originalIatRva + 4 <= 2^32 &&
        context.candidatePe.imageBase + binding.candidateIatRva + 4 <= 2^32 &&
        binding.originalAddress != BitVec.ofNat 32 0 &&
        binding.candidateAddress != BitVec.ofNat 32 0
  | _, _ => false

theorem ImportAddressPair.originalImportWitness
    (context : StaticProofContext) (binding : ImportAddressPair)
    (valid : binding.staticValid context = true) :
    ∃ imported, imported ∈ context.originalImports ∧
      imported.iatRva = binding.originalIatRva := by
  cases found : importAtIatRva context.originalImports binding.originalIatRva with
  | none => simp [ImportAddressPair.staticValid, found] at valid
  | some imported =>
      refine ⟨imported, ?_, ?_⟩
      · unfold importAtIatRva at found
        exact List.mem_of_find?_eq_some found
      · unfold importAtIatRva at found
        exact beq_iff_eq.mp (List.find?_some
          (p := fun candidate : PEImport =>
            candidate.iatRva == binding.originalIatRva)
          (a := imported) found)

theorem ImportAddressPair.candidateImportWitness
    (context : StaticProofContext) (binding : ImportAddressPair)
    (valid : binding.staticValid context = true) :
    ∃ imported, imported ∈ context.candidateImports ∧
      imported.iatRva = binding.candidateIatRva := by
  cases found : importAtIatRva context.candidateImports binding.candidateIatRva with
  | none => simp [ImportAddressPair.staticValid, found] at valid
  | some imported =>
      refine ⟨imported, ?_, ?_⟩
      · unfold importAtIatRva at found
        exact List.mem_of_find?_eq_some found
      · unfold importAtIatRva at found
        exact beq_iff_eq.mp (List.find?_some
          (p := fun candidate : PEImport =>
            candidate.iatRva == binding.candidateIatRva)
          (a := imported) found)

def importAddressIdsUnique (bindings : List ImportAddressPair) : Bool :=
  bindings.all fun binding =>
    (bindings.filter (fun other => other.id == binding.id)).length == 1

def importAddressIatPairsUnique (bindings : List ImportAddressPair) : Bool :=
  bindings.all fun binding =>
    (bindings.filter (fun other =>
      other.originalIatRva == binding.originalIatRva ||
        other.candidateIatRva == binding.candidateIatRva)).length == 1

def importAddressIdentitiesConsistent (bindings : List ImportAddressPair) : Bool :=
  bindings.all fun binding =>
    bindings.all fun other =>
      if other.imported == binding.imported then
        other.originalAddress == binding.originalAddress &&
          other.candidateAddress == binding.candidateAddress
      else true

def RelationalWorld.importAddressesStaticValid
    (context : StaticProofContext) (world : RelationalWorld) : Bool :=
  importAddressIdsUnique world.importAddresses &&
    importAddressIatPairsUnique world.importAddresses &&
    importAddressIdentitiesConsistent world.importAddresses &&
    world.importAddresses.all (ImportAddressPair.staticValid context)

def RelationalWorld.importAddressesComplete
    (context : StaticProofContext) (world : RelationalWorld) : Bool :=
  (context.originalImports.all fun imported =>
      world.importAddresses.any fun binding =>
        binding.originalIatRva == imported.iatRva &&
          binding.imported == normalizeImport imported) &&
    (context.candidateImports.all fun imported =>
      world.importAddresses.any fun binding =>
        binding.candidateIatRva == imported.iatRva &&
          binding.imported == normalizeImport imported)

def rootTargetValid (context : StaticProofContext) (root : CutpointPair) : Bool :=
  match context.codeMap.get? root.targetId with
  | none => false
  | some target =>
      match root.kind with
      | .entrypoint =>
          target.originalRva == context.originalPe.entrypointRva &&
            target.candidateRva == context.candidatePe.entrypointRva
      | .exported => true
      | .callback => context.observations.callbacks
      | .tlsInitializer => context.observations.tls

def rootsUnique (roots : List CutpointPair) : Bool :=
  roots.all fun root => (roots.filter (·.targetId == root.targetId)).length == 1

def rootsValid (context : StaticProofContext) : Bool :=
  context.roots.length > 0 && rootsUnique context.roots &&
    context.roots.all (rootTargetValid context) &&
    context.roots.any (·.kind == .entrypoint)

def observationProfileValid (observations : ObservationModel) : Bool :=
  observations.imports && observations.returns && observations.faults &&
    !observations.threads && !observations.directSyscalls && !observations.seh &&
    !observations.executableMemoryWrites

def StaticProofContext.structureValid (context : StaticProofContext) : Bool :=
  parsePE32Tree context.originalPe.bytes == some context.originalPe &&
    parsePE32Tree context.candidatePe.bytes == some context.candidatePe &&
    importTableValid context.originalPe context.originalImportCertificate &&
    importTableValid context.candidatePe context.candidateImportCertificate &&
    parseRelocations context.originalPe == some context.originalRelocations &&
    parseRelocations context.candidatePe == some context.candidateRelocations &&
    context.codeMap.valid context.originalPe context.candidatePe &&
    context.dataMap.valid context.originalPe context.candidatePe &&
    staticDynamicPointerSlotsValid context &&
    staticWordRelationSlotsValid context &&
    machineImportCallContractsValid context.originalImportCertificate.imports
      context.machineImportCallContracts &&
    machineImportCallContractsValid context.candidateImportCertificate.imports
      context.machineImportCallContracts &&
    rootsValid context && observationProfileValid context.observations

def StaticProofContext.StructurallyValid (context : StaticProofContext) : Prop :=
  parsePE32Tree context.originalPe.bytes = some context.originalPe ∧
    parsePE32Tree context.candidatePe.bytes = some context.candidatePe ∧
    importTableValid context.originalPe context.originalImportCertificate = true ∧
    importTableValid context.candidatePe context.candidateImportCertificate = true ∧
    parseRelocations context.originalPe = some context.originalRelocations ∧
    parseRelocations context.candidatePe = some context.candidateRelocations ∧
    context.codeMap.IndexedValid context.originalPe context.candidatePe ∧
    context.dataMap.valid context.originalPe context.candidatePe = true ∧
    staticDynamicPointerSlotsValid context = true ∧
    staticWordRelationSlotsValid context = true ∧
    machineImportCallContractsValid context.originalImportCertificate.imports
      context.machineImportCallContracts = true ∧
    machineImportCallContractsValid context.candidateImportCertificate.imports
      context.machineImportCallContracts = true ∧
    rootsValid context = true ∧ observationProfileValid context.observations = true

theorem StaticProofContext.structurallyValid_of_components
    (context : StaticProofContext)
    (originalParsed : parsePE32Tree context.originalPe.bytes = some context.originalPe)
    (candidateParsed : parsePE32Tree context.candidatePe.bytes = some context.candidatePe)
    (originalImportsChecked :
      importTableValid context.originalPe context.originalImportCertificate = true)
    (candidateImportsChecked :
      importTableValid context.candidatePe context.candidateImportCertificate = true)
    (originalRelocationsParsed :
      parseRelocations context.originalPe = some context.originalRelocations)
    (candidateRelocationsParsed :
      parseRelocations context.candidatePe = some context.candidateRelocations)
    (codeMapChecked :
      context.codeMap.IndexedValid context.originalPe context.candidatePe)
    (dataMapChecked : context.dataMap.valid context.originalPe context.candidatePe = true)
    (staticDynamicPointerSlotsChecked :
      staticDynamicPointerSlotsValid context = true)
    (staticWordRelationSlotsChecked :
      staticWordRelationSlotsValid context = true)
    (originalMachineCallContractsChecked :
      machineImportCallContractsValid context.originalImportCertificate.imports
        context.machineImportCallContracts = true)
    (candidateMachineCallContractsChecked :
      machineImportCallContractsValid context.candidateImportCertificate.imports
        context.machineImportCallContracts = true)
    (rootsChecked : rootsValid context = true)
    (observationsChecked : observationProfileValid context.observations = true) :
    context.StructurallyValid :=
  ⟨originalParsed, candidateParsed, originalImportsChecked, candidateImportsChecked,
    originalRelocationsParsed, candidateRelocationsParsed, codeMapChecked, dataMapChecked,
    staticDynamicPointerSlotsChecked, staticWordRelationSlotsChecked,
    originalMachineCallContractsChecked,
    candidateMachineCallContractsChecked, rootsChecked, observationsChecked⟩

end StageA.Relational
