import StageA.RelationalInterpreterMixedOriginal

namespace StageA.Relational.InterpreterOriginalCarrierBinding

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedOriginal
open StageA.Relational.InterpreterMixedWorldBridge

/-! # Exact original carrier binding

The mixed original/native theorem still executes the original through the
historical `DecodedWorldProgram` carrier.  This module checks that carrier as a
projection of one exact, one-sided original context.  In particular, neither
lookup-algorithm equality is submitted as generated evidence: both are derived
below from the checked canonical target and reverse-address inventories.
-/

def mapFiniteIndex (transform : alpha -> beta) : FiniteIndex alpha -> FiniteIndex beta
  | .empty => .empty
  | .leaf values => .leaf (values.map transform)
  | .branch totalSize leftSize left right =>
      .branch totalSize leftSize (mapFiniteIndex transform left)
        (mapFiniteIndex transform right)

@[simp] theorem mapFiniteIndex_size (transform : alpha -> beta)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).size = index.size := by
  induction index <;> simp_all [mapFiniteIndex, FiniteIndex.size]

@[simp] theorem mapFiniteIndex_toList (transform : alpha -> beta)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).toList = index.toList.map transform := by
  induction index <;> simp_all [mapFiniteIndex, FiniteIndex.toList]

@[simp] theorem mapFiniteIndex_get? (transform : alpha -> beta)
    (index : FiniteIndex alpha) (position : Nat) :
    (mapFiniteIndex transform index).get? position =
      (index.get? position).map transform := by
  induction index generalizing position with
  | empty => simp [mapFiniteIndex, FiniteIndex.get?]
  | leaf values => simp [mapFiniteIndex, FiniteIndex.get?, List.getElem?_map]
  | branch totalSize leftSize left right leftIH rightIH =>
      simp only [mapFiniteIndex, FiniteIndex.get?]
      by_cases outside : totalSize <= position
      · simp [outside]
      · by_cases inLeft : position < leftSize
        · simp [outside, inLeft, leftIH]
        · simp [outside, inLeft, rightIH]

@[simp] theorem mapFiniteIndex_height (transform : alpha -> beta)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).height = index.height := by
  induction index <;>
    simp_all [mapFiniteIndex, FiniteIndex.height]

@[simp] theorem mapFiniteIndex_sizesSound (transform : alpha -> beta)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).sizesSound = index.sizesSound := by
  induction index <;>
    simp_all [mapFiniteIndex, FiniteIndex.sizesSound]

@[simp] theorem mapFiniteIndex_leavesBounded
    (transform : alpha -> beta) (leafCapacity : Nat)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).leavesBounded leafCapacity =
      index.leavesBounded leafCapacity := by
  induction index <;>
    simp_all [mapFiniteIndex, FiniteIndex.leavesBounded]

@[simp] theorem mapFiniteIndex_branchesNonempty
    (transform : alpha -> beta) (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).branchesNonempty =
      index.branchesNonempty := by
  induction index <;>
    simp_all [mapFiniteIndex, FiniteIndex.branchesNonempty]

@[simp] theorem mapFiniteIndex_balanced (transform : alpha -> beta)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).balanced = index.balanced := by
  induction index <;>
    simp_all [mapFiniteIndex, FiniteIndex.balanced]

@[simp] theorem mapFiniteIndex_structurallyValid
    (transform : alpha -> beta) (leafCapacity : Nat)
    (index : FiniteIndex alpha) :
    (mapFiniteIndex transform index).structurallyValid leafCapacity =
      index.structurallyValid leafCapacity := by
  simp [FiniteIndex.structurallyValid]

def originalTargetToStatic (target : OriginalCodeTarget) : CodeTargetPair := {
  id := target.id
  regionIndex := target.regionIndex
  originalRva := target.rva
  candidateRva := target.rva
  originalAliases := target.aliases
  candidateAliases := target.aliases
}

def originalAddressToStatic (address : OriginalCodeAddress) : StaticCodeAddress := {
  targetId := address.targetId
  kind := address.kind
}

def originalCodeMapToStatic (mapping : OriginalCodeMap) : StaticCodeMap := {
  entries := mapFiniteIndex originalTargetToStatic mapping.entries
  originalAddresses := mapFiniteIndex originalAddressToStatic mapping.addresses
  candidateAddresses := mapFiniteIndex originalAddressToStatic mapping.addresses
}

@[simp] theorem originalCodeMapToStatic_entries
    (mapping : OriginalCodeMap) :
    (originalCodeMapToStatic mapping).entries =
      mapFiniteIndex originalTargetToStatic mapping.entries := rfl

@[simp] theorem originalCodeMapToStatic_originalAddresses
    (mapping : OriginalCodeMap) :
    (originalCodeMapToStatic mapping).originalAddresses =
      mapFiniteIndex originalAddressToStatic mapping.addresses := rfl

@[simp] theorem originalCodeMapToStatic_candidateAddresses
    (mapping : OriginalCodeMap) :
    (originalCodeMapToStatic mapping).candidateAddresses =
      mapFiniteIndex originalAddressToStatic mapping.addresses := rfl

@[simp] theorem originalCodeMapToStatic_get?
    (mapping : OriginalCodeMap) (targetId : Nat) :
    (originalCodeMapToStatic mapping).get? targetId =
      (mapping.get? targetId).map originalTargetToStatic := by
  simp [originalCodeMapToStatic, OriginalCodeMap.get?, StaticCodeMap.get?]

@[simp] theorem originalCodeMapToStatic_sideAddresses
    (mapping : OriginalCodeMap) (candidate : Bool) :
    (originalCodeMapToStatic mapping).sideAddresses candidate =
      mapFiniteIndex originalAddressToStatic mapping.addresses := by
  cases candidate <;> rfl

@[simp] theorem originalCodeMapToStatic_addressRva
    (mapping : OriginalCodeMap) (candidate : Bool)
    (address : OriginalCodeAddress) :
    staticCodeAddressRva candidate (originalCodeMapToStatic mapping)
      (originalAddressToStatic address) =
      originalCodeAddressRva mapping address := by
  cases address with
  | mk targetId kind =>
      cases candidate <;>
        cases targetResult : mapping.get? targetId <;> cases kind <;>
        simp [originalAddressToStatic, staticCodeAddressRva,
          originalCodeAddressRva, originalTargetToStatic, targetResult]

@[simp] theorem originalCodeMapToStatic_addressRvaAt?
    (mapping : OriginalCodeMap) (candidate : Bool) (index : Nat) :
    (originalCodeMapToStatic mapping).addressRvaAt? candidate index =
      mapping.addressRvaAt? index := by
  unfold StaticCodeMap.addressRvaAt? OriginalCodeMap.addressRvaAt?
  simp only [originalCodeMapToStatic_sideAddresses, mapFiniteIndex_get?]
  cases addressResult : mapping.addresses.get? index <;>
    simp [originalCodeMapToStatic_addressRva]

@[simp] theorem originalCodeMapToStatic_entryAtValid
    (mapping : OriginalCodeMap) (index : Nat) :
    (originalCodeMapToStatic mapping).entryAtValid index =
      mapping.entryAtValid index := by
  cases targetResult : mapping.get? index <;>
    simp [StaticCodeMap.entryAtValid, OriginalCodeMap.entryAtValid,
      targetResult, originalTargetToStatic]

@[simp] theorem originalCodeMapToStatic_addressContribution
    (mapping : OriginalCodeMap) (candidate : Bool) (index : Nat) :
    (originalCodeMapToStatic mapping).addressContribution candidate index =
      mapping.addressContribution index := by
  cases candidate <;>
    cases targetResult : mapping.get? index <;>
    simp [StaticCodeMap.addressContribution,
      OriginalCodeMap.addressContribution, targetResult,
      originalTargetToStatic]

@[simp] theorem originalCodeMapToStatic_expectedAddressCount
    (mapping : OriginalCodeMap) (candidate : Bool) :
    (originalCodeMapToStatic mapping).expectedAddressCount candidate =
      mapping.expectedAddressCount := by
  simp only [StaticCodeMap.expectedAddressCount,
    OriginalCodeMap.expectedAddressCount, originalCodeMapToStatic,
    mapFiniteIndex_size]
  congr 1
  funext index
  exact originalCodeMapToStatic_addressContribution mapping candidate index

@[simp] theorem originalCodeMapToStatic_addressAtValid
    (mapping : OriginalCodeMap) (candidate : Bool) (pe : PE32)
    (index : Nat) :
    (originalCodeMapToStatic mapping).addressAtValid candidate pe index =
      mapping.addressAtValid pe index := by
  cases candidate with
  | false =>
      unfold StaticCodeMap.addressAtValid OriginalCodeMap.addressAtValid
      simp only [Bool.false_eq_true, ↓reduceIte,
        originalCodeMapToStatic_originalAddresses,
        mapFiniteIndex_get?]
      cases addressResult : mapping.addresses.get? index with
      | none => rfl
      | some address =>
          simp only [Option.map_some,
            originalCodeMapToStatic_addressRva]
          cases rvaResult : originalCodeAddressRva mapping address with
          | none => rfl
          | some rva =>
              simp only [rvaResult]
              cases index with
              | zero => rfl
              | succ prior =>
                  simp only [mapFiniteIndex_get?]
                  cases priorResult : mapping.addresses.get? prior <;>
                    simp [priorResult,
                      originalCodeMapToStatic_addressRva] <;> rfl
  | true =>
      unfold StaticCodeMap.addressAtValid OriginalCodeMap.addressAtValid
      simp only [Bool.true_eq, ↓reduceIte,
        originalCodeMapToStatic_candidateAddresses,
        mapFiniteIndex_get?]
      cases addressResult : mapping.addresses.get? index with
      | none => rfl
      | some address =>
          simp only [Option.map_some,
            originalCodeMapToStatic_addressRva]
          cases rvaResult : originalCodeAddressRva mapping address with
          | none => rfl
          | some rva =>
              simp only [rvaResult]
              cases index with
              | zero => rfl
              | succ prior =>
                  simp only [mapFiniteIndex_get?]
                  cases priorResult : mapping.addresses.get? prior <;>
                    simp [priorResult,
                      originalCodeMapToStatic_addressRva] <;> rfl

theorem originalCodeMapToStatic_findRvaAux
    (mapping : OriginalCodeMap) (candidate : Bool)
    (needle fuel lower upper : Nat) :
    (originalCodeMapToStatic mapping).findRvaAux candidate needle fuel lower upper =
      (mapping.findRvaAux needle fuel lower upper).map fun result =>
        (result.1, originalAddressToStatic result.2) := by
  induction fuel generalizing lower upper with
  | zero => simp [StaticCodeMap.findRvaAux, OriginalCodeMap.findRvaAux]
  | succ fuel induction =>
      unfold StaticCodeMap.findRvaAux OriginalCodeMap.findRvaAux
      simp only [originalCodeMapToStatic_sideAddresses, mapFiniteIndex_get?]
      by_cases inside : lower < upper
      · simp only [inside, ↓reduceIte]
        cases addressResult : mapping.addresses.get?
            (lower + (upper - lower) / 2) with
        | none => simp [addressResult]
        | some address =>
            simp only [addressResult, Option.map_some,
              originalCodeMapToStatic_addressRva]
            cases rvaResult : originalCodeAddressRva mapping address with
            | none => simp [rvaResult]
            | some rva =>
                simp only [rvaResult]
                by_cases before : needle < rva
                · simp [before, induction]
                · by_cases after : rva < needle
                  · simp [before, after, induction]
                  · simp [before, after]
      · simp [inside]

theorem originalCodeMapToStatic_findRva?
    (mapping : OriginalCodeMap) (candidate : Bool) (needle : Nat) :
    (originalCodeMapToStatic mapping).findRva? candidate needle =
      (mapping.findRva? needle).map fun result =>
        (result.1, originalAddressToStatic result.2) := by
  simp [StaticCodeMap.findRva?, OriginalCodeMap.findRva?,
    originalCodeMapToStatic_findRvaAux]

theorem originalCodeMapToStatic_rawEipMatches
    (mapping : OriginalCodeMap) (candidate : Bool)
    (imageBase : Nat) (address : Word) :
    (originalCodeMapToStatic mapping).rawEipMatches candidate imageBase address =
      mapping.rawEipMatches imageBase address := by
  unfold StaticCodeMap.rawEipMatches OriginalCodeMap.rawEipMatches
  by_cases inside : imageBase <= address.toNat
  · simp only [inside, ↓reduceIte, originalCodeMapToStatic_findRva?]
    generalize resultEquation : mapping.findRva? (address.toNat - imageBase) = result
    cases result with
    | none => rfl
    | some resultValue =>
        rcases resultValue with ⟨index, originalAddress⟩
        simp [originalAddressToStatic, originalCodeMapToStatic_addressRvaAt?]
        rfl
  · simp [inside]

theorem originalCodeMapToStatic_resolveRawEip
    (mapping : OriginalCodeMap) (candidate : Bool)
    (imageBase : Nat) (address : Word) :
    (originalCodeMapToStatic mapping).resolveRawEip candidate imageBase address =
      mapping.resolveRawEip imageBase address := by
  unfold StaticCodeMap.resolveRawEip OriginalCodeMap.resolveRawEip
  rw [originalCodeMapToStatic_rawEipMatches]
  rfl

@[simp] theorem originalCodeMapToStatic_targetAddressesRoundTripAt
    (mapping : OriginalCodeMap) (candidate : Bool)
    (pe : PE32) (targetId : Nat) :
    (originalCodeMapToStatic mapping).targetAddressesRoundTripAt candidate
      pe.imageBase targetId =
    mapping.targetRoundTripsAt pe targetId := by
  cases candidate <;>
    cases targetResult : mapping.get? targetId <;>
    simp [StaticCodeMap.targetAddressesRoundTripAt,
      OriginalCodeMap.targetRoundTripsAt, targetResult,
      originalCodeMapToStatic_resolveRawEip, originalTargetToStatic]

theorem originalCodeMapToStatic_indexedValid
    (mapping : OriginalCodeMap)
    (certificate : OriginalCodeMapCertificate pe imports mapping) :
    (originalCodeMapToStatic mapping).IndexedValid pe pe := by
  refine ⟨?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · simpa [originalCodeMapToStatic] using
      certificate.entriesStructurallyValid
  · simpa [originalCodeMapToStatic] using
      certificate.addressesStructurallyValid
  · simpa [originalCodeMapToStatic] using
      certificate.addressesStructurallyValid
  · intro index before
    have before' : index < mapping.entries.size := by
      simpa [originalCodeMapToStatic] using before
    rw [originalCodeMapToStatic_entryAtValid]
    exact certificate.entry_valid index before'
  · rw [originalCodeMapToStatic_expectedAddressCount]
    simpa [originalCodeMapToStatic] using certificate.addressCountExact
  · rw [originalCodeMapToStatic_expectedAddressCount]
    simpa [originalCodeMapToStatic] using certificate.addressCountExact
  · intro index before
    have before' : index < mapping.addresses.size := by
      simpa [originalCodeMapToStatic] using before
    have checked := certificate.addressChecks.holds_of_checked
      (mapping.addressAtValid pe) mapping.addresses.size
      certificate.addressChecksValid index before'
    rw [originalCodeMapToStatic_addressAtValid]
    exact checked
  · intro index before
    have before' : index < mapping.addresses.size := by
      simpa [originalCodeMapToStatic] using before
    have checked := certificate.addressChecks.holds_of_checked
      (mapping.addressAtValid pe) mapping.addresses.size
      certificate.addressChecksValid index before'
    rw [originalCodeMapToStatic_addressAtValid]
    exact checked
  · intro targetId before
    have before' : targetId < mapping.entries.size := by
      simpa [originalCodeMapToStatic] using before
    rw [originalCodeMapToStatic_targetAddressesRoundTripAt]
    exact certificate.target_round_trips targetId before'
  · intro targetId before
    have before' : targetId < mapping.entries.size := by
      simpa [originalCodeMapToStatic] using before
    rw [originalCodeMapToStatic_targetAddressesRoundTripAt]
    exact certificate.target_round_trips targetId before'

def originalTargetMatches (imageBase : Nat) (target : OriginalCodeTarget)
    (address : Word) : Bool :=
  codeAddressMatches imageBase target.rva target.aliases address

def resolveOriginalCodeTargetLinear (mapping : OriginalCodeMap)
    (imageBase : Nat) (address : Word) : Option Nat :=
  (mapping.entries.toList.find? (originalTargetMatches imageBase · address)).map
    (·.id)

theorem findOriginalTargetProjection
    (targets : List OriginalCodeTarget) (imageBase : Nat) (address : Word) :
    (targets.map originalTargetToStatic).find? (fun target =>
        codeAddressMatches imageBase target.originalRva
          target.originalAliases address) =
      (targets.find? (originalTargetMatches imageBase · address)).map
        originalTargetToStatic := by
  induction targets with
  | nil => rfl
  | cons target targets induction =>
      simp only [List.map_cons, List.find?_cons, originalTargetMatches,
        originalTargetToStatic]
      rw [induction]
      cases codeAddressMatches imageBase target.rva target.aliases address <;> rfl

@[simp] theorem resolveMappedCodeTarget_originalCodeMapToStatic
    (mapping : OriginalCodeMap) (imageBase : Nat) (address : Word) :
    resolveMappedCodeTarget false imageBase
        (originalCodeMapToStatic mapping).entries.toList address =
      resolveOriginalCodeTargetLinear mapping imageBase address := by
  simp only [originalCodeMapToStatic, mapFiniteIndex_toList,
    resolveMappedCodeTarget, resolveOriginalCodeTargetLinear,
    Bool.false_eq_true, ↓reduceIte]
  rw [findOriginalTargetProjection]
  cases mapping.entries.toList.find?
      (originalTargetMatches imageBase · address) <;> rfl

theorem finiteIndex_mem_toList_get?
    (index : FiniteIndex alpha) (value : alpha)
    (sizesSound : index.sizesSound = true)
    (member : value ∈ index.toList) :
    exists position, index.get? position = some value :=
  FiniteIndex.mem_toList_implies_exists_get? index value sizesSound member

theorem codeMapEntriesSizesSound
    (certificate : OriginalCodeMapCertificate pe imports mapping) :
    mapping.entries.sizesSound = true := by
  have checked := certificate.entriesStructurallyValid
  simp only [FiniteIndex.structurallyValid, Bool.and_eq_true] at checked
  exact checked.1.1.1

theorem if_duplicate_else_single_eq_single
    {value expected : alpha} (condition : Prop) [Decidable condition]
    (found : (if condition then [value, value] else [value]) = [expected]) :
    value = expected := by
  by_cases condition <;> simp_all

theorem OriginalCodeMap.findRvaAux_rva
    (mapping : OriginalCodeMap) (needle fuel lower upper index : Nat)
    (address : OriginalCodeAddress)
    (found : mapping.findRvaAux needle fuel lower upper = some (index, address)) :
    originalCodeAddressRva mapping address = some needle := by
  induction fuel generalizing lower upper with
  | zero => simp [OriginalCodeMap.findRvaAux] at found
  | succ fuel induction =>
      unfold OriginalCodeMap.findRvaAux at found
      by_cases inside : lower < upper
      · simp only [inside, ↓reduceIte] at found
        cases addressResult : mapping.addresses.get?
            (lower + (upper - lower) / 2) with
        | none => simp [addressResult] at found
        | some indexedAddress =>
            simp only [addressResult] at found
            cases rvaResult : originalCodeAddressRva mapping indexedAddress with
            | none => simp [rvaResult] at found
            | some rva =>
                simp only [rvaResult] at found
                by_cases before : needle < rva
                · simp only [before, ↓reduceIte] at found
                  exact induction _ _ found
                · simp only [before, Bool.false_eq_true, ↓reduceIte] at found
                  by_cases after : rva < needle
                  · simp only [after, ↓reduceIte] at found
                    exact induction _ _ found
                  · simp only [after, Bool.false_eq_true, ↓reduceIte] at found
                    have sameAddress : indexedAddress = address := by
                      exact congrArg Prod.snd (Option.some.inj found)
                    have sameRva : rva = needle := Nat.le_antisymm
                      (Nat.le_of_not_gt before) (Nat.le_of_not_gt after)
                    simpa [sameAddress, sameRva] using rvaResult
      · simp [inside] at found

theorem OriginalCodeMap.resolveRawEip_witness
    (mapping : OriginalCodeMap)
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (imageBase : Nat) (address : Word)
    (targetId : Nat)
    (found : mapping.resolveRawEip imageBase address = some targetId) :
    exists target, target ∈ mapping.entries.toList /\ target.id = targetId /\
      originalTargetMatches imageBase target address = true := by
  have rawSingle : mapping.rawEipMatches imageBase address = [targetId] := by
    unfold OriginalCodeMap.resolveRawEip at found
    cases result : mapping.rawEipMatches imageBase address with
    | nil => simp [result] at found
    | cons first rest =>
        cases rest with
        | nil =>
            simp only [result, Option.some.injEq] at found
            simpa [found] using result
        | cons second tail => simp [result] at found
  by_cases inside : imageBase <= address.toNat
  · simp only [OriginalCodeMap.rawEipMatches, inside, ↓reduceIte] at rawSingle
    cases result : mapping.findRva? (address.toNat - imageBase) with
    | none => simp [result] at rawSingle
    | some resultValue =>
        rcases resultValue with ⟨index, codeAddress⟩
        rcases codeAddress with ⟨codeAddressTargetId, codeAddressKind⟩
        simp only [result] at rawSingle
        have addressId : codeAddressTargetId = targetId :=
          if_duplicate_else_single_eq_single _ rawSingle
        have findResult :
            mapping.findRvaAux (address.toNat - imageBase)
              (mapping.addresses.size + 1) 0 mapping.addresses.size =
                some (index,
                  { targetId := codeAddressTargetId, kind := codeAddressKind }) := by
          simpa [OriginalCodeMap.findRva?] using result
        have rva := OriginalCodeMap.findRvaAux_rva mapping
          (address.toNat - imageBase) (mapping.addresses.size + 1) 0
          mapping.addresses.size index
          { targetId := codeAddressTargetId, kind := codeAddressKind } findResult
        unfold originalCodeAddressRva at rva
        cases targetResult : mapping.get? codeAddressTargetId with
        | none =>
            rw [targetResult] at rva
            simp at rva
        | some target =>
            have targetMember := FiniteIndex.get?_eq_some_implies_mem_toList
              mapping.entries codeAddressTargetId target targetResult
            have targetIdExact := certificate.target_id_eq
              codeAddressTargetId target targetResult
            refine ⟨target, targetMember, targetIdExact.trans addressId, ?_⟩
            have addressExact :
                BitVec.ofNat 32 (imageBase + (address.toNat - imageBase)) =
                  address := by
              apply BitVec.eq_of_toNat_eq
              rw [Nat.add_sub_of_le inside]
              simp [BitVec.toNat_ofNat,
                Nat.mod_eq_of_lt (BitVec.isLt address)]
            rw [targetResult] at rva
            cases codeAddressKind with
            | canonical =>
                have rvaExact : target.rva = address.toNat - imageBase := by
                  simpa using rva
                simp only [originalTargetMatches, codeAddressMatches,
                  Bool.or_eq_true]
                apply Or.inl
                apply beq_iff_eq.mpr
                rw [← addressExact, rvaExact]
            | alias aliasIndex =>
                cases aliasResult : target.aliases[aliasIndex]? with
                | none => simp [aliasResult] at rva
                | some alias =>
                    have rvaExact : alias.rva = address.toNat - imageBase := by
                      simpa [aliasResult] using rva
                    simp only [originalTargetMatches, codeAddressMatches,
                      Bool.or_eq_true]
                    apply Or.inr
                    simp only [List.any_eq_true]
                    refine ⟨alias, List.mem_of_getElem? aliasResult, ?_⟩
                    apply beq_iff_eq.mpr
                    rw [← addressExact, rvaExact]
  · have impossible : ([] : List Nat) = [targetId] := by
      simpa only [OriginalCodeMap.rawEipMatches, inside, ↓reduceIte] using rawSingle
    simp at impossible

theorem resolveOriginalCodeTargetLinear_sound
    (mapping : OriginalCodeMap)
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (imageBase : Nat) (address : Word) (targetId : Nat)
    (imageBaseExact : imageBase = pe.imageBase)
    (found : resolveOriginalCodeTargetLinear mapping imageBase address =
      some targetId) :
    mapping.resolveRawEip imageBase address = some targetId := by
  subst imageBase
  unfold resolveOriginalCodeTargetLinear at found
  cases targetResult : mapping.entries.toList.find?
      (originalTargetMatches pe.imageBase · address) with
  | none => simp [targetResult] at found
  | some target =>
      have targetIdExact : target.id = targetId := by simpa [targetResult] using found
      subst targetId
      have targetMember := List.mem_of_find?_eq_some targetResult
      have targetMatches := List.find?_some targetResult
      obtain ⟨index, indexed⟩ := finiteIndex_mem_toList_get?
        mapping.entries target (codeMapEntriesSizesSound certificate) targetMember
      have targetId := certificate.target_id_eq index target indexed
      have before := FiniteIndex.get?_eq_some_implies_lt_size
        mapping.entries index target indexed
      have roundTrip := certificate.target_round_trips index before
      have indexed' : mapping.get? index = some target := indexed
      simp only [OriginalCodeMap.targetRoundTripsAt, indexed'] at roundTrip
      have roundTripPair :
          (mapping.resolveRawEip pe.imageBase
              (BitVec.ofNat 32 (pe.imageBase + target.rva)) == some index) = true ∧
            (target.aliases.all fun alias =>
              mapping.resolveRawEip pe.imageBase
                (BitVec.ofNat 32 (pe.imageBase + alias.rva)) == some index) = true := by
        simpa only [Bool.and_eq_true] using roundTrip
      rw [targetId]
      simp only [originalTargetMatches, codeAddressMatches,
        Bool.or_eq_true] at targetMatches
      rcases targetMatches with canonical | alias
      · have addressExact := beq_iff_eq.mp canonical
        rw [addressExact]
        exact beq_iff_eq.mp roundTripPair.1
      · simp only [List.any_eq_true] at alias
        obtain ⟨matchedAlias, member, matched⟩ := alias
        have addressExact := beq_iff_eq.mp matched
        rw [addressExact]
        have aliases := List.all_eq_true.mp roundTripPair.2
        exact beq_iff_eq.mp (aliases matchedAlias member)

theorem resolveOriginalCodeTargetLinear_complete
    (mapping : OriginalCodeMap)
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (imageBase : Nat) (address : Word) (targetId : Nat)
    (imageBaseExact : imageBase = pe.imageBase)
    (found : mapping.resolveRawEip imageBase address = some targetId) :
    resolveOriginalCodeTargetLinear mapping imageBase address = some targetId := by
  obtain ⟨target, targetMember, targetIdExact, targetMatches⟩ :=
    OriginalCodeMap.resolveRawEip_witness mapping certificate imageBase address
      targetId found
  unfold resolveOriginalCodeTargetLinear
  cases linearResult : mapping.entries.toList.find?
      (originalTargetMatches imageBase · address) with
  | none =>
      have absent := List.find?_eq_none.mp linearResult target targetMember
      simp [targetMatches] at absent
  | some selected =>
      have selectedMatches := List.find?_some linearResult
      have selectedMember := List.mem_of_find?_eq_some linearResult
      obtain ⟨selectedIndex, selectedAt⟩ := finiteIndex_mem_toList_get?
        mapping.entries selected (codeMapEntriesSizesSound certificate) selectedMember
      have selectedId := certificate.target_id_eq selectedIndex selected selectedAt
      have selectedBefore := FiniteIndex.get?_eq_some_implies_lt_size
        mapping.entries selectedIndex selected selectedAt
      have selectedRoundTrip := certificate.target_round_trips
        selectedIndex selectedBefore
      have selectedResolves :
          mapping.resolveRawEip imageBase address = some selected.id := by
        apply resolveOriginalCodeTargetLinear_sound mapping certificate imageBase
          address selected.id imageBaseExact
        simp [resolveOriginalCodeTargetLinear, linearResult]
      have idsEqual : selected.id = targetId := by
        rw [found] at selectedResolves
        exact Option.some.inj selectedResolves.symm
      simp [linearResult, idsEqual]

theorem resolveOriginalCodeTargetLinear_eq_resolveRawEip
    (mapping : OriginalCodeMap)
    (certificate : OriginalCodeMapCertificate pe imports mapping)
    (imageBase : Nat) (address : Word) :
    imageBase = pe.imageBase ->
    resolveOriginalCodeTargetLinear mapping imageBase address =
      mapping.resolveRawEip imageBase address := by
  intro imageBaseExact
  cases linear : resolveOriginalCodeTargetLinear mapping imageBase address with
  | none =>
      cases indexed : mapping.resolveRawEip imageBase address with
      | none => rfl
      | some targetId =>
          have complete := resolveOriginalCodeTargetLinear_complete mapping certificate
            imageBase address targetId imageBaseExact indexed
          simp [linear] at complete
  | some targetId =>
      exact (resolveOriginalCodeTargetLinear_sound mapping certificate imageBase
        address targetId imageBaseExact linear).symm

def carrierTargetBound (context : OriginalDecodedStaticContext)
    (target : CodeTargetPair) : Bool :=
  match context.codeMap.get? target.id with
  | none => false
  | some originalTarget =>
      target.originalRva == originalTarget.rva &&
        target.originalAliases == originalTarget.aliases

def carrierRegionBound (context : OriginalDecodedStaticContext)
    (region : RegionRelation) : Bool :=
  match context.source? region.id with
  | none => false
  | some source =>
      region.original == source.region.span &&
        region.targets.map (fun target => target.id) == source.region.targets &&
        region.targets.all (carrierTargetBound context)

def sourceRegionBoundAt (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) (targetId : Nat) : Bool :=
  match context.source? targetId with
  | none => false
  | some source =>
      match regionById original.regions targetId with
      | none => false
      | some region =>
          region.id == source.target.id && region.original == source.region.span &&
            region.root == source.region.root &&
            region.targets.map (fun target => target.id) == source.region.targets

def idsUnique (regions : List RegionRelation) : Bool :=
  regions.all fun region =>
    (regions.filter fun other => other.id == region.id).length == 1

structure Proposal where
  entryChecks : IndexedBoolCertificate
  addressChecks : IndexedBoolCertificate
deriving Repr, DecidableEq

def Proposal.exactContextChecked (proposal : Proposal)
    (context : OriginalDecodedStaticContext) : Bool :=
  parsePE32Tree context.pe.bytes == some context.pe &&
    importTableValid context.pe context.importCertificate &&
    parseRelocations context.pe == some context.relocations &&
    preferredBaseLoaderImageValid context.pe &&
    context.codeMap.entries.structurallyValid 16 &&
    context.codeMap.addresses.structurallyValid 16 &&
    proposal.entryChecks.checked context.codeMap.entryAtValid
      context.codeMap.entries.size &&
    context.codeMap.addresses.size == context.codeMap.expectedAddressCount &&
    proposal.addressChecks.checked (context.codeMap.addressAtValid context.pe)
      context.codeMap.addresses.size &&
    proposal.entryChecks.checked (context.codeMap.targetRoundTripsAt context.pe)
      context.codeMap.entries.size &&
    proposal.entryChecks.checked
      (context.codeMap.aliasesSemanticallyValidAt context.pe context.imports)
      context.codeMap.entries.size &&
    context.regions.structurallyValid 16 &&
    proposal.entryChecks.checked context.sourceAtValid
      context.codeMap.entries.size &&
    machineImportCallContractsValid context.imports
      context.machineImportCallContracts

def Proposal.carrierChecked (proposal : Proposal)
    (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) : Bool :=
  original.candidate == false && original.context.originalPe == context.pe &&
    original.context.originalImports == context.imports &&
    original.context.machineImportCallContracts == context.machineImportCallContracts &&
    original.context.codeMap == originalCodeMapToStatic context.codeMap &&
    original.regions.length == context.codeMap.entries.size &&
    idsUnique original.regions &&
    proposal.entryChecks.checked (sourceRegionBoundAt context original)
      context.codeMap.entries.size &&
    original.regions.all (carrierRegionBound context)

def Proposal.checked (proposal : Proposal) (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) : Bool :=
  proposal.exactContextChecked context && proposal.carrierChecked context original

structure Certificate (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) where
  authority : ExactOriginalDecodedAuthority context
  proposal : Proposal
  checked : proposal.checked context original = true

theorem Certificate.carrier_checked
    (certificate : Certificate context original) :
    certificate.proposal.carrierChecked context original = true := by
  have checked := certificate.checked
  simp only [Proposal.checked, Bool.and_eq_true] at checked
  exact checked.2

structure CheckedCarrierFacts (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram) (proposal : Proposal) : Prop where
  originalRole : original.candidate = false
  peBound : original.context.originalPe = context.pe
  importsBound : original.context.originalImports = context.imports
  machineContractsBound :
    original.context.machineImportCallContracts = context.machineImportCallContracts
  codeMapBound :
    original.context.codeMap = originalCodeMapToStatic context.codeMap
  sourceChecksValid :
    proposal.entryChecks.checked (sourceRegionBoundAt context original)
      context.codeMap.entries.size = true
  regionsChecked : original.regions.all (carrierRegionBound context) = true

theorem Certificate.carrierFacts
    (certificate : Certificate context original) :
    CheckedCarrierFacts context original certificate.proposal := by
  have checked := certificate.carrier_checked
  have check9 := Bool.and_eq_true_iff.mp checked
  have check8 := Bool.and_eq_true_iff.mp check9.1
  have check7 := Bool.and_eq_true_iff.mp check8.1
  have check6 := Bool.and_eq_true_iff.mp check7.1
  have check5 := Bool.and_eq_true_iff.mp check6.1
  have check4 := Bool.and_eq_true_iff.mp check5.1
  have check3 := Bool.and_eq_true_iff.mp check4.1
  have check2 := Bool.and_eq_true_iff.mp check3.1
  exact {
    originalRole := beq_iff_eq.mp check2.1
    peBound := beq_iff_eq.mp check2.2
    importsBound := beq_iff_eq.mp check3.2
    machineContractsBound := beq_iff_eq.mp check4.2
    codeMapBound := beq_iff_eq.mp check5.2
    sourceChecksValid := check8.2
    regionsChecked := check9.2
  }

def Certificate.toFiniteBinding
    (certificate : Certificate context original) :
    GeneratedOriginalFiniteCarrierBinding context original := by
  have facts := certificate.carrierFacts
  have sourceChecks := certificate.proposal.entryChecks.holds_of_checked
    (sourceRegionBoundAt context original) context.codeMap.entries.size
    facts.sourceChecksValid
  refine {
    originalRole := facts.originalRole
    peBound := facts.peBound
    importsBound := facts.importsBound
    machineContractsBound := facts.machineContractsBound
    sourceRegionsBound := ?_
    regionsHaveSources := ?_
    originalTargetsBound := ?_
  }
  · intro targetId source sourceFound
    cases targetResult : context.codeMap.get? targetId with
    | none =>
        simp [OriginalDecodedStaticContext.source?, targetResult] at sourceFound
    | some target =>
        have before := FiniteIndex.get?_eq_some_implies_lt_size
          context.codeMap.entries targetId target targetResult
        have bounded := sourceChecks targetId before
        cases regionResult : regionById original.regions targetId with
        | none =>
            simp [sourceRegionBoundAt, sourceFound, regionResult] at bounded
        | some region =>
            refine ⟨region, rfl, ?_⟩
            have boundFacts :
                ((region.id = source.target.id ∧
                    region.original = source.region.span) ∧
                  region.root = source.region.root) ∧
                region.targets.map (fun selected => selected.id) =
                  source.region.targets := by
              simpa [sourceRegionBoundAt, sourceFound, regionResult,
                Bool.and_eq_true, beq_iff_eq] using bounded
            exact ⟨boundFacts.1.1.1, boundFacts.1.1.2,
              boundFacts.1.2, boundFacts.2⟩
  · intro region member
    have regionChecked := List.all_eq_true.mp facts.regionsChecked region member
    cases sourceResult : context.source? region.id with
    | none => simp [carrierRegionBound, sourceResult] at regionChecked
    | some source =>
        have facts :
            (region.original = source.region.span ∧
              region.targets.map (fun target => target.id) = source.region.targets) ∧
              ∀ target, target ∈ region.targets ->
                carrierTargetBound context target = true := by
          simpa [carrierRegionBound, sourceResult, Bool.and_eq_true,
            beq_iff_eq] using regionChecked
        exact ⟨source, rfl, facts.1.1, facts.1.2⟩
  · intro region member target targetMember
    have regionChecked := List.all_eq_true.mp facts.regionsChecked region member
    cases sourceResult : context.source? region.id with
    | none => simp [carrierRegionBound, sourceResult] at regionChecked
    | some source =>
        have facts :
            (region.original = source.region.span ∧
              region.targets.map (fun selected => selected.id) =
                source.region.targets) ∧
              ∀ selected, selected ∈ region.targets ->
                carrierTargetBound context selected = true := by
          simpa [carrierRegionBound, sourceResult, Bool.and_eq_true,
            beq_iff_eq] using regionChecked
        have targetChecked := facts.2 target targetMember
        cases targetResult : context.codeMap.get? target.id with
        | none => simp [carrierTargetBound, targetResult] at targetChecked
        | some originalTarget =>
            have facts :
                target.originalRva = originalTarget.rva ∧
                  target.originalAliases = originalTarget.aliases := by
              simpa [carrierTargetBound, targetResult, Bool.and_eq_true,
                beq_iff_eq] using targetChecked
            exact ⟨originalTarget, rfl, facts.1, facts.2⟩

theorem Certificate.indexedResolution
    (certificate : Certificate context original) (address : Word) :
    original.context.codeMap.resolveRawEip false context.pe.imageBase address =
      context.codeMap.resolveRawEip context.pe.imageBase address := by
  rw [certificate.carrierFacts.codeMapBound,
    originalCodeMapToStatic_resolveRawEip]

theorem Certificate.returnResolution
    (certificate : Certificate context original) (address : Word) :
    resolveMappedCodeTarget false context.pe.imageBase
        original.context.codeMap.entries.toList address =
      context.codeMap.resolveRawEip context.pe.imageBase address := by
  rw [certificate.carrierFacts.codeMapBound,
    resolveMappedCodeTarget_originalCodeMapToStatic]
  exact resolveOriginalCodeTargetLinear_eq_resolveRawEip context.codeMap
    certificate.authority.codeMap context.pe.imageBase address rfl

def Certificate.toExactBinding
    (certificate : Certificate context original) :
    ExactDecodedOriginalCarrierBinding context original :=
  certificate.toFiniteBinding.toExact certificate.indexedResolution
    certificate.returnResolution

def Certificate.toMixedBinding
    (certificate : Certificate context original) :
    ExactMixedProgramBinding context original := {
  original := certificate.toExactBinding
}

end StageA.Relational.InterpreterOriginalCarrierBinding
