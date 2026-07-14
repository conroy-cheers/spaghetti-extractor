import StageA.Relational

namespace StageA.Relational

open StageA.Formal

inductive IndexTree (α : Type) where
  | empty
  | leaf (value : α)
  | node (leftSize : Nat) (left right : IndexTree α)
deriving Repr, DecidableEq

namespace IndexTree

def size : IndexTree α -> Nat
  | .empty => 0
  | .leaf _ => 1
  | .node leftSize _ right => leftSize + right.size

def toList : IndexTree α -> List α
  | .empty => []
  | .leaf value => [value]
  | .node _ left right => left.toList ++ right.toList

def get? : IndexTree α -> Nat -> Option α
  | .empty, _ => none
  | .leaf value, 0 => some value
  | .leaf _, _ => none
  | .node leftSize left right, index =>
      if index < leftSize then left.get? index else right.get? (index - leftSize)

end IndexTree

structure SortedSpanCertificate where
  sorted : List Span := []
  sourceIndex : IndexTree Span := .empty
  sortedSourceIndices : List Nat := []
  sourceToSorted : IndexTree Nat := .empty
deriving Repr, DecidableEq

structure PaddingAliasCertificate where
  sorted : SortedSpanCertificate := {}
  runStops : IndexTree Nat := .empty
deriving Repr, DecidableEq

def sortedSpanEntriesValidAux (sourceIndex : IndexTree Span)
    (sourceToSorted : IndexTree Nat) :
    Nat -> List Span -> List Nat -> Bool
  | _, [], [] => true
  | ordinal, span :: spans, source :: sources =>
      sourceIndex.get? source == some span &&
        sourceToSorted.get? source == some ordinal &&
        sortedSpanEntriesValidAux sourceIndex sourceToSorted (ordinal + 1) spans sources
  | _, _, _ => false

def spansNondecreasing : List Span -> Bool
  | [] | [_] => true
  | left :: right :: tail =>
      left.start <= right.start && spansNondecreasing (right :: tail)

def sortedSpanCertificateValid (source : List Span)
    (certificate : SortedSpanCertificate) : Bool :=
  source == certificate.sourceIndex.toList &&
    certificate.sorted.length == source.length &&
    certificate.sortedSourceIndices.length == source.length &&
    certificate.sourceToSorted.size == source.length &&
    spansNondecreasing certificate.sorted &&
    sortedSpanEntriesValidAux certificate.sourceIndex certificate.sourceToSorted 0
      certificate.sorted certificate.sortedSourceIndices

def executableCoverageCertified (pe : PE32) (source : List Span)
    (certificate : SortedSpanCertificate) : Bool :=
  sortedSpanCertificateValid source certificate &&
    certificate.sorted.all (spanInExecutableSection pe) &&
    (pe.sections.filter (fun sec => sec.executable)).all (fun sec =>
      spansCoverFrom sec.virtualAddress (sec.virtualAddress + sec.mappedSize)
        (spansInSection sec certificate.sorted))

def paddingRunsValidAux (runStops : IndexTree Nat) : List Span -> List Nat -> Bool
  | [], [] => true
  | [span], [source] => runStops.get? source == some span.stop
  | span :: next :: spans, source :: nextSource :: sources =>
      span.stop <= next.start &&
        runStops.get? source ==
          (if span.stop == next.start then runStops.get? nextSource else some span.stop) &&
        paddingRunsValidAux runStops (next :: spans) (nextSource :: sources)
  | _, _ => false

def paddingAliasCertificateValid (padding : List Span)
    (certificate : PaddingAliasCertificate) : Bool :=
  sortedSpanCertificateValid padding certificate.sorted &&
    certificate.runStops.size == padding.length &&
    paddingRunsValidAux certificate.runStops certificate.sorted.sorted
      certificate.sorted.sortedSourceIndices

def codeAliasClosed (padding : IndexTree Span) (runStops : IndexTree Nat)
    (canonical : Nat) (alias : CodeAlias) : Bool :=
  match padding.get? alias.paddingIndex, runStops.get? alias.paddingIndex with
  | some span, some stop =>
      span.start == alias.rva && alias.rva < canonical && stop == canonical
  | _, _ => false

def targetAliasesCertified (regions : List RegionRelation)
    (original candidate : PaddingAliasCertificate) : Bool :=
  regions.all fun region => region.targets.all fun target =>
    target.originalAliases.all
      (codeAliasClosed original.sorted.sourceIndex original.runStops target.originalRva) &&
    target.candidateAliases.all
      (codeAliasClosed candidate.sorted.sourceIndex candidate.runStops target.candidateRva)

structure ProofBundle where
  originalBytes : ByteTree
  candidateBytes : ByteTree
  originalImports : ImportTableCertificate
  candidateImports : ImportTableCertificate
  machineImportCallContracts : List MachineImportCallContract := []
  regions : List RegionRelation
  regionIndex : IndexTree RegionRelation := .empty
  originalPadding : List Span
  candidatePadding : List Span
  originalCoverage : SortedSpanCertificate := {}
  candidateCoverage : SortedSpanCertificate := {}
  originalAliasCoverage : PaddingAliasCertificate := {}
  candidateAliasCoverage : PaddingAliasCertificate := {}
deriving Repr, DecidableEq

def parsedImages (bundle : ProofBundle) : Option (PE32 × PE32) := do
  pure (← parsePE32Tree bundle.originalBytes, ← parsePE32Tree bundle.candidateBytes)

def entryRegionMatches (originalPe candidatePe : PE32) (region : RegionRelation) : Bool :=
  region.root && region.original.start == originalPe.entrypointRva &&
    region.candidate.start == candidatePe.entrypointRva

def targetPairClosed (regions : IndexTree RegionRelation) (target : CodeTargetPair) : Bool :=
  match regions.get? target.regionIndex with
  | some region =>
      region.id == target.id && region.original.start == target.originalRva &&
        region.candidate.start == target.candidateRva
  | none => false

def targetCoverageClosed (index : IndexTree RegionRelation) (regions : List RegionRelation) : Bool :=
  regions.all fun region => region.targets.all (targetPairClosed index)

def paddingAliasValid (padding : List Span) (alias canonical : Nat) : Bool :=
  alias < canonical &&
    spansCoverFrom alias canonical (sortSpans (padding.filter fun span =>
      alias <= span.start && span.stop <= canonical))

def targetAliasesClosed (regions : List RegionRelation)
    (originalPadding candidatePadding : List Span) : Bool :=
  regions.all fun region => region.targets.all fun target =>
    target.originalAliases.all (fun alias =>
      paddingAliasValid originalPadding alias.rva target.originalRva) &&
    target.candidateAliases.all (fun alias =>
      paddingAliasValid candidatePadding alias.rva target.candidateRva)

def relocationContains (relocations : List BaseRelocation) (rva : Nat) : Bool :=
  relocations.any fun relocation => relocation.rva == rva && relocation.kind == 3

def relocationCount (relocations : List BaseRelocation) (rva : Nat) : Nat :=
  (relocations.filter fun relocation => relocation.rva == rva && relocation.kind == 3).length

def relocationOffsetsStrictlyIncreasing : List Nat -> Bool
  | [] | [_] => true
  | left :: right :: tail => left < right && relocationOffsetsStrictlyIncreasing (right :: tail)

def relocationOffsetsValid (object : ValueTargetPair) : Bool :=
  relocationOffsetsStrictlyIncreasing object.relocationOffsets &&
    object.relocationOffsets.all fun offset =>
      offset % 4 == 0 && offset + 4 <= object.mappedSize

def mappedObjectContentValidAux (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (object : ValueTargetPair) : Nat -> Nat -> Bool
  | _, 0 => false
  | offset, fuel + 1 =>
      if offset == object.mappedSize then true
      else if object.mappedSize < offset then false
      else
        let originalRva := object.originalValue - originalPe.imageBase + offset
        let candidateRva := object.candidateValue - candidatePe.imageBase + offset
        let declaredRelocated := object.relocationOffsets.contains offset
        let declaredCount := if declaredRelocated then 1 else 0
        if relocationCount originalRelocations originalRva != declaredCount ||
            relocationCount candidateRelocations candidateRva != declaredCount then false
        else if declaredRelocated then
          object.mappedSize - offset >= 4 &&
            match readRvaU32 originalPe originalRva, readRvaU32 candidatePe candidateRva with
            | some original, some candidate =>
                wordRelated originalPe.imageBase candidatePe.imageBase targets values
                  (BitVec.ofNat 32 original) (BitVec.ofNat 32 candidate) &&
                mappedObjectContentValidAux originalPe candidatePe originalRelocations
                  candidateRelocations targets values object (offset + 4) fuel
            | _, _ => false
        else
          rvaByte originalPe originalRva == rvaByte candidatePe candidateRva &&
            mappedObjectContentValidAux originalPe candidatePe originalRelocations
              candidateRelocations targets values object (offset + 1) fuel

def mappedObjectContentValid (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (object : ValueTargetPair) : Bool :=
  relocationOffsetsValid object &&
    (object.mappedSize == 0 || mappedObjectContentValidAux originalPe candidatePe
      originalRelocations candidateRelocations targets values object 0 (object.mappedSize + 1))

def valueTargetValid (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (targets : List CodeTargetPair) (values : List ValueTargetPair)
    (target : ValueTargetPair) : Bool :=
  relocationContains originalRelocations target.originalRelocationRva &&
  relocationContains candidateRelocations target.candidateRelocationRva &&
  readRvaU32 originalPe target.originalRelocationRva == some target.originalValue &&
  readRvaU32 candidatePe target.candidateRelocationRva == some target.candidateValue &&
  (target.mappedSize == 0 ||
    (originalPe.imageBase <= target.originalValue &&
      candidatePe.imageBase <= target.candidateValue &&
      originalPe.sections.any (fun sec =>
        sec.virtualAddress <= target.originalValue - originalPe.imageBase &&
          target.originalValue - originalPe.imageBase + target.mappedSize <=
            sec.virtualAddress + sec.mappedSize) &&
      candidatePe.sections.any (fun sec =>
        sec.virtualAddress <= target.candidateValue - candidatePe.imageBase &&
          target.candidateValue - candidatePe.imageBase + target.mappedSize <=
            sec.virtualAddress + sec.mappedSize))) &&
  mappedObjectContentValid originalPe candidatePe originalRelocations candidateRelocations
    targets values target

def valueTargetPairCompatible (left right : ValueTargetPair) : Bool :=
  left.id == right.id || left.mappedSize == 0 || right.mappedSize == 0 ||
    ((left.originalValue + left.mappedSize <= right.originalValue ||
        right.originalValue + right.mappedSize <= left.originalValue) &&
      (left.candidateValue + left.mappedSize <= right.candidateValue ||
        right.candidateValue + right.mappedSize <= left.candidateValue)) ||
    left.originalValue + right.candidateValue ==
      right.originalValue + left.candidateValue

def valueTargetSpansCompatible (targets : List ValueTargetPair) : Bool :=
  targets.all fun left => targets.all (valueTargetPairCompatible left)

def valueRegionClosed (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (region : RegionRelation) : Bool :=
  valueTargetSpansCompatible region.values && region.values.all
    (valueTargetValid originalPe candidatePe originalRelocations candidateRelocations
      region.targets region.values)

def valueRegionsClosed (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation) : Bool :=
  regions.all (valueRegionClosed originalPe candidatePe originalRelocations candidateRelocations)

def AllMappedRelocationImageRelations (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation) : Prop :=
  ∀ region, region ∈ regions →
    ∀ object, object ∈ region.values →
      object.mappedSize > 0 → object.relocationOffsets ≠ [] →
        valueTargetValid originalPe candidatePe originalRelocations candidateRelocations
          region.targets region.values object = true

theorem allMappedRelocationImageRelations_of_valueRegionsClosed
    (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation)
    (checked : valueRegionsClosed originalPe candidatePe originalRelocations
      candidateRelocations regions = true) :
    AllMappedRelocationImageRelations originalPe candidatePe originalRelocations
      candidateRelocations regions := by
  intro region regionMember object objectMember _ _
  unfold valueRegionsClosed at checked
  simp only [List.all_eq_true] at checked
  have regionChecked := checked region regionMember
  unfold valueRegionClosed at regionChecked
  simp only [Bool.and_eq_true] at regionChecked
  have objectsChecked := regionChecked.2
  simp only [List.all_eq_true] at objectsChecked
  exact objectsChecked object objectMember

def valueTargetsClosed (originalPe candidatePe : PE32) (regions : List RegionRelation) : Bool :=
  match parseRelocations originalPe, parseRelocations candidatePe with
  | some originalRelocations, some candidateRelocations =>
      valueRegionsClosed originalPe candidatePe originalRelocations candidateRelocations regions
  | _, _ => false

def StaticProofContext.dataMappingsValid (context : StaticProofContext) : Bool :=
  context.dataMap.entries.toList.all
    (valueTargetValid context.originalPe context.candidatePe
      context.originalRelocations context.candidateRelocations
      context.codeMap.entries.toList context.dataMap.entries.toList)

def staticDataUsageWitnessValid (context : StaticProofContext)
    (regions : Array RegionRelation) (witnesses : Array Nat) : Bool :=
  witnesses.size == context.dataMap.entries.size &&
    (List.range context.dataMap.entries.size).all fun targetId =>
      match context.dataMap.get? targetId, witnesses[targetId]? with
      | some target, some regionId =>
          match regions[regionId]? with
          | some region => region.values.contains target
          | none => false
      | _, _ => false

def StaticDataUsageWitnessValid (context : StaticProofContext)
    (regions : Array RegionRelation) (witnesses : Array Nat) : Prop :=
  staticDataUsageWitnessValid context regions witnesses = true

theorem staticDataUsageWitnessValid_of_checked (context : StaticProofContext)
    (regions : Array RegionRelation) (witnesses : Array Nat)
    (checked : staticDataUsageWitnessValid context regions witnesses = true) :
    StaticDataUsageWitnessValid context regions witnesses :=
  checked

theorem valueTargetsClosed_of_parsed (originalPe candidatePe : PE32)
    (originalRelocations candidateRelocations : List BaseRelocation)
    (regions : List RegionRelation)
    (originalParsed : parseRelocations originalPe = some originalRelocations)
    (candidateParsed : parseRelocations candidatePe = some candidateRelocations)
    (regionsChecked : valueRegionsClosed originalPe candidatePe originalRelocations
      candidateRelocations regions = true) :
    valueTargetsClosed originalPe candidatePe regions = true := by
  simp [valueTargetsClosed, originalParsed, candidateParsed, regionsChecked]

def insertRegisterPair (pairs : List RegisterPair) (pair : RegisterPair) : List RegisterPair :=
  if pairs.contains pair then pairs else pair :: pairs

def requiredInputPairsFrom (initial : List RegisterPair)
    (regions : List RegionRelation) : List RegisterPair :=
  regions.foldl (fun pairs region => region.inputs.foldl insertRegisterPair pairs) initial

def requiredInputPairs (regions : List RegionRelation) : List RegisterPair :=
  requiredInputPairsFrom [] regions

theorem requiredInputPairsFrom_append (initial : List RegisterPair)
    (left right : List RegionRelation) :
    requiredInputPairsFrom initial (left ++ right) =
      requiredInputPairsFrom (requiredInputPairsFrom initial left) right := by
  simp [requiredInputPairsFrom, List.foldl_append]

def relationCompositionClosed (regions : List RegionRelation) : Bool :=
  let required := requiredInputPairs regions
  regions.all fun source => required.all source.outputs.contains

def targetFlagRelationClosed (regions : IndexTree RegionRelation)
    (source : RegionRelation) (target : CodeTargetPair) : Bool :=
  match regions.get? target.regionIndex with
  | some destination => destination.flagInputs.all source.flagOutputs.contains
  | none => false

def flagRelationCompositionClosed (index : IndexTree RegionRelation)
    (regions : List RegionRelation) : Bool :=
  regions.all fun source => source.targets.all (targetFlagRelationClosed index source)

theorem relationCompositionClosed_of_certificate
    (regions : List RegionRelation) (required : List RegisterPair)
    (requiredChecked : requiredInputPairs regions = required)
    (outputsChecked : regions.all (fun source => required.all source.outputs.contains) = true) :
    relationCompositionClosed regions = true := by
  simp [relationCompositionClosed, requiredChecked, outputsChecked]

def imageStructureClosed (originalPe candidatePe : PE32) : Bool :=
  (executableEntrySection originalPe).isSome &&
    (executableEntrySection candidatePe).isSome

def regionStructureItemsClosed (originalPe candidatePe : PE32)
    (regions : List RegionRelation) : Bool :=
  regions.all (fun region =>
    spanInExecutableSection originalPe region.original &&
    spanInExecutableSection candidatePe region.candidate &&
    region.inputs.length > 0 && region.outputs.length > 0)

def regionStructureClosed (originalPe candidatePe : PE32)
    (regions : List RegionRelation) : Bool :=
  regions.length > 0 && regionStructureItemsClosed originalPe candidatePe regions

def regionIndexClosed (regions : List RegionRelation)
    (index : IndexTree RegionRelation) : Bool :=
  regions == index.toList

def paddingBytesClosed (pe : PE32) (padding : List Span) : Bool :=
  padding.all (paddingSpanValid pe)

def entryRootClosed (originalPe candidatePe : PE32)
    (regions : List RegionRelation) : Bool :=
  regions.any (entryRegionMatches originalPe candidatePe)

theorem listAllAppendTrue (predicate : α -> Bool) (left right : List α)
    (leftChecked : left.all predicate = true)
    (rightChecked : right.all predicate = true) :
    (left ++ right).all predicate = true := by
  simp [leftChecked, rightChecked]

def structuralEligible (bundle : ProofBundle) : Bool :=
  match parsedImages bundle with
  | none => false
  | some (originalPe, candidatePe) =>
      imageStructureClosed originalPe candidatePe &&
      regionIndexClosed bundle.regions bundle.regionIndex &&
      regionStructureClosed originalPe candidatePe bundle.regions &&
      executableCoverageCertified originalPe
        (bundle.regions.map (fun region => region.original) ++ bundle.originalPadding)
        bundle.originalCoverage &&
      executableCoverageCertified candidatePe
        (bundle.regions.map (fun region => region.candidate) ++ bundle.candidatePadding)
        bundle.candidateCoverage &&
      paddingBytesClosed originalPe bundle.originalPadding &&
      paddingBytesClosed candidatePe bundle.candidatePadding &&
      entryRootClosed originalPe candidatePe bundle.regions &&
      targetCoverageClosed bundle.regionIndex bundle.regions &&
      paddingAliasCertificateValid bundle.originalPadding bundle.originalAliasCoverage &&
      paddingAliasCertificateValid bundle.candidatePadding bundle.candidateAliasCoverage &&
      targetAliasesCertified bundle.regions bundle.originalAliasCoverage
        bundle.candidateAliasCoverage &&
      valueTargetsClosed originalPe candidatePe bundle.regions &&
      relationCompositionClosed bundle.regions &&
      flagRelationCompositionClosed bundle.regionIndex bundle.regions

theorem structuralEligible_of_checks (bundle : ProofBundle)
    (originalPe candidatePe : PE32)
    (originalParsed : parsePE32Tree bundle.originalBytes = some originalPe)
    (candidateParsed : parsePE32Tree bundle.candidateBytes = some candidatePe)
    (imagesChecked : imageStructureClosed originalPe candidatePe = true)
    (indexChecked : regionIndexClosed bundle.regions bundle.regionIndex = true)
    (regionsChecked : regionStructureClosed originalPe candidatePe bundle.regions = true)
    (originalCoverageChecked : executableCoverageCertified originalPe
      (bundle.regions.map (fun region => region.original) ++ bundle.originalPadding)
      bundle.originalCoverage = true)
    (candidateCoverageChecked : executableCoverageCertified candidatePe
      (bundle.regions.map (fun region => region.candidate) ++ bundle.candidatePadding)
      bundle.candidateCoverage = true)
    (originalPaddingChecked : paddingBytesClosed originalPe bundle.originalPadding = true)
    (candidatePaddingChecked : paddingBytesClosed candidatePe bundle.candidatePadding = true)
    (entryChecked : entryRootClosed originalPe candidatePe bundle.regions = true)
    (targetsChecked : targetCoverageClosed bundle.regionIndex bundle.regions = true)
    (originalAliasCoverageChecked :
      paddingAliasCertificateValid bundle.originalPadding bundle.originalAliasCoverage = true)
    (candidateAliasCoverageChecked :
      paddingAliasCertificateValid bundle.candidatePadding bundle.candidateAliasCoverage = true)
    (targetAliasesChecked : targetAliasesCertified bundle.regions
      bundle.originalAliasCoverage bundle.candidateAliasCoverage = true)
    (valuesChecked : valueTargetsClosed originalPe candidatePe bundle.regions = true)
    (compositionChecked : relationCompositionClosed bundle.regions = true)
    (flagCompositionChecked :
      flagRelationCompositionClosed bundle.regionIndex bundle.regions = true) :
    structuralEligible bundle = true := by
  unfold structuralEligible parsedImages
  rw [originalParsed, candidateParsed]
  simp [imagesChecked, indexChecked, regionsChecked, originalCoverageChecked,
    candidateCoverageChecked, originalPaddingChecked, candidatePaddingChecked,
    entryChecked, targetsChecked, originalAliasCoverageChecked,
    candidateAliasCoverageChecked, targetAliasesChecked, valuesChecked,
    compositionChecked, flagCompositionChecked]

def regionGoal (bundle : ProofBundle) (region : RegionRelation) : Prop :=
  match parsedImages bundle with
  | some (originalPe, candidatePe) =>
      regionEquivalentWithImports originalPe candidatePe bundle.originalImports.imports
        bundle.candidateImports.imports bundle.machineImportCallContracts region
  | none => False

def allRegionGoals (bundle : ProofBundle) : List RegionRelation -> Prop
  | [] => True
  | region :: tail => regionGoal bundle region ∧ allRegionGoals bundle tail

def allDirectRegionGoals (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract) : List RegionRelation -> Prop
  | [] => True
  | region :: tail =>
      regionEquivalentWithImports originalPe candidatePe originalImports candidateImports
          machineCallContracts region ∧
        allDirectRegionGoals originalPe candidatePe originalImports candidateImports
          machineCallContracts tail

theorem allDirectRegionGoals_append (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (machineCallContracts : List MachineImportCallContract) (left right : List RegionRelation)
    (leftChecked : allDirectRegionGoals originalPe candidatePe originalImports
      candidateImports machineCallContracts left)
    (rightChecked : allDirectRegionGoals originalPe candidatePe originalImports
      candidateImports machineCallContracts right) :
    allDirectRegionGoals originalPe candidatePe originalImports candidateImports
      machineCallContracts (left ++ right) := by
  induction left with
  | nil => simpa [allDirectRegionGoals] using rightChecked
  | cons region tail ih =>
      exact ⟨leftChecked.1, ih leftChecked.2⟩

theorem allRegionGoals_of_direct_for (bundle : ProofBundle)
    (originalPe candidatePe : PE32)
    (originalParsed : parsePE32Tree bundle.originalBytes = some originalPe)
    (candidateParsed : parsePE32Tree bundle.candidateBytes = some candidatePe) :
    ∀ regions,
      allDirectRegionGoals originalPe candidatePe bundle.originalImports.imports
        bundle.candidateImports.imports bundle.machineImportCallContracts regions ->
      allRegionGoals bundle regions := by
  intro regions
  induction regions with
  | nil => intro _; trivial
  | cons region tail ih =>
      intro direct
      constructor
      · unfold regionGoal parsedImages
        rw [originalParsed, candidateParsed]
        exact direct.1
      · exact ih direct.2

theorem allRegionGoals_of_direct (bundle : ProofBundle)
    (originalPe candidatePe : PE32)
    (originalParsed : parsePE32Tree bundle.originalBytes = some originalPe)
    (candidateParsed : parsePE32Tree bundle.candidateBytes = some candidatePe)
    (direct : allDirectRegionGoals originalPe candidatePe bundle.originalImports.imports
      bundle.candidateImports.imports bundle.machineImportCallContracts bundle.regions) :
    allRegionGoals bundle bundle.regions :=
  allRegionGoals_of_direct_for bundle originalPe candidatePe originalParsed candidateParsed
    bundle.regions direct

def importTablesCertified (bundle : ProofBundle) : Prop :=
  match parsedImages bundle with
  | some (originalPe, candidatePe) =>
      importTableValid originalPe bundle.originalImports = true ∧
        importTableValid candidatePe bundle.candidateImports = true
  | none => False

def RelationalImageCertificate (bundle : ProofBundle) : Prop :=
  structuralEligible bundle = true ∧
  importTablesCertified bundle ∧
  allRegionGoals bundle bundle.regions

theorem relationalImageCertificate_intro (bundle : ProofBundle)
    (structural : structuralEligible bundle = true)
    (imports : importTablesCertified bundle)
    (regions : allRegionGoals bundle bundle.regions) :
    RelationalImageCertificate bundle :=
  And.intro structural (And.intro imports regions)

end StageA.Relational
