import StageA.RelationalNativeSourceReachableBoundaryDomain

namespace StageA.Relational.CanonicalExternalResponseSynthesis

open StageA.Formal
open StageA.Relational
open StageA.Relational.NativeSource

/-! # Canonical external-response synthesis

Machine-call contracts describe the permitted ABI, memory, and relational-world
effects of an external call.  This module turns a checked, state-indexed effect
plan into a pair of concrete returning results.  It does not model any named
API and it does not infer external behavior from an import name.

The construction deliberately keeps each side's flat memory unchanged.  This
is a valid member of every currently supported returning memory-effect class:
read and argument-range contracts still require their runtime footprints to be
valid, while a no-write response is permitted inside those footprints.  World
updates remain explicit because allocation, release, callback registration,
opaque resources, and TLS can change the pointer relation used by result words.
-/

structure PairedResultRegister where
  register : Reg
  original : Word
  candidate : Word
deriving Repr, DecidableEq

def applyResultRegisters (candidate : Bool) (before : Registers Word)
    (results : List PairedResultRegister) : Registers Word :=
  results.foldl (fun registers result =>
    registers.set result.register
      (if candidate then result.candidate else result.original)) before

def canonicalResultState (candidate : Bool)
    (contract : MachineImportCallContract) (before : MachineState)
    (results : List PairedResultRegister) : MachineState := {
  before with
  registers := (applyResultRegisters candidate before.registers results).set
    .esp (before.registers.esp + BitVec.ofNat 32 contract.stackResultDelta)
}

structure CheckedCanonicalRegisterResults
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (arguments : List Word) (world : RelationalWorld)
    (originalBefore candidateBefore : MachineState) where
  results : List PairedResultRegister
  originalABI : machineCallAbiResultHolds contract originalBefore
    (canonicalResultState false contract originalBefore results) = true
  candidateABI : machineCallAbiResultHolds contract candidateBefore
    (canonicalResultState true contract candidateBefore results) = true
  related : machineCallResultRegistersRelated context world contract arguments
    (canonicalResultState false contract originalBefore results)
    (canonicalResultState true contract candidateBefore results) = true

def canonicalRegisterResultsChecked
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (arguments : List Word) (world : RelationalWorld)
    (originalBefore candidateBefore : MachineState)
    (results : List PairedResultRegister) : Bool :=
  machineCallAbiResultHolds contract originalBefore
      (canonicalResultState false contract originalBefore results) &&
    machineCallAbiResultHolds contract candidateBefore
      (canonicalResultState true contract candidateBefore results) &&
    machineCallResultRegistersRelated context world contract arguments
      (canonicalResultState false contract originalBefore results)
      (canonicalResultState true contract candidateBefore results)

def CheckedCanonicalRegisterResults.of_checked
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (arguments : List Word) (world : RelationalWorld)
    (originalBefore candidateBefore : MachineState)
    (results : List PairedResultRegister)
    (checked : canonicalRegisterResultsChecked context contract arguments world
      originalBefore candidateBefore results = true) :
    CheckedCanonicalRegisterResults context contract arguments world
      originalBefore candidateBefore := by
  simp only [canonicalRegisterResultsChecked, Bool.and_eq_true] at checked
  exact {
    results
    originalABI := checked.1.1
    candidateABI := checked.1.2
    related := checked.2
  }

inductive PairedWorldUpdatePlan where
  | preserve
  | addDynamicRanges (ranges : List DynamicAddressRangePair)
  | releaseDynamicRange (range : DynamicAddressRangePair)
  | addOpaqueResources (resources : List OpaqueResourcePair)
  | registerCallback (callback : RegisteredCallbackPair)
  | setTlsState (state : RelationalTlsState)
deriving Repr, DecidableEq

def PairedWorldUpdatePlan.after (before : RelationalWorld) :
    PairedWorldUpdatePlan -> RelationalWorld
  | .preserve => before
  | .addDynamicRanges ranges => {
      before with dynamicRanges := before.dynamicRanges ++ ranges
    }
  | .releaseDynamicRange range => {
      before with dynamicRanges := before.dynamicRanges.erase range
    }
  | .addOpaqueResources resources => {
      before with opaqueResources := before.opaqueResources ++ resources
    }
  | .registerCallback callback => {
      before with registeredCallbacks := callback :: before.registeredCallbacks
    }
  | .setTlsState state => { before with tlsState := state }

def PairedWorldUpdatePlan.addedDynamicRanges :
    PairedWorldUpdatePlan -> List DynamicAddressRangePair
  | .addDynamicRanges ranges => ranges
  | _ => []

def PairedWorldUpdatePlan.matches
    (context : StaticProofContext) (effect : MachineCallWorldEffect)
    (originalArguments candidateArguments : List Word)
    (before : RelationalWorld) (plan : PairedWorldUpdatePlan) : Bool :=
  let after := plan.after before
  after.valid context && match effect, plan with
  | .none, .preserve => true
  | .opaqueResources, .preserve => true
  | .opaqueResources, .addOpaqueResources resources =>
      resources.all fun resource => !before.opaqueResources.contains resource
  | .dynamicRanges, .preserve => true
  | .dynamicRanges, .addDynamicRanges ranges =>
      ranges.all fun range => !before.dynamicRanges.contains range
  | .dynamicRangeRelease argumentIndex, .preserve =>
      originalArguments[argumentIndex]? == some (BitVec.ofNat 32 0) &&
        candidateArguments[argumentIndex]? == some (BitVec.ofNat 32 0)
  | .dynamicRangeRelease argumentIndex, .releaseDynamicRange range =>
      before.dynamicRanges.contains range &&
        range.originalBase != BitVec.ofNat 32 0 &&
        range.candidateBase != BitVec.ofNat 32 0 &&
        originalArguments[argumentIndex]? == some range.originalBase &&
        candidateArguments[argumentIndex]? == some range.candidateBase
  | .callbackRegistration argumentIndex, .registerCallback callback =>
      originalArguments[argumentIndex]? == some callback.originalAddress &&
        candidateArguments[argumentIndex]? == some callback.candidateAddress &&
        callback.valid context
  | .tlsState, .preserve => true
  | .tlsState, .setTlsState _ => true
  | _, _ => false

structure CheckedPairedWorldUpdate
    (context : StaticProofContext) (effect : MachineCallWorldEffect)
    (originalArguments candidateArguments : List Word)
    (before : RelationalWorld) where
  plan : PairedWorldUpdatePlan
  checked : plan.matches context effect originalArguments candidateArguments
    before = true

def CheckedPairedWorldUpdate.after
    {context : StaticProofContext} {effect : MachineCallWorldEffect}
    {originalArguments candidateArguments : List Word}
    {before : RelationalWorld}
    (update : CheckedPairedWorldUpdate context effect originalArguments
      candidateArguments before) : RelationalWorld :=
  update.plan.after before

theorem CheckedPairedWorldUpdate.after_valid
    {context : StaticProofContext} {effect : MachineCallWorldEffect}
    {originalArguments candidateArguments : List Word}
    {before : RelationalWorld}
    (update : CheckedPairedWorldUpdate context effect originalArguments
      candidateArguments before) :
    update.after.valid context = true := by
  have checked := update.checked
  simp only [PairedWorldUpdatePlan.matches, Bool.and_eq_true] at checked
  exact checked.1

theorem CheckedPairedWorldUpdate.original_holds
    {context : StaticProofContext} {effect : MachineCallWorldEffect}
    {originalArguments candidateArguments : List Word}
    {before : RelationalWorld}
    (update : CheckedPairedWorldUpdate context effect originalArguments
      candidateArguments before) :
    machineCallWorldEffectHolds false context effect originalArguments before
      update.after := by
  rcases update with ⟨plan, checked⟩
  simp only [PairedWorldUpdatePlan.matches, Bool.and_eq_true] at checked
  constructor
  · exact checked.1
  · cases effect <;> cases plan <;>
      simp_all [CheckedPairedWorldUpdate.after, PairedWorldUpdatePlan.after,
        dynamicRangesExtend, opaqueResourcesExtend, dynamicRangeReleaseHolds,
        callbackRegistrationHolds, List.mem_append]
    all_goals
      rename_i range checkedRaw
      exact ⟨range, checked.2.1.1.1.1, rfl, rfl⟩

theorem CheckedPairedWorldUpdate.candidate_holds
    {context : StaticProofContext} {effect : MachineCallWorldEffect}
    {originalArguments candidateArguments : List Word}
    {before : RelationalWorld}
    (update : CheckedPairedWorldUpdate context effect originalArguments
      candidateArguments before) :
    machineCallWorldEffectHolds true context effect candidateArguments before
      update.after := by
  rcases update with ⟨plan, checked⟩
  simp only [PairedWorldUpdatePlan.matches, Bool.and_eq_true] at checked
  constructor
  · exact checked.1
  · cases effect <;> cases plan <;>
      simp_all [CheckedPairedWorldUpdate.after, PairedWorldUpdatePlan.after,
        dynamicRangesExtend, opaqueResourcesExtend, dynamicRangeReleaseHolds,
        callbackRegistrationHolds, List.mem_append]
    all_goals
      rename_i range checkedRaw
      exact ⟨range, checked.2.1.1.1.1, rfl, rfl⟩

theorem unchangedMemoryEffectHolds
    (candidate : Bool) (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (afterWorld : RelationalWorld)
    (admissible : MachineMemoryEffectInputAdmissible contract event) :
    machineCallMemoryEffectHoldsWithWorld candidate contract event.arguments
      event.world afterWorld event.state.memory event.state.memory := by
  cases effect : contract.memoryEffect <;>
    simp_all [MachineMemoryEffectInputAdmissible,
      machineCallMemoryEffectHoldsWithWorld, machineCallMemoryEffectHolds]

def freshDynamicResultRegistersChecked
    (contract : MachineImportCallContract) (arguments : List Word)
    (plan : PairedWorldUpdatePlan) (original candidate : MachineState) : Bool :=
  if contract.memoryEffect == .newDynamicRanges then
    let addedWorld : RelationalWorld := {
      dynamicRanges := plan.addedDynamicRanges
    }
    contract.resultRegisterRelations.all fun relation =>
      match relation.relation with
      | .dynamicRangeBase size minimumSize requiredWords nullable =>
          dynamicRangeBaseResultHolds arguments addedWorld size minimumSize
            requiredWords nullable (original.registers.get relation.register)
            (candidate.registers.get relation.register)
      | .exact | .relatedWord => true
  else true

structure CheckedCanonicalExternalResponsePair
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (originalEvent candidateEvent : WorldExternalEvent) where
  contractValid : contract.shapeValid = true
  siteIdExact : originalEvent.siteId = candidateEvent.siteId
  originalImportExact : originalEvent.imported = contract.imported
  candidateImportExact : candidateEvent.imported = contract.imported
  beforeWorldExact : originalEvent.world = candidateEvent.world
  argumentsRelated : externalCallArgumentsRelated context originalEvent.world
    originalEvent.arguments candidateEvent.arguments = true
  registerResults : List PairedResultRegister
  originalResult : WorldExternalResult
  candidateResult : WorldExternalResult
  worldPlan : PairedWorldUpdatePlan
  originalStateCanonical : originalResult.state = canonicalResultState false
    contract originalEvent.state registerResults
  candidateStateCanonical : candidateResult.state = canonicalResultState true
    contract candidateEvent.state registerResults
  resultWorldFromPlan : originalResult.world = worldPlan.after originalEvent.world
  resultWorldExact : originalResult.world = candidateResult.world
  originalConforms : machineCallResultConforms false context contract
    originalEvent originalResult
  candidateConforms : machineCallResultConforms true context contract
    candidateEvent candidateResult
  resultRegistersRelated : machineCallResultRegistersRelated context
    originalResult.world contract originalEvent.arguments originalResult.state
    candidateResult.state = true
  freshDynamicResults : freshDynamicResultRegistersChecked contract
    originalEvent.arguments worldPlan originalResult.state candidateResult.state =
      true

def synthesizeCanonicalExternalResponsePair
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (originalEvent candidateEvent : WorldExternalEvent)
    (contractValid : contract.shapeValid = true)
    (siteIdExact : originalEvent.siteId = candidateEvent.siteId)
    (originalImportExact : originalEvent.imported = contract.imported)
    (candidateImportExact : candidateEvent.imported = contract.imported)
    (sameBeforeWorld : originalEvent.world = candidateEvent.world)
    (argumentsRelated : externalCallArgumentsRelated context originalEvent.world
      originalEvent.arguments candidateEvent.arguments = true)
    (returns : contract.disposition = .returns)
    (originalMemoryAdmissible : MachineMemoryEffectInputAdmissible contract
      originalEvent)
    (candidateMemoryAdmissible : MachineMemoryEffectInputAdmissible contract
      candidateEvent)
    (worldUpdate : CheckedPairedWorldUpdate context contract.worldEffect
      originalEvent.arguments candidateEvent.arguments originalEvent.world)
    (registers : CheckedCanonicalRegisterResults context contract
      originalEvent.arguments worldUpdate.after originalEvent.state
      candidateEvent.state)
    (freshDynamicResults : freshDynamicResultRegistersChecked contract
      originalEvent.arguments worldUpdate.plan
      (canonicalResultState false contract originalEvent.state registers.results)
      (canonicalResultState true contract candidateEvent.state registers.results) =
        true) :
    CheckedCanonicalExternalResponsePair context contract originalEvent
      candidateEvent := by
  let originalResult : WorldExternalResult := {
    state := canonicalResultState false contract originalEvent.state
      registers.results
    world := worldUpdate.after
  }
  let candidateResult : WorldExternalResult := {
    state := canonicalResultState true contract candidateEvent.state
      registers.results
    world := worldUpdate.after
  }
  refine {
    contractValid
    siteIdExact
    originalImportExact
    candidateImportExact
    beforeWorldExact := sameBeforeWorld
    argumentsRelated
    registerResults := registers.results
    originalResult
    candidateResult
    worldPlan := worldUpdate.plan
    originalStateCanonical := rfl
    candidateStateCanonical := rfl
    resultWorldFromPlan := rfl
    resultWorldExact := rfl
    originalConforms := ?_
    candidateConforms := ?_
    resultRegistersRelated := registers.related
    freshDynamicResults := freshDynamicResults
  }
  · exact ⟨returns, registers.originalABI,
      unchangedMemoryEffectHolds false contract originalEvent worldUpdate.after
        originalMemoryAdmissible,
      worldUpdate.original_holds⟩
  · exact ⟨returns, registers.candidateABI,
      unchangedMemoryEffectHolds true contract candidateEvent worldUpdate.after
        candidateMemoryAdmissible,
      by simpa only [sameBeforeWorld] using worldUpdate.candidate_holds⟩

theorem CheckedCanonicalExternalResponsePair.exactPairConforms
    {context : StaticProofContext} {contract : MachineImportCallContract}
    {originalEvent candidateEvent : WorldExternalEvent}
    (pair : CheckedCanonicalExternalResponsePair context contract originalEvent
      candidateEvent) :
    ExactExternalCallPairConforms context contract originalEvent candidateEvent
      pair.originalResult pair.candidateResult := {
  siteId := pair.siteIdExact
  originalImported := pair.originalImportExact
  candidateImported := pair.candidateImportExact
  eventWorld := pair.beforeWorldExact
  resultWorld := pair.resultWorldExact
  originalConforms := pair.originalConforms
  candidateConforms := pair.candidateConforms
}

end StageA.Relational.CanonicalExternalResponseSynthesis
