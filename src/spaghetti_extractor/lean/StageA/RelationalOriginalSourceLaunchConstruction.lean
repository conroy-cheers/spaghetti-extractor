import StageA.RelationalOriginalSourceLaunchContext

namespace StageA.Relational.OriginalSourceLaunchConstruction

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalSourceLaunchContext
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.ValueProvenance

/-!
# Checked source-launch construction

This module turns finite, decidable launch proposals into the six inventory
propositions required by `OriginalCombinedPE32ConsoleLaunchSeed`.  The seventh,
runtime-memory partition proposition follows directly from the checked launch
world.  The module is independent of any particular executable.  Generated
modules supply only concrete data and proofs that these Boolean checkers
evaluate to `true`.
-/

/-- Every code-map entry at the original PE entrypoint is represented by the
declared reachable inventory. -/
def entryReachabilityChecked (context : StaticProofContext)
    (targetIds : List Nat) : Bool :=
  context.codeMap.entries.toList.all fun target =>
    target.originalRva != context.originalPe.entrypointRva ||
      targetIds.contains target.id

/-- No entrypoint target activates a value-flow fact. -/
def entryValueFlowsVacuousChecked (context : StaticProofContext)
    (inventory : OriginalValueFlowInventory context) : Bool :=
  context.codeMap.entries.toList.all fun target =>
    target.originalRva != context.originalPe.entrypointRva ||
      inventory.facts.all fun fact => !fact.targetIds.contains target.id

/-- No entrypoint target activates a register-mediated indirect-control fact. -/
def entryRegisterTargetsVacuousChecked
    (carrier : StaticProofContext)
    (context : OriginalDecodedStaticContext)
    (requirements : List (OriginalRegisterTargetRequirement context)) : Bool :=
  carrier.codeMap.entries.toList.all fun target =>
    target.originalRva != carrier.originalPe.entrypointRva ||
      requirements.all fun requirement =>
        requirement.certificate.certificate.site.sourceTargetId != target.id

/-- No entrypoint target activates a stack/dynamic indirect-control fact. -/
def entryStackDynamicTargetsVacuousChecked
    (carrier : StaticProofContext)
    (context : OriginalDecodedStaticContext)
    (requirements : List (OriginalStackDynamicTargetRequirement context)) : Bool :=
  carrier.codeMap.entries.toList.all fun target =>
    target.originalRva != carrier.originalPe.entrypointRva ||
      requirements.all fun requirement =>
        requirement.site.sourceTargetId != target.id

private theorem target_id_eq_of_entry
    (context : StaticProofContext) (valid : context.StructurallyValid)
    (targetId : Nat) (target : CodeTargetPair)
    (found : context.codeMap.get? targetId = some target) :
    target.id = targetId := by
  have before := FiniteIndex.get?_eq_some_implies_lt_size
    context.codeMap.entries targetId target found
  have checked := context.codeMapIndexed_of_structurallyValid valid
  have row := checked.2.2.2.1 targetId before
  simpa [StaticCodeMap.entryAtValid, found] using row

private theorem target_mem_of_found
    (context : StaticProofContext) (targetId : Nat) (target : CodeTargetPair)
    (found : context.codeMap.get? targetId = some target) :
    target ∈ context.codeMap.entries.toList :=
  FiniteIndex.get?_eq_some_implies_mem_toList
    context.codeMap.entries targetId target found

theorem entryReachabilityChecked_sound
    (context : StaticProofContext) (valid : context.StructurallyValid)
    (targetIds : List Nat)
    (checked : entryReachabilityChecked context targetIds = true)
    (targetId : Nat) (target : CodeTargetPair)
    (found : context.codeMap.get? targetId = some target)
    (entry : target.originalRva = context.originalPe.entrypointRva) :
    targetId ∈ targetIds := by
  simp only [entryReachabilityChecked, List.all_eq_true] at checked
  have row := checked target (target_mem_of_found context targetId target found)
  simp [entry] at row
  simpa [target_id_eq_of_entry context valid targetId target found] using row

theorem entryValueFlowsVacuousChecked_sound
    (context : StaticProofContext) (valid : context.StructurallyValid)
    (inventory : OriginalValueFlowInventory context)
    (checked : entryValueFlowsVacuousChecked context inventory = true)
    (targetId : Nat) (target : CodeTargetPair)
    (found : context.codeMap.get? targetId = some target)
    (entry : target.originalRva = context.originalPe.entrypointRva) :
    inventory.Holds (.running targetId state [] 0 world) := by
  intro fact member active
  simp only [entryValueFlowsVacuousChecked, List.all_eq_true] at checked
  have row := checked target (target_mem_of_found context targetId target found)
  simp [entry, List.all_eq_true] at row
  have absent := row fact member
  have idExact := target_id_eq_of_entry context valid targetId target found
  have notMember : target.id ∉ fact.targetIds := by simpa using absent
  exact (notMember (by simpa [idExact] using active)).elim

theorem entryRegisterTargetsVacuousChecked_sound
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (valid : carrier.StructurallyValid)
    (requirements : List (OriginalRegisterTargetRequirement context))
    (checked : entryRegisterTargetsVacuousChecked carrier context
      requirements = true)
    (targetId : Nat) (target : CodeTargetPair)
    (found : carrier.codeMap.get? targetId = some target)
    (entry : target.originalRva = carrier.originalPe.entrypointRva) :
    OriginalRegisterTargetsHold requirements
      (.running targetId state [] 0 world) := by
  intro requirement member active
  simp only [entryRegisterTargetsVacuousChecked, List.all_eq_true] at checked
  have row := checked target (target_mem_of_found carrier targetId target found)
  simp [entry, List.all_eq_true] at row
  have absent := row requirement member
  have idExact := target_id_eq_of_entry carrier valid targetId target found
  exact (absent (by simpa [idExact] using active.symm)).elim

theorem entryStackDynamicTargetsVacuousChecked_sound
    (context : OriginalDecodedStaticContext)
    (carrier : StaticProofContext)
    (valid : carrier.StructurallyValid)
    (requirements : List (OriginalStackDynamicTargetRequirement context))
    (checked : entryStackDynamicTargetsVacuousChecked carrier context
      requirements = true)
    (targetId : Nat) (target : CodeTargetPair)
    (found : carrier.codeMap.get? targetId = some target)
    (entry : target.originalRva = carrier.originalPe.entrypointRva) :
    OriginalStackDynamicTargetsHold requirements
      (.running targetId state [] 0 world) := by
  intro requirement member active
  simp only [entryStackDynamicTargetsVacuousChecked, List.all_eq_true] at checked
  have row := checked target (target_mem_of_found carrier targetId target found)
  simp [entry, List.all_eq_true] at row
  have absent := row requirement member
  have idExact := target_id_eq_of_entry carrier valid targetId target found
  exact (absent (by simpa [idExact] using active.symm)).elim

/-- Static origins have a canonical companion independent of the runtime
world.  Runtime-selected imports, ranges, resources, and callbacks are rejected
by this launch checker and must use an explicit world-dependent seed. -/
def staticOriginalOriginCompanion? (context : StaticProofContext)
    (original : Word) : ValueOriginAtom -> Option Word
  | .exactBits value =>
      if original == BitVec.ofNat 32 value then some original else none
  | .staticCodeTarget targetId offset => do
      let target <- context.codeMap.get? targetId
      let originalValue := BitVec.ofNat 32
        (context.originalPe.imageBase + target.originalRva + offset)
      let candidateValue := BitVec.ofNat 32
        (context.candidatePe.imageBase + target.candidateRva + offset)
      if original == originalValue then some candidateValue else none
  | .staticDataLocation targetId offset => do
      let target <- context.dataMap.get? targetId
      let originalValue := BitVec.ofNat 32 (target.originalValue + offset)
      let candidateValue := BitVec.ofNat 32 (target.candidateValue + offset)
      if original == originalValue then some candidateValue else none
  | _ => none

theorem staticOriginalOriginCompanion?_sound
    (context : StaticProofContext) (world : RelationalWorld)
    (original companion : Word) (origin : ValueOriginAtom)
    (checked : staticOriginalOriginCompanion? context original origin =
      some companion) :
    OriginalValueOriginAtomHolds context world original origin := by
  refine ⟨companion, ?_⟩
  cases origin with
  | exactBits value =>
      simp [staticOriginalOriginCompanion?] at checked
      rcases checked with ⟨rfl, rfl⟩
      simp [ValueOriginAtom.Holds]
  | staticCodeTarget targetId offset =>
      simp only [staticOriginalOriginCompanion?] at checked
      cases found : context.codeMap.get? targetId with
      | none => simp [found] at checked
      | some target =>
          simp [found] at checked
          rcases checked with ⟨rfl, rfl⟩
          refine ⟨target, found, ?_⟩
          by_cases zero : offset = 0
          · subst offset
            left
            simp [codeAddressMatches]
          · right
            exact ⟨Nat.pos_of_ne_zero zero, rfl, rfl⟩
  | staticDataLocation targetId offset =>
      simp only [staticOriginalOriginCompanion?] at checked
      cases found : context.dataMap.get? targetId with
      | none => simp [found] at checked
      | some target =>
          simp [found] at checked
          rcases checked with ⟨rfl, rfl⟩
          exact ⟨target, found, rfl, rfl⟩
  | importTarget identity => simp [staticOriginalOriginCompanion?] at checked
  | stackFrameLocation rangeId offset =>
      simp [staticOriginalOriginCompanion?] at checked
  | dynamicRangeLocation rangeId offset =>
      simp [staticOriginalOriginCompanion?] at checked
  | opaqueResource resourceId =>
      simp [staticOriginalOriginCompanion?] at checked
  | registeredCallback targetId =>
      simp [staticOriginalOriginCompanion?] at checked

def staticOriginalOriginAt? (context : StaticProofContext) (value : Word)
    (origins : List ValueOriginAtom) : Option (ValueOriginAtom × Word) :=
  origins.findSome? fun origin => do
    let companion <- staticOriginalOriginCompanion? context value origin
    pure (origin, companion)

theorem staticOriginalOriginAt?_sound
    (context : StaticProofContext) (world : RelationalWorld)
    (value : Word) (origins : List ValueOriginAtom)
    (origin : ValueOriginAtom) (companion : Word)
    (checked : staticOriginalOriginAt? context value origins =
      some (origin, companion)) :
    origin ∈ origins ∧ OriginalValueOriginAtomHolds context world value origin := by
  unfold staticOriginalOriginAt? at checked
  rcases List.exists_of_findSome?_eq_some checked with
    ⟨selected, member, selectedExact⟩
  cases companionFound : staticOriginalOriginCompanion? context value selected with
  | none => simp [companionFound] at selectedExact
  | some selectedCompanion =>
      simp [companionFound] at selectedExact
      rcases selectedExact with ⟨rfl, rfl⟩
      exact ⟨member, staticOriginalOriginCompanion?_sound context world
        value selectedCompanion selected companionFound⟩

/-- Exact four-byte preferred-image read, including writable image sections.
The explicit IAT exclusion is essential because loader writes supersede PE
bytes there. -/
theorem preferredBaseImageMemory_read32_of_checked
    (pe : PE32) (imports : List PEImport) (memory : Memory)
    (rva expected : Nat)
    (mapped : PreferredBaseImageMemory pe imports memory)
    (bounded : pe.imageBase + pe.sizeOfImage <= 2 ^ 32)
    (inside : rva + 4 <= pe.sizeOfImage)
    (excluded : imageRangeExcludesIat imports rva 4 = true)
    (readChecked : readRvaLittleEndian pe rva 4 = some expected)
    (bytesValid : pe32ByteTreeValid pe.bytes = true) :
    Memory.read32 memory (BitVec.ofNat 32 (pe.imageBase + rva)) =
      BitVec.ofNat 32 expected := by
  have absoluteBefore : pe.imageBase + rva < 2 ^ 32 := by omega
  have address1Before : pe.imageBase + rva + 1 < 2 ^ 32 := by omega
  have address2Before : pe.imageBase + rva + 2 < 2 ^ 32 := by omega
  have address3Before : pe.imageBase + rva + 3 < 2 ^ 32 := by omega
  have rangeFour : List.range 4 = [0, 1, 2, 3] := by decide
  unfold readRvaLittleEndian at readChecked
  simp only [rangeFour, List.mapM_cons, List.mapM_nil] at readChecked
  cases byte0Result : rvaByte pe (rva + 0) with
  | none =>
    have byte0Read : rvaByte pe rva = none := by simpa using byte0Result
    simp [byte0Read] at readChecked
  | some byte0 =>
    have byte0Read : rvaByte pe rva = some byte0 := by simpa using byte0Result
    cases byte1Result : rvaByte pe (rva + 1) with
    | none => simp [byte0Read, byte1Result] at readChecked
    | some byte1 =>
      cases byte2Result : rvaByte pe (rva + 2) with
      | none => simp [byte0Read, byte1Result, byte2Result] at readChecked
      | some byte2 =>
        cases byte3Result : rvaByte pe (rva + 3) with
        | none => simp [byte0Read, byte1Result, byte2Result, byte3Result]
            at readChecked
        | some byte3 =>
          have notIat0 := importIatByteCovered_false_of_range_excludes
            imports rva 4 0 excluded (by omega)
          have notIat1 := importIatByteCovered_false_of_range_excludes
            imports rva 4 1 excluded (by omega)
          have notIat2 := importIatByteCovered_false_of_range_excludes
            imports rva 4 2 excluded (by omega)
          have notIat3 := importIatByteCovered_false_of_range_excludes
            imports rva 4 3 excluded (by omega)
          have memory0 : memory (BitVec.ofNat 32 (pe.imageBase + rva)) =
              BitVec.ofNat 8 byte0 := by
            exact mapped rva byte0 (by omega) (by simpa using notIat0) byte0Read
          have memory1 : memory
                (BitVec.ofNat 32 (pe.imageBase + rva) + BitVec.ofNat 32 1) =
              BitVec.ofNat 8 byte1 := by
            have row := mapped (rva + 1) byte1 (by omega)
              (by simpa using notIat1) byte1Result
            have addressEq : (BitVec.ofNat 32 (pe.imageBase + rva + 1) : Word) =
                BitVec.ofNat 32 (pe.imageBase + rva) + BitVec.ofNat 32 1 := by
              apply BitVec.eq_of_toNat_eq
              simp [BitVec.toNat_add, BitVec.toNat_ofNat,
                Nat.mod_eq_of_lt absoluteBefore,
                Nat.mod_eq_of_lt address1Before]
            rw [← addressEq]
            simpa [Nat.add_assoc] using row
          have memory2 : memory
                (BitVec.ofNat 32 (pe.imageBase + rva) + BitVec.ofNat 32 2) =
              BitVec.ofNat 8 byte2 := by
            have row := mapped (rva + 2) byte2 (by omega)
              (by simpa using notIat2) byte2Result
            have addressEq : (BitVec.ofNat 32 (pe.imageBase + rva + 2) : Word) =
                BitVec.ofNat 32 (pe.imageBase + rva) + BitVec.ofNat 32 2 := by
              apply BitVec.eq_of_toNat_eq
              simp [BitVec.toNat_add, BitVec.toNat_ofNat,
                Nat.mod_eq_of_lt absoluteBefore,
                Nat.mod_eq_of_lt address2Before]
            rw [← addressEq]
            simpa [Nat.add_assoc] using row
          have memory3 : memory
                (BitVec.ofNat 32 (pe.imageBase + rva) + BitVec.ofNat 32 3) =
              BitVec.ofNat 8 byte3 := by
            have row := mapped (rva + 3) byte3 (by omega)
              (by simpa using notIat3) byte3Result
            have addressEq : (BitVec.ofNat 32 (pe.imageBase + rva + 3) : Word) =
                BitVec.ofNat 32 (pe.imageBase + rva) + BitVec.ofNat 32 3 := by
              apply BitVec.eq_of_toNat_eq
              simp [BitVec.toNat_add, BitVec.toNat_ofNat,
                Nat.mod_eq_of_lt absoluteBefore,
                Nat.mod_eq_of_lt address3Before]
            rw [← addressEq]
            simpa [Nat.add_assoc] using row
          have byte0Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte0Read
          have byte1Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte1Result
          have byte2Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte2Result
          have byte3Bound := pe32ByteTreeValid_rvaByte_lt pe bytesValid byte3Result
          simp [byte0Read, byte1Result, byte2Result, byte3Result,
            littleEndianValue] at readChecked
          simp only [Memory.read32, memory0, memory1, memory2, memory3,
            BitVec.zeroExtend_eq_setWidth]
          rw [← readChecked]
          rw [fourBytesAssembleLittleEndian byte0 byte1 byte2 byte3
            byte0Bound byte1Bound byte2Bound byte3Bound]
          congr 1
          omega

def staticWordImageValue (context : StaticProofContext)
    (requirement : OriginalStaticWordRequirement) : Nat :=
  (readRvaLittleEndian context.originalPe requirement.slot.id 4).getD 0

def staticWordImageOrigin (context : StaticProofContext)
    (requirement : OriginalStaticWordRequirement) : ValueOriginAtom × Word :=
  (staticOriginalOriginAt? context
    (BitVec.ofNat 32 (staticWordImageValue context requirement))
    requirement.origins).getD (.exactBits 0, BitVec.ofNat 32 0)

def staticWordImageSeedChecked (context : StaticProofContext)
    (requirement : OriginalStaticWordRequirement) : Bool :=
  requirement.slot.originalAddress ==
      BitVec.ofNat 32 (context.originalPe.imageBase + requirement.slot.id) &&
    requirement.slot.id + 4 <= context.originalPe.sizeOfImage &&
    imageRangeExcludesIat context.originalImports requirement.slot.id 4 &&
    (readRvaLittleEndian context.originalPe requirement.slot.id 4).isSome &&
    let value := BitVec.ofNat 32 (staticWordImageValue context requirement)
    (requirement.admissibility != .finiteWords ||
      requirement.allowedOriginalWords.contains value) &&
    (staticOriginalOriginAt? context value requirement.origins).isSome

private theorem original_loader_valid
    (context : StaticProofContext) (valid : context.StructurallyValid) :
    preferredBaseLoaderImageValid context.originalPe = true := by
  rcases valid with
    ⟨_, _, _, _, _, _, _, _, _, _, _, _, _, _, _, originalLoader, _⟩
  exact originalLoader

def staticWordImageSeedChecked_sound
    (context : StaticProofContext) (world : RelationalWorld)
    (requirement : OriginalStaticWordRequirement)
    (contextValid : context.StructurallyValid)
    (requirementValid : requirement.Valid context)
    (checked : staticWordImageSeedChecked context requirement = true) :
    OriginalStaticWordImageSeed context world requirement := by
  simp only [staticWordImageSeedChecked, Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨⟨slotExact, inside⟩, excluded⟩, readSome⟩, tail⟩
  have readResult : readRvaLittleEndian context.originalPe
      requirement.slot.id 4 =
        some (staticWordImageValue context requirement) := by
    unfold staticWordImageValue
    cases result : readRvaLittleEndian context.originalPe
        requirement.slot.id 4 with
    | none => simp [result] at readSome
    | some expected => simp [result]
  let expected := staticWordImageValue context requirement
  rcases tail with ⟨admissible, originSome⟩
  let selected := staticWordImageOrigin context requirement
  have originFound : staticOriginalOriginAt? context
      (BitVec.ofNat 32 expected) requirement.origins = some selected := by
    unfold selected staticWordImageOrigin expected
    cases result : staticOriginalOriginAt? context
        (BitVec.ofNat 32 (staticWordImageValue context requirement))
        requirement.origins with
    | none => simp [result] at originSome
    | some value => simp [result]
  have originEvidence := staticOriginalOriginAt?_sound context world
    (BitVec.ofNat 32 expected) requirement.origins selected.1 selected.2
    originFound
  refine {
    valid := requirementValid
    value := BitVec.ofNat 32 expected
    valueAdmissible := ?_
    origin := selected.1
    originMember := originEvidence.1
    originHolds := originEvidence.2
    readFromPreferredImage := ?_
  }
  · cases mode : requirement.admissibility with
    | finiteWords =>
        exact OriginalStaticWordRequirement.wordAdmissibleOfFinite
          context world requirement (BitVec.ofNat 32 expected) mode
          (List.contains_iff_mem.mp (by simpa [mode] using admissible))
    | worldOrigins =>
        exact OriginalStaticWordRequirement.wordAdmissibleOfOrigin
          context world requirement (BitVec.ofNat 32 expected) mode
          selected.1 originEvidence.1 originEvidence.2
  · intro memory mapped
    have slotEq : requirement.slot.originalAddress =
        BitVec.ofNat 32
          (context.originalPe.imageBase + requirement.slot.id) :=
      beq_iff_eq.mp slotExact
    rw [slotEq]
    exact preferredBaseImageMemory_read32_of_checked context.originalPe
      context.originalImports memory requirement.slot.id expected mapped
      (by
        have span := preferredBaseLoaderImageValid_image_span
          context.originalPe (original_loader_valid context contextValid)
        simp [pe32SpanBounded, pe32AddressSpaceSize] at span
        omega)
      (by simpa using inside) excluded readResult
      (preferredBaseLoaderImageValid_bytes context.originalPe
        (original_loader_valid context contextValid))

def staticWordInventoryLaunchChecked (context : StaticProofContext)
    (inventory : OriginalStaticWordInventory) : Bool :=
  inventory.requirements.all (staticWordImageSeedChecked context)

theorem staticWordInventoryLaunchChecked_sound
    (context : StaticProofContext) (world : RelationalWorld)
    (inventory : OriginalStaticWordInventory)
    (contextValid : context.StructurallyValid)
    (requirementsValid : forall requirement,
      requirement ∈ inventory.requirements -> requirement.Valid context)
    (checked : staticWordInventoryLaunchChecked context inventory = true)
    (memory : Memory)
    (mapped : PreferredBaseImageMemory context.originalPe
      context.originalImports memory) :
    inventory.HoldsIn context world memory := by
  intro requirement member
  simp only [staticWordInventoryLaunchChecked, List.all_eq_true] at checked
  exact requirement.holdsOfImageSeed context world memory mapped
    (staticWordImageSeedChecked_sound context world requirement contextValid
      (requirementsValid requirement member) (checked requirement member))

/-- The finite Boolean inventory needed to establish the six data families;
the runtime partition is checked by the launch witness itself. -/
def combinedLaunchSeedChecked
    (project : NativeSourceProject)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext) : Bool :=
  entryReachabilityChecked project.program.worldProgram.context
      inventory.reachableTargets.targetIds &&
    staticWordInventoryLaunchChecked project.program.worldProgram.context
      inventory.staticWords &&
    entryValueFlowsVacuousChecked project.program.worldProgram.context
      inventory.valueFlows &&
    entryRegisterTargetsVacuousChecked project.program.worldProgram.context
      originalContext
      inventory.registerTargets &&
    entryStackDynamicTargetsVacuousChecked project.program.worldProgram.context
      originalContext
      inventory.stackDynamicTargets

theorem combinedLaunchSeedChecked_sound
    (project : NativeSourceProject)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext)
    (contextValid : project.program.worldProgram.context.StructurallyValid)
    (staticRequirementsValid : forall requirement,
      requirement ∈ inventory.staticWords.requirements ->
        requirement.Valid project.program.worldProgram.context)
    (checked : combinedLaunchSeedChecked project originalContext inventory = true) :
    OriginalCombinedPE32ConsoleLaunchSeed project originalContext inventory := by
  simp only [combinedLaunchSeedChecked, Bool.and_eq_true] at checked
  rcases checked with
    ⟨⟨⟨⟨reachableChecked, staticChecked⟩, valueChecked⟩,
      registerChecked⟩, stackChecked⟩
  refine {
    reachable := ?_
    staticWords := ?_
    callFrames := ?_
    valueFlows := ?_
    registerTargets := ?_
    stackDynamicTargets := ?_
    runtimeMemory := ?_
  }
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        _worldValid, _image, _imports⟩
    exact ⟨entryReachabilityChecked_sound _ contextValid _ reachableChecked
      targetId target found entry, by simp⟩
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        _worldValid, image, _imports⟩
    exact staticWordInventoryLaunchChecked_sound _ world inventory.staticWords
      contextValid staticRequirementsValid staticChecked state.memory image
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        _worldValid, image, _imports⟩
    exact ⟨{}, rfl, by simp [OriginalCallFramesHold]⟩
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        _worldValid, image, _imports⟩
    exact entryValueFlowsVacuousChecked_sound _ contextValid _ valueChecked
      targetId target found entry
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        _worldValid, image, _imports⟩
    exact entryRegisterTargetsVacuousChecked_sound originalContext _
      contextValid _ registerChecked targetId target found entry
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        _worldValid, image, _imports⟩
    exact entryStackDynamicTargetsVacuousChecked_sound originalContext _
      contextValid _ stackChecked targetId target found entry
  · intro sourceRoot launch
    rcases launch.launch with
      ⟨targetId, state, world, rfl, _original, ⟨target, found, entry⟩,
        worldValid, image, _imports⟩
    exact holdsIn_of_worldValid project.program.worldProgram.context world
      worldValid.1

#print axioms entryReachabilityChecked_sound
#print axioms staticWordImageSeedChecked_sound
#print axioms combinedLaunchSeedChecked_sound

end StageA.Relational.OriginalSourceLaunchConstruction
