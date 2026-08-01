import StageA.RelationalNativeSource
import StageA.RelationalOriginalCallFrameExecutionInvariant
import StageA.RelationalRelocatedWritableStaticPointerSlot

namespace StageA.Relational.OriginalStaticWordExecutionInvariant

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.RelocatedWritableStaticPointerSlot
open StageA.Relational.ValueProvenance

/-!
# One-sided original static-word execution invariant

This module keeps a finite inventory of checked provenance alternatives for
words stored at static slots in the original image.  A requirement either
admits an explicit finite set of concrete words or admits the world-selected
word justified by one of those checked provenance alternatives.  The companion
word in that witness is proof data only; there is no candidate execution state.

The inventory is checked in active states and in every suspended callback
layer.  Internal writes and external results preserve it only through explicit
write frames, finite replacement facts, and world-origin preservation.  The
module supplies transition constructors, but deliberately does not infer that
they cover a whole program.
-/

/-- Concrete finite words remain the default.  `worldOrigins` is required for
values selected by the external world, such as import addresses and opaque
resources whose concrete words cannot be enumerated statically. -/
inductive OriginalStaticWordAdmissibility where
  | finiteWords
  | worldOrigins
deriving Repr, DecidableEq

/-- A finite one-sided requirement for one checked static relation slot. -/
structure OriginalStaticWordRequirement where
  slot : StaticWordRelationSlotPair
  finiteAlternativeBudget : Nat
  origins : List ValueOriginAtom
  allowedOriginalWords : List Word
  admissibility : OriginalStaticWordAdmissibility := .finiteWords
deriving Repr, DecidableEq

/-- Static well-formedness is independent of a runtime world or memory. -/
structure OriginalStaticWordRequirement.Valid
    (context : StaticProofContext)
    (requirement : OriginalStaticWordRequirement) : Prop where
  slotMember : requirement.slot ∈ context.staticWordRelationSlots
  positiveBudget : 0 < requirement.finiteAlternativeBudget
  originsNonempty : requirement.origins ≠ []
  originsWithinBudget :
    requirement.origins.length <= requirement.finiteAlternativeBudget
  originsUnique : requirement.origins.Nodup
  originsChecked : forall origin, origin ∈ requirement.origins ->
    origin.checked context = true
  wordsNonempty : requirement.admissibility = .finiteWords ->
    requirement.allowedOriginalWords ≠ []
  wordsUnique : requirement.admissibility = .finiteWords ->
    requirement.allowedOriginalWords.Nodup

/-- A runtime word is admissible either by concrete finite membership or by a
checked origin that holds in the current world.  The latter is deliberately
world-indexed and cannot admit a value without a bounded provenance witness. -/
def OriginalStaticWordRequirement.WordAdmissible
    (context : StaticProofContext) (world : RelationalWorld)
    (requirement : OriginalStaticWordRequirement) (value : Word) : Prop :=
  match requirement.admissibility with
  | .finiteWords => value ∈ requirement.allowedOriginalWords
  | .worldOrigins =>
      exists origin, origin ∈ requirement.origins /\
        OriginalValueOriginAtomHolds context world value origin

theorem OriginalStaticWordRequirement.wordAdmissibleOfFinite
    (context : StaticProofContext) (world : RelationalWorld)
    (requirement : OriginalStaticWordRequirement) (value : Word)
    (mode : requirement.admissibility = .finiteWords)
    (member : value ∈ requirement.allowedOriginalWords) :
    requirement.WordAdmissible context world value := by
  simp [OriginalStaticWordRequirement.WordAdmissible, mode, member]

theorem OriginalStaticWordRequirement.wordAdmissibleOfOrigin
    (context : StaticProofContext) (world : RelationalWorld)
    (requirement : OriginalStaticWordRequirement) (value : Word)
    (mode : requirement.admissibility = .worldOrigins)
    (origin : ValueOriginAtom) (member : origin ∈ requirement.origins)
    (holds : OriginalValueOriginAtomHolds context world value origin) :
    requirement.WordAdmissible context world value := by
  simp only [OriginalStaticWordRequirement.WordAdmissible, mode]
  exact ⟨origin, member, holds⟩

/-- The concrete original word is admitted by the selected mode and justified
by one of the finite shared provenance atoms. -/
def OriginalStaticWordRequirement.Holds
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement) : Prop :=
  requirement.Valid context /\
    requirement.WordAdmissible context world
      (Memory.read32 memory requirement.slot.originalAddress) /\
    exists origin, origin ∈ requirement.origins /\
      OriginalValueOriginAtomHolds context world
        (Memory.read32 memory requirement.slot.originalAddress) origin

def OriginalStaticWordRequirement.OriginsPreserved
    (context : StaticProofContext) (before after : RelationalWorld)
    (requirement : OriginalStaticWordRequirement) : Prop :=
  forall origin, origin ∈ requirement.origins ->
    OriginalValueOriginAtomPreserved context before after origin

theorem OriginalStaticWordRequirement.afterReadExact
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory afterMemory : Memory)
    (requirement : OriginalStaticWordRequirement)
    (before : requirement.Holds context beforeWorld beforeMemory)
    (readExact :
      Memory.read32 afterMemory requirement.slot.originalAddress =
        Memory.read32 beforeMemory requirement.slot.originalAddress)
    (originsPreserved :
      requirement.OriginsPreserved context beforeWorld afterWorld) :
    requirement.Holds context afterWorld afterMemory := by
  rcases before with ⟨valid, allowed, origin, member, originHolds⟩
  have originAfter : OriginalValueOriginAtomHolds context afterWorld
      (Memory.read32 afterMemory requirement.slot.originalAddress) origin := by
    apply originsPreserved origin member
    simpa [readExact] using originHolds
  refine ⟨valid, ?_, origin, member, ?_⟩
  · cases mode : requirement.admissibility with
    | finiteWords =>
        simpa [OriginalStaticWordRequirement.WordAdmissible, mode, readExact]
          using allowed
    | worldOrigins =>
        exact requirement.wordAdmissibleOfOrigin context afterWorld
          (Memory.read32 afterMemory requirement.slot.originalAddress)
          mode origin member originAfter
  · exact originAfter

/-- Construct a world-origin requirement directly from one checked origin.
This is the generic entry point for environment-selected import addresses,
opaque resources, dynamic ranges, and registered callbacks. -/
theorem OriginalStaticWordRequirement.holdsOfWorldOrigin
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (valid : requirement.Valid context)
    (mode : requirement.admissibility = .worldOrigins)
    (origin : ValueOriginAtom) (member : origin ∈ requirement.origins)
    (originHolds : OriginalValueOriginAtomHolds context world
      (Memory.read32 memory requirement.slot.originalAddress) origin) :
    requirement.Holds context world memory :=
  ⟨valid, requirement.wordAdmissibleOfOrigin context world
      (Memory.read32 memory requirement.slot.originalAddress)
      mode origin member originHolds,
    origin, member, originHolds⟩

/-! ## Exact launch seeds -/

/-- The exact image and IAT facts retained by the bounded source launch. -/
structure OriginalStaticWordLaunchFacts
    (context : StaticProofContext) (world : RelationalWorld)
    (state : MachineState) : Prop where
  imageMemory : PreferredBaseImageMemory context.originalPe
    context.originalImports state.memory
  importMemory : forall binding, binding ∈ world.importAddresses ->
    Memory.read32 state.memory
        (BitVec.ofNat 32
          (context.originalPe.imageBase + binding.originalIatRva)) =
      binding.originalAddress

/-- Extract the exact image and IAT launch facts without weakening the launch
predicate to a bare entrypoint assertion. -/
theorem CheckedNativeSourcePE32ConsoleLaunch.staticWordLaunchFacts
    {project : NativeSourceProject} {sourceRoot : SourceExecution}
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    exists targetId state world,
      sourceRoot = .running targetId state [] 0 world /\
      OriginalStaticWordLaunchFacts project.program.worldProgram.context
        world state := by
  rcases launch.launch with
    ⟨targetId, state, world, rootExact, _originalSide, _entry,
      _worldValid, imageMemory, importMemory⟩
  exact ⟨targetId, state, world, rootExact,
    { imageMemory := imageMemory, importMemory := importMemory }⟩

/-- A checked image seed states exactly how the preferred-image bytes establish
one concrete static word.  The byte-level loader fact remains authoritative;
the seed cannot be used with an unrelated memory. -/
structure OriginalStaticWordImageSeed
    (context : StaticProofContext) (world : RelationalWorld)
    (requirement : OriginalStaticWordRequirement) where
  valid : requirement.Valid context
  value : Word
  valueAdmissible : requirement.WordAdmissible context world value
  origin : ValueOriginAtom
  originMember : origin ∈ requirement.origins
  originHolds : OriginalValueOriginAtomHolds context world value origin
  readFromPreferredImage : forall memory,
    PreferredBaseImageMemory context.originalPe context.originalImports memory ->
      Memory.read32 memory requirement.slot.originalAddress = value

theorem OriginalStaticWordRequirement.holdsOfImageSeed
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (imageMemory : PreferredBaseImageMemory context.originalPe
      context.originalImports memory)
    (seed : OriginalStaticWordImageSeed context world requirement) :
    requirement.Holds context world memory := by
  have readExact := seed.readFromPreferredImage memory imageMemory
  exact ⟨seed.valid, by simpa [readExact] using seed.valueAdmissible,
    seed.origin, seed.originMember, by simpa [readExact] using seed.originHolds⟩

/-- Loader-populated IAT memory directly seeds an import-target provenance
fact.  The slot must still be a member of the canonical static-word inventory. -/
theorem OriginalStaticWordRequirement.holdsOfImportSeed
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (valid : requirement.Valid context)
    (binding : ImportAddressPair) (bindingMember : binding ∈ world.importAddresses)
    (slotExact : requirement.slot.originalAddress =
      BitVec.ofNat 32
        (context.originalPe.imageBase + binding.originalIatRva))
    (wordAdmissible :
      requirement.WordAdmissible context world binding.originalAddress)
    (originMember : ValueOriginAtom.importTarget binding.imported ∈
      requirement.origins)
    (importMemory : forall selected, selected ∈ world.importAddresses ->
      Memory.read32 memory
          (BitVec.ofNat 32
            (context.originalPe.imageBase + selected.originalIatRva)) =
        selected.originalAddress) :
    requirement.Holds context world memory := by
  have readExact :
      Memory.read32 memory requirement.slot.originalAddress =
        binding.originalAddress := by
    rw [slotExact]
    exact importMemory binding bindingMember
  refine ⟨valid, by simpa [readExact] using wordAdmissible,
    .importTarget binding.imported, originMember, ?_⟩
  refine ⟨binding.candidateAddress, binding, bindingMember, rfl, ?_, rfl⟩
  exact readExact

/-- An IAT binding can seed a world-origin requirement without enumerating the
loader-selected concrete import address in `allowedOriginalWords`. -/
theorem OriginalStaticWordRequirement.holdsOfImportSeedFromWorldOrigin
    (context : StaticProofContext) (world : RelationalWorld)
    (memory : Memory) (requirement : OriginalStaticWordRequirement)
    (valid : requirement.Valid context)
    (mode : requirement.admissibility = .worldOrigins)
    (binding : ImportAddressPair) (bindingMember : binding ∈ world.importAddresses)
    (slotExact : requirement.slot.originalAddress =
      BitVec.ofNat 32
        (context.originalPe.imageBase + binding.originalIatRva))
    (originMember : ValueOriginAtom.importTarget binding.imported ∈
      requirement.origins)
    (importMemory : forall selected, selected ∈ world.importAddresses ->
      Memory.read32 memory
          (BitVec.ofNat 32
            (context.originalPe.imageBase + selected.originalIatRva)) =
        selected.originalAddress) :
    requirement.Holds context world memory := by
  have originHolds : OriginalValueOriginAtomHolds context world
      binding.originalAddress (.importTarget binding.imported) := by
    exact ⟨binding.candidateAddress, binding, bindingMember, rfl, rfl, rfl⟩
  exact requirement.holdsOfImportSeed context world memory valid binding
    bindingMember slotExact
    (requirement.wordAdmissibleOfOrigin context world binding.originalAddress
      mode (.importTarget binding.imported) originMember originHolds)
    originMember importMemory

/-! ## Checked internal and external updates -/

/-- One exact original write set either avoids a required word or supplies a
new fully checked finite value. -/
inductive OriginalStaticWordWriteFrame
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory : Memory) (writes : List (Word × Word))
    (requirement : OriginalStaticWordRequirement) : Prop where
  | disjoint
      (avoids : WritesAvoidWord requirement.slot.originalAddress writes)
      (originsPreserved :
        requirement.OriginsPreserved context beforeWorld afterWorld) :
      OriginalStaticWordWriteFrame context beforeWorld afterWorld beforeMemory
        writes requirement
  | relatedUpdate
      (afterHolds : requirement.Holds context afterWorld
        (applyConcreteWrites beforeMemory writes)) :
      OriginalStaticWordWriteFrame context beforeWorld afterWorld beforeMemory
        writes requirement

theorem OriginalStaticWordRequirement.afterInternalWrites
    (context : StaticProofContext)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory : Memory) (writes : List (Word × Word))
    (requirement : OriginalStaticWordRequirement)
    (before : requirement.Holds context beforeWorld beforeMemory)
    (frame : OriginalStaticWordWriteFrame context beforeWorld afterWorld
      beforeMemory writes requirement) :
    requirement.Holds context afterWorld
      (applyConcreteWrites beforeMemory writes) := by
  cases frame with
  | relatedUpdate afterHolds => exact afterHolds
  | disjoint avoids originsPreserved =>
      exact requirement.afterReadExact context beforeWorld afterWorld
        beforeMemory (applyConcreteWrites beforeMemory writes) before
        (Memory.read32_applyConcreteWrites_of_avoids beforeMemory
          requirement.slot.originalAddress writes avoids)
        originsPreserved

/-- An external result either has a checked bounded write footprint which
leaves the word unchanged, or explicitly supplies a new related value. -/
inductive OriginalStaticWordMachineCallFrame
    (context : StaticProofContext)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (requirement : OriginalStaticWordRequirement) : Prop where
  | footprints
      (supported :
        MachineCallMemoryEffectFootprintBounded contract.memoryEffect)
      (avoids : ExternalWriteFootprintsAvoidWord contract.memoryFootprints
        event.state.memory event.arguments requirement.slot.originalAddress)
      (originsPreserved :
        requirement.OriginsPreserved context event.world result.world) :
      OriginalStaticWordMachineCallFrame context contract event result
        requirement
  | relatedUpdate
      (afterHolds : requirement.Holds context result.world result.state.memory) :
      OriginalStaticWordMachineCallFrame context contract event result
        requirement

/-- Reuse the checked machine-call footprint theorem on the original side,
then transport the unchanged value-origin witness through the world update.
Stateful finite replacements must use the explicit `relatedUpdate` case. -/
theorem OriginalStaticWordRequirement.afterMachineCall
    (context : StaticProofContext)
    (contract : MachineImportCallContract)
    (event : WorldExternalEvent) (result : WorldExternalResult)
    (requirement : OriginalStaticWordRequirement)
    (before : requirement.Holds context event.world event.state.memory)
    (conforms : machineCallResultConforms false context contract event result)
    (frame : OriginalStaticWordMachineCallFrame context contract event result
      requirement) :
    requirement.Holds context result.world result.state.memory := by
  cases frame with
  | relatedUpdate afterHolds => exact afterHolds
  | footprints supported avoids originsPreserved =>
      have direct : machineCallMemoryEffectHolds contract event.arguments
          event.state.memory result.state.memory := by
        have withWorld := conforms.2.2.1
        unfold machineCallMemoryEffectHoldsWithWorld at withWorld
        rcases supported with effect | effect | effect
        · simpa [effect] using withWorld
        · simpa [effect] using withWorld
        · simpa [effect] using withWorld
      have readExact := machineCallMemoryEffectHolds_preservesWord contract
        event.arguments event.state.memory result.state.memory
        requirement.slot.originalAddress supported direct avoids
      have after := requirement.afterReadExact context event.world result.world
        event.state.memory result.state.memory before readExact originsPreserved
      exact after

structure OriginalStaticWordInventory where
  requirements : List OriginalStaticWordRequirement := []
deriving Repr, DecidableEq

def OriginalStaticWordInventory.HoldsIn
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (world : RelationalWorld) (memory : Memory) : Prop :=
  forall requirement, requirement ∈ inventory.requirements ->
    requirement.Holds context world memory

theorem OriginalStaticWordInventory.HoldsIn.afterInternalWrites
    (context : StaticProofContext)
    (inventory : OriginalStaticWordInventory)
    (beforeWorld afterWorld : RelationalWorld)
    (beforeMemory : Memory) (writes : List (Word × Word))
    (before : inventory.HoldsIn context beforeWorld beforeMemory)
    (frames : forall requirement, requirement ∈ inventory.requirements ->
      OriginalStaticWordWriteFrame context beforeWorld afterWorld beforeMemory
        writes requirement) :
    inventory.HoldsIn context afterWorld
      (applyConcreteWrites beforeMemory writes) := by
  intro requirement member
  exact requirement.afterInternalWrites context beforeWorld afterWorld
    beforeMemory writes (before requirement member) (frames requirement member)

/-- The same finite inventory is checked in every suspended callback state. -/
def SuspendedOriginalStaticWordsHold
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory) :
    List WorldExternalCallbackRuntime -> Prop
  | [] => True
  | callback :: callbacks =>
      KnownCallbackRuntime context callback /\
        inventory.HoldsIn context callback.suspension.world
          callback.suspension.state.memory /\
        SuspendedOriginalStaticWordsHold context inventory callbacks

theorem SuspendedOriginalStaticWordsHold.known
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : SuspendedOriginalStaticWordsHold context inventory callbacks)
    (callback : WorldExternalCallbackRuntime) (member : callback ∈ callbacks) :
    KnownCallbackRuntime context callback := by
  induction callbacks with
  | nil => simp at member
  | cons head callbacks induction =>
      simp only [SuspendedOriginalStaticWordsHold] at holds
      rcases List.mem_cons.mp member with same | member
      · simpa [same] using holds.1
      · exact induction holds.2.2 member

/-- Concrete execution predicate.  Terminal states no longer expose memory;
blocked states are deliberately excluded. -/
def OriginalStaticWordInventory.Holds
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory) :
    WorldExecution -> Prop
  | .running _ state _ _ world => inventory.HoldsIn context world state.memory
  | .returned state world => inventory.HoldsIn context world state.memory
  | .terminated _ | .fault _ => True
  | .awaitingExternal suspension callbacks =>
      inventory.HoldsIn context suspension.world suspension.state.memory /\
        SuspendedOriginalStaticWordsHold context inventory callbacks
  | .callbackRunning _ state _ _ world callbacks =>
      inventory.HoldsIn context world state.memory /\
        SuspendedOriginalStaticWordsHold context inventory callbacks
  | .blocked _ => False

theorem OriginalStaticWordInventory.blockedFalse
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (reason : ExecutionBlock) :
    Not (inventory.Holds context (.blocked reason)) := by
  simp [OriginalStaticWordInventory.Holds]

theorem OriginalStaticWordInventory.unknownCallbackFalse
    (context : StaticProofContext) (inventory : OriginalStaticWordInventory)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime)
    (unknown : Not (KnownCallbackRuntime context callback)) :
    Not (inventory.Holds context
      (.callbackRunning targetId state calls eventIndex world
        (callback :: callbacks))) := by
  intro holds
  exact unknown (holds.2.known context inventory (callback :: callbacks)
    callback (by simp))

/-! ## Exact transition constructors -/

theorem OriginalStaticWordInventory.internalPreserved
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (before : WorldExecution) (callbacks : List WorldExternalCallbackRuntime)
    (nextTargetId : Nat) (afterState : MachineState) (calls : List Nat)
    (eventIndex : Nat) (afterWorld : RelationalWorld)
    (stepExact :
      program.pe32TransitionSystem.step before = {
        next := resumeWorldExecution callbacks nextTargetId afterState calls
          eventIndex afterWorld
        observation := none
      })
    (afterHolds : inventory.HoldsIn program.context afterWorld afterState.memory)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (program.pe32TransitionSystem.step before).next := by
  rw [stepExact]
  cases callbacks with
  | nil => exact afterHolds
  | cons callback callbacks => exact ⟨afterHolds, suspendedHolds⟩

theorem OriginalStaticWordInventory.internalExactWrites
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (before : WorldExecution) (callbacks : List WorldExternalCallbackRuntime)
    (nextTargetId : Nat) (beforeState afterState : MachineState)
    (calls : List Nat) (eventIndex : Nat)
    (beforeWorld afterWorld : RelationalWorld)
    (writes : List (Word × Word))
    (stepExact :
      program.pe32TransitionSystem.step before = {
        next := resumeWorldExecution callbacks nextTargetId afterState calls
          eventIndex afterWorld
        observation := none
      })
    (memoryExact :
      afterState.memory = applyConcreteWrites beforeState.memory writes)
    (beforeHolds : inventory.HoldsIn program.context beforeWorld
      beforeState.memory)
    (frames : forall requirement, requirement ∈ inventory.requirements ->
      OriginalStaticWordWriteFrame program.context beforeWorld afterWorld
        beforeState.memory writes requirement)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (program.pe32TransitionSystem.step before).next := by
  have afterHolds := beforeHolds.afterInternalWrites program.context inventory
    beforeWorld afterWorld beforeState.memory writes frames
  rw [← memoryExact] at afterHolds
  exact inventory.internalPreserved program before callbacks nextTargetId
    afterState calls eventIndex afterWorld stepExact afterHolds suspendedHolds

theorem OriginalStaticWordInventory.externalSuspended
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (before : WorldExecution) (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (nextExact : (program.pe32TransitionSystem.step before).next =
      .awaitingExternal suspension callbacks)
    (activeHolds : inventory.HoldsIn program.context suspension.world
      suspension.state.memory)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (program.pe32TransitionSystem.step before).next := by
  rw [nextExact]
  exact ⟨activeHolds, suspendedHolds⟩

theorem OriginalStaticWordInventory.externalReturned
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (result : WorldExternalResult)
    (actionExact :
      program.protocolEnvironment.action suspension.request = .returned result)
    (afterHolds : inventory.HoldsIn program.context result.world
      result.state.memory)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension, actionExact]
  cases callbacks with
  | nil => exact afterHolds
  | cons callback callbacks => exact ⟨afterHolds, suspendedHolds⟩

/-- A checked machine return supplies each requirement's footprint or finite
replacement proof; no blanket environment-state preservation is assumed. -/
theorem OriginalStaticWordInventory.externalReturnedByMachineFrames
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (result : WorldExternalResult) (contract : MachineImportCallContract)
    (actionExact :
      program.protocolEnvironment.action suspension.request = .returned result)
    (beforeHolds : inventory.HoldsIn program.context suspension.world
      suspension.state.memory)
    (conforms : machineCallResultConforms false program.context contract
      suspension.currentEvent result)
    (frames : forall requirement, requirement ∈ inventory.requirements ->
      OriginalStaticWordMachineCallFrame program.context contract
        suspension.currentEvent result requirement)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  have afterHolds : inventory.HoldsIn program.context result.world
      result.state.memory := by
    intro requirement member
    have prior := beforeHolds requirement member
    exact requirement.afterMachineCall program.context contract
      suspension.currentEvent
      result prior conforms (frames requirement member)
  exact inventory.externalReturned program suspension callbacks result
    actionExact afterHolds suspendedHolds

theorem OriginalStaticWordInventory.externalCallbackEntry
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (suspension : WorldExternalSuspension)
    (callbacks : List WorldExternalCallbackRuntime)
    (entry : WorldExternalCallbackAction)
    (actionExact :
      program.protocolEnvironment.action suspension.request = .callback entry)
    (known : KnownCallbackRuntime program.context
      { suspension := suspension, entry := entry })
    (entryHolds : inventory.HoldsIn program.context entry.world
      entry.state.memory)
    (suspensionHolds : inventory.HoldsIn program.context suspension.world
      suspension.state.memory)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (program.pe32TransitionSystem.step
        (.awaitingExternal suspension callbacks)).next := by
  unfold DecodedWorldProgram.pe32TransitionSystem
  simp only [stepPE32WorldExecution, stepWorldExternalSuspension, actionExact,
    OriginalStaticWordInventory.Holds, SuspendedOriginalStaticWordsHold]
  exact ⟨entryHolds, known, suspensionHolds, suspendedHolds⟩

/-- Pop one callback layer.  Its exact suspended state already carries the
static-word inventory; mismatched callback returns are blocked by the machine
transition and therefore cannot use this constructor. -/
theorem OriginalStaticWordInventory.callbackReturnRestored
    (program : DecodedWorldProgram) (inventory : OriginalStaticWordInventory)
    (sourceTargetId : Nat) (state : MachineState) (eventIndex : Nat)
    (world : RelationalWorld) (callback : WorldExternalCallbackRuntime)
    (callbacks : List WorldExternalCallbackRuntime) (target : Word)
    (targetExact : target = callback.entry.returnAddress)
    (currentHolds : inventory.HoldsIn program.context world state.memory)
    (suspendedHolds :
      SuspendedOriginalStaticWordsHold program.context inventory callbacks) :
    inventory.Holds program.context
      (transitionFromWorldOutcome program sourceTargetId state [] eventIndex
        world (callback :: callbacks) (.returned target)).next := by
  subst target
  simp only [transitionFromWorldOutcome, beq_self_eq_true, if_true,
    OriginalStaticWordInventory.Holds]
  exact ⟨currentHolds, suspendedHolds⟩

/-! ## Combined original-invariant component -/

/-- A program adapter must classify every exact reachable step using the
constructors above.  This is intentionally a proof obligation, not a generated
status bit and not an automatic whole-program claim. -/
structure CheckedOriginalStaticWordExecutionInvariant
    (program : DecodedWorldProgram)
    (inventory : OriginalStaticWordInventory) : Prop where
  stepClosed : forall before,
    inventory.Holds program.context before ->
      inventory.Holds program.context
        (program.pe32TransitionSystem.step before).next

def CheckedOriginalStaticWordExecutionInvariant.toOriginalInvariant
    (checked : CheckedOriginalStaticWordExecutionInvariant program inventory) :
    OriginalWorldExecutionInvariant program where
  holds := inventory.Holds program.context
  stepClosed := checked.stepClosed

@[simp]
theorem CheckedOriginalStaticWordExecutionInvariant.toOriginalInvariant_holds
    (checked : CheckedOriginalStaticWordExecutionInvariant program inventory)
    (execution : WorldExecution) :
    checked.toOriginalInvariant.holds execution <->
      inventory.Holds program.context execution :=
  Iff.rfl

#print axioms CheckedNativeSourcePE32ConsoleLaunch.staticWordLaunchFacts
#print axioms OriginalStaticWordRequirement.holdsOfWorldOrigin
#print axioms OriginalStaticWordRequirement.holdsOfImageSeed
#print axioms OriginalStaticWordRequirement.holdsOfImportSeed
#print axioms OriginalStaticWordRequirement.holdsOfImportSeedFromWorldOrigin
#print axioms OriginalStaticWordRequirement.afterInternalWrites
#print axioms OriginalStaticWordRequirement.afterMachineCall
#print axioms OriginalStaticWordInventory.internalExactWrites
#print axioms OriginalStaticWordInventory.externalReturnedByMachineFrames
#print axioms OriginalStaticWordInventory.externalCallbackEntry
#print axioms OriginalStaticWordInventory.callbackReturnRestored
#print axioms CheckedOriginalStaticWordExecutionInvariant.toOriginalInvariant

end StageA.Relational.OriginalStaticWordExecutionInvariant
