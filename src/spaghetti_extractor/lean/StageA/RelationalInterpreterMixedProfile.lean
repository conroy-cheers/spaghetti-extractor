import StageA.RelationalInterpreterKernelABI
import StageA.RelationalInterpreterMixedEnvironment
import StageA.RelationalInterpreterMixedLaunchRefinement

namespace StageA.Relational.InterpreterMixedProfile

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-! # Canonical relation profile for a decoded original and native interpreter

The native interpreter has one exact executable address per kernel/helper block,
not one address per original semantic record.  Consequently this profile is
intentionally one-sided: original control authority comes from
`ExactOriginalDecodedAuthority`, while candidate execution and the engine-state
encoding come directly from `ExactNativeCandidateAuthority` and
`ConcreteKernelABI`.

Only the small set of real native entry/callback anchors is related to original
code targets.  Internal semantic records never acquire invented candidate RVAs.
The runtime, value, world, launch, and callback relations below are definitions,
not caller-supplied predicates.
-/

/-- One checked correspondence between an original decoded target and a real
candidate executable anchor, such as the PE entrypoint or a TLS callback. -/
structure MixedNativeCodeAnchor where
  originalTargetId : Nat
  candidateRva : Nat
deriving Repr, DecidableEq

def MixedNativeCodeAnchor.Valid
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (reachableTargetIds : List Nat)
    (anchor : MixedNativeCodeAnchor) : Bool :=
  original.sourceAtValid anchor.originalTargetId &&
    reachableTargetIds.contains anchor.originalTargetId &&
    executableRva candidate.pe anchor.candidateRva

def MixedNativeCodeAnchorsValid
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (reachableTargetIds : List Nat)
    (anchors : List MixedNativeCodeAnchor) : Bool :=
  decide anchors.Nodup &&
    decide (anchors.map (·.originalTargetId)).Nodup &&
    decide (anchors.map (·.candidateRva)).Nodup &&
    anchors.all (MixedNativeCodeAnchor.Valid original candidate reachableTargetIds)

/-- The native anchor map is small, but it cannot be empty or omit a launch
surface.  Candidate entry/TLS addresses are parsed from exact PE bytes and are
paired positionally with the exact original launch inventory. -/
def MixedNativeLaunchAnchorsComplete
    (candidate : ExactNativeWorldProgram)
    (launch : PE32ConsoleLaunchV2)
    (anchors : List MixedNativeCodeAnchor) : Bool :=
  match candidatePELaunchRoots? candidate.pe with
  | none => false
  | some roots =>
      roots.tlsCallbackRvas.length == launch.tlsCallbackTargetIds.length &&
        anchors.contains {
          originalTargetId := launch.rootTargetId
          candidateRva := roots.initialRva
        } &&
        anchors.contains {
          originalTargetId := launch.entryTargetId
          candidateRva := roots.entryRva
        } &&
        (List.zip launch.tlsCallbackTargetIds roots.tlsCallbackRvas).all
          fun pair => anchors.contains {
            originalTargetId := pair.1
            candidateRva := pair.2
          }

/-- A parsed launch RVA must remain a concrete PE32 image address.  This is
strictly an address-width and image-bounds check; executable classification is
kept in `MixedNativeCodeAnchorsValid`. -/
def mixedNativeLaunchRvaAddressable (pe : PE32) (rva : Nat) : Bool :=
  rva < pe.sizeOfImage && pe.imageBase + rva < 2 ^ 32

/-- Address-width checks for every root recovered from the exact candidate PE.
The whole image must fit in PE32 address space so later anchor addition cannot
silently wrap. -/
def candidatePELaunchRootsAddressable
    (pe : PE32) (roots : CandidatePELaunchRoots) : Bool :=
  pe.imageBase + pe.sizeOfImage <= 2 ^ 32 &&
    mixedNativeLaunchRvaAddressable pe roots.entryRva &&
    roots.tlsCallbackRvas.all (mixedNativeLaunchRvaAddressable pe)

/-- Pair the exact original launch target inventory with candidate RVAs parsed
from the candidate PE.  The initial root is already either the entrypoint or
the first TLS callback, so it is not inserted a second time. -/
def mixedNativeLaunchAnchorInventory
    (launch : PE32ConsoleLaunchV2)
    (roots : CandidatePELaunchRoots) : List MixedNativeCodeAnchor :=
  {
    originalTargetId := launch.entryTargetId
    candidateRva := roots.entryRva
  } :: (List.zip launch.tlsCallbackTargetIds roots.tlsCallbackRvas).map
    fun pair => {
      originalTargetId := pair.1
      candidateRva := pair.2
    }

/-- Construct the canonical launch anchors from exact candidate PE facts.
Malformed roots, callback-count disagreement, a non-canonical initial root, or
PE32 address overflow all fail closed.  This deliberately does not replace the
separate executable-range and uniqueness check in
`MixedNativeCodeAnchorsValid`. -/
def canonicalMixedLaunchAnchors?
    (candidate : ExactNativeWorldProgram)
    (launch : PE32ConsoleLaunchV2) : Option (List MixedNativeCodeAnchor) := do
  let roots <- candidatePELaunchRoots? candidate.pe
  if roots.tlsCallbackRvas.length != launch.tlsCallbackTargetIds.length then
    none
  else if launch.rootTargetId != launch.initialTargetId then
    none
  else if !candidatePELaunchRootsAddressable candidate.pe roots then
    none
  else
    some (mixedNativeLaunchAnchorInventory launch roots)

/-- Successful construction is sufficient for launch-anchor completeness.  The
original root witness keeps this bridge tied to the exact original launch
inventory; candidate RVAs still come only from the exact candidate PE parser. -/
theorem canonicalMixedLaunchAnchors?_complete
    {original : OriginalDecodedStaticContext}
    {candidate : ExactNativeWorldProgram}
    {launch : PE32ConsoleLaunchV2}
    (originalRoot : DirectExactOriginalDecodedLaunchRoot original launch)
    {anchors : List MixedNativeCodeAnchor}
    (built : canonicalMixedLaunchAnchors? candidate launch = some anchors) :
    MixedNativeLaunchAnchorsComplete candidate launch anchors = true := by
  have rootExact : launch.rootTargetId = launch.initialTargetId :=
    originalRoot.initialExact
  unfold canonicalMixedLaunchAnchors? at built
  cases rootsParsed : candidatePELaunchRoots? candidate.pe with
  | none =>
      simp [rootsParsed] at built
  | some roots =>
      simp [rootsParsed, rootExact] at built
      rcases built with ⟨callbackCount, _, rfl⟩
      simp [MixedNativeLaunchAnchorsComplete, rootsParsed,
        mixedNativeLaunchAnchorInventory, rootExact, callbackCount]
      constructor
      · cases targetIdsExact : launch.tlsCallbackTargetIds with
        | nil =>
            cases rvasExact : roots.tlsCallbackRvas with
            | nil =>
                simp [PE32ConsoleLaunchV2.initialTargetId,
                  CandidatePELaunchRoots.initialRva, targetIdsExact, rvasExact]
            | cons rva rvas =>
                simp [targetIdsExact, rvasExact] at callbackCount
        | cons targetId targetIds =>
            cases rvasExact : roots.tlsCallbackRvas with
            | nil =>
                simp [targetIdsExact, rvasExact] at callbackCount
            | cons rva rvas =>
                simp [PE32ConsoleLaunchV2.initialTargetId,
                  CandidatePELaunchRoots.initialRva, targetIdsExact, rvasExact]
      · intro originalTargetId candidateRva member
        exact Or.inr member

theorem mixedProfileOptionEqSomeGet {alpha : Type} (value : Option alpha)
    (present : value.isSome = true) : value = some (value.get present) := by
  cases value <;> simp_all

theorem canonicalMixedLaunchAnchors?_eq_some_get
    (candidate : ExactNativeWorldProgram)
    (launch : PE32ConsoleLaunchV2)
    (present : (canonicalMixedLaunchAnchors? candidate launch).isSome = true) :
    canonicalMixedLaunchAnchors? candidate launch =
      some ((canonicalMixedLaunchAnchors? candidate launch).get present) :=
  mixedProfileOptionEqSomeGet _ present

def mixedRangeDisjointFromImages (originalPe candidatePe : PE32)
    (range : DynamicAddressRangePair) : Bool :=
  range.size > 0 &&
    range.originalBase.toNat + range.size <= 2 ^ 32 &&
    range.candidateBase.toNat + range.size <= 2 ^ 32 &&
    (range.originalBase.toNat + range.size <= originalPe.imageBase ||
      originalPe.imageBase + originalPe.sizeOfImage <= range.originalBase.toNat) &&
    (range.candidateBase.toNat + range.size <= candidatePe.imageBase ||
      candidatePe.imageBase + candidatePe.sizeOfImage <= range.candidateBase.toNat)

def mixedImportAddressValid (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram) (binding : ImportAddressPair) : Bool :=
  match importAtIatRva original.imports binding.originalIatRva,
      importAtIatRva candidate.imports binding.candidateIatRva with
  | some originalImport, some candidateImport =>
      normalizeImport originalImport == binding.imported &&
        normalizeImport candidateImport == binding.imported &&
        binding.originalAddress != BitVec.ofNat 32 0 &&
        binding.candidateAddress != BitVec.ofNat 32 0 &&
        !(original.pe.imageBase <= binding.originalAddress.toNat &&
          binding.originalAddress.toNat <
            original.pe.imageBase + original.pe.sizeOfImage) &&
        !(candidate.pe.imageBase <= binding.candidateAddress.toNat &&
          binding.candidateAddress.toNat <
            candidate.pe.imageBase + candidate.pe.sizeOfImage)
  | _, _ => false

def mixedCallbackAddressValid (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram) (anchors : List MixedNativeCodeAnchor)
    (callback : RegisteredCallbackPair) : Bool :=
  anchors.any fun anchor =>
    anchor.originalTargetId == callback.targetId &&
      match original.source? anchor.originalTargetId with
      | none => false
      | some source =>
          codeAddressMatches original.pe.imageBase source.target.rva
              source.target.aliases callback.originalAddress &&
            callback.candidateAddress == BitVec.ofNat 32
              (candidate.pe.imageBase + anchor.candidateRva)

/-- The part of `RelationalWorld` consumed by this profile is checked without
constructing a synthetic paired `StaticProofContext`.  Dynamic/stack maps must
be disjoint from both images, resources and import bindings are unambiguous,
and every registered callback resolves through the small checked anchor map. -/
def CanonicalMixedRelationalWorldValid
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (world : RelationalWorld) : Bool :=
  dynamicAddressRangeIdsUnique (world.dynamicRanges ++ world.stackRanges) &&
    (world.dynamicRanges ++ world.stackRanges).all
      (mixedRangeDisjointFromImages original.pe candidate.pe) &&
    (world.dynamicRanges ++ world.stackRanges).all
      DynamicAddressRangePair.wordRelationsValid &&
    dynamicAddressRangesDisjointOn false world.dynamicRanges &&
    dynamicAddressRangesDisjointOn true world.dynamicRanges &&
    dynamicAddressRangesDisjointOn false world.stackRanges &&
    dynamicAddressRangesDisjointOn true world.stackRanges &&
    dynamicAddressRangesCrossDisjointOn false world.dynamicRanges world.stackRanges &&
    dynamicAddressRangesCrossDisjointOn true world.dynamicRanges world.stackRanges &&
    world.opaqueResourcesValid &&
    importAddressIdsUnique world.importAddresses &&
    importAddressIatPairsUnique world.importAddresses &&
    importAddressIdentitiesConsistent world.importAddresses &&
    world.importAddresses.all (mixedImportAddressValid original candidate) &&
    world.registeredCallbacks.all
      (mixedCallbackAddressValid original candidate anchors) &&
    world.tlsState.slots.all fun slot =>
      match slot.target with
      | .staticData .. => false
      | _ => true

def opaqueResourceValueTarget (resource : OpaqueResourcePair) : ValueTargetPair := {
  id := resource.id
  originalValue := resource.original.toNat
  candidateValue := resource.candidate.toNat
  originalRelocationRva := 0
  candidateRelocationRva := 0
  mappedSize := 0
  relocationOffsets := []
}

def importAddressValueTarget (binding : ImportAddressPair) : ValueTargetPair := {
  id := binding.id
  originalValue := binding.originalAddress.toNat
  candidateValue := binding.candidateAddress.toNat
  originalRelocationRva := binding.originalIatRva
  candidateRelocationRva := binding.candidateIatRva
  mappedSize := 0
  relocationOffsets := []
}

def imageBaseValueTarget (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram) : ValueTargetPair := {
  id := 0
  originalValue := original.pe.imageBase
  candidateValue := candidate.pe.imageBase
  originalRelocationRva := 0
  candidateRelocationRva := 0
  mappedSize := 0
  relocationOffsets := []
}

def CanonicalMixedRuntimeValueTargets (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) :
    List ValueTargetPair :=
  imageBaseValueTarget original candidate :: world.runtimeValueTargets ++
    world.opaqueResources.map opaqueResourceValueTarget ++
    world.importAddresses.map importAddressValueTarget

def CheckedMixedAnchorValuesRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (originalValue candidateValue : Word) : Prop :=
  exists anchor source,
    anchor ∈ anchors /\
      original.source? anchor.originalTargetId = some source /\
      codeAddressMatches original.pe.imageBase source.target.rva
        source.target.aliases originalValue = true /\
      candidateValue = BitVec.ofNat 32
        (candidate.pe.imageBase + anchor.candidateRva)

def CheckedMixedCallbackTargetsRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (originalTarget candidateTarget : Nat) : Prop :=
  exists anchor source,
    anchor ∈ anchors /\
      anchor.originalTargetId = originalTarget /\
      anchor.candidateRva = candidateTarget /\
      original.source? originalTarget = some source /\
      executableRva candidate.pe candidateTarget = true

def CanonicalMixedWordPayloadRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (world : RelationalWorld)
    (originalValue candidateValue : Word) : Prop :=
  wordRelated original.pe.imageBase candidate.pe.imageBase []
      (CanonicalMixedRuntimeValueTargets original candidate world)
      originalValue candidateValue = true \/
    CheckedMixedAnchorValuesRelated original candidate anchors
      originalValue candidateValue

def CanonicalMixedWorldsRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (originalWorld candidateWorld : RelationalWorld) : Prop :=
  originalWorld = candidateWorld /\
    CanonicalMixedRelationalWorldValid original candidate anchors originalWorld = true

/-! ## Bounded PE32 console launch relation

The launch relation describes loader-owned state before the native wrapper has
allocated or populated an interpreter engine.  Range identifiers are labels
for standard Win32 launch objects; they do not choose concrete addresses or
contents.  The relation quantifies over every pair of concrete states whose
stack, TEB/PEB, process parameters, command-line/argv backing, environment,
TLS array, imports, registers, and memory satisfy these checked constraints.
-/

structure MixedPE32ConsoleLaunchMemoryProfile where
  stackRangeId : Nat
  tebRangeId : Nat
  pebRangeId : Nat
  processParametersRangeId : Nat
  argvRangeId : Nat
  environmentRangeId : Nat
  tlsArrayRangeId : Nat
deriving Repr, DecidableEq

def MixedPE32ConsoleLaunchMemoryProfile.roleIds
    (profile : MixedPE32ConsoleLaunchMemoryProfile) : List Nat :=
  [profile.stackRangeId, profile.tebRangeId, profile.pebRangeId,
    profile.processParametersRangeId, profile.argvRangeId,
    profile.environmentRangeId, profile.tlsArrayRangeId]

def MixedPE32ConsoleLaunchMemoryProfile.dynamicRoleIds
    (profile : MixedPE32ConsoleLaunchMemoryProfile) : List Nat :=
  [profile.tebRangeId, profile.pebRangeId,
    profile.processParametersRangeId, profile.argvRangeId,
    profile.environmentRangeId, profile.tlsArrayRangeId]

def mixedRangeWithId? (ranges : List DynamicAddressRangePair) (id : Nat) :
    Option DynamicAddressRangePair :=
  ranges.find? fun range => range.id == id

def mixedLaunchImportsComplete (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram) (world : RelationalWorld) : Bool :=
  (original.imports.all fun imported =>
      world.importAddresses.any fun binding =>
        binding.originalIatRva == imported.iatRva &&
          binding.imported == normalizeImport imported) &&
    (candidate.imports.all fun imported =>
      world.importAddresses.any fun binding =>
        binding.candidateIatRva == imported.iatRva &&
          binding.imported == normalizeImport imported)

def CanonicalMixedLaunchWorldShape
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (profile : MixedPE32ConsoleLaunchMemoryProfile)
    (world : RelationalWorld) : Bool :=
  decide profile.roleIds.Nodup &&
    world.stackRanges.length == 1 &&
    (mixedRangeWithId? world.stackRanges profile.stackRangeId).isSome &&
    (profile.dynamicRoleIds.all fun id =>
      (mixedRangeWithId? world.dynamicRanges id).isSome) &&
    world.opaqueResources.isEmpty &&
    world.registeredCallbacks.isEmpty &&
    world.tlsState.lastError == BitVec.ofNat 32 0 &&
    ((world.dynamicRanges ++ world.stackRanges).all fun range =>
      range.originalBase.toNat % 4 == 0 &&
        range.candidateBase.toNat % 4 == 0 && range.size % 4 == 0) &&
    mixedLaunchImportsComplete original candidate world

def CanonicalMixedRangeMemoryRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (world : RelationalWorld)
    (range : DynamicAddressRangePair)
    (originalMemory candidateMemory : Memory) : Prop :=
  forall offset, offset + 4 <= range.size -> offset % 4 = 0 ->
    CanonicalMixedWordPayloadRelated original candidate anchors world
      (Memory.read32 originalMemory
        (range.originalBase + BitVec.ofNat 32 offset))
      (Memory.read32 candidateMemory
        (range.candidateBase + BitVec.ofNat 32 offset))

def CanonicalMixedImportAddressesMemoryHold
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (world : RelationalWorld)
    (originalMemory candidateMemory : Memory) : Prop :=
  forall binding, binding ∈ world.importAddresses ->
    Memory.read32 originalMemory
        (BitVec.ofNat 32 (original.pe.imageBase + binding.originalIatRva)) =
          binding.originalAddress /\
      Memory.read32 candidateMemory
        (BitVec.ofNat 32 (candidate.pe.imageBase + binding.candidateIatRva)) =
          binding.candidateAddress

def resolveMixedTlsTarget (candidateSide : Bool) (world : RelationalWorld) :
    RelationalTlsValueTarget -> Option Word
  | .exact value => some value
  | .dynamicRange rangeId offset => do
      let range <- mixedRangeWithId? world.dynamicRanges rangeId
      if offset < range.size then
        some ((if candidateSide then range.candidateBase else range.originalBase) +
          BitVec.ofNat 32 offset)
      else none
  | .opaqueResource resourceId => do
      let resource <- world.opaqueResources.find? fun resource =>
        resource.id == resourceId
      some (if candidateSide then resource.candidate else resource.original)
  | .staticData .. => none

def CanonicalMixedTlsSlotsMemoryHold (world : RelationalWorld)
    (tlsRange : DynamicAddressRangePair)
    (originalMemory candidateMemory : Memory) : Prop :=
  forall slot, slot ∈ world.tlsState.slots ->
    exists originalValue candidateValue,
      resolveMixedTlsTarget false world slot.target = some originalValue /\
        resolveMixedTlsTarget true world slot.target = some candidateValue /\
        slot.index * 4 + 4 <= tlsRange.size /\
        Memory.read32 originalMemory
            (tlsRange.originalBase + BitVec.ofNat 32 (slot.index * 4)) =
          originalValue /\
        Memory.read32 candidateMemory
            (tlsRange.candidateBase + BitVec.ofNat 32 (slot.index * 4)) =
          candidateValue

def mixedMachineRegisters : List Reg :=
  [.eax, .ebx, .ecx, .edx, .esi, .edi, .ebp, .esp]

/-- Concrete pre-wrapper launch states.  The fixed x86 offsets are the bounded
`pe32-console-launch-v2` Win32 TEB/PEB contract: TLS vector at `fs:[0x2c]`,
PEB at `fs:[0x30]`, last-error at `fs:[0x34]`, process parameters at
`PEB+0x10`, command-line backing at `params+0x44`, and environment at
`params+0x48`. -/
structure CanonicalMixedPE32ConsoleLaunchStatePair
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (profile : MixedPE32ConsoleLaunchMemoryProfile)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) where
  worldsRelated : CanonicalMixedWorldsRelated original candidate anchors
    originalWorld candidateWorld
  worldShape : CanonicalMixedLaunchWorldShape original candidate profile
    originalWorld = true
  rangeMemory : forall range,
    range ∈ originalWorld.dynamicRanges ++ originalWorld.stackRanges ->
      CanonicalMixedRangeMemoryRelated original candidate anchors originalWorld
        range originalState.memory candidateState.memory
  importsMemory : CanonicalMixedImportAddressesMemoryHold original candidate
    originalWorld originalState.memory candidateState.memory
  /-- Loader-owned image bytes are part of the launch premise.  In particular,
  `rvaByte` supplies zero for every mapped virtual tail beyond raw section
  data; generated wrappers may rely on those bytes only through this fact. -/
  originalImageMemory : PreferredBaseImageMemory original.pe original.imports
    originalState.memory
  candidateImageMemory : PreferredBaseImageMemory candidate.pe candidate.imports
    candidateState.memory
  registersRelated : forall register, register ∈ mixedMachineRegisters ->
    CanonicalMixedWordPayloadRelated original candidate anchors originalWorld
      (originalState.registers.get register)
      (candidateState.registers.get register)
  /-- The first native-engine profile captures concrete launch words directly.
  It therefore admits only the lockstep launch coupling here.  A future
  address-translating engine representation must introduce and prove a
  distinct mapped-value launch profile rather than silently reusing this one. -/
  registersExact : originalState.registers = candidateState.registers
  flagsExact : originalState.eflags = candidateState.eflags
  undefinedExact : originalState.undefinedValue = candidateState.undefinedValue
  x87Exact : MachineX87Exact originalState candidateState
  fsBaseExact : originalState.fsBase = candidateState.fsBase
  stackRange : DynamicAddressRangePair
  stackRangeExact : mixedRangeWithId? originalWorld.stackRanges
    profile.stackRangeId = some stackRange
  stackPointerOffset : Nat
  stackPointerInside : stackPointerOffset < stackRange.size
  originalStackPointer : originalState.registers.esp =
    stackRange.originalBase + BitVec.ofNat 32 stackPointerOffset
  candidateStackPointer : candidateState.registers.esp =
    stackRange.candidateBase + BitVec.ofNat 32 stackPointerOffset
  tebRange : DynamicAddressRangePair
  tebRangeExact : mixedRangeWithId? originalWorld.dynamicRanges profile.tebRangeId =
    some tebRange
  tebHeaderInside : 0x38 <= tebRange.size
  originalFsBase : originalState.fsBase = tebRange.originalBase
  candidateFsBase : candidateState.fsBase = tebRange.candidateBase
  originalTebSelf : Memory.read32 originalState.memory
      (tebRange.originalBase + BitVec.ofNat 32 0x18) = tebRange.originalBase
  candidateTebSelf : Memory.read32 candidateState.memory
      (tebRange.candidateBase + BitVec.ofNat 32 0x18) = tebRange.candidateBase
  pebRange : DynamicAddressRangePair
  pebRangeExact : mixedRangeWithId? originalWorld.dynamicRanges profile.pebRangeId =
    some pebRange
  pebHeaderInside : 0x14 <= pebRange.size
  processParametersRange : DynamicAddressRangePair
  processParametersRangeExact : mixedRangeWithId? originalWorld.dynamicRanges
    profile.processParametersRangeId = some processParametersRange
  processParametersHeaderInside : 0x4c <= processParametersRange.size
  argvRange : DynamicAddressRangePair
  argvRangeExact : mixedRangeWithId? originalWorld.dynamicRanges profile.argvRangeId =
    some argvRange
  environmentRange : DynamicAddressRangePair
  environmentRangeExact : mixedRangeWithId? originalWorld.dynamicRanges
    profile.environmentRangeId = some environmentRange
  tlsArrayRange : DynamicAddressRangePair
  tlsArrayRangeExact : mixedRangeWithId? originalWorld.dynamicRanges
    profile.tlsArrayRangeId = some tlsArrayRange
  originalTebTlsArray : Memory.read32 originalState.memory
      (tebRange.originalBase + BitVec.ofNat 32 0x2c) = tlsArrayRange.originalBase
  candidateTebTlsArray : Memory.read32 candidateState.memory
      (tebRange.candidateBase + BitVec.ofNat 32 0x2c) = tlsArrayRange.candidateBase
  originalTebPeb : Memory.read32 originalState.memory
      (tebRange.originalBase + BitVec.ofNat 32 0x30) = pebRange.originalBase
  candidateTebPeb : Memory.read32 candidateState.memory
      (tebRange.candidateBase + BitVec.ofNat 32 0x30) = pebRange.candidateBase
  originalLastError : Memory.read32 originalState.memory
      (tebRange.originalBase + BitVec.ofNat 32 0x34) = originalWorld.tlsState.lastError
  candidateLastError : Memory.read32 candidateState.memory
      (tebRange.candidateBase + BitVec.ofNat 32 0x34) = candidateWorld.tlsState.lastError
  originalProcessParameters : Memory.read32 originalState.memory
      (pebRange.originalBase + BitVec.ofNat 32 0x10) =
    processParametersRange.originalBase
  candidateProcessParameters : Memory.read32 candidateState.memory
      (pebRange.candidateBase + BitVec.ofNat 32 0x10) =
    processParametersRange.candidateBase
  originalArgv : Memory.read32 originalState.memory
      (processParametersRange.originalBase + BitVec.ofNat 32 0x44) =
    argvRange.originalBase
  candidateArgv : Memory.read32 candidateState.memory
      (processParametersRange.candidateBase + BitVec.ofNat 32 0x44) =
    argvRange.candidateBase
  originalEnvironment : Memory.read32 originalState.memory
      (processParametersRange.originalBase + BitVec.ofNat 32 0x48) =
    environmentRange.originalBase
  candidateEnvironment : Memory.read32 candidateState.memory
      (processParametersRange.candidateBase + BitVec.ofNat 32 0x48) =
    environmentRange.candidateBase
  tlsSlotsMemory : CanonicalMixedTlsSlotsMemoryHold originalWorld tlsArrayRange
    originalState.memory candidateState.memory

def CanonicalMixedLaunchStatesRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (profile : MixedPE32ConsoleLaunchMemoryProfile)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) : Prop :=
  Nonempty (CanonicalMixedPE32ConsoleLaunchStatePair original candidate anchors
    profile originalWorld candidateWorld originalState candidateState)

theorem CanonicalMixedPE32ConsoleLaunchStatePair.candidateLoaderByte
    (pair : CanonicalMixedPE32ConsoleLaunchStatePair original candidate anchors
      profile originalWorld candidateWorld originalState candidateState)
    (rva expected : Nat) (inside : rva < candidate.pe.sizeOfImage)
    (notIat : importIatByteCovered candidate.imports rva = false)
    (loaded : rvaByte candidate.pe rva = some expected) :
    candidateState.memory
        (BitVec.ofNat 32 (candidate.pe.imageBase + rva)) =
      BitVec.ofNat 8 expected :=
  pair.candidateImageMemory rva expected inside notIat loaded

theorem CanonicalMixedPE32ConsoleLaunchStatePair.candidateLoaderZeroFill
    (pair : CanonicalMixedPE32ConsoleLaunchStatePair original candidate anchors
      profile originalWorld candidateWorld originalState candidateState)
    (rva : Nat) (inside : rva < candidate.pe.sizeOfImage)
    (notIat : importIatByteCovered candidate.imports rva = false)
    (zeroFilled : rvaByte candidate.pe rva = some 0) :
    candidateState.memory
        (BitVec.ofNat 32 (candidate.pe.imageBase + rva)) =
      BitVec.ofNat 8 0 :=
  pair.candidateLoaderByte rva 0 inside notIat zeroFilled

/-- Exact reflected wrapper semantics for every declared launch, return, and
termination source.  Static coverage supplies one path per parsed PE entry/TLS
root and per wrapper cutpoint.  `replayTotal` rules out certificates whose
checked paths cannot execute from a matching concrete state.  Root paths must
establish the runtime engine relation without emitting an external event. -/
structure LegacyCanonicalMixedLaunchWrapperRefinement
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2) where
  reflected : ExactNativeLaunchWrapperCertificate
  staticChecked : reflected.staticChecked candidate.pe candidate.imports = true
  replayTotal : forall path, path ∈ reflected.paths -> forall before,
    path.source.matches candidate.pe reflected.cutpoints before = true ->
      exists result, path.replay? candidate reflected.cutpoints before = some result
  rootsEstablishRuntime : forall root rootRva originalWorld candidateWorld
      originalState candidateState calls,
    root.rva? candidate.pe = some rootRva ->
      MixedLaunchStatesRelated original candidate contract originalWorld
        candidateWorld originalState candidateState ->
      candidateNativeLaunchCallFrames? candidate launch candidateState = some calls ->
      exists path result candidateAfterRva candidateAfter candidateAfterCalls,
        path ∈ reflected.paths /\
          path.source = .canonicalRoot root /\
          path.replay? candidate reflected.cutpoints
              (.running rootRva 0 candidateState calls 0 [] candidateWorld) =
            some result /\
          result.observations = [] /\
          result.after = .running candidateAfterRva 0 candidateAfter
            candidateAfterCalls 0 [] candidateWorld /\
          contract.runtimeStatesRelated originalWorld candidateWorld originalState
            candidateAfter

/-- Guard-complete wrapper authority used by the canonical mixed profile.
Unlike the legacy linear inventory, concrete replay chooses the checked arm of
each wrapper branch.  Establishing the runtime relation remains a separate
semantic obligation over every launch state. -/
structure CanonicalMixedLaunchWrapperRefinement
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (launch : PE32ConsoleLaunchV2) where
  reflected : ExactNativeLaunchGraphCertificate
  staticChecked : reflected.staticChecked candidate.pe candidate.imports = true
  replayTotal : forall route, route ∈ reflected.routes -> forall before,
    route.source.matches candidate.pe reflected.cutpoints before = true ->
      exists result,
        route.replay? candidate reflected.cutpoints before = some result
  rootsEstablishRuntime : forall root rootRva originalWorld candidateWorld
      originalState candidateState calls,
    root.rva? candidate.pe = some rootRva ->
      MixedLaunchStatesRelated original candidate contract originalWorld
        candidateWorld originalState candidateState ->
      candidateNativeLaunchCallFrames? candidate launch candidateState = some calls ->
      exists route result candidateAfter,
        route ∈ reflected.routes /\
          route.source = .canonicalRoot root /\
          route.replay? candidate reflected.cutpoints
              (.running rootRva 0 candidateState calls 0 [] candidateWorld) =
            some result /\
          result.observations = [] /\
          result.after.machine? = some candidateAfter /\
          contract.runtimeStatesRelated originalWorld candidateWorld originalState
            candidateAfter

def decodedWorldProgramWithProtocolEnvironment
    (program : DecodedWorldProgram)
    (environment : WorldExternalProtocolEnvironment) : DecodedWorldProgram :=
  { program with protocolEnvironment := environment }

def exactNativeWorldProgramWithEnvironment
    (program : ExactNativeWorldProgram)
    (environment : NativeWorldEnvironment) : ExactNativeWorldProgram :=
  { program with environment := environment }

def exactNativeCandidateAuthorityWithEnvironment
    (authority : ExactNativeCandidateAuthority candidate)
    (environment : NativeWorldEnvironment) :
    ExactNativeCandidateAuthority
      (exactNativeWorldProgramWithEnvironment candidate environment) := {
  importCertificate := authority.importCertificate
  relocations := authority.relocations
  tableRva := authority.tableRva
  countRva := authority.countRva
  semanticRecords := authority.semanticRecords
  peParsed := authority.peParsed
  importsBound := authority.importsBound
  importsParsed := authority.importsParsed
  relocationsParsed := authority.relocationsParsed
  loaderImageValid := authority.loaderImageValid
  table := authority.table
}

def exactMixedProgramBindingWithProtocolEnvironment
    (binding : ExactMixedProgramBinding original originalProgram)
    (environment : WorldExternalProtocolEnvironment) :
    ExactMixedProgramBinding original
      (decodedWorldProgramWithProtocolEnvironment originalProgram environment) := {
  original := {
    originalRole := binding.original.originalRole
    peBound := binding.original.peBound
    importsBound := binding.original.importsBound
    machineContractsBound := binding.original.machineContractsBound
    sourceRegionsBound := binding.original.sourceRegionsBound
    regionsHaveSources := binding.original.regionsHaveSources
    originalTargetsBound := binding.original.originalTargetsBound
    indexedIndirectResolutionBound :=
      binding.original.indexedIndirectResolutionBound
    concreteReturnResolutionBound :=
      binding.original.concreteReturnResolutionBound
  }
}

def directExactCandidateNativeLaunchRootWithEnvironment
    (root : DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva)
    (environment : NativeWorldEnvironment) :
    DirectExactCandidateNativeLaunchRoot
      (exactNativeWorldProgramWithEnvironment candidate environment) launch
      candidateRootRva := by
  simpa [exactNativeWorldProgramWithEnvironment] using root

def mixedLaunchRealizableWithEnvironment
    (realizable : MixedLaunchRealizable original candidate contract)
    (environment : NativeWorldEnvironment) :
    MixedLaunchRealizable original
      (exactNativeWorldProgramWithEnvironment candidate environment) contract := by
  simpa [exactNativeWorldProgramWithEnvironment] using realizable

/-- The native machine contains an exact engine encoding of one reachable
original state.  The disjunction represents the checked input/output engine
buffers, not arbitrary caller predicates. -/
def CanonicalMixedRuntimeStatesRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (abi : ConcreteKernelABI candidate.pe candidate.imports relocations
      tableRva countRva records)
    (reachableTargetIds : List Nat)
    (anchors : List MixedNativeCodeAnchor)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) : Prop :=
  CanonicalMixedWorldsRelated original candidate anchors
      originalWorld candidateWorld /\
    exists targetId source,
      targetId ∈ reachableTargetIds /\
        original.source? targetId = some source /\
        (OriginalEngineStateHolds abi.engineLayout abi.parameters.inputAddress
            source.target.rva originalState candidateState \/
          OriginalEngineStateHolds abi.engineLayout
            (abi.parameters.outputAddress abi.engineLayout)
            source.target.rva originalState candidateState)

def CanonicalMixedValuesRelated
    (original : OriginalDecodedStaticContext)
    (candidate : ExactNativeWorldProgram)
    (anchors : List MixedNativeCodeAnchor)
    (originalWorld candidateWorld : RelationalWorld)
    (originalValue candidateValue : Word) : Prop :=
  CanonicalMixedWorldsRelated original candidate anchors
      originalWorld candidateWorld /\
    CanonicalMixedWordPayloadRelated original candidate anchors originalWorld
      originalValue candidateValue

/-- Exact immutable authorities and the one-sided runtime relation.  A value of
this structure cannot be built from a status field or from a candidate address
invented for every original semantic record. -/
structure CanonicalMixedRelationCore
    (original : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority original)
    (originalProgram : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (programBinding : ExactMixedProgramBinding original originalProgram)
    (abi : ConcreteKernelABI candidate.pe candidate.imports
      candidateAuthority.relocations candidateAuthority.tableRva
      candidateAuthority.countRva candidateAuthority.semanticRecords)
    (reachabilityTargetIds : List Nat) where
  anchors : List MixedNativeCodeAnchor
  anchorsValid : MixedNativeCodeAnchorsValid original candidate
    reachabilityTargetIds anchors = true
  launchMemoryProfile : MixedPE32ConsoleLaunchMemoryProfile

def CanonicalMixedRelationCore.contract
    (core : CanonicalMixedRelationCore original originalAuthority originalProgram
      candidate candidateAuthority programBinding abi reachabilityTargetIds) :
    MixedRelationContract := {
  worldsRelated := CanonicalMixedWorldsRelated original candidate core.anchors
  launchStatesRelated := CanonicalMixedLaunchStatesRelated original candidate
    core.anchors core.launchMemoryProfile
  runtimeStatesRelated := CanonicalMixedRuntimeStatesRelated original candidate abi
    reachabilityTargetIds core.anchors
  valuesRelated := CanonicalMixedValuesRelated original candidate core.anchors
  callbackTargetsRelated := CheckedMixedCallbackTargetsRelated original candidate
    core.anchors
}

/-- Final relation policy.  Launch is explicitly inhabited, while environment
refinement remains a premise of the exported theorem rather than a selected
field here.  The wrapper family is therefore valid for every candidate
environment that may later satisfy exact pointwise machine-level refinement. -/
structure CanonicalMixedRelationProfile
    (original : OriginalDecodedStaticContext)
    (originalAuthority : ExactOriginalDecodedAuthority original)
    (originalProgram : DecodedWorldProgram)
    (candidate : ExactNativeWorldProgram)
    (candidateAuthority : ExactNativeCandidateAuthority candidate)
    (programBinding : ExactMixedProgramBinding original originalProgram)
    (abi : ConcreteKernelABI candidate.pe candidate.imports
      candidateAuthority.relocations candidateAuthority.tableRva
      candidateAuthority.countRva candidateAuthority.semanticRecords)
    (launch : PE32ConsoleLaunchV2)
    (originalRoot : DirectExactOriginalDecodedLaunchRoot original launch)
    (reachability : ExactOriginalDecodedReachability original originalAuthority
      launch originalRoot) where
  core : CanonicalMixedRelationCore original originalAuthority originalProgram
    candidate candidateAuthority programBinding abi reachability.targetIds
  launchAnchorsComplete : MixedNativeLaunchAnchorsComplete candidate launch
    core.anchors = true
  externalFrames : MixedExternalFrameContract
  launchRealizable : MixedLaunchRealizable original candidate core.contract
  launchWrapperRefines : forall originalEnvironment candidateEnvironment,
    ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment originalProgram
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
        core.contract externalFrames ->
      CanonicalMixedLaunchWrapperRefinement original
        (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
        core.contract launch

def CanonicalMixedRelationProfile.contract
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability) : MixedRelationContract :=
  profile.core.contract

@[simp] theorem CanonicalMixedRelationProfile.worldsRelated_iff
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability) (originalWorld candidateWorld : RelationalWorld) :
    profile.contract.worldsRelated originalWorld candidateWorld <->
      originalWorld = candidateWorld /\
        CanonicalMixedRelationalWorldValid original candidate
          profile.core.anchors originalWorld = true := by
  rfl

@[simp] theorem CanonicalMixedRelationProfile.runtimeStatesRelated_iff
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) :
    profile.contract.runtimeStatesRelated originalWorld candidateWorld
        originalState candidateState <->
      CanonicalMixedRuntimeStatesRelated original candidate abi
        reachability.targetIds profile.core.anchors originalWorld candidateWorld
        originalState candidateState := by
  rfl

@[simp] theorem CanonicalMixedRelationProfile.launchStatesRelated_iff
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState) :
    profile.contract.launchStatesRelated originalWorld candidateWorld
        originalState candidateState <->
      Nonempty (CanonicalMixedPE32ConsoleLaunchStatePair original candidate
        profile.core.anchors profile.core.launchMemoryProfile originalWorld
        candidateWorld originalState candidateState) := by
  rfl

@[simp] theorem CanonicalMixedRelationProfile.valuesRelated_iff
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (originalWorld candidateWorld : RelationalWorld)
    (originalValue candidateValue : Word) :
    profile.contract.valuesRelated originalWorld candidateWorld
        originalValue candidateValue <->
      CanonicalMixedValuesRelated original candidate profile.core.anchors
        originalWorld candidateWorld originalValue candidateValue := by
  rfl

theorem CanonicalMixedRelationProfile.runtimeStateRepresented
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (related : profile.contract.runtimeStatesRelated originalWorld candidateWorld
      originalState candidateState) :
    exists targetId source,
      targetId ∈ reachability.targetIds /\
        original.source? targetId = some source /\
        (OriginalEngineStateHolds abi.engineLayout abi.parameters.inputAddress
            source.target.rva originalState candidateState \/
          OriginalEngineStateHolds abi.engineLayout
            (abi.parameters.outputAddress abi.engineLayout)
            source.target.rva originalState candidateState) :=
  related.2

theorem CanonicalMixedRelationProfile.callbackTargetMapped
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (related : profile.contract.callbackTargetsRelated originalTarget
      candidateTarget) :
    exists anchor source,
      anchor ∈ profile.core.anchors /\
        anchor.originalTargetId = originalTarget /\
        anchor.candidateRva = candidateTarget /\
        original.source? originalTarget = some source /\
        executableRva candidate.pe candidateTarget = true :=
  related

theorem CanonicalMixedRelationProfile.mixedLaunchRealizable
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability) :
    MixedLaunchRealizable original candidate profile.contract :=
  profile.launchRealizable

/-- Operation-local execution relations remain separate.  Their checked union
exists only to satisfy the shared mixed component interface; an operation proof
is lifted into that union with its operation tag. -/
abbrev KernelOperationDispatchFamily := KernelOperation -> KernelDispatchRelation

def combinedKernelDispatchRelation (family : KernelOperationDispatchFamily) :
    KernelDispatchRelation :=
  fun entryRva before after events =>
    exists operation, family operation entryRva before after events

theorem kernelOperationRefinesUsing_combined
    (family : KernelOperationDispatchFamily)
    (refines : KernelOperationRefinesUsing program abi (family operation) operation) :
    KernelOperationRefinesUsing program abi
      (combinedKernelDispatchRelation family) operation := by
  intro request before operationExact requestRelated response transition
  rcases refines request before operationExact requestRelated response transition with
    ⟨entryRva, after, events, entryExact, dispatched, responseRelated, frame⟩
  exact ⟨entryRva, after, events, entryExact, ⟨operation, dispatched⟩,
    responseRelated, frame⟩

/-! ## Canonical acceptance -/

structure CanonicalMixedWorldAcceptanceCertificate
    (original : OriginalDecodedStaticContext)
    (originalTemplate : DecodedWorldProgram)
    (candidateTemplate : ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (externalFrames : MixedExternalFrameContract)
    (launch : PE32ConsoleLaunchV2) where
  certificates : forall originalEnvironment candidateEnvironment,
    ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment originalTemplate
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment candidateTemplate
          candidateEnvironment)
        contract externalFrames ->
      MixedWorldAcceptanceCertificate original
        (decodedWorldProgramWithProtocolEnvironment originalTemplate
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment candidateTemplate
          candidateEnvironment)
        contract launch

def CanonicalMixedWorldProgramsChunkObservationallyEquivalent
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability) : Prop :=
  forall originalEnvironment candidateEnvironment,
    ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment originalProgram
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
        profile.contract profile.externalFrames ->
      ExactMixedWorldProgramsChunkObservationallyEquivalent original
        (decodedWorldProgramWithProtocolEnvironment originalProgram
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
        profile.contract launch

theorem canonicalMixedWorldProgramsEquivalent
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (certificate : CanonicalMixedWorldAcceptanceCertificate original originalProgram
      candidate profile.contract profile.externalFrames launch)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentRefines : ExactOneToOneMixedExternalEnvironmentsRefine
      (decodedWorldProgramWithProtocolEnvironment originalProgram
        originalEnvironment)
      (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
      profile.contract profile.externalFrames) :
    ExactMixedWorldProgramsChunkObservationallyEquivalent original
      (decodedWorldProgramWithProtocolEnvironment originalProgram
        originalEnvironment)
      (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
      profile.contract launch :=
  mixedWorldProgramsEquivalent
    (certificate.certificates originalEnvironment candidateEnvironment
      environmentRefines)

theorem canonicalMixedWorldProgramsEquivalent_trace
    (profile : CanonicalMixedRelationProfile original originalAuthority
      originalProgram candidate candidateAuthority programBinding abi launch
      originalRoot reachability)
    (certificate : CanonicalMixedWorldAcceptanceCertificate original originalProgram
      candidate profile.contract profile.externalFrames launch)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentRefines : ExactOneToOneMixedExternalEnvironmentsRefine
      (decodedWorldProgramWithProtocolEnvironment originalProgram
        originalEnvironment)
      (exactNativeWorldProgramWithEnvironment candidate candidateEnvironment)
      profile.contract profile.externalFrames)
    (fuel : Nat)
    (initial : MixedLaunchStatesRelated original candidate profile.contract
      originalWorld candidateWorld originalState candidateState) :
    let selected := certificate.certificates originalEnvironment
      candidateEnvironment environmentRefines
    ChunkedRelatedTrace
      (decodedWorldProgramWithProtocolEnvironment originalProgram
        originalEnvironment).pe32TransitionSystem
      (exactNativeWorldProgramWithEnvironment candidate
        candidateEnvironment).transitionSystem
      selected.composition.invariant.holds
      profile.contract.eventObservationsRelated fuel
      (.running launch.rootTargetId originalState
        launch.continuationTargetIds 0 originalWorld)
      (.running selected.candidateRootRva 0 candidateState
        (selected.composition.candidateLaunchCalls candidateState) 0 []
        candidateWorld) := by
  exact mixedWorldProgramsEquivalent_trace
    (certificate.certificates originalEnvironment candidateEnvironment
      environmentRefines) fuel originalWorld candidateWorld originalState
      candidateState initial

#print axioms CanonicalMixedRelationProfile.runtimeStateRepresented
#print axioms CanonicalMixedRelationProfile.callbackTargetMapped
#print axioms CanonicalMixedRelationProfile.mixedLaunchRealizable
#print axioms kernelOperationRefinesUsing_combined
#print axioms canonicalMixedWorldProgramsEquivalent
#print axioms canonicalMixedWorldProgramsEquivalent_trace

end StageA.Relational.InterpreterMixedProfile
