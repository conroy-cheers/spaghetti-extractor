import StageA.RelationalCallableExternalIdentity

namespace StageA.Relational.CallableExternalCapability

open StageA.Formal StageA.Relational

/-! # Callable external capabilities

This module is a scoped proof layer for opaque callable values returned by an
external resolver.  It intentionally does not add a dynamic-external variant
to the shared execution outcomes.  A concrete target word is usable here only
when it is the side-specific value of a named `OpaqueResourcePair`; ordinary
`relatedWord` evidence and internal code-target identities are not authority.
-/

/-- Exact machine-level argument extraction.  Resolver contracts use the
stack-only subset already represented by `MachineImportCallContract`; resolved
capabilities may additionally use registers or constants. -/
inductive CallableArgumentSource where
  | register (register : Reg)
  | stackWord (offset : Nat)
  | constant (value : Word)
deriving Repr, DecidableEq

def CallableArgumentSource.shapeValid : CallableArgumentSource -> Bool
  | .register _ => true
  | .stackWord offset => offset < 2^32 && offset % 4 == 0
  | .constant _ => true

def CallableArgumentSource.eval (source : CallableArgumentSource)
    (state : MachineState) : Word :=
  match source with
  | .register reg => state.registers.get reg
  | .stackWord offset =>
      state.read32 (state.registers.esp + BitVec.ofNat 32 offset)
  | .constant value => value

def callableArgumentsExtracted (sources : List CallableArgumentSource)
    (state : MachineState) (arguments : List Word) : Prop :=
  arguments = sources.map (fun source => source.eval state)

structure ExactImmutableIdentityArgument where
  index : Nat
  value : Word
deriving Repr, DecidableEq

/-- A pointer-valued immutable identity whose bytes are owned by one canonical
paired static-data target.  The bytes exclude the terminating zero. -/
structure CanonicalStaticStringIdentityArgument where
  argumentIndex : Nat
  targetId : Nat
  offset : Nat := 0
  bytes : Bytes
deriving Repr, DecidableEq

def CanonicalStaticStringIdentityArgument.shapeValid
    (identity : CanonicalStaticStringIdentityArgument) : Bool :=
  identity.offset < 2^32 && identity.bytes.length < 2^32 &&
    identity.bytes.all (· != 0)

def CanonicalStaticStringIdentityArgument.sideAddress?
    (candidate : Bool) (context : StaticProofContext)
    (identity : CanonicalStaticStringIdentityArgument) : Option Word := do
  let target <- context.dataMap.get? identity.targetId
  if identity.offset + identity.bytes.length + 1 <= target.mappedSize then
    let base := if candidate then target.candidateValue else target.originalValue
    if base + identity.offset < 2^32 then
      some (BitVec.ofNat 32 (base + identity.offset))
    else none
  else none

def immutableStaticByteRange
    (pe : PE32) (address size : Nat) : Bool :=
  0 < size && address + size <= 2^32 && pe.sections.any fun sec =>
    !sec.writable &&
      pe.imageBase + sec.virtualAddress <= address &&
      address + size <=
        pe.imageBase + sec.virtualAddress + sec.mappedSize

def CanonicalStaticStringIdentityArgument.staticValid
    (context : StaticProofContext)
    (identity : CanonicalStaticStringIdentityArgument) : Bool :=
  identity.shapeValid &&
    context.dataMap.valid context.originalPe context.candidatePe &&
    match context.dataMap.get? identity.targetId with
    | none => false
    | some target =>
        let originalAddress := target.originalValue + identity.offset
        let candidateAddress := target.candidateValue + identity.offset
        let size := identity.bytes.length + 1
        identity.offset + size <= target.mappedSize &&
          context.originalPe.imageBase <= originalAddress &&
          context.candidatePe.imageBase <= candidateAddress &&
          immutableStaticByteRange context.originalPe originalAddress size &&
          immutableStaticByteRange context.candidatePe candidateAddress size &&
          cStringAtRva context.originalPe
            (originalAddress - context.originalPe.imageBase)
            identity.bytes &&
          cStringAtRva context.candidatePe
            (candidateAddress - context.candidatePe.imageBase)
            identity.bytes

def CanonicalStaticStringIdentityArgument.holds
    (candidate : Bool) (context : StaticProofContext)
    (identity : CanonicalStaticStringIdentityArgument)
    (event : WorldExternalEvent) : Bool :=
  identity.staticValid context &&
    event.arguments[identity.argumentIndex]? ==
      identity.sideAddress? candidate context

def exactIdentityArgumentIndicesUnique
    (arguments : List ExactImmutableIdentityArgument) : Bool :=
  arguments.all fun argument =>
    (arguments.filter fun other => other.index == argument.index).length == 1

/-- A wrapper around one existing machine contract.  The wrapped contract
continues to own ABI and world effects.  This wrapper contributes only the
stronger result-register interpretation. -/
structure ResolverCallContract where
  id : Nat
  machineContractId : Nat
  resultRegister : Reg
  argumentSources : List CallableArgumentSource
  immutableIdentityArgumentIndices : List Nat := []
  /-- A nullable resolver may return zero on both sides without issuing a
  callable capability.  Nonzero results must still issue exactly one pair. -/
  nullable : Bool := false
deriving Repr, DecidableEq

def resolverCallContractIdsUnique
    (contracts : List ResolverCallContract) : Bool :=
  contracts.all fun contract =>
    (contracts.filter fun other => other.id == contract.id).length == 1

def ResolverCallContract.shapeValid (contract : ResolverCallContract) : Bool :=
  contract.resultRegister != .esp &&
    contract.argumentSources.all CallableArgumentSource.shapeValid &&
    contract.immutableIdentityArgumentIndices.all fun index =>
      (contract.immutableIdentityArgumentIndices.filter (· == index)).length == 1

/-- The result register must be clobbered by a returning opaque-resource
contract and must have no generic result relation.  In particular, a
`relatedWord` result row cannot be reinterpreted as callable authority. -/
def ResolverCallContract.validForMachineContract
    (resolver : ResolverCallContract)
    (machine : MachineImportCallContract) : Bool :=
  resolver.shapeValid && machine.shapeValid &&
    machine.id == resolver.machineContractId &&
    machine.disposition == .returns &&
    machine.worldEffect == .opaqueResources &&
    machine.clobberedRegisters.contains resolver.resultRegister &&
    !machine.preservedRegisters.contains resolver.resultRegister &&
    resolver.argumentSources ==
      machine.stackArgumentOffsets.map CallableArgumentSource.stackWord &&
    (machine.resultRegisterRelations.filter fun relation =>
      relation.register == resolver.resultRegister).isEmpty &&
    resolver.immutableIdentityArgumentIndices.all fun index =>
      index < machine.stackArgumentOffsets.length

structure CallableExternalCapability where
  id : Nat
  resourceId : Nat
  resolverContractId : Nat
  resolverSiteId : Nat
  immutableIdentityArguments : List ExactImmutableIdentityArgument := []
  immutableStringIdentityArguments :
    List CanonicalStaticStringIdentityArgument := []
deriving Repr, DecidableEq

def callableCapabilityIdsUnique
    (capabilities : List CallableExternalCapability) : Bool :=
  capabilities.all fun capability =>
    (capabilities.filter fun other => other.id == capability.id).length == 1

def callableCapabilityResourceIdsUnique
    (capabilities : List CallableExternalCapability) : Bool :=
  capabilities.all fun capability =>
    (capabilities.filter fun other =>
      other.resourceId == capability.resourceId).length == 1

/-- Capability and opaque-resource IDs are intentionally identical at this
boundary.  Keeping both fields makes a mistaken integration mapping fail
closed instead of silently selecting another resource. -/
def CallableExternalCapability.validFor
    (capability : CallableExternalCapability)
    (resolver : ResolverCallContract) : Bool :=
  capability.id == capability.resourceId &&
    capability.resolverContractId == resolver.id &&
    exactIdentityArgumentIndicesUnique capability.immutableIdentityArguments &&
    capability.immutableStringIdentityArguments.all
      CanonicalStaticStringIdentityArgument.shapeValid &&
    (capability.immutableIdentityArguments.map (·.index) ++
      capability.immutableStringIdentityArguments.map (·.argumentIndex)) ==
      resolver.immutableIdentityArgumentIndices

def CallableExternalCapability.staticIdentityValid
    (context : StaticProofContext)
    (capability : CallableExternalCapability) : Bool :=
  capability.immutableStringIdentityArguments.all
    (CanonicalStaticStringIdentityArgument.staticValid context)

def capabilityResource? (world : RelationalWorld)
    (capability : CallableExternalCapability) : Option OpaqueResourcePair :=
  world.opaqueResources.find? fun resource =>
    resource.id == capability.resourceId

def ExactImmutableIdentityArgument.holds
    (argument : ExactImmutableIdentityArgument)
    (event : WorldExternalEvent) : Bool :=
  event.arguments[argument.index]? == some argument.value

def resolverIdentityArgumentsHoldOn
    (candidate : Bool) (context : StaticProofContext)
    (capability : CallableExternalCapability)
    (event : WorldExternalEvent) : Bool :=
  capability.immutableIdentityArguments.all (fun argument =>
      argument.holds event) &&
    capability.immutableStringIdentityArguments.all (fun identity =>
      identity.holds candidate context event)

def resolverIdentityArgumentsHold
    (context : StaticProofContext)
    (capability : CallableExternalCapability)
    (original candidate : WorldExternalEvent) : Bool :=
  resolverIdentityArgumentsHoldOn false context capability original &&
    resolverIdentityArgumentsHoldOn true context capability candidate

/-- The resolver event remains a normal imported external boundary.  The
extra clauses bind its exact site, wrapped machine contract, capability
descriptor, and immutable identity arguments. -/
structure ResolverCapabilityBoundaryRelated
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (original candidate : WorldExternalEvent) : Prop where
  resolverValid : resolver.validForMachineContract machine = true
  capabilityValid : capability.validFor resolver = true
  machineContractResolved : machineImportCallContractById? context
    resolver.machineContractId = some machine
  siteMachineContract : site.machineContractId = resolver.machineContractId
  resolverSite : site.id = capability.resolverSiteId
  externalBoundary :
    ExternalCallBoundaryRelated context site machine original candidate
  originalArgumentsExtracted :
    callableArgumentsExtracted resolver.argumentSources original.state
      original.arguments
  candidateArgumentsExtracted :
    callableArgumentsExtracted resolver.argumentSources candidate.state
      candidate.arguments
  immutableIdentity :
    resolverIdentityArgumentsHold context capability original candidate = true

/-- Exact resolver issuance: append one pair and preserve every unrelated
world component and every prior opaque resource in order.  World validity
then rejects duplicate IDs, duplicate side values, zeroes, and collisions. -/
def ExactlyOneFreshCallableResourceIssued
    (context : StaticProofContext) (before after : RelationalWorld)
    (resource : OpaqueResourcePair) : Prop :=
  after.valid context = true ∧
    after.dynamicRanges = before.dynamicRanges ∧
    after.stackRanges = before.stackRanges ∧
    after.importAddresses = before.importAddresses ∧
    after.registeredCallbacks = before.registeredCallbacks ∧
    after.tlsState = before.tlsState ∧
    after.opaqueResources = before.opaqueResources ++ [resource]

/-- One side of resolver issuance.  This is reusable by the operational
wrapper and does not rely on a pre-submitted paired result. -/
structure ResolverCapabilitySideResultConforms
    (candidate : Bool) (context : StaticProofContext)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (event : WorldExternalEvent) (result : WorldExternalResult) : Prop where
  immutableIdentity : resolverIdentityArgumentsHoldOn candidate context
    capability event = true
  machineConforms : machineCallResultConforms candidate context machine event result
  absentBefore : capabilityResource? event.world capability = none
  resultCase :
    (resolver.nullable = true ∧
      result.state.registers.get resolver.resultRegister = BitVec.ofNat 32 0 ∧
      result.world = event.world) ∨
    ∃ resource : OpaqueResourcePair,
      ExactlyOneFreshCallableResourceIssued context event.world result.world resource ∧
        resource.id = capability.resourceId ∧
        result.state.registers.get resolver.resultRegister =
          (if candidate then resource.candidate else resource.original) ∧
        resource.original != BitVec.ofNat 32 0 ∧
        resource.candidate != BitVec.ofNat 32 0

/-- A successful paired resolver step consists of two conforming side results
for one shared successor world. -/
structure ResolverCapabilityResultRelated
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop where
  resultWorld : originalResult.world = candidateResult.world
  originalConforms : ResolverCapabilitySideResultConforms false context machine
    resolver capability originalEvent originalResult
  candidateConforms : ResolverCapabilitySideResultConforms true context machine
    resolver capability candidateEvent candidateResult
  availabilityMatched :
    (originalResult.state.registers.get resolver.resultRegister ==
      BitVec.ofNat 32 0) =
    (candidateResult.state.registers.get resolver.resultRegister ==
      BitVec.ofNat 32 0)
  targetState : StateRel context originalResult.world site.targetInvariant
    originalResult.state candidateResult.state
  runtimeFrames : ExternalRuntimeFramesPreserved originalEvent candidateEvent
    originalResult candidateResult

/-- Availability contains no raw target classification.  It says only that a
specific capability descriptor selects one nonzero resource pair in a world. -/
def CallableCapabilityAvailable
    (capability : CallableExternalCapability)
    (world : RelationalWorld) : Prop :=
  ∃ resource : OpaqueResourcePair,
    resource ∈ world.opaqueResources ∧
      resource.id = capability.resourceId ∧
      resource.original != BitVec.ofNat 32 0 ∧
      resource.candidate != BitVec.ofNat 32 0

theorem ResolverCapabilityResultRelated.available
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    CallableCapabilityAvailable capability originalResult.world := by
  rcases related.originalConforms.resultCase with unavailable | issuedResource
  · simp [unavailable.2.1] at nonzero
  rcases issuedResource with
    ⟨resource, issued, resourceId, _resultValue, originalNonzero,
      candidateNonzero⟩
  refine ⟨resource, ?_, resourceId, originalNonzero, candidateNonzero⟩
  rw [issued.2.2.2.2.2.2]
  simp

/-- A non-null paired resolver result denotes one and the same checked opaque
resource pair on both sides.  Side-local issuance witnesses cannot select
different resources with the same ID because the successor world checks ID
uniqueness. -/
theorem ResolverCapabilityResultRelated.resolvedResultPair
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult)
    (related : ResolverCapabilityResultRelated context site machine resolver
      capability originalEvent candidateEvent originalResult candidateResult)
    (nonzero : originalResult.state.registers.get resolver.resultRegister !=
      BitVec.ofNat 32 0) :
    ∃ resource : OpaqueResourcePair,
      resource ∈ originalResult.world.opaqueResources ∧
        resource.id = capability.resourceId ∧
        originalResult.state.registers.get resolver.resultRegister =
          resource.original ∧
        candidateResult.state.registers.get resolver.resultRegister =
          resource.candidate := by
  rcases related.originalConforms.resultCase with unavailable | originalIssued
  · simp [unavailable.2.1] at nonzero
  rcases originalIssued with
    ⟨originalResource, originalFresh, originalId, originalValue,
      _originalNonzero, _originalCandidateNonzero⟩
  have candidateNe :
      candidateResult.state.registers.get resolver.resultRegister ≠
        BitVec.ofNat 32 0 := by
    intro candidateZero
    have originalNe :
        originalResult.state.registers.get resolver.resultRegister ≠
          BitVec.ofNat 32 0 := by
      simpa using nonzero
    apply originalNe
    have originalZero :
        (originalResult.state.registers.get resolver.resultRegister ==
          BitVec.ofNat 32 0) = true := by
      rw [related.availabilityMatched]
      simp [candidateZero]
    exact beq_iff_eq.mp originalZero
  have candidateNonzero :
      candidateResult.state.registers.get resolver.resultRegister !=
        BitVec.ofNat 32 0 := by
    simpa using candidateNe
  rcases related.candidateConforms.resultCase with unavailable | candidateIssued
  · simp [unavailable.2.1] at candidateNonzero
  rcases candidateIssued with
    ⟨candidateResource, candidateFresh, candidateId, candidateValue,
      _candidateOriginalNonzero, _candidateNonzero⟩
  have originalMember :
      originalResource ∈ originalResult.world.opaqueResources := by
    rw [originalFresh.2.2.2.2.2.2]
    simp
  have candidateMember :
      candidateResource ∈ originalResult.world.opaqueResources := by
    rw [related.resultWorld, candidateFresh.2.2.2.2.2.2]
    simp
  have worldValid : originalResult.world.valid context = true :=
    related.targetState.1
  simp only [RelationalWorld.valid, Bool.and_eq_true] at worldValid
  have opaqueValid : originalResult.world.opaqueResourcesValid = true :=
    RelationalWorld.opaqueResourcesValid_of_valid context originalResult.world
      related.targetState.1
  simp only [RelationalWorld.opaqueResourcesValid, Bool.and_eq_true] at opaqueValid
  have sameResource : originalResource = candidateResource :=
    opaqueResource_eq_of_same_id originalResult.world.opaqueResources
      opaqueValid.1.1.1 originalResource candidateResource originalMember
      candidateMember (originalId.trans candidateId.symm)
  subst candidateResource
  refine ⟨originalResource, originalMember, originalId, ?_, ?_⟩
  · simpa using originalValue
  · simpa using candidateValue

theorem CallableCapabilityAvailable.carry
    (capability : CallableExternalCapability)
    (before after : RelationalWorld)
    (available : CallableCapabilityAvailable capability before)
    (preserved : ∀ resource, resource ∈ before.opaqueResources ->
      resource ∈ after.opaqueResources) :
    CallableCapabilityAvailable capability after := by
  rcases available with
    ⟨resource, member, resourceId, originalNonzero, candidateNonzero⟩
  exact ⟨resource, preserved resource member, resourceId, originalNonzero,
    candidateNonzero⟩

/-- Same-index refinement gives exact pointwise resolver ordering.  No result
relation is manufactured by generated static data. -/
def ResolverCapabilityEnvironmentRefinesAt
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (original candidate : WorldExternalEnvironment) : Prop :=
  ∀ eventIndex originalEvent candidateEvent,
    ResolverCapabilityBoundaryRelated context site machine resolver capability
      originalEvent candidateEvent ->
    ResolverCapabilityResultRelated context site machine resolver capability
      originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent)

theorem resolverCapabilityResultsRelated
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (machine : MachineImportCallContract)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (original candidate : WorldExternalEnvironment)
    (refines : ResolverCapabilityEnvironmentRefinesAt context site machine
      resolver capability original candidate)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : ResolverCapabilityBoundaryRelated context site machine resolver
      capability originalEvent candidateEvent) :
    ResolverCapabilityResultRelated context site machine resolver capability
      originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent) :=
  refines eventIndex originalEvent candidateEvent boundary

/-- ABI facts for a later call or jump.  There is no `ExternalTarget`: the
capability ID is the event identity. -/
structure ResolvedExternalABIContract where
  id : Nat
  capabilityId : Nat
  transfer : ResolvedExternalTransfer
  argumentSources : List CallableArgumentSource
  stackResultDelta : Nat
  preservedRegisters : List Reg
  clobberedRegisters : List Reg
  memoryEffect : MachineCallMemoryEffect
  memoryFootprints : List MachineCallMemoryFootprint := []
  worldEffect : MachineCallWorldEffect := .none
deriving Repr, DecidableEq

def resolvedExternalABIContractIdsUnique
    (contracts : List ResolvedExternalABIContract) : Bool :=
  contracts.all fun contract =>
    (contracts.filter fun other => other.id == contract.id).length == 1

def ResolvedExternalABIContract.effectShapeValid
    (contract : ResolvedExternalABIContract) : Bool :=
  (contract.memoryFootprints.all fun footprint =>
      footprint.shapeValid contract.argumentSources.length &&
        (contract.memoryFootprints.filter (· == footprint)).length == 1) &&
    (match contract.memoryEffect with
    | .none => contract.memoryFootprints.isEmpty
    | .readOnly =>
        contract.memoryFootprints.all (·.access == .read)
    | .argumentRanges =>
        !contract.memoryFootprints.isEmpty &&
          contract.memoryFootprints.any (·.access == .write)
    | .newDynamicRanges | .relationalState => false) &&
    contract.worldEffect == .none

def ResolvedExternalABIContract.shapeValid
    (contract : ResolvedExternalABIContract) : Bool :=
  contract.stackResultDelta % 4 == 0 &&
    contract.stackResultDelta < 2^32 &&
    contract.argumentSources.all CallableArgumentSource.shapeValid &&
    (contract.preservedRegisters.all fun register =>
      register != .esp &&
        (contract.preservedRegisters.filter (· == register)).length == 1 &&
        !contract.clobberedRegisters.contains register) &&
    (contract.clobberedRegisters.all fun register =>
      register != .esp &&
        (contract.clobberedRegisters.filter (· == register)).length == 1 &&
        !contract.preservedRegisters.contains register) &&
    (machineCallAbiRegisters.all fun register =>
      contract.preservedRegisters.contains register ||
        contract.clobberedRegisters.contains register) &&
    contract.effectShapeValid

def resolvedExternalABIResultHolds
    (contract : ResolvedExternalABIContract)
    (before after : MachineState) : Bool :=
  after.registers.esp ==
      before.registers.esp + BitVec.ofNat 32 contract.stackResultDelta &&
    contract.preservedRegisters.all fun register =>
      after.registers.get register == before.registers.get register

def resolvedExternalMemoryFootprintsRuntimeValid
    (contract : ResolvedExternalABIContract)
    (memory : Memory) (arguments : List Word) : Bool :=
  contract.memoryFootprints.all fun footprint =>
    (footprint.range? memory arguments).isSome

/-- Every memory effect admitted by `effectShapeValid` has a complete runtime
constraint.  Unsupported broad effects are rejected statically. -/
def resolvedExternalMemoryEffectHolds
    (contract : ResolvedExternalABIContract) (arguments : List Word)
    (before after : Memory) : Prop :=
  match contract.memoryEffect with
  | .none => before = after
  | .readOnly =>
      resolvedExternalMemoryFootprintsRuntimeValid contract before arguments = true ∧
        before = after
  | .argumentRanges =>
      resolvedExternalMemoryFootprintsRuntimeValid contract before arguments = true ∧
        ∀ address,
          (contract.memoryFootprints.any fun footprint =>
            footprint.access == .write &&
              footprint.contains before arguments address) = false ->
          after address = before address
  | .newDynamicRanges | .relationalState => False

/-- Module-local event used until shared outcomes can carry dynamic external
identity.  `target` is checked against the resource pair and never normalized
as an internal code address. -/
structure ResolvedExternalEvent where
  capabilityId : Nat
  resourceId : Nat
  abiContractId : Nat
  transfer : ResolvedExternalTransfer
  target : Word
  arguments : List Word
  state : MachineState
  world : RelationalWorld

structure ResolvedExternalEnvironment where
  result : Nat -> ResolvedExternalEvent -> WorldExternalResult

structure ResolvedExternalBoundaryRelated
    (context : StaticProofContext)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (invariant : StateInvariant)
    (original candidate : ResolvedExternalEvent) : Prop where
  capabilityValid : capability.validFor resolver = true
  abiValid : abi.shapeValid = true
  abiCapability : abi.capabilityId = capability.id
  originalCapability : original.capabilityId = capability.id
  candidateCapability : candidate.capabilityId = capability.id
  originalResource : original.resourceId = capability.resourceId
  candidateResource : candidate.resourceId = capability.resourceId
  originalABI : original.abiContractId = abi.id
  candidateABI : candidate.abiContractId = abi.id
  originalTransfer : original.transfer = abi.transfer
  candidateTransfer : candidate.transfer = abi.transfer
  eventWorld : original.world = candidate.world
  capabilityTargets : ∃ resource : OpaqueResourcePair,
    resource ∈ original.world.opaqueResources ∧
      resource.id = capability.resourceId ∧
      resource.original != BitVec.ofNat 32 0 ∧
      resource.candidate != BitVec.ofNat 32 0 ∧
      original.target = resource.original ∧
      candidate.target = resource.candidate
  stateRelated : StateRel context original.world invariant
    original.state candidate.state
  originalArgumentsExtracted : callableArgumentsExtracted abi.argumentSources
    original.state original.arguments
  candidateArgumentsExtracted : callableArgumentsExtracted abi.argumentSources
    candidate.state candidate.arguments
  argumentsRelated : externalCallArgumentsRelated context original.world
    original.arguments candidate.arguments = true

def ResolvedRuntimeFramesPreserved
    (originalEvent candidateEvent : ResolvedExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop :=
  ∀ (frame : RelationalRuntimeCallFrame)
      (inventory : ReturnSlotOffsetInventory),
    frame.memoryHolds originalEvent.state.memory candidateEvent.state.memory ->
    inventory.exactWordsHold frame originalEvent.state.memory
      candidateEvent.state.memory ->
    frame.memoryHolds originalResult.state.memory candidateResult.state.memory ∧
      inventory.exactWordsHold frame originalResult.state.memory
        candidateResult.state.memory

/-- Complete one-side result constraint for every effect allowed by a resolved
ABI contract. -/
structure ResolvedExternalSideResultConforms
    (candidate : Bool) (context : StaticProofContext)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (event : ResolvedExternalEvent) (result : WorldExternalResult) : Prop where
  abiHolds : resolvedExternalABIResultHolds abi event.state result.state = true
  memoryHolds : resolvedExternalMemoryEffectHolds abi event.arguments
    event.state.memory result.state.memory
  worldHolds : machineCallWorldEffectHolds candidate context abi.worldEffect
    event.arguments event.world result.world
  capabilityPreserved : capabilityResource? event.world capability =
    capabilityResource? result.world capability

structure ResolvedExternalResultRelated
    (context : StaticProofContext)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (targetInvariant : StateInvariant)
    (originalEvent candidateEvent : ResolvedExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop where
  resultWorld : originalResult.world = candidateResult.world
  originalConforms : ResolvedExternalSideResultConforms false context capability
    abi originalEvent originalResult
  candidateConforms : ResolvedExternalSideResultConforms true context capability
    abi candidateEvent candidateResult
  targetState : StateRel context originalResult.world targetInvariant
    originalResult.state candidateResult.state
  runtimeFrames : ResolvedRuntimeFramesPreserved originalEvent candidateEvent
    originalResult candidateResult

/-- Same-index refinement is the only source of resolved-call successor
facts.  Omitting or reordering a call changes the index/identity pair and does
not satisfy this premise. -/
def ResolvedExternalEnvironmentRefinesAt
    (context : StaticProofContext)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (boundaryInvariant targetInvariant : StateInvariant)
    (original candidate : ResolvedExternalEnvironment) : Prop :=
  ∀ eventIndex originalEvent candidateEvent,
    ResolvedExternalBoundaryRelated context resolver capability abi
      boundaryInvariant originalEvent candidateEvent ->
    ResolvedExternalResultRelated context capability abi targetInvariant
      originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent)

theorem resolvedExternalResultsRelated
    (context : StaticProofContext)
    (resolver : ResolverCallContract)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract)
    (boundaryInvariant targetInvariant : StateInvariant)
    (original candidate : ResolvedExternalEnvironment)
    (refines : ResolvedExternalEnvironmentRefinesAt context resolver capability
      abi boundaryInvariant targetInvariant original candidate)
    (eventIndex : Nat) (originalEvent candidateEvent : ResolvedExternalEvent)
    (boundary : ResolvedExternalBoundaryRelated context resolver capability abi
      boundaryInvariant originalEvent candidateEvent) :
    ResolvedExternalResultRelated context capability abi targetInvariant
      originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent) :=
  refines eventIndex originalEvent candidateEvent boundary

end StageA.Relational.CallableExternalCapability
