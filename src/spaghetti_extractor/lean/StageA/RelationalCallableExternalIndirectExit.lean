import StageA.RelationalCallableExternalExecution
import StageA.RelationalCallableExternalValueProvenance

namespace StageA.Relational.CallableExternalIndirectExit

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.CallableExternalExecution
open StageA.Relational.ValueProvenance

/-! # Resolver-issued callable indirect exits

This module connects the generic value-provenance certificate to the strict
runtime callable classifiers.  An opaque resource is a value class until this
certificate also names a capability, an ABI route, and exact collision-aware
classifier results on both binaries.
-/

def resolvedTransfer : IndirectTransfer -> ResolvedExternalTransfer
  | .call _ => .call
  | .jump => .jump

structure CallableIndirectExternalRoute where
  resolver : ResolverCallContract
  capability : CallableExternalCapability
  abi : ResolvedExternalABIContract
deriving Repr, DecidableEq

def CallableIndirectExternalRoute.checked
    (program : OriginalCallableProgram)
    (transfer : ResolvedExternalTransfer)
    (external : CallableIndirectExternalRoute) : Bool :=
  program.resolverContracts.contains external.resolver &&
    program.capabilities.contains external.capability &&
    program.resolvedABIContracts.contains external.abi &&
    external.capability.validFor external.resolver &&
    external.capability.staticIdentityValid program.context &&
    external.abi.shapeValid &&
    external.abi.capabilityId == external.capability.id &&
    external.abi.transfer == transfer

structure CallableIndirectExternalRoute.CheckedFacts
    (program : OriginalCallableProgram)
    (transfer : ResolvedExternalTransfer)
    (external : CallableIndirectExternalRoute) : Prop where
  resolverMember : external.resolver ∈ program.resolverContracts
  capabilityMember : external.capability ∈ program.capabilities
  abiMember : external.abi ∈ program.resolvedABIContracts
  capabilityValid : external.capability.validFor external.resolver = true
  identityValid :
    external.capability.staticIdentityValid program.context = true
  abiValid : external.abi.shapeValid = true
  abiCapability : external.abi.capabilityId = external.capability.id
  abiTransfer : external.abi.transfer = transfer

theorem CallableIndirectExternalRoute.facts_of_checked
    (program : OriginalCallableProgram)
    (transfer : ResolvedExternalTransfer)
    (external : CallableIndirectExternalRoute)
    (checked : external.checked program transfer = true) :
    external.CheckedFacts program transfer := by
  simp only [CallableIndirectExternalRoute.checked, Bool.and_eq_true,
    List.contains_iff_mem, beq_iff_eq] at checked
  rcases checked with
    ⟨⟨⟨⟨⟨⟨⟨resolverMember, capabilityMember⟩, abiMember⟩,
      capabilityValid⟩, identityValid⟩, abiValid⟩, abiCapability⟩,
      abiTransfer⟩
  exact {
    resolverMember
    capabilityMember
    abiMember
    capabilityValid
    identityValid
    abiValid
    abiCapability
    abiTransfer
  }

structure CallableIndirectExitRoute where
  externalRoutes : List CallableIndirectExternalRoute
  originalTarget : Expr
  candidateTarget : Expr
  source : ValueSource
  transfer : IndirectTransfer
  internalTargetIds : List Nat := []
deriving Repr, DecidableEq

def CallableIndirectExitRoute.indirectCertificate
    (route : CallableIndirectExitRoute) : IndirectExitCertificate := {
  finiteAlternativeBudget :=
    route.internalTargetIds.length + route.externalRoutes.length
  target := {
    original := route.originalTarget
    candidate := route.candidateTarget
    source := route.source
    origin := {
      alternatives :=
        route.internalTargetIds.map (fun targetId => .staticCodeTarget targetId 0) ++
          route.externalRoutes.map
            (fun external => .opaqueResource external.capability.resourceId)
    }
  }
  destinations :=
    route.internalTargetIds.map IndirectDestination.internalCode ++
      route.externalRoutes.map
        (fun external => .opaqueResource external.capability.resourceId)
  transfer := route.transfer
}

/-- Static route validity is inventory based.  Runtime target values are
intentionally absent: they can only be introduced by resolver refinement. -/
def CallableIndirectExitRoute.checked
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute) : Bool :=
  !route.externalRoutes.isEmpty &&
    route.externalRoutes.all
      (CallableIndirectExternalRoute.checked program
        (resolvedTransfer route.transfer)) &&
    route.indirectCertificate.checked program.context

theorem CallableIndirectExitRoute.externalChecked_of_checked
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (external : CallableIndirectExternalRoute)
    (routeChecked : route.checked program = true)
    (member : external ∈ route.externalRoutes) :
    external.checked program (resolvedTransfer route.transfer) = true := by
  simp only [CallableIndirectExitRoute.checked, Bool.and_eq_true] at routeChecked
  exact List.all_eq_true.mp routeChecked.1.2 external member

def CallableIndirectExitRoute.registerOriginRelation
    (route : CallableIndirectExitRoute)
    (originalRegister candidateRegister : Reg) :
    RegisterValueOriginRelation := {
  original := originalRegister
  candidate := candidateRegister
  finiteAlternativeBudget := route.indirectCertificate.finiteAlternativeBudget
  origins := route.indirectCertificate.target.origin.alternatives
}

def CallableIndirectExitRoute.memoryOriginRelation
    (route : CallableIndirectExitRoute)
    (originalAddress candidateAddress : Expr) :
    MemoryValueOriginRelation := {
  originalAddress
  candidateAddress
  finiteAlternativeBudget := route.indirectCertificate.finiteAlternativeBudget
  origins := route.indirectCertificate.target.origin.alternatives
}

/-- Bind a register-carried indirect target to the exact finite origin
inventory consumed by the callable exit certificate. -/
structure CallableIndirectRegisterOriginBinding
    (route : CallableIndirectExitRoute) (sourceInvariant : StateInvariant) where
  originalRegister : Reg
  candidateRegister : Reg
  originalTarget :
    route.originalTarget = .inputReg originalRegister
  candidateTarget :
    route.candidateTarget = .inputReg candidateRegister
  relationMember :
    route.registerOriginRelation originalRegister candidateRegister ∈
      sourceInvariant.registerValueOriginRelations

/-- Bind a memory-carried indirect target to the same finite origin inventory.
The address expressions cover static words, stack fields, and dynamic ranges
without introducing a storage-specific target classifier. -/
structure CallableIndirectMemoryOriginBinding
    (route : CallableIndirectExitRoute) (sourceInvariant : StateInvariant) where
  originalAddress : Expr
  candidateAddress : Expr
  originalTarget :
    route.originalTarget = .read32 originalAddress
  candidateTarget :
    route.candidateTarget = .read32 candidateAddress
  relationMember :
    route.memoryOriginRelation originalAddress candidateAddress ∈
      sourceInvariant.memoryValueOriginRelations

/-- Bind a static-word target directly to the authoritative finite-origin slot
inventory in `StaticProofContext`. This avoids duplicating the same relation in
every source invariant that reads the slot. -/
structure CallableIndirectStaticWordOriginBinding
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute) where
  slot : StaticWordRelationSlotPair
  slotMember : slot ∈ program.context.staticWordRelationSlots
  source :
    route.source = .staticWord slot.id
  originalTarget :
    route.originalTarget = .read32 (.constant slot.originalAddress.toNat)
  candidateTarget :
    route.candidateTarget = .read32 (.constant slot.candidateAddress.toNat)
  relation :
    slot.relation =
      .finiteOrigins route.indirectCertificate.finiteAlternativeBudget
        route.indirectCertificate.target.origin.alternatives

/-- Exact runtime selection.  Both variants carry original and candidate
classifier equations, so finite value provenance cannot conceal a collision
with another internal target, import address, or opaque resource. -/
inductive CallableIndirectRuntimeSelection
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (world : RelationalWorld)
    (originalState candidateState : MachineState) : Type where
  | internal
      (targetId : Nat)
      (targetMember : targetId ∈ route.internalTargetIds)
      (originHolds :
        ValueOriginAtom.Holds program.context world
          (route.originalTarget.eval originalState)
          (route.candidateTarget.eval candidateState)
          (.staticCodeTarget targetId 0))
      (originalResolved :
        resolveDecodedCallableIndirect false program world
            (route.originalTarget.eval originalState)
            (resolvedTransfer route.transfer) = .internal targetId)
      (candidateResolved :
        resolveDecodedCallableIndirect true program world
            (route.candidateTarget.eval candidateState)
              (resolvedTransfer route.transfer) = .internal targetId) :
      CallableIndirectRuntimeSelection program route world originalState
        candidateState
  | callable
      (external : CallableIndirectExternalRoute)
      (externalMember : external ∈ route.externalRoutes)
      (resource : OpaqueResourcePair)
      (resourceMember : resource ∈ world.opaqueResources)
      (resourceId : resource.id = external.capability.resourceId)
      (originalTarget :
        route.originalTarget.eval originalState = resource.original)
      (candidateTarget :
        route.candidateTarget.eval candidateState = resource.candidate)
      (originalResolved :
        resolveDecodedCallableIndirect false program world
        (route.originalTarget.eval originalState) (resolvedTransfer route.transfer) =
          .callable external.capability external.abi resource)
      (candidateResolved :
        resolveDecodedCallableIndirect true program world
        (route.candidateTarget.eval candidateState)
          (resolvedTransfer route.transfer) =
          .callable external.capability external.abi resource) :
      CallableIndirectRuntimeSelection program route world originalState
        candidateState

def CallableIndirectRuntimeResolution
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant) : Prop :=
  ∀ world originalState candidateState,
    StateRel program.context world sourceInvariant originalState candidateState ->
      Nonempty (CallableIndirectRuntimeSelection program route world
        originalState candidateState)

def CallableIndirectTargetOriginHolds
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant) : Prop :=
  ∀ world originalState candidateState,
    StateRel program.context world sourceInvariant originalState candidateState ->
      route.indirectCertificate.target.origin.Holds program.context world
        (route.originalTarget.eval originalState)
        (route.candidateTarget.eval candidateState)

/-- The exact runtime classifier depends only on a checked finite origin for
the target value. Register and memory storage are adapters to this theorem. -/
theorem CallableIndirectRuntimeResolution.of_targetOrigin
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant)
    (programValid : program.Valid)
    (routeChecked : route.checked program = true)
    (targetOrigin :
      CallableIndirectTargetOriginHolds program route sourceInvariant) :
    CallableIndirectRuntimeResolution program route sourceInvariant := by
  intro world originalState candidateState related
  have callableWorldValid :
      callableExternalWorldValid program.context world = true := by
    simp only [callableExternalWorldValid, Bool.and_eq_true]
    exact ⟨related.1,
      related.importAddressesStaticValid program.context world sourceInvariant⟩
  rcases targetOrigin world originalState candidateState related with
    ⟨origin, originMember, originHoldsTargets⟩
  simp only [CallableIndirectExitRoute.indirectCertificate, List.mem_append,
    List.mem_map, List.mem_singleton] at originMember
  rcases originMember with internalOrigin | callableOrigin
  · rcases internalOrigin with ⟨targetId, targetMember, rfl⟩
    have internalOriginHolds := originHoldsTargets
    rcases internalOriginHolds with
      ⟨target, targetFound, targetShape⟩
    simp at targetShape
    rcases targetShape with ⟨originalAddress, candidateAddress⟩
    have indexed :=
      program.context.codeMapIndexed_of_structurallyValid
        programValid.contextValid
    have originalLookup :=
      program.context.codeMap.resolveRawEip_of_codeAddressMatches false
        program.context.originalPe program.context.candidatePe indexed targetId
        target (route.originalTarget.eval originalState) targetFound
        originalAddress
    have candidateLookup :=
      program.context.codeMap.resolveRawEip_of_codeAddressMatches true
        program.context.originalPe program.context.candidatePe indexed targetId
        target (route.candidateTarget.eval candidateState) targetFound
        candidateAddress
    have originalResolved :=
      resolveDecodedCallableIndirect_of_internal false program world
        (route.originalTarget.eval originalState)
        (resolvedTransfer route.transfer) targetId callableWorldValid
        originalLookup
    have candidateResolved :=
      resolveDecodedCallableIndirect_of_internal true program world
        (route.candidateTarget.eval candidateState)
        (resolvedTransfer route.transfer) targetId callableWorldValid
        candidateLookup
    exact ⟨.internal targetId targetMember originHoldsTargets originalResolved
      candidateResolved⟩
  · rcases callableOrigin with ⟨external, externalMember, rfl⟩
    rcases originHoldsTargets with
      ⟨resource, resourceMember, resourceId, originalTarget, candidateTarget⟩
    have externalChecked :=
      route.externalChecked_of_checked program external routeChecked
        externalMember
    have externalFacts :=
      external.facts_of_checked program (resolvedTransfer route.transfer)
        externalChecked
    have originalResolved :=
      resolveDecodedCallableIndirect_of_opaqueResource false program world
        (route.originalTarget.eval originalState)
        (resolvedTransfer route.transfer) external.capability external.abi resource
        programValid callableWorldValid externalFacts.capabilityMember
        externalFacts.abiMember resourceMember resourceId
        externalFacts.abiCapability externalFacts.abiTransfer originalTarget
    have candidateResolved :=
      resolveDecodedCallableIndirect_of_opaqueResource true program world
        (route.candidateTarget.eval candidateState)
        (resolvedTransfer route.transfer) external.capability external.abi resource
        programValid callableWorldValid externalFacts.capabilityMember
        externalFacts.abiMember resourceMember resourceId
        externalFacts.abiCapability externalFacts.abiTransfer candidateTarget
    exact ⟨.callable external externalMember resource resourceMember resourceId
      originalTarget candidateTarget originalResolved candidateResolved⟩

/-- Derive target provenance from a register relation carried by `StateRel`. -/
theorem CallableIndirectRuntimeResolution.of_registerOrigin
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant)
    (programValid : program.Valid)
    (routeChecked : route.checked program = true)
    (binding : CallableIndirectRegisterOriginBinding route sourceInvariant) :
    CallableIndirectRuntimeResolution program route sourceInvariant := by
  apply CallableIndirectRuntimeResolution.of_targetOrigin program route
    sourceInvariant programValid routeChecked
  intro world originalState candidateState related
  have allOrigins :=
    related.registerValueOriginsHold program.context world sourceInvariant
  have selectedOrigin :=
    registerValueOriginRelationsHold_member program.context world
      sourceInvariant.registerValueOriginRelations originalState.registers
      candidateState.registers
      (route.registerOriginRelation binding.originalRegister
        binding.candidateRegister)
      allOrigins binding.relationMember
  simp only [CallableIndirectExitRoute.registerOriginRelation,
    RegisterValueOriginRelation.holds, CallableIndirectExitRoute.indirectCertificate,
    List.any_eq_true] at selectedOrigin
  rcases selectedOrigin with ⟨origin, originMember, originMatches⟩
  have originHoldsRegisters :=
    (ValueOriginAtom.matches_eq_true_iff program.context world
      (originalState.registers.get binding.originalRegister)
      (candidateState.registers.get binding.candidateRegister) origin).mp
        originMatches
  have originHoldsTargets :
      origin.Holds program.context world
        (route.originalTarget.eval originalState)
        (route.candidateTarget.eval candidateState) := by
    simpa [binding.originalTarget, binding.candidateTarget, Expr.eval] using
      originHoldsRegisters
  exact ⟨origin, originMember, originHoldsTargets⟩

/-- Derive target provenance from a paired memory-word relation carried by
`StateRel`. This covers writable static slots, stack callbacks, and dynamic
object fields with the same runtime classifier. -/
theorem CallableIndirectRuntimeResolution.of_memoryOrigin
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant)
    (programValid : program.Valid)
    (routeChecked : route.checked program = true)
    (binding : CallableIndirectMemoryOriginBinding route sourceInvariant) :
    CallableIndirectRuntimeResolution program route sourceInvariant := by
  apply CallableIndirectRuntimeResolution.of_targetOrigin program route
    sourceInvariant programValid routeChecked
  intro world originalState candidateState related
  have allOrigins :=
    related.memoryValueOriginsHold program.context world sourceInvariant
  have selectedOrigin :=
    memoryValueOriginRelationsHold_member program.context world
      sourceInvariant.memoryValueOriginRelations originalState candidateState
      (route.memoryOriginRelation binding.originalAddress
        binding.candidateAddress)
      allOrigins binding.relationMember
  simp only [CallableIndirectExitRoute.memoryOriginRelation,
    MemoryValueOriginRelation.holds,
    CallableIndirectExitRoute.indirectCertificate, List.any_eq_true]
      at selectedOrigin
  rcases selectedOrigin with ⟨origin, originMember, originMatches⟩
  have originHoldsMemory :=
    (ValueOriginAtom.matches_eq_true_iff program.context world
      (Memory.read32 originalState.memory
        (binding.originalAddress.eval originalState))
      (Memory.read32 candidateState.memory
        (binding.candidateAddress.eval candidateState)) origin).mp originMatches
  have originHoldsTargets :
      origin.Holds program.context world
        (route.originalTarget.eval originalState)
        (route.candidateTarget.eval candidateState) := by
    simpa [binding.originalTarget, binding.candidateTarget, Expr.eval] using
      originHoldsMemory
  exact ⟨origin, originMember, originHoldsTargets⟩

/-- Derive target provenance from the globally authoritative finite-origin
static-word relation carried by `StateRel`. -/
theorem CallableIndirectRuntimeResolution.of_staticWordOrigin
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant)
    (programValid : program.Valid)
    (routeChecked : route.checked program = true)
    (binding : CallableIndirectStaticWordOriginBinding program route) :
    CallableIndirectRuntimeResolution program route sourceInvariant := by
  apply CallableIndirectRuntimeResolution.of_targetOrigin program route
    sourceInvariant programValid routeChecked
  intro world originalState candidateState related
  have slotsHold :=
    related.staticWordRelationSlotsMemoryHold program.context world
      sourceInvariant originalState candidateState
  have slotHolds := slotsHold binding.slot binding.slotMember
  simp only [StaticWordRelationSlotPair.memoryHolds] at slotHolds
  rw [binding.relation] at slotHolds
  have originHolds :=
    ValueOrigin.holds_of_finiteRelationHolds program.context world
      (Memory.read32 originalState.memory binding.slot.originalAddress)
      (Memory.read32 candidateState.memory binding.slot.candidateAddress)
      route.indirectCertificate.finiteAlternativeBudget
      route.indirectCertificate.target.origin slotHolds
  simpa [binding.originalTarget, binding.candidateTarget, Expr.eval,
    machineStateRead32_eq_memoryRead32] using originHolds

theorem CallableIndirectRuntimeResolution.targetEvaluation
    (program : OriginalCallableProgram) (route : CallableIndirectExitRoute)
    (sourceInvariant : StateInvariant)
    (resolution :
      CallableIndirectRuntimeResolution program route sourceInvariant) :
    route.indirectCertificate.TargetEvaluation program.context
      sourceInvariant := by
  intro world originalState candidateState related
  rcases resolution world originalState candidateState related with ⟨selected⟩
  cases selected with
  | internal targetId targetMember originHolds _originalResolved
      _candidateResolved =>
      constructor
      · refine ⟨.staticCodeTarget targetId 0, ?_, originHolds⟩
        simp [CallableIndirectExitRoute.indirectCertificate, targetMember]
      · refine ⟨.internalCode targetId, ?_, ?_⟩
        · simp [CallableIndirectExitRoute.indirectCertificate, targetMember]
        · simpa [ValueOriginAtom.Holds, IndirectDestination.Matches] using
            originHolds
  | callable external externalMember resource resourceMember resourceId
      originalTarget candidateTarget _originalResolved _candidateResolved =>
      constructor
      · refine ⟨.opaqueResource external.capability.resourceId, ?_, ?_⟩
        · apply List.mem_append_right
          exact List.mem_map.mpr ⟨external, externalMember, rfl⟩
        · exact ⟨resource, resourceMember, resourceId, originalTarget,
            candidateTarget⟩
      · refine ⟨.opaqueResource external.capability.resourceId, ?_, ?_⟩
        · apply List.mem_append_right
          exact List.mem_map.mpr ⟨external, externalMember, rfl⟩
        · exact ⟨resource, resourceMember, resourceId, originalTarget,
            candidateTarget⟩

/-- Acceptance-facing package for a callable indirect exit.  The ordinary
indirect certificate proves value provenance and exact decoded outcomes; the
runtime resolution additionally authorizes external execution. -/
structure CheckedCallableIndirectExitCertificate
    (program : OriginalCallableProgram) (sourceInvariant : StateInvariant)
    (originalBehavior candidateBehavior : NormalizedSymbolicBehavior) where
  route : CallableIndirectExitRoute
  programValid : program.Valid
  staticChecked : route.checked program = true
  outcomeChecked :
    route.indirectCertificate.outcomeChecked originalBehavior
      candidateBehavior = true
  runtimeResolution :
    CallableIndirectRuntimeResolution program route sourceInvariant

/-- Existentially packages the exact program, invariant, behaviors, and checked
callable certificate behind one route-indexed interface.  Composition clients
can require this type without duplicating the adapter's local mixed-original
types, while the route index prevents a certificate for another finite target
inventory from being substituted. -/
structure CheckedCallableIndirectExitRouteAuthority
    (route : CallableIndirectExitRoute) where
  program : OriginalCallableProgram
  sourceInvariant : StateInvariant
  originalBehavior : NormalizedSymbolicBehavior
  candidateBehavior : NormalizedSymbolicBehavior
  certificate :
    CheckedCallableIndirectExitCertificate program sourceInvariant
      originalBehavior candidateBehavior
  routeExact : certificate.route = route

def CheckedCallableIndirectExitCertificate.generic
    {program : OriginalCallableProgram} {sourceInvariant : StateInvariant}
    {originalBehavior candidateBehavior : NormalizedSymbolicBehavior}
    (certificate : CheckedCallableIndirectExitCertificate program sourceInvariant
      originalBehavior candidateBehavior) :
    CheckedIndirectExitCertificate program.context sourceInvariant
      originalBehavior candidateBehavior := {
  certificate := certificate.route.indirectCertificate
  staticChecked := by
    have checked := certificate.staticChecked
    simp only [CallableIndirectExitRoute.checked, Bool.and_eq_true] at checked
    exact checked.2
  outcomeChecked := certificate.outcomeChecked
  targetEvaluation := certificate.runtimeResolution.targetEvaluation program
    certificate.route sourceInvariant
}

end StageA.Relational.CallableExternalIndirectExit
