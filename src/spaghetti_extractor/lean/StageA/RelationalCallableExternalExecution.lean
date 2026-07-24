import StageA.RelationalCallableExternalCapability
import StageA.RelationalInterpreterKernel

namespace StageA.Relational.CallableExternalExecution

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalCapability
open StageA.Relational.InterpreterKernel

/-! # Original-side callable external execution wrapper

The shared concrete outcomes remain unchanged.  This module classifies a
stopped indirect outcome before deciding whether it is internal, imported, or
a callable opaque capability.  External observations and their one global
index are derived only by successful runtime transitions.
-/

structure OriginalExternalSite where
  id : Nat
  sourceTargetId : Nat
  machineContractId : Nat
  argumentSources : List CallableArgumentSource
  resolverContractId : Option Nat := none
  capabilityId : Option Nat := none
deriving Repr, DecidableEq

def originalExternalSiteIdsUnique (sites : List OriginalExternalSite) : Bool :=
  sites.all fun site =>
    (sites.filter fun other => other.id == site.id).length == 1

def resolvedExternalABIRoutesUnique
    (contracts : List ResolvedExternalABIContract) : Bool :=
  contracts.all fun contract =>
    (contracts.filter fun other =>
      other.capabilityId == contract.capabilityId &&
        other.transfer == contract.transfer).length == 1

structure OriginalCallableProgram where
  context : StaticProofContext
  resolverContracts : List ResolverCallContract
  capabilities : List CallableExternalCapability
  resolvedABIContracts : List ResolvedExternalABIContract
  externalSites : List OriginalExternalSite

/-- The core world predicate does not include the separately checked import
address inventory, which this wrapper reads during indirect classification. -/
def callableExternalWorldValid
    (context : StaticProofContext) (world : RelationalWorld) : Bool :=
  world.valid context && world.importAddressesStaticValid context

def OriginalExternalSite.staticValid
    (program : OriginalCallableProgram) (site : OriginalExternalSite) : Bool :=
  match machineImportCallContractById? program.context site.machineContractId with
  | none => false
  | some machine =>
      machine.disposition == .returns &&
        site.argumentSources ==
          machine.stackArgumentOffsets.map CallableArgumentSource.stackWord &&
        match site.resolverContractId, site.capabilityId with
        | none, none => true
        | some resolverId, some capabilityId =>
            match program.resolverContracts.find? (fun resolver =>
                resolver.id == resolverId),
                program.capabilities.find? (fun capability =>
                  capability.id == capabilityId) with
            | some resolver, some capability =>
                resolver.validForMachineContract machine &&
                  capability.validFor resolver &&
                  capability.staticIdentityValid program.context &&
                  capability.resolverSiteId == site.id &&
                  resolver.argumentSources == site.argumentSources
            | _, _ => false
        | _, _ => false

def callableCapabilityStaticValid
    (program : OriginalCallableProgram)
    (capability : CallableExternalCapability) : Bool :=
  match program.resolverContracts.find? (fun resolver =>
      resolver.id == capability.resolverContractId) with
  | none => false
  | some resolver =>
      capability.validFor resolver &&
        capability.staticIdentityValid program.context &&
        program.externalSites.any fun site =>
          site.id == capability.resolverSiteId &&
            site.resolverContractId == some resolver.id &&
            site.capabilityId == some capability.id

structure OriginalCallableProgram.Valid
    (program : OriginalCallableProgram) : Prop where
  contextValid : program.context.StructurallyValid
  resolverIds : resolverCallContractIdsUnique program.resolverContracts = true
  capabilityIds : callableCapabilityIdsUnique program.capabilities = true
  capabilityResourceIds :
    callableCapabilityResourceIdsUnique program.capabilities = true
  capabilityShapes : program.capabilities.all
    (callableCapabilityStaticValid program) = true
  abiIds : resolvedExternalABIContractIdsUnique
    program.resolvedABIContracts = true
  abiRoutes : resolvedExternalABIRoutesUnique
    program.resolvedABIContracts = true
  abiShapes : program.resolvedABIContracts.all
    ResolvedExternalABIContract.shapeValid = true
  siteIds : originalExternalSiteIdsUnique program.externalSites = true
  sites : program.externalSites.all
    (OriginalExternalSite.staticValid program) = true

inductive OriginalExternalRoute where
  | ordinary (site : OriginalExternalSite) (machine : MachineImportCallContract)
  | resolver (site : OriginalExternalSite) (machine : MachineImportCallContract)
      (resolver : ResolverCallContract)
      (capability : CallableExternalCapability)
deriving Repr, DecidableEq

def originalSourceTargetId?
    (program : OriginalCallableProgram) (sourceRva : Nat) : Option Nat :=
  program.context.codeMap.resolveRawEip false
    program.context.originalPe.imageBase
    (BitVec.ofNat 32 (program.context.originalPe.imageBase + sourceRva))

def originalExternalRoutes
    (program : OriginalCallableProgram) (sourceTargetId : Nat)
    (imported : ExternalTarget) : List OriginalExternalRoute :=
  program.externalSites.filterMap fun site =>
    if site.sourceTargetId != sourceTargetId then none else do
    let machine <- machineImportCallContractById? program.context
      site.machineContractId
    if machine.imported != imported then none else
    match site.resolverContractId, site.capabilityId with
    | none, none => some (.ordinary site machine)
    | some resolverId, some capabilityId => do
        let resolver <- program.resolverContracts.find? (fun candidate =>
          candidate.id == resolverId)
        let capability <- program.capabilities.find? (fun candidate =>
          candidate.id == capabilityId)
        some (.resolver site machine resolver capability)
    | _, _ => none

def originalExternalRoute?
    (program : OriginalCallableProgram) (sourceTargetId : Nat)
    (imported : ExternalTarget) : Option OriginalExternalRoute :=
  match originalExternalRoutes program sourceTargetId imported with
  | [route] => some route
  | _ => none

inductive OriginalIndirectResolution where
  | internal (targetId : Nat)
  | imported (binding : ImportAddressPair)
  | callable (capability : CallableExternalCapability)
      (abi : ResolvedExternalABIContract) (resource : OpaqueResourcePair)
  | invalidWorld
  | unmapped
  | invalidCallable
  | ambiguous
deriving Repr, DecidableEq

/-- Classify precomputed category matches.  Any duplicate or cross-category
match is ambiguous.  A resource value without exactly one capability and ABI
route is invalid rather than silently falling back to an internal target. -/
def classifyOriginalIndirectMatches
    (internalMatches : List Nat) (importMatches : List ImportAddressPair)
    (resourceMatches : List OpaqueResourcePair)
    (capabilities : List CallableExternalCapability)
    (abis : List ResolvedExternalABIContract)
    (transfer : ResolvedExternalTransfer) : OriginalIndirectResolution :=
  match internalMatches, importMatches, resourceMatches with
  | [targetId], [], [] => .internal targetId
  | [], [binding], [] => .imported binding
  | [], [], [resource] =>
      match capabilities.filter (fun capability =>
          capability.resourceId == resource.id) with
      | [capability] =>
          match abis.filter (fun abi =>
              abi.capabilityId == capability.id && abi.transfer == transfer) with
          | [abi] => .callable capability abi resource
          | _ => .invalidCallable
      | _ => .invalidCallable
  | [], [], [] => .unmapped
  | _, _, _ => .ambiguous

/-- Strict decoded-side resolution with collision checks across every
category.  The same resolver is used for both decoded PEs; only the selected
side of the canonical code/import/resource maps differs. -/
def resolveDecodedCallableIndirect
    (candidate : Bool) (program : OriginalCallableProgram)
    (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer) : OriginalIndirectResolution :=
  if callableExternalWorldValid program.context world != true then
    .invalidWorld
  else
  let imageBase :=
    if candidate then program.context.candidatePe.imageBase
    else program.context.originalPe.imageBase
  let internalMatches := program.context.codeMap.rawEipMatches candidate
    imageBase target
  let importMatches := world.importAddresses.filter fun binding =>
    (if candidate then binding.candidateAddress else binding.originalAddress) ==
      target
  let resourceMatches := world.opaqueResources.filter fun resource =>
    (if candidate then resource.candidate else resource.original) == target
  classifyOriginalIndirectMatches internalMatches importMatches resourceMatches
    program.capabilities program.resolvedABIContracts transfer

private theorem filter_eq_nil_of_forall_false
    {α : Type} (items : List α) (predicate : α -> Bool)
    (rejected : ∀ item, item ∈ items -> predicate item = false) :
    items.filter predicate = [] := by
  induction items with
  | nil => rfl
  | cons head tail ih =>
      have headRejected := rejected head (by simp)
      have tailRejected :
          ∀ item, item ∈ tail -> predicate item = false := by
        intro item member
        exact rejected item (by simp [member])
      simp [headRejected, ih tailRejected]

private theorem filter_eq_singleton_of_member_and_length_one
    {α : Type} [DecidableEq α] (items : List α) (predicate : α -> Bool)
    (item : α) (member : item ∈ items)
    (predicateMatches : predicate item = true)
    (lengthOne : (items.filter predicate).length = 1) :
    items.filter predicate = [item] := by
  have filteredMember : item ∈ items.filter predicate :=
    List.mem_filter.mpr ⟨member, predicateMatches⟩
  rcases List.length_eq_one_iff.mp lengthOne with ⟨only, filtered⟩
  rw [filtered] at filteredMember
  simp only [List.mem_singleton] at filteredMember
  simpa [filteredMember] using filtered

/-- A canonical code-map result determines the internal branch of the strict
callable classifier.  Valid import and opaque-resource inventories rule out
cross-category aliases. -/
theorem resolveDecodedCallableIndirect_of_internal
    (candidate : Bool) (program : OriginalCallableProgram)
    (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer) (targetId : Nat)
    (worldValid : callableExternalWorldValid program.context world = true)
    (resolved :
      program.context.codeMap.resolveRawEip candidate
        (if candidate then program.context.candidatePe.imageBase
          else program.context.originalPe.imageBase) target = some targetId) :
    resolveDecodedCallableIndirect candidate program world target transfer =
      .internal targetId := by
  have callableValid := worldValid
  simp only [callableExternalWorldValid, Bool.and_eq_true] at worldValid
  have rawMatches :=
    program.context.codeMap.rawEipMatches_eq_singleton_of_resolveRawEip
      candidate
      (if candidate then program.context.candidatePe.imageBase
        else program.context.originalPe.imageBase)
      target targetId resolved
  have importsStatic := worldValid.2
  simp only [RelationalWorld.importAddressesStaticValid, Bool.and_eq_true]
    at importsStatic
  have importMatches :
      (world.importAddresses.filter fun binding =>
        (if candidate then binding.candidateAddress else binding.originalAddress) ==
          target) = [] := by
    apply filter_eq_nil_of_forall_false
    intro binding member
    have bindingValid :=
      List.all_eq_true.mp importsStatic.2 binding member
    have bindingUnresolved :
        program.context.codeMap.resolveRawEip candidate
          (if candidate then program.context.candidatePe.imageBase
            else program.context.originalPe.imageBase)
          (if candidate then binding.candidateAddress
            else binding.originalAddress) = none := by
      cases candidate with
      | false =>
          simpa using
            binding.originalCodeUnresolved program.context bindingValid
      | true =>
          simpa using
            binding.candidateCodeUnresolved program.context bindingValid
    by_cases sameAddress :
        (if candidate then binding.candidateAddress else binding.originalAddress) =
          target
    · have targetUnresolved :
          program.context.codeMap.resolveRawEip candidate
            (if candidate then program.context.candidatePe.imageBase
              else program.context.originalPe.imageBase) target = none := by
          simpa [sameAddress] using bindingUnresolved
      simp [resolved] at targetUnresolved
    · simp [sameAddress]
  have resourcesAvoidCode :=
    RelationalWorld.opaqueResourcesAvoidCodeOn_of_valid candidate program.context
      world worldValid.1
  simp only [RelationalWorld.opaqueResourcesAvoidCodeOn, List.all_eq_true]
    at resourcesAvoidCode
  have resourceMatches :
      (world.opaqueResources.filter fun resource =>
        (if candidate then resource.candidate else resource.original) == target) =
          [] := by
    apply filter_eq_nil_of_forall_false
    intro resource member
    have resourceUnresolved := resourcesAvoidCode resource member
    by_cases sameAddress :
        (if candidate then resource.candidate else resource.original) = target
    · have targetUnresolved :
          program.context.codeMap.rawEipMatches candidate
            (if candidate then program.context.candidatePe.imageBase
              else program.context.originalPe.imageBase) target = [] := by
          simpa [sameAddress] using resourceUnresolved
      simp [rawMatches] at targetUnresolved
    · simp [sameAddress]
  simp [resolveDecodedCallableIndirect, callableValid, rawMatches, importMatches,
    resourceMatches, classifyOriginalIndirectMatches]

/-- A unique world resource together with the canonical capability and ABI
inventories determines the callable branch of the strict classifier. -/
theorem resolveDecodedCallableIndirect_of_opaqueResource
    (candidate : Bool) (program : OriginalCallableProgram)
    (world : RelationalWorld) (target : Word)
    (transfer : ResolvedExternalTransfer)
    (capability : CallableExternalCapability)
    (abi : ResolvedExternalABIContract) (resource : OpaqueResourcePair)
    (programValid : program.Valid)
    (worldValid : callableExternalWorldValid program.context world = true)
    (capabilityMember : capability ∈ program.capabilities)
    (abiMember : abi ∈ program.resolvedABIContracts)
    (resourceMember : resource ∈ world.opaqueResources)
    (resourceId : resource.id = capability.resourceId)
    (abiCapability : abi.capabilityId = capability.id)
    (abiTransfer : abi.transfer = transfer)
    (targetValue :
      target = if candidate then resource.candidate else resource.original) :
    resolveDecodedCallableIndirect candidate program world target transfer =
      .callable capability abi resource := by
  have callableValid := worldValid
  simp only [callableExternalWorldValid, Bool.and_eq_true] at worldValid
  have resourcesAvoidCode :=
    RelationalWorld.opaqueResourcesAvoidCodeOn_of_valid candidate program.context
      world worldValid.1
  simp only [RelationalWorld.opaqueResourcesAvoidCodeOn, List.all_eq_true]
    at resourcesAvoidCode
  have internalMatches :
      program.context.codeMap.rawEipMatches candidate
        (if candidate then program.context.candidatePe.imageBase
          else program.context.originalPe.imageBase) target = [] := by
    simpa [targetValue] using resourcesAvoidCode resource resourceMember
  have resourcesAvoidImports :=
    RelationalWorld.opaqueResourcesAvoidImportsOn_of_valid candidate program.context
      world worldValid.1
  simp only [RelationalWorld.opaqueResourcesAvoidImportsOn, List.all_eq_true]
    at resourcesAvoidImports
  have importMatches :
      (world.importAddresses.filter fun binding =>
        (if candidate then binding.candidateAddress else binding.originalAddress) ==
          target) = [] := by
    apply filter_eq_nil_of_forall_false
    intro binding member
    have distinct := resourcesAvoidImports resource resourceMember binding member
    simp only [bne_iff_ne] at distinct
    by_cases sameAddress :
        (if candidate then binding.candidateAddress else binding.originalAddress) =
          target
    · have forbidden :
          (if candidate then resource.candidate else resource.original) =
            (if candidate then binding.candidateAddress
              else binding.originalAddress) := by
          exact targetValue.symm.trans sameAddress.symm
      exact False.elim (distinct forbidden)
    · simp [sameAddress]
  have resourceValuesUnique :=
    RelationalWorld.opaqueResourceValuesUniqueOn_of_valid candidate
      program.context world worldValid.1
  simp only [opaqueResourceValuesUniqueOn, List.all_eq_true]
    at resourceValuesUnique
  have resourceLength := resourceValuesUnique resource resourceMember
  have resourceMatches :
      (world.opaqueResources.filter fun other =>
        (if candidate then other.candidate else other.original) == target) =
          [resource] := by
    apply filter_eq_singleton_of_member_and_length_one
    · exact resourceMember
    · simp [targetValue]
    · simpa [targetValue] using resourceLength
  have capabilityResourceIds := programValid.capabilityResourceIds
  simp only [callableCapabilityResourceIdsUnique, List.all_eq_true]
    at capabilityResourceIds
  have capabilityLength := capabilityResourceIds capability capabilityMember
  have capabilityMatches :
      (program.capabilities.filter fun other =>
        other.resourceId == resource.id) = [capability] := by
    apply filter_eq_singleton_of_member_and_length_one
    · exact capabilityMember
    · simp [resourceId]
    · simpa [resourceId] using capabilityLength
  have abiRoutes := programValid.abiRoutes
  simp only [resolvedExternalABIRoutesUnique, List.all_eq_true] at abiRoutes
  have abiLength := abiRoutes abi abiMember
  have abiMatches :
      (program.resolvedABIContracts.filter fun other =>
        other.capabilityId == capability.id && other.transfer == transfer) =
          [abi] := by
    apply filter_eq_singleton_of_member_and_length_one
    · exact abiMember
    · simp [abiCapability, abiTransfer]
    · simpa [abiCapability, abiTransfer] using abiLength
  simp [resolveDecodedCallableIndirect, callableValid, internalMatches,
    importMatches, resourceMatches, classifyOriginalIndirectMatches,
    capabilityMatches, abiMatches]

/-- Compatibility name for original-side callable execution. -/
def resolveOriginalIndirect
    (program : OriginalCallableProgram) (world : RelationalWorld)
    (target : Word) (transfer : ResolvedExternalTransfer) :
    OriginalIndirectResolution :=
  resolveDecodedCallableIndirect false program world target transfer

structure CallableRuntimeExternalEvent where
  identity : CallableExternalIdentity
  arguments : List Word
  target : Option Word := none
  state : MachineState
  world : RelationalWorld

def CallableRuntimeExternalEvent.observe
    (event : CallableRuntimeExternalEvent) (globalExternalIndex : Nat) :
    CallableExternalObservation := {
  globalExternalIndex
  identity := event.identity
  arguments := event.arguments
  world := event.world
}

structure OriginalCallableExternalEnvironment where
  result : Nat -> CallableRuntimeExternalEvent -> WorldExternalResult

structure OriginalCallableExecutionState where
  rva : Nat
  state : MachineState
  calls : List NativeCallFrame
  world : RelationalWorld
  globalExternalIndex : Nat
  externalTrace : List CallableExternalObservation

def OriginalCallableExecutionState.afterExternalCall
    (before : OriginalCallableExecutionState) (continuation : Nat)
    (event : CallableRuntimeExternalEvent) (result : WorldExternalResult) :
    OriginalCallableExecutionState := {
  rva := continuation
  state := result.state
  calls := before.calls
  world := result.world
  globalExternalIndex := before.globalExternalIndex + 1
  externalTrace := before.externalTrace ++
    [event.observe before.globalExternalIndex]
}

def OriginalCallableExecutionState.afterExternalTail
    (before : OriginalCallableExecutionState) (frame : NativeCallFrame)
    (tail : List NativeCallFrame) (event : CallableRuntimeExternalEvent)
    (result : WorldExternalResult) : OriginalCallableExecutionState := {
  rva := frame.continuationRva
  state := result.state
  calls := tail
  world := result.world
  globalExternalIndex := before.globalExternalIndex + 1
  externalTrace := before.externalTrace ++
    [event.observe before.globalExternalIndex]
}

def routeSite : OriginalExternalRoute -> OriginalExternalSite
  | .ordinary site _ | .resolver site _ _ _ => site

def routeMachine : OriginalExternalRoute -> MachineImportCallContract
  | .ordinary _ machine | .resolver _ machine _ _ => machine

def routeIdentity (route : OriginalExternalRoute)
    (transfer : ResolvedExternalTransfer) : CallableExternalIdentity :=
  match route with
  | .ordinary site machine =>
      .imported site.id machine.id machine.imported transfer
  | .resolver site _ resolver capability =>
      .resolver site.id resolver.id capability.id

def routeArgumentsExtracted (route : OriginalExternalRoute)
    (state : MachineState) (arguments : List Word) : Prop :=
  callableArgumentsExtracted (routeSite route).argumentSources state arguments

def routeWorldEvent (route : OriginalExternalRoute)
    (event : CallableRuntimeExternalEvent) : WorldExternalEvent := {
  siteId := (routeSite route).id
  imported := (routeMachine route).imported
  arguments := event.arguments
  state := event.state
  world := event.world
}

/-- Calls resume the exact continuation encoded by the concrete outcome.
Arguments are always derived from the current machine state. -/
inductive OriginalCallableCallDispatch
    (program : OriginalCallableProgram)
    (before : OriginalCallableExecutionState) :
    ConcreteOutcome -> CallableRuntimeExternalEvent -> Nat -> Prop where
  | direct (imported : PEImport) (arguments : List Word) (continuation : Nat)
      (sourceTargetId : Nat) (route : OriginalExternalRoute)
      (source : originalSourceTargetId? program before.rva = some sourceTargetId)
      (resolved : originalExternalRoute? program sourceTargetId
        (normalizeImport imported) = some route)
      (extracted : routeArgumentsExtracted route before.state arguments) :
      OriginalCallableCallDispatch program before
        (.externalCall imported arguments continuation)
        { identity := routeIdentity route .call, arguments,
          state := before.state, world := before.world }
        continuation
  | indirectImport (target : Word) (continuation returnAddress : Nat)
      (binding : ImportAddressPair) (sourceTargetId : Nat)
      (route : OriginalExternalRoute)
      (targetResolved : resolveOriginalIndirect program before.world target .call =
        .imported binding)
      (source : originalSourceTargetId? program before.rva = some sourceTargetId)
      (routeResolved : originalExternalRoute? program sourceTargetId
        binding.imported = some route)
      (arguments : List Word)
      (extracted : routeArgumentsExtracted route before.state arguments) :
      OriginalCallableCallDispatch program before
        (.indirectCall target continuation returnAddress)
        { identity := routeIdentity route .call, arguments,
          state := before.state, world := before.world }
        continuation
  | indirectCapability (target : Word) (continuation returnAddress : Nat)
      (capability : CallableExternalCapability)
      (abi : ResolvedExternalABIContract) (resource : OpaqueResourcePair)
      (targetResolved : resolveOriginalIndirect program before.world target .call =
        .callable capability abi resource)
      (arguments : List Word)
      (extracted : callableArgumentsExtracted abi.argumentSources before.state
        arguments) :
      OriginalCallableCallDispatch program before
        (.indirectCall target continuation returnAddress)
        { identity := .resolved capability.id capability.resourceId abi.id .call,
          arguments, target := some target, state := before.state,
          world := before.world }
        continuation

/-- Tail jumps are external only when an exact runtime frame is available to
pop.  Resolver routes are excluded because issuance must return to code that
can subsequently use the capability. -/
inductive OriginalCallableTailDispatch
    (program : OriginalCallableProgram)
    (before : OriginalCallableExecutionState) :
    ConcreteOutcome -> CallableRuntimeExternalEvent -> Prop where
  | direct (imported : PEImport) (arguments : List Word)
      (sourceTargetId : Nat) (site : OriginalExternalSite)
      (machine : MachineImportCallContract)
      (source : originalSourceTargetId? program before.rva = some sourceTargetId)
      (resolved : originalExternalRoute? program sourceTargetId
        (normalizeImport imported) = some (.ordinary site machine))
      (extracted : callableArgumentsExtracted site.argumentSources before.state
        arguments) :
      OriginalCallableTailDispatch program before
        (.externalJump imported arguments)
        { identity := .imported site.id machine.id machine.imported .jump,
          arguments, state := before.state, world := before.world }
  | indirectImport (target : Word) (binding : ImportAddressPair)
      (sourceTargetId : Nat) (site : OriginalExternalSite)
      (machine : MachineImportCallContract)
      (targetResolved : resolveOriginalIndirect program before.world target .jump =
        .imported binding)
      (source : originalSourceTargetId? program before.rva = some sourceTargetId)
      (routeResolved : originalExternalRoute? program sourceTargetId
        binding.imported = some (.ordinary site machine))
      (arguments : List Word)
      (extracted : callableArgumentsExtracted site.argumentSources before.state
        arguments) :
      OriginalCallableTailDispatch program before (.indirectJump target)
        { identity := .imported site.id machine.id machine.imported .jump,
          arguments, state := before.state, world := before.world }
  | indirectCapability (target : Word)
      (capability : CallableExternalCapability)
      (abi : ResolvedExternalABIContract) (resource : OpaqueResourcePair)
      (targetResolved : resolveOriginalIndirect program before.world target .jump =
        .callable capability abi resource)
      (arguments : List Word)
      (extracted : callableArgumentsExtracted abi.argumentSources before.state
        arguments) :
      OriginalCallableTailDispatch program before (.indirectJump target)
        { identity := .resolved capability.id capability.resourceId abi.id .jump,
          arguments, target := some target, state := before.state,
          world := before.world }

inductive OriginalCallableResultConforms
    (program : OriginalCallableProgram)
    (event : CallableRuntimeExternalEvent)
    (result : WorldExternalResult) : Prop where
  | ordinary (site : OriginalExternalSite) (machine : MachineImportCallContract)
      (transfer : ResolvedExternalTransfer)
      (siteMember : site ∈ program.externalSites)
      (machineResolved : machineImportCallContractById? program.context
        site.machineContractId = some machine)
      (identity : event.identity =
        .imported site.id machine.id machine.imported transfer)
      (conforms : machineCallResultConforms false program.context machine
        (routeWorldEvent (.ordinary site machine) event) result) :
      OriginalCallableResultConforms program event result
  | resolver (site : OriginalExternalSite) (machine : MachineImportCallContract)
      (resolver : ResolverCallContract)
      (capability : CallableExternalCapability)
      (siteMember : site ∈ program.externalSites)
      (machineResolved : machineImportCallContractById? program.context
        site.machineContractId = some machine)
      (resolverMember : resolver ∈ program.resolverContracts)
      (capabilityMember : capability ∈ program.capabilities)
      (siteResolver : site.resolverContractId = some resolver.id)
      (siteCapability : site.capabilityId = some capability.id)
      (resolverValid : resolver.validForMachineContract machine = true)
      (capabilityValid : capability.validFor resolver = true)
      (identity : event.identity = .resolver site.id resolver.id capability.id)
      (conforms : ResolverCapabilitySideResultConforms false program.context
        machine resolver capability (routeWorldEvent
          (.resolver site machine resolver capability) event) result) :
      OriginalCallableResultConforms program event result
  | resolved (resolver : ResolverCallContract)
      (capability : CallableExternalCapability)
      (abi : ResolvedExternalABIContract) (target : Word)
      (resolverMember : resolver ∈ program.resolverContracts)
      (capabilityMember : capability ∈ program.capabilities)
      (abiMember : abi ∈ program.resolvedABIContracts)
      (capabilityValid : capability.validFor resolver = true)
      (abiValid : abi.shapeValid = true)
      (abiCapability : abi.capabilityId = capability.id)
      (identity : event.identity = .resolved capability.id capability.resourceId
        abi.id abi.transfer)
      (eventTarget : event.target = some target)
      (conforms : ResolvedExternalSideResultConforms false program.context
        capability abi
        { capabilityId := capability.id, resourceId := capability.resourceId,
          abiContractId := abi.id, transfer := abi.transfer,
          target,
          arguments := event.arguments, state := event.state,
          world := event.world }
        result) :
      OriginalCallableResultConforms program event result

/-- One successful external transition.  Every constructor increments the
single global index once and appends exactly the runtime-derived observation. -/
inductive OriginalCallableExternalStep
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment) :
    OriginalCallableExecutionState -> ConcreteOutcome ->
      OriginalCallableExecutionState -> Prop where
  | call (before : OriginalCallableExecutionState) (outcome : ConcreteOutcome)
      (event : CallableRuntimeExternalEvent) (continuation : Nat)
      (result : WorldExternalResult)
      (programValid : program.Valid)
      (worldValid : callableExternalWorldValid program.context before.world = true)
      (dispatch : OriginalCallableCallDispatch program before outcome event
        continuation)
      (environmentResult : environment.result before.globalExternalIndex event =
        result)
      (conforms : OriginalCallableResultConforms program event result) :
      OriginalCallableExternalStep program environment before outcome
        (before.afterExternalCall continuation event result)
  | tail (before : OriginalCallableExecutionState) (outcome : ConcreteOutcome)
      (event : CallableRuntimeExternalEvent) (frame : NativeCallFrame)
      (tail : List NativeCallFrame) (result : WorldExternalResult)
      (programValid : program.Valid)
      (worldValid : callableExternalWorldValid program.context before.world = true)
      (frames : before.calls = frame :: tail)
      (dispatch : OriginalCallableTailDispatch program before outcome event)
      (environmentResult : environment.result before.globalExternalIndex event =
        result)
      (conforms : OriginalCallableResultConforms program event result) :
      OriginalCallableExternalStep program environment before outcome
        (before.afterExternalTail frame tail event result)

def OriginalCallableExecutionState.RuntimeTraceConsistent
    (state : OriginalCallableExecutionState) : Prop :=
  state.globalExternalIndex = state.externalTrace.length

theorem OriginalCallableExternalStep.preservesRuntimeTraceConsistency
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (before after : OriginalCallableExecutionState)
    (outcome : ConcreteOutcome)
    (step : OriginalCallableExternalStep program environment before outcome after)
    (consistent : before.RuntimeTraceConsistent) :
    after.RuntimeTraceConsistent := by
  cases step <;>
    simp_all [OriginalCallableExecutionState.RuntimeTraceConsistent,
      OriginalCallableExecutionState.afterExternalCall,
      OriginalCallableExecutionState.afterExternalTail]

theorem OriginalCallableExternalStep.appendsRuntimeObservation
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (before after : OriginalCallableExecutionState)
    (outcome : ConcreteOutcome)
    (step : OriginalCallableExternalStep program environment before outcome after) :
    ∃ observation,
      observation.globalExternalIndex = before.globalExternalIndex ∧
      after.globalExternalIndex = before.globalExternalIndex + 1 ∧
      after.externalTrace = before.externalTrace ++ [observation] := by
  cases step <;>
    simp [OriginalCallableExecutionState.afterExternalCall,
      OriginalCallableExecutionState.afterExternalTail,
      CallableRuntimeExternalEvent.observe]

/-- The indexed dispatch forces an indirect call to resume at the exact
continuation carried by the concrete outcome. -/
theorem OriginalCallableExternalStep.indirectCallResumesExactContinuation
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (before after : OriginalCallableExecutionState)
    (target : Word) (continuation returnAddress : Nat)
    (step : OriginalCallableExternalStep program environment before
      (.indirectCall target continuation returnAddress) after) :
    after.rva = continuation := by
  cases step
  case call _ _ _ _ _ dispatch _ _ =>
    cases dispatch <;>
      rfl
  case tail _ _ _ _ _ _ _ dispatch _ _ =>
    cases dispatch

/-- No external tail transition exists without the exact runtime frame that
will be popped by the transition. -/
theorem OriginalCallableExternalStep.indirectTailRequiresRuntimeFrame
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (before after : OriginalCallableExecutionState)
    (target : Word) (noFrames : before.calls = []) :
    ¬ OriginalCallableExternalStep program environment before
      (.indirectJump target) after := by
  intro step
  cases step
  case call _ _ _ _ _ dispatch _ _ =>
    cases dispatch
  case tail _ _ _ _ _ _ frames _ _ _ =>
    simp_all

inductive OriginalCallableExternalSteps
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment) :
    OriginalCallableExecutionState -> OriginalCallableExecutionState -> Prop where
  | refl (state) : OriginalCallableExternalSteps program environment state state
  | step {before middle after outcome}
      (head : OriginalCallableExternalStep program environment before outcome middle)
      (tail : OriginalCallableExternalSteps program environment middle after) :
      OriginalCallableExternalSteps program environment before after

theorem OriginalCallableExternalSteps.preservesRuntimeTraceConsistency
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (before after : OriginalCallableExecutionState)
    (steps : OriginalCallableExternalSteps program environment before after)
    (consistent : before.RuntimeTraceConsistent) :
    after.RuntimeTraceConsistent := by
  induction steps with
  | refl => exact consistent
  | step head _ induction =>
      exact induction (head.preservesRuntimeTraceConsistency program environment
        _ _ _ consistent)

def CallableExternalObservationsRelated
    (context : StaticProofContext)
    (original candidate : CallableExternalObservation) : Prop :=
  original.globalExternalIndex = candidate.globalExternalIndex ∧
    original.identity = candidate.identity ∧
    original.world = candidate.world ∧
    externalCallArgumentsRelated context original.world original.arguments
      candidate.arguments = true

inductive RuntimeCallableTracesRelated
    (context : StaticProofContext) :
    List CallableExternalObservation -> List CallableExternalObservation -> Prop where
  | nil : RuntimeCallableTracesRelated context [] []
  | cons {originalHead candidateHead originalTail candidateTail}
      (head : CallableExternalObservationsRelated context
        originalHead candidateHead)
      (tail : RuntimeCallableTracesRelated context originalTail candidateTail) :
      RuntimeCallableTracesRelated context
        (originalHead :: originalTail) (candidateHead :: candidateTail)

theorem runtimeCallableTracesRejectOmittedEvent
    (context : StaticProofContext) (observation : CallableExternalObservation) :
    ¬ RuntimeCallableTracesRelated context [observation] [] := by
  intro related
  cases related

theorem runtimeCallableTracesRejectReorderedEvents
    (context : StaticProofContext)
    (first second : CallableExternalObservation)
    (different : first.identity ≠ second.identity) :
    ¬ RuntimeCallableTracesRelated context [first, second] [second, first] := by
  intro related
  cases related with
  | cons head _ => exact different head.2.1

theorem runtimeCallableTracesRejectMismatchedArguments
    (context : StaticProofContext)
    (original candidate : CallableExternalObservation)
    (mismatch : externalCallArgumentsRelated context original.world
      original.arguments candidate.arguments = false) :
    ¬ RuntimeCallableTracesRelated context [original] [candidate] := by
  intro related
  cases related with
  | cons head _ => simp_all [CallableExternalObservationsRelated]

theorem RuntimeCallableTracesRelated.appendObservation
    (context : StaticProofContext)
    (original candidate : List CallableExternalObservation)
    (originalObservation candidateObservation : CallableExternalObservation)
    (relatedPrefix : RuntimeCallableTracesRelated context original candidate)
    (observation : CallableExternalObservationsRelated context
      originalObservation candidateObservation) :
    RuntimeCallableTracesRelated context
      (original ++ [originalObservation]) (candidate ++ [candidateObservation]) := by
  induction relatedPrefix with
  | nil => exact .cons observation .nil
  | cons head tail induction => exact .cons head induction

theorem RuntimeCallableTracesRelated.length_eq
    (context : StaticProofContext)
    (original candidate : List CallableExternalObservation)
    (related : RuntimeCallableTracesRelated context original candidate) :
    original.length = candidate.length := by
  induction related with
  | nil => rfl
  | cons _ _ induction => simp [induction]

/-- Typed kernel frontier for the candidate side.  Instantiation requires the
shared candidate decoder/kernel to expose callable classification. -/
structure CandidateKernelCallableFrontier where
  capabilities : List CallableExternalCapability
  resolvedABIContracts : List ResolvedExternalABIContract
  internalMatches : StaticProofContext -> Word -> List Nat
  importMatches : RelationalWorld -> Word -> List ImportAddressPair
  resourceMatches : RelationalWorld -> Word -> List OpaqueResourcePair
  classifyIndirect : StaticProofContext -> RelationalWorld -> Word ->
    ResolvedExternalTransfer -> OriginalIndirectResolution
  classificationExact : ∀ context world target transfer,
    callableExternalWorldValid context world = true ->
    classifyIndirect context world target transfer =
      classifyOriginalIndirectMatches
        (internalMatches context target)
        (importMatches world target)
        (resourceMatches world target)
        capabilities resolvedABIContracts transfer
  callableUsesCandidateValue : ∀ context world target transfer capability abi resource,
    classifyIndirect context world target transfer =
      .callable capability abi resource ->
    resource.candidate = target
  rejectsInvalidWorld : ∀ context world target transfer,
    callableExternalWorldValid context world != true ->
    classifyIndirect context world target transfer = .invalidWorld

/-- Typed native frontier for candidate transition integration. -/
structure CandidateNativeCallableFrontier where
  State : Type
  rva : State -> Nat
  machineState : State -> MachineState
  calls : State -> List NativeCallFrame
  world : State -> RelationalWorld
  globalExternalIndex : State -> Nat
  externalTrace : State -> List CallableExternalObservation
  transition : State -> ConcreteOutcome -> State -> Prop
  externalStepSound : ∀ before outcome after,
    transition before outcome after ->
    ∃ observation,
      observation.globalExternalIndex = globalExternalIndex before ∧
      globalExternalIndex after = globalExternalIndex before + 1 ∧
      externalTrace after = externalTrace before ++ [observation]
  indirectCallContinuation : ∀ before after target continuation returnAddress,
    transition before (.indirectCall target continuation returnAddress) after ->
    rva after = continuation
  indirectTailFrame : ∀ before after target,
    transition before (.indirectJump target) after ->
    ∃ frame tail,
      calls before = frame :: tail ∧
      calls after = tail ∧
      rva after = frame.continuationRva

/-- Compose one original wrapper transition with one candidate transition.
The refinement premise applies only to the two observations produced by those
runtime transitions; no submitted trace is trusted. -/
theorem composeOriginalWithCandidateRuntimeTrace
    (context : StaticProofContext)
    (program : OriginalCallableProgram)
    (environment : OriginalCallableExternalEnvironment)
    (candidateFrontier : CandidateNativeCallableFrontier)
    (originalBefore originalAfter : OriginalCallableExecutionState)
    (candidateBefore candidateAfter : candidateFrontier.State)
    (outcome : ConcreteOutcome)
    (originalStep : OriginalCallableExternalStep program environment
      originalBefore outcome originalAfter)
    (candidateStep : candidateFrontier.transition
      candidateBefore outcome candidateAfter)
    (relatedPrefix : RuntimeCallableTracesRelated context originalBefore.externalTrace
      (candidateFrontier.externalTrace candidateBefore))
    (environmentRefines : ∀ originalObservation candidateObservation,
      originalAfter.externalTrace = originalBefore.externalTrace ++
          [originalObservation] ->
      candidateFrontier.externalTrace candidateAfter =
          candidateFrontier.externalTrace candidateBefore ++
            [candidateObservation] ->
      CallableExternalObservationsRelated context originalObservation
        candidateObservation) :
    RuntimeCallableTracesRelated context originalAfter.externalTrace
      (candidateFrontier.externalTrace candidateAfter) := by
  rcases originalStep.appendsRuntimeObservation program environment
      originalBefore originalAfter outcome with
    ⟨originalObservation, _originalIndex, _originalNext, originalTrace⟩
  rcases candidateFrontier.externalStepSound candidateBefore outcome candidateAfter
      candidateStep with
    ⟨candidateObservation, _candidateIndex, _candidateNext, candidateTrace⟩
  rw [originalTrace, candidateTrace]
  exact relatedPrefix.appendObservation context _ _ originalObservation
    candidateObservation (environmentRefines originalObservation
      candidateObservation originalTrace candidateTrace)

end StageA.Relational.CallableExternalExecution
