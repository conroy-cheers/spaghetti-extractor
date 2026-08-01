import StageA.RelationalNativeSourceResponseFamilyCompletion

namespace StageA.Relational.NativeSource

open StageA.Formal
open StageA.Relational
open StageA.Relational.StaticMachineImportContracts

/-! # Machine-derived external response requirements

This inventory is computed from checked machine contracts.  It contains no API
names and grants no proof authority: it tells a response producer which
state-indexed facts must be established before a total response schedule can
exist.
-/

inductive MachineResponseRequirementKind where
  | runtimeMemoryFootprints
  | dynamicRangeRelease (argumentIndex : Nat)
  | callbackRegistration (argumentIndex : Nat)
  | nonnullableDynamicRangeResult (register : Reg)
deriving Repr, DecidableEq

structure MachineResponseRequirement where
  boundaryId : Nat
  kind : MachineResponseRequirementKind
deriving Repr, DecidableEq

def machineCallMemoryEffectRequiresRuntimeFootprints :
    MachineCallMemoryEffect -> Bool
  | .readOnly | .argumentRanges => true
  | .none | .newDynamicRanges | .relationalState => false

def machineCallResultRegisterRelationNonnullableDynamicRangeResult :
    MachineCallResultRegisterRelation -> Bool
  | { relation := .dynamicRangeBase _ _ _ nullable, .. } => !nullable
  | _ => false

def machineResponseRequirementsForContract (boundaryId : Nat)
    (contract : MachineImportCallContract) : List MachineResponseRequirement :=
  let memory :=
    if machineCallMemoryEffectRequiresRuntimeFootprints contract.memoryEffect then
      [{ boundaryId, kind := .runtimeMemoryFootprints }]
    else []
  let world :=
    match contract.worldEffect with
    | .dynamicRangeRelease argumentIndex =>
        [{ boundaryId, kind := .dynamicRangeRelease argumentIndex }]
    | .callbackRegistration argumentIndex =>
        [{ boundaryId, kind := .callbackRegistration argumentIndex }]
    | .none | .opaqueResources | .dynamicRanges | .tlsState => []
  let results := contract.resultRegisterRelations.filterMap fun relation =>
    if machineCallResultRegisterRelationNonnullableDynamicRangeResult relation then
      some { boundaryId, kind := .nonnullableDynamicRangeResult relation.register }
    else none
  memory ++ world ++ results

def checkedMachineResponseRequirements
    (inventory : List StaticMachineImportResolvedBoundary) :
    List MachineResponseRequirement :=
  inventory.flatMap fun resolved =>
    machineResponseRequirementsForContract resolved.boundary.id resolved.contract

def MachineResponseRequirementIdsUniqueWithinKind
    (requirements : List MachineResponseRequirement) : Bool :=
  requirements.all fun requirement =>
    (requirements.filter fun other =>
      other.boundaryId == requirement.boundaryId &&
        other.kind == requirement.kind).length == 1

end StageA.Relational.NativeSource
