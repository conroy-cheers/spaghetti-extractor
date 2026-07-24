import StageA.RelationalEnvironment
import StageA.RelationalEngine

namespace StageA.Relational

/-- A prototype-free external synchronization site.  Unlike
`MachineImportCallContract`, this contract does not predict a stack delta,
register clobber set, or memory footprint.  It instead requires the paired
environment to re-establish the complete target `StateRel`.  This is a strong,
explicit theorem assumption intended for candidates that issue the exact same
machine-level call against the same pinned external implementation. -/
structure FullMachineLockstepCallSite where
  id : Nat
  imported : ExternalTarget
  boundaryInvariant : StateInvariant
  targetInvariant : StateInvariant
deriving Repr, DecidableEq

def fullMachineLockstepCallSiteIdsUnique
    (sites : List FullMachineLockstepCallSite) : Bool :=
  (sites.map (fun site => site.id)).all fun id =>
    (sites.filter (fun site => site.id == id)).length == 1

def FullMachineLockstepBoundaryRelated (context : StaticProofContext)
    (site : FullMachineLockstepCallSite)
    (original candidate : WorldExternalEvent) : Prop :=
  original.siteId = site.id ∧
    candidate.siteId = site.id ∧
    original.world = candidate.world ∧
    original.imported = site.imported ∧
    candidate.imported = site.imported ∧
    StateRel context original.world site.boundaryInvariant
      original.state candidate.state ∧
    externalCallArgumentsRelated context original.world
      original.arguments candidate.arguments = true

/-- Pointwise stateful environment refinement at one external-event index.

The transition is deliberately abstract.  It may return different concrete
handles or allocation addresses only when the target `StateRel` and successor
world relate them.  It cannot reorder, batch, replace, or omit the call because
the boundary fixes both site and import identity. -/
def FullMachineLockstepEnvironmentRefinesAt (context : StaticProofContext)
    (site : FullMachineLockstepCallSite)
    (original candidate : WorldExternalEnvironment) : Prop :=
  ∀ eventIndex originalEvent candidateEvent,
    FullMachineLockstepBoundaryRelated context site originalEvent candidateEvent ->
      let originalResult := original.result eventIndex originalEvent
      let candidateResult := candidate.result eventIndex candidateEvent
      originalResult.world = candidateResult.world ∧
        StateRel context originalResult.world site.targetInvariant
          originalResult.state candidateResult.state ∧
        ExternalRuntimeFramesPreserved originalEvent candidateEvent
          originalResult candidateResult

/-- The canonical full-machine synchronization site for a checked machine-call
site.  Keeping this conversion in the proof kernel prevents generated evidence
from choosing a different import or boundary invariant for the lockstep proof. -/
def ExternalCallSiteContract.fullMachineLockstepSite
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract) :
    FullMachineLockstepCallSite :=
  {
    id := site.id
    imported := contract.imported
    boundaryInvariant := site.boundaryInvariant
    targetInvariant := site.targetInvariant
  }

/-- Evidence that the ordinary external boundary establishes the stronger
full-state boundary required by exact lockstep execution.  The ordinary
boundary deliberately omits general memory equivalence, so this implication is
an explicit proof obligation rather than an implicit relaxation. -/
def ExactLockstepBoundaryStateEstablished (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract) : Prop :=
  forall originalEvent candidateEvent,
    ExternalCallBoundaryRelated context site contract originalEvent candidateEvent ->
      FullMachineLockstepBoundaryRelated context
        (site.fullMachineLockstepSite contract) originalEvent candidateEvent

/-- Machine-contract evidence for the paired result of every exact lockstep
call.  `machineCallResultConforms` checks each side's stack delta, preserved
registers, memory footprint, and world update.  The relational result check
allows paired concrete handles and addresses while retaining the contract's
declared result relation. -/
def ExactLockstepMachineCallResultsConformAt (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment) : Prop :=
  forall eventIndex originalEvent candidateEvent,
    ExternalCallBoundaryRelated context site contract originalEvent candidateEvent ->
      let originalResult := original.result eventIndex originalEvent
      let candidateResult := candidate.result eventIndex candidateEvent
      ExactExternalCallPairConforms context contract originalEvent candidateEvent
        originalResult candidateResult ∧
        machineCallResultRegistersRelated context originalResult.world contract
          originalEvent.arguments originalResult.state candidateResult.state = true

/-- Complete checked evidence for composing one exact 1:1 stateful external
call.  Static validity fixes the binary imports and machine ABI contract;
lockstep refinement fixes event order and restores the target state relation;
the remaining fields close the deliberately explicit boundary and result
contract obligations. -/
structure CheckedExactLockstepExternalReturn
    (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment) : Prop where
  staticContextValid : context.StructurallyValid
  siteStaticValid : site.staticValid context = true
  contractResolved :
    machineImportCallContractById? context site.machineContractId = some contract
  contractShapeValid : contract.shapeValid = true
  returns : contract.disposition = .returns
  boundaryStateEstablished :
    ExactLockstepBoundaryStateEstablished context site contract
  environmentLockstep :
    FullMachineLockstepEnvironmentRefinesAt context
      (site.fullMachineLockstepSite contract) original candidate
  machineResultsConform :
    ExactLockstepMachineCallResultsConformAt context site contract original candidate

/-- Exact lockstep execution plus a checked machine-call contract discharges
the existing external-return composition obligation.  This theorem preserves
paired concrete environments and arbitrarily nested runtime frames; no API
behavior is defined in the proof core. -/
theorem externalEnvironmentRefinesAt_of_checkedExactLockstep
    (context : StaticProofContext)
    (site : ExternalCallSiteContract) (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment)
    (checked : CheckedExactLockstepExternalReturn context site contract
      original candidate) :
    ExternalEnvironmentRefinesAt context site contract original candidate := by
  unfold ExternalEnvironmentRefinesAt
  rw [checked.returns]
  intro eventIndex originalEvent candidateEvent boundary
  have fullBoundary := checked.boundaryStateEstablished
    originalEvent candidateEvent boundary
  have lockstep := checked.environmentLockstep eventIndex originalEvent
    candidateEvent fullBoundary
  have conforms := checked.machineResultsConform eventIndex originalEvent
    candidateEvent boundary
  exact ⟨lockstep.1, conforms.1.originalConforms,
    conforms.1.candidateConforms, conforms.2, lockstep.2.1, lockstep.2.2⟩

def FullMachineLockstepEnvironmentsRefined (context : StaticProofContext)
    (sites : List FullMachineLockstepCallSite)
    (original candidate : WorldExternalEnvironment) : Prop :=
  fullMachineLockstepCallSiteIdsUnique sites = true ∧
    ∀ site, site ∈ sites ->
      FullMachineLockstepEnvironmentRefinesAt context site original candidate

theorem FullMachineLockstepEnvironmentsRefined.at
    (context : StaticProofContext)
    (sites : List FullMachineLockstepCallSite)
    (original candidate : WorldExternalEnvironment)
    (refines : FullMachineLockstepEnvironmentsRefined context sites
      original candidate)
    (site : FullMachineLockstepCallSite) (member : site ∈ sites) :
    FullMachineLockstepEnvironmentRefinesAt context site original candidate :=
  refines.2 site member

theorem fullMachineLockstepResultsRelated
    (context : StaticProofContext) (site : FullMachineLockstepCallSite)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (environmentRefines : FullMachineLockstepEnvironmentRefinesAt context site
      originalEnvironment candidateEnvironment)
    (eventIndex : Nat) (originalEvent candidateEvent : WorldExternalEvent)
    (boundary : FullMachineLockstepBoundaryRelated context site
      originalEvent candidateEvent) :
    let originalResult := originalEnvironment.result eventIndex originalEvent
    let candidateResult := candidateEnvironment.result eventIndex candidateEvent
    originalResult.world = candidateResult.world ∧
      StateRel context originalResult.world site.targetInvariant
        originalResult.state candidateResult.state ∧
      ExternalRuntimeFramesPreserved originalEvent candidateEvent
        originalResult candidateResult :=
  environmentRefines eventIndex originalEvent candidateEvent boundary

theorem FullMachineLockstepBoundaryRelated.import_identity
    (context : StaticProofContext) (site : FullMachineLockstepCallSite)
    (original candidate : WorldExternalEvent)
    (related : FullMachineLockstepBoundaryRelated context site original candidate) :
    original.imported = candidate.imported := by
  rw [related.2.2.2.1, related.2.2.2.2.1]

theorem FullMachineLockstepBoundaryRelated.event_index_anchor
    (context : StaticProofContext) (site : FullMachineLockstepCallSite)
    (original candidate : WorldExternalEvent)
    (related : FullMachineLockstepBoundaryRelated context site original candidate) :
    original.siteId = candidate.siteId := by
  rw [related.1, related.2.1]

end StageA.Relational
