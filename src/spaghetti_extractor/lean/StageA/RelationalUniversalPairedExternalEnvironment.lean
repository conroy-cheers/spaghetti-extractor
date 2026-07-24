import StageA.RelationalLockstepEnvironment
import StageA.RelationalStaticMachineImportContracts

namespace StageA.Relational.UniversalPairedExternalEnvironment

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts

/-! # Universal paired external environments

This module separates two facts which must not be conflated:

* both exact PE byte trees use one checked machine-import contract inventory;
* a pair of external environments returns related responses for every related
  call boundary.

The second fact remains a quantified environment premise.  Matching imports
cannot prove that two arbitrary external response functions agree.  The proof
core therefore accepts an abstract response relation only together with a
universal soundness proof and evidence that both concrete environments
implement it.
-/

def machineImportCallContractMatchesSignature
    (contract : MachineImportCallContract)
    (signature : StaticMachineImportSignature) : Bool :=
  match signature.bridgeContract? contract.stackArgumentOffsets.length with
  | none => false
  | some expected => { expected with id := contract.id } == contract

def pinnedMachineImportContractsValid
    (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature)
    (contracts : List MachineImportCallContract) : Bool :=
  !contracts.isEmpty &&
    (contracts.all fun contract =>
      (contracts.filter fun other => other.id == contract.id).length == 1) &&
    (contracts.all fun contract =>
      required.contains contract.imported &&
        (signatures.filter fun signature =>
          machineImportCallContractMatchesSignature contract signature).length == 1)

/-- Both binaries are parsed from exact byte trees, expose exactly the same
normalized import inventory, and validate one shared signature/contract
inventory.  Different IAT RVAs remain permitted because the equality is over
normalized import identities rather than loader addresses. -/
structure PinnedStaticMachineImportPair
    (originalBytes candidateBytes : ByteTree)
    (originalPe candidatePe : PE32)
    (originalImports candidateImports : List PEImport)
    (required : List ExternalTarget)
    (signatures : List StaticMachineImportSignature)
    (contracts : List MachineImportCallContract) : Prop where
  originalPeParsed : parsePE32Tree originalBytes = some originalPe
  candidatePeParsed : parsePE32Tree candidateBytes = some candidatePe
  importIdentitiesExact :
    originalImports.map normalizeImport = candidateImports.map normalizeImport
  originalProfile :
    StaticMachineImportProfileCertificate originalPe originalImports
      required signatures
  candidateProfile :
    StaticMachineImportProfileCertificate candidatePe candidateImports
      required signatures
  contractsPinned :
    pinnedMachineImportContractsValid required signatures contracts = true

/-- Bind the exact pair to the context consumed by ordinary relational
composition.  In particular, the context cannot substitute a different
machine-contract inventory after the two PE profiles have been checked. -/
structure PinnedStaticMachineImportPair.BoundToContext
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext) : Prop where
  originalPeExact : context.originalPe = originalPe
  candidatePeExact : context.candidatePe = candidatePe
  originalImportsExact : context.originalImports = originalImports
  candidateImportsExact : context.candidateImports = candidateImports
  machineContractsExact : context.machineImportCallContracts = contracts

/-- Complete machine-level relation for one pair of returning external
responses.  It mentions no API-specific behavior. -/
def PairedMachineExternalResultsRelated
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop :=
  originalResult.world = candidateResult.world /\
    machineCallResultConforms false context contract originalEvent
      originalResult /\
    machineCallResultConforms true context contract candidateEvent
      candidateResult /\
    machineCallResultRegistersRelated context originalResult.world contract
      originalEvent.arguments originalResult.state candidateResult.state = true /\
    StateRel context originalResult.world site.targetInvariant
      originalResult.state candidateResult.state /\
    ExternalRuntimeFramesPreserved originalEvent candidateEvent
      originalResult candidateResult

/-- An API-neutral relation over possible paired responses.  `sound` quantifies
over arbitrary event indices, related request states/worlds, and response
states/worlds.  A permissive relation cannot close an obligation unless its
soundness theorem establishes every machine-contract and continuation fact. -/
structure UniversalPairedMachineResponseRelation
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract) where
  related :
    Nat -> WorldExternalEvent -> WorldExternalEvent ->
      WorldExternalResult -> WorldExternalResult -> Prop
  sound : forall eventIndex originalEvent candidateEvent
      originalResult candidateResult,
    ExternalCallBoundaryRelated context site contract
        originalEvent candidateEvent ->
    related eventIndex originalEvent candidateEvent
        originalResult candidateResult ->
    PairedMachineExternalResultsRelated context site contract
      originalEvent candidateEvent originalResult candidateResult

def WorldExternalEnvironmentPairImplements
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (relation : UniversalPairedMachineResponseRelation context site contract)
    (original candidate : WorldExternalEnvironment) : Prop :=
  forall eventIndex originalEvent candidateEvent,
    ExternalCallBoundaryRelated context site contract
        originalEvent candidateEvent ->
    relation.related eventIndex originalEvent candidateEvent
      (original.result eventIndex originalEvent)
      (candidate.result eventIndex candidateEvent)

/-- Response-law evidence for one returning site.  The relation is abstract;
the two fields force it to be universally sound and implemented by the actual
environment functions. -/
structure CheckedUniversalPairedMachineResponse
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment) where
  relation : UniversalPairedMachineResponseRelation context site contract
  implemented :
    WorldExternalEnvironmentPairImplements context site contract relation
      original candidate

theorem externalEnvironmentRefinesAt_of_universalPairedResponse
    (context : StaticProofContext)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (original candidate : WorldExternalEnvironment)
    (returns : contract.disposition = .returns)
    (checked : CheckedUniversalPairedMachineResponse context site contract
      original candidate) :
    ExternalEnvironmentRefinesAt context site contract original candidate := by
  unfold ExternalEnvironmentRefinesAt
  rw [returns]
  intro eventIndex originalEvent candidateEvent boundary
  exact checked.relation.sound eventIndex originalEvent candidateEvent
    (original.result eventIndex originalEvent)
    (candidate.result eventIndex candidateEvent) boundary
    (checked.implemented eventIndex originalEvent candidateEvent boundary)

/-- Program-wide synchronous environment certificate.  Protocol/callback
actions remain governed by `WorldExternalProtocolEnvironmentsRefine`; this
certificate supplies exactly the `WorldExternalEnvironment` component used by
returning imports.  Terminating and protocol dispositions have no result in
that component and are discharged by the existing disposition split. -/
structure UniversalPairedExternalEnvironmentCertificate
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment) where
  contextBound : pair.BoundToContext context
  siteIdsUnique : externalCallSiteIdsUnique sites = true
  sitesStaticValid :
    sites.all (ExternalCallSiteContract.staticValid context) = true
  contractsResolved : forall site, site ∈ sites ->
    exists contract,
      machineImportCallContractById? context site.machineContractId =
        some contract
  returningResponses : forall site contract,
    site ∈ sites ->
    machineImportCallContractById? context site.machineContractId =
      some contract ->
    contract.disposition = .returns ->
    CheckedUniversalPairedMachineResponse context site contract
      original candidate

theorem UniversalPairedExternalEnvironmentCertificate.refines
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (certificate : UniversalPairedExternalEnvironmentCertificate pair context
      sites original candidate) :
    ExternalEnvironmentRefines context sites original candidate := by
  refine ⟨certificate.siteIdsUnique, certificate.sitesStaticValid, ?_⟩
  intro site member
  rcases certificate.contractsResolved site member with
    ⟨contract, resolved⟩
  refine ⟨contract, resolved, ?_⟩
  cases disposition : contract.disposition with
  | returns =>
      exact externalEnvironmentRefinesAt_of_universalPairedResponse context
        site contract original candidate disposition
        (certificate.returningResponses site contract member resolved disposition)
  | terminates =>
      simp [ExternalEnvironmentRefinesAt, disposition]
  | protocol =>
      simp [ExternalEnvironmentRefinesAt, disposition]

theorem UniversalPairedExternalEnvironmentCertificate.atReturning
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (certificate : UniversalPairedExternalEnvironmentCertificate pair context
      sites original candidate)
    (site : ExternalCallSiteContract)
    (contract : MachineImportCallContract)
    (member : site ∈ sites)
    (resolved : machineImportCallContractById? context site.machineContractId =
      some contract)
    (returns : contract.disposition = .returns) :
    ExternalEnvironmentRefinesAt context site contract original candidate :=
  externalEnvironmentRefinesAt_of_universalPairedResponse context site contract
    original candidate returns
    (certificate.returningResponses site contract member resolved returns)

#print axioms externalEnvironmentRefinesAt_of_universalPairedResponse
#print axioms UniversalPairedExternalEnvironmentCertificate.refines
#print axioms UniversalPairedExternalEnvironmentCertificate.atReturning

end StageA.Relational.UniversalPairedExternalEnvironment
