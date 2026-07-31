import StageA.RelationalUniversalPairedExternalEnvironment

namespace StageA.Relational.UniversalPairedExternalEnvironmentStaticAuthority

open StageA.Formal StageA.Relational
open StageA.Relational.StaticMachineImportContracts
open StageA.Relational.UniversalPairedExternalEnvironment

/-! # Static authority for universal paired external environments

Candidate routes are checked against the exact candidate PE and import table,
then pinned one-to-one to the call sites and machine contracts selected by the
shared static context.  No external response or environment behavior is
constructed here.
-/

def candidateStaticMachineImportCallRoutePinned
    (context : StaticProofContext)
    (regions : List RegionRelation)
    (signatures : List StaticMachineImportSignature)
    (boundary : StaticMachineImportBoundary)
    (site : ExternalCallSiteContract) : Bool :=
  boundary.id == site.id &&
    boundary.id == site.machineContractId &&
    boundary.valid context.candidatePe context.candidateImports signatures &&
    match boundary.resolveContract? signatures,
        context.codeMap.get? site.sourceTargetId with
    | some resolved, some sourceTarget =>
        context.candidatePe.imageBase + boundary.executionSourceRva < 2^32 &&
          context.candidatePe.imageBase + boundary.continuationRva < 2^32 &&
          resolved.boundary == boundary &&
          machineImportCallContractById? context site.machineContractId ==
            some resolved.contract &&
          sourceTarget.id == site.sourceTargetId &&
          (match regions[sourceTarget.regionIndex]? with
          | none => false
          | some sourceRegion =>
              sourceRegion.id == sourceTarget.regionIndex &&
              sourceRegion.candidate.start == sourceTarget.candidateRva &&
              sourceRegion.candidate.start <= boundary.executionSpan.start &&
              boundary.executionSpan.start < sourceRegion.candidate.stop) &&
          context.codeMap.resolveRawEip true context.candidatePe.imageBase
              (BitVec.ofNat 32
                (context.candidatePe.imageBase + boundary.continuationRva)) ==
            some site.continuationTargetId
    | _, _ => false

def candidateStaticMachineImportCallRoutesPinned
    (context : StaticProofContext)
    (regions : List RegionRelation)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary)
    (sites : List ExternalCallSiteContract) : Bool :=
  !boundaries.isEmpty &&
    (boundaries.all fun boundary =>
      (boundaries.filter fun other => other.id == boundary.id).length == 1 &&
        (sites.filter fun site => site.id == boundary.id).length == 1 &&
        match sites.find? fun site => site.id == boundary.id with
        | none => false
        | some site =>
            candidateStaticMachineImportCallRoutePinned context regions
              signatures boundary site) &&
    (sites.all fun site =>
      (boundaries.filter fun boundary => boundary.id == site.id).length == 1)

/-- The three static authority groups needed before response behavior can be
supplied: exact candidate routes, exact context binding, and finite site
validity. -/
structure UniversalPairedExternalEnvironmentStaticAuthority
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext)
    (regions : List RegionRelation)
    (candidateBoundaries : List StaticMachineImportBoundary)
    (sites : List ExternalCallSiteContract) : Prop where
  candidateRoutesPinned :
    candidateStaticMachineImportCallRoutesPinned context regions signatures
      candidateBoundaries sites = true
  contextBound : pair.BoundToContext context
  siteIdsUnique : externalCallSiteIdsUnique sites = true
  sitesStaticValid :
    sites.all (ExternalCallSiteContract.staticValid context) = true

/-- Add only the genuinely behavioral response theorem data to static
authority.  Contract resolution follows from the checked finite site list. -/
def UniversalPairedExternalEnvironmentStaticAuthority.certificate
    (pair : PinnedStaticMachineImportPair originalBytes candidateBytes
      originalPe candidatePe originalImports candidateImports required
      signatures contracts)
    (context : StaticProofContext)
    (regions : List RegionRelation)
    (candidateBoundaries : List StaticMachineImportBoundary)
    (sites : List ExternalCallSiteContract)
    (original candidate : WorldExternalEnvironment)
    (authority : UniversalPairedExternalEnvironmentStaticAuthority pair context
      regions candidateBoundaries sites)
    (returningResponses : forall site contract,
      site ∈ sites ->
      machineImportCallContractById? context site.machineContractId =
        some contract ->
      contract.disposition = .returns ->
      CheckedUniversalPairedMachineResponse context site contract
        original candidate) :
    UniversalPairedExternalEnvironmentCertificate pair context sites
      original candidate := {
  contextBound := authority.contextBound
  siteIdsUnique := authority.siteIdsUnique
  sitesStaticValid := authority.sitesStaticValid
  contractsResolved := by
    intro site member
    have valid :=
      List.all_eq_true.mp authority.sitesStaticValid site member
    cases resolved :
        machineImportCallContractById? context site.machineContractId with
    | none =>
        simp [ExternalCallSiteContract.staticValid, resolved] at valid
    | some contract =>
        exact ⟨contract, rfl⟩
  returningResponses := returningResponses
}

#print axioms
  UniversalPairedExternalEnvironmentStaticAuthority.certificate

end StageA.Relational.UniversalPairedExternalEnvironmentStaticAuthority
