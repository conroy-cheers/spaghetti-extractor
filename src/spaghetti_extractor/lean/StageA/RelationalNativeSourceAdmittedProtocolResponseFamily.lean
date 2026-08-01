import StageA.RelationalInterpreterMixedEnvironment
import StageA.RelationalNativeSourceAdmittedResponseFamily
import StageA.RelationalOriginalCombinedAwaitingExternalPreservation
import StageA.RelationalStaticMachineImportContracts

namespace StageA.Relational.NativeSource

open StageA.Formal
open StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterNativeWorld
open StageA.Relational.InterpreterWorldBridge
open StageA.Relational.OriginalCombinedAwaitingExternalPreservation
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.StaticMachineImportContracts

/-! # Checked admitted callback/protocol response families

This module extends the synchronous admitted-response family with the two
machine-level forms needed by nested external protocols:

* a returning call whose checked world effect registers a callback pair; and
* a protocol call which suspends, enters zero or more checked callbacks, and
  eventually returns or terminates.

No imported API identity appears in the classification.  The trusted core
looks only at the exact decoded boundary, machine ABI/effect contract, and
static callback mode.  Unknown combinations have no classification and fail
the complete-inventory check.
-/

inductive MachineExternalResponseMode where
  | synchronous
  | registration (argumentIndex : Nat)
  | nestedFrames
deriving Repr, DecidableEq

/-- Structural classification of one exact machine-call contract. -/
def MachineExternalResponseMode.matches
    (mode : MachineExternalResponseMode)
    (signature : StaticMachineImportSignature)
    (contract : MachineImportCallContract) : Bool :=
  match mode, signature.callbackMode, contract.disposition,
      contract.worldEffect with
  | .synchronous, .none, .returns, effect =>
      match effect with
      | .callbackRegistration _ => false
      | _ => true
  | .synchronous, .none, .terminates, .none => true
  | .registration argumentIndex, .registration, .returns,
      .callbackRegistration registeredIndex =>
      argumentIndex == registeredIndex
  | .nestedFrames, .nestedFrames, .protocol, .none =>
      contract.memoryEffect == .relationalState &&
        contract.memoryFootprints.isEmpty
  | _, _, _, _ => false

/-- One response classification keyed by the exact boundary ID. -/
structure CheckedMachineExternalSite where
  boundaryId : Nat
  signatureId : Nat
  mode : MachineExternalResponseMode
deriving Repr, DecidableEq

def CheckedMachineExternalSite.staticValid
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (site : CheckedMachineExternalSite) : Bool :=
  match signatures.find? (fun signature => signature.id == site.signatureId),
      boundaries.find? (fun boundary => boundary.id == site.boundaryId),
      inventory.find? (fun resolved =>
        resolved.boundary.id == site.boundaryId) with
  | some signature, some boundary, some resolved =>
      boundary.signatureId == site.signatureId &&
        resolved.boundary == boundary &&
        resolved.contract.id == site.boundaryId &&
        site.mode.matches signature resolved.contract
  | _, _, _ => false

/-- Exact bidirectional coverage of the checked boundary inventory. -/
def checkedMachineExternalSitesValid
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary)
    (inventory : List StaticMachineImportResolvedBoundary)
    (sites : List CheckedMachineExternalSite) : Bool :=
  (sites.all fun site =>
      (sites.filter (fun other => other.boundaryId == site.boundaryId)).length == 1 &&
        site.staticValid signatures boundaries inventory) &&
    (boundaries.all fun boundary =>
      (sites.filter (fun site => site.boundaryId == boundary.id)).length == 1)

/-- A checked, fail-closed response classification for every exact boundary.
The route checker remains authoritative for the decoded bytes and import. -/
structure CheckedMachineExternalSiteInventory
    (pe : PE32) (imports : List PEImport)
    (signatures : List StaticMachineImportSignature)
    (boundaries : List StaticMachineImportBoundary) where
  boundaryContracts : CheckedStaticMachineImportBoundaryContracts pe imports
    signatures boundaries
  sites : List CheckedMachineExternalSite
  checked : checkedMachineExternalSitesValid signatures boundaries
    boundaryContracts.inventory sites = true

def CheckedMachineExternalSite.isNested
    (site : CheckedMachineExternalSite) : Bool :=
  match site.mode with
  | .nestedFrames => true
  | .synchronous | .registration _ => false

def CheckedMachineExternalSite.isRegistration
    (site : CheckedMachineExternalSite) : Bool :=
  match site.mode with
  | .registration _ => true
  | .synchronous | .nestedFrames => false

def MachineExternalResponseMode.registrationArgument? :
    MachineExternalResponseMode -> Option Nat
  | .registration argumentIndex => some argumentIndex
  | .synchronous | .nestedFrames => none

/-- The ordinary opaque inventory covers exactly the non-protocol partition;
the nested partition remains represented by its exact decoded source sites. -/
def machineExternalSitesCoverProgram
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (classified : List CheckedMachineExternalSite)
    (ordinarySites : List OpaqueLockstepCallSite) : Bool :=
  (program.externalCallSites.all fun programSite =>
      match classified.find? (fun site => site.boundaryId == programSite.id) with
      | none => false
      | some classifiedSite =>
          programSite.machineContractId == classifiedSite.boundaryId &&
            if classifiedSite.isNested then
              match machineImportCallContractById? context
                  programSite.machineContractId with
              | some contract => contract.disposition == .protocol
              | none => false
            else
              (ordinarySites.filter fun ordinary =>
                ordinary.matchesExternalCallSite context programSite).length == 1) &&
    (classified.all fun classifiedSite =>
      (program.externalCallSites.filter fun programSite =>
        programSite.id == classifiedSite.boundaryId).length == 1) &&
    (ordinarySites.all fun ordinary =>
      match classified.find? (fun site => site.boundaryId == ordinary.id) with
      | some classifiedSite => !classifiedSite.isNested
      | none => false)

/-- Both source response functions are part of the admitted pair.  Keeping the
protocol function inside a fixed source project would silently specialize the
family to one callback schedule. -/
structure SourceWorldResponseEnvironment where
  ordinary : WorldExternalEnvironment
  protocol : WorldExternalProtocolEnvironment

def decodedWorldProgramWithResponseEnvironment
    (program : DecodedWorldProgram)
    (environment : SourceWorldResponseEnvironment) : DecodedWorldProgram := {
  program with
  environment := environment.ordinary
  protocolEnvironment := environment.protocol
}

def checkedNativeProgramInputWithResponseEnvironment
    {worldProgram : DecodedWorldProgram}
    (input : CheckedNativeProgramInput worldProgram)
    (environment : SourceWorldResponseEnvironment) :
    CheckedNativeProgramInput
      (decodedWorldProgramWithResponseEnvironment worldProgram environment) := {
  ir := {
    records := input.ir.records
    x87Witnesses := input.ir.x87Witnesses
  }
  recordsUnique := input.recordsUnique
  x87SourcesUnique := input.x87SourcesUnique
}

def nativeSourceProjectWithResponseEnvironment
    (project : NativeSourceProject)
    (environment : SourceWorldResponseEnvironment) : NativeSourceProject := {
  profile := project.profile
  worldProgram := decodedWorldProgramWithResponseEnvironment project.worldProgram
    environment
  checkedInput := checkedNativeProgramInputWithResponseEnvironment
    project.checkedInput environment
  bundleManifest := project.bundleManifest
  rendererInputArtifact := project.rendererInputArtifact
  sourceArtifacts := project.sourceArtifacts
  nixIdentity := project.nixIdentity
}

theorem nativeSourceProjectValidWithResponseEnvironment
    {project : NativeSourceProject}
    (environment : SourceWorldResponseEnvironment)
    (valid : project.Valid) :
    (nativeSourceProjectWithResponseEnvironment project environment).Valid := by
  simpa [NativeSourceProject.Valid, nativeSourceProjectWithResponseEnvironment,
    checkedNativeProgramInputWithResponseEnvironment,
    decodedWorldProgramWithResponseEnvironment,
    CanonicalNativeProgramIR.x87SourceRvas] using valid

/-- Retarget both source response functions and the ordinary native action
without changing source, PE, import, relocation, or Nix authority. -/
def exactNativeCompilationAtResponseEnvironments
    (compilation : ExactNativeCompilation)
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldEnvironment) : ExactNativeCompilation := {
  profile := compilation.profile
  project := nativeSourceProjectWithResponseEnvironment compilation.project
    sourceEnvironment
  artifact := compilation.artifact
  machineAuthority := exactCompiledPE32AuthorityWithEnvironment
    compilation.machineAuthority nativeEnvironment
  projectValid := nativeSourceProjectValidWithResponseEnvironment
    sourceEnvironment compilation.projectValid
  profilePinned := compilation.profilePinned
  profileMatches := compilation.profileMatches
  builtFrom := {
    buildIdentityValid := compilation.builtFrom.buildIdentityValid
    sourceProjectExact := compilation.builtFrom.sourceProjectExact
    toolchainExact := compilation.builtFrom.toolchainExact
  }
}

/-- Native environment data for the callback-capable carrier.  The ordinary
action remains separate from the subsequent protocol phases. -/
structure NativeWorldResponseEnvironment where
  ordinary : NativeWorldEnvironment
  callbackTargetRvas : List Nat
  protocolAction : NativeWorldExternalRequest -> NativeWorldExternalAction

def NativeWorldResponseEnvironment.nestedProgram
    (environment : NativeWorldResponseEnvironment)
    (candidate : ExactNativeWorldProgram) : ExactNestedNativeWorldProgram := {
  candidate with
  callbackTargetRvas := environment.callbackTargetRvas
  protocolAction := environment.protocolAction
}

/-- The callback target relation may only relate checked original target IDs
to executable candidate RVAs admitted by the nested carrier. -/
def CheckedNestedCallbackTargetRelation
    (context : StaticProofContext) (candidate : ExactNestedNativeWorldProgram)
    (relation : Nat -> Nat -> Prop) : Prop :=
  forall targetId candidateRva,
    relation targetId candidateRva ->
      exists target,
        context.codeMap.get? targetId = some target /\
          (candidateRva = target.candidateRva \/
            exists alias, alias ∈ target.candidateAliases /\
              candidateRva = alias.rva) /\
          nestedNativeCallbackTargetAllowed candidate candidateRva = true

/-- Pointed-to read bytes for a protocol boundary. -/
def MachineProtocolReadFootprintsRelated
    (context : StaticProofContext) (contract : MachineImportCallContract)
    (original : WorldExternalEvent)
    (candidate : WorldExternalEvent) : Prop :=
  forall footprint, footprint ∈ contract.memoryFootprints ->
    footprint.access = .read ->
      MachineCallReadFootprintRelated context original.world footprint original
        candidate

/-- A later callback action must select a callback previously registered in
the shared relational world.  This is independent of the API that initiated
registration or protocol execution. -/
def RegisteredNestedCallbackActionsRelated
    (context : StaticProofContext) (candidate : ExactNestedNativeWorldProgram)
    (suspension : WorldExternalSuspension) :
    WorldExternalProtocolAction -> NativeWorldExternalAction -> Prop
  | .callback originalEntry, .callback candidateEntry =>
      exists callback,
        callback ∈ suspension.world.registeredCallbacks /\
          callback.valid context = true /\
          originalEntry.targetId = callback.targetId /\
          candidateEntry.targetRva + candidate.pe.imageBase =
            callback.candidateAddress.toNat /\
          nestedNativeCallbackTargetAllowed candidate candidateEntry.targetRva = true
  | .returned _, .returned _ => True
  | .terminated _, .terminated _ => True
  | _, _ => False

/-- Concrete result of a checked callback-registration call.  The relational
world stores one pair, while each side's machine argument supplies its own
concrete callback address. -/
def WorldNativeRegistrationResult
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (site : OpaqueLockstepCallSite) (argumentIndex eventIndex : Nat)
    (sourceEnvironment : WorldExternalEnvironment)
    (nativeEnvironment : NativeWorldEnvironment)
    (originalEvent : WorldExternalEvent)
    (candidateEvent : StageA.Relational.InterpreterKernel.NativeExternalEvent) :
    Prop :=
  exists candidateResult callback originalAddress candidateAddress,
    nativeEnvironment.action eventIndex candidateEvent originalEvent.world =
        .returned candidateResult /\
      OpaqueWorldNativeABIResultRelated context program site originalEvent
        candidateEvent (sourceEnvironment.result eventIndex originalEvent)
        candidateResult /\
      (sourceEnvironment.result eventIndex originalEvent).world =
        candidateResult.world /\
      originalEvent.arguments[argumentIndex]? = some originalAddress /\
      candidateEvent.arguments[argumentIndex]? = some candidateAddress /\
      callback ∈ candidateResult.world.registeredCallbacks /\
      callback.originalAddress = originalAddress /\
      callback.candidateAddress = candidateAddress /\
      callback.valid context = true

/-- ABI, memory/world effect, result-value, and continuation `StateRel` for a
protocol action that eventually returns.  Callback and termination cases are
checked by their dedicated relations. -/
def WorldNativeProtocolContinuationRelated
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (suspension : WorldExternalSuspension)
    (boundary : ExactNestedNativeExternalProtocolBoundary candidate) : Prop :=
  match program.protocolEnvironment.action suspension.request,
      boundary.action with
  | .returned originalResult, .returned candidateResult =>
      exists contract,
        CheckedOriginalMachineProtocolBoundary program suspension contract /\
          machineCallResultConforms false context
            (protocolReturnContract contract) suspension.currentEvent
              originalResult /\
          machineCallResultConforms true context
            (protocolReturnContract contract)
            (boundary.suspension.currentWorldEvent suspension.siteId)
              candidateResult /\
          originalResult.world = candidateResult.world /\
          machineCallResultRegistersRelated context originalResult.world
            (protocolReturnContract contract) suspension.arguments
            originalResult.state candidateResult.state = true /\
          StateRel context originalResult.world suspension.site.targetInvariant
            originalResult.state candidateResult.state
  | .callback _, .callback _ => True
  | .terminated originalWorld, .terminated candidateWorld =>
      originalWorld = candidateWorld
  | _, _ => False

/-- Complete external-response evidence for the combined ordinary and nested
site partition.  `nestedRefines` quantifies over every admitted reachable
suspension and recursive callback-frame stack, so callbacks may nest and must
return to the exact next protocol phase. -/
structure CheckedWorldNativeProtocolResponseSchedule
    (context : StaticProofContext) (program : DecodedWorldProgram)
    (candidate : ExactNestedNativeWorldProgram)
    (classified : List CheckedMachineExternalSite)
    (ordinarySites : List OpaqueLockstepCallSite)
    (sourceEnvironment : WorldExternalEnvironment)
    (mixed : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract) where
  contextValid : context.StructurallyValid
  classificationChecked : exists
      (signatures : List StaticMachineImportSignature)
      (boundaries : List StaticMachineImportBoundary)
      (authority : CheckedMachineExternalSiteInventory context.originalPe
        context.originalImports signatures boundaries),
      authority.sites = classified
  completeCoverage : machineExternalSitesCoverProgram context program classified
    ordinarySites = true
  ordinaryUnique : opaqueLockstepCallSiteIdsUnique ordinarySites = true
  ordinaryValid : ordinarySites.all
    (OpaqueLockstepCallSite.staticValid context) = true
  originalContext : OriginalDecodedStaticContext
  sourceInventory : OriginalCombinedExecutionInventory program originalContext
  ordinaryResponses : forall site, site ∈ ordinarySites ->
    CheckedWorldNativeResponseAt context program site sourceEnvironment
      candidate.environment
  ordinaryBoundaryDomain :
    CheckedOriginalCombinedReachableBoundaryDomain context program
      originalContext sourceInventory ordinarySites
  ordinaryDomainsExact : forall site (member : site ∈ ordinarySites),
    (ordinaryResponses site member).boundaryDomain =
      ordinaryBoundaryDomain.domain site member
  protocolBoundaryDomain :
    CheckedReachableWorldNativeProtocolBoundaryDomain context program candidate
      mixed frames originalContext sourceInventory
  sourceAwaitingExternalResponses :
    CheckedOriginalCombinedMachineProtocolResponses program originalContext
      sourceInventory
  registrationResponses : forall classifiedSite,
    classifiedSite ∈ classified -> forall argumentIndex,
      classifiedSite.mode.registrationArgument? = some argumentIndex ->
      forall site (member : site ∈ ordinarySites),
        site.id = classifiedSite.boundaryId ->
        forall request,
          (ordinaryResponses site member).boundaryDomain.Admits
            request ->
          WorldNativeRegistrationResult context program site argumentIndex
            request.eventIndex sourceEnvironment candidate.environment
            request.originalEvent request.candidateEvent
  worldsExact : forall originalWorld candidateWorld,
    mixed.worldsRelated originalWorld candidateWorld ->
      originalWorld = candidateWorld
  callbackTargetsChecked : CheckedNestedCallbackTargetRelation context candidate
    mixed.callbackTargetsRelated
  nestedRefines : forall request,
    protocolBoundaryDomain.Admits request ->
      MixedNestedExternalEnvironmentActionsRelated candidate mixed frames
        (program.protocolEnvironment.action request.suspension.request)
        request.boundary.action
  protocolBoundaries : forall request,
    protocolBoundaryDomain.Admits request ->
      exists contract,
        CheckedOriginalMachineProtocolBoundary program request.suspension contract
  protocolReadFootprints : forall request,
    protocolBoundaryDomain.Admits request ->
      exists contract,
        CheckedOriginalMachineProtocolBoundary program request.suspension contract /\
          MachineProtocolReadFootprintsRelated context contract
            request.suspension.currentEvent
            (request.boundary.suspension.currentWorldEvent
              request.suspension.siteId)
  protocolContinuations : forall request,
    protocolBoundaryDomain.Admits request ->
      WorldNativeProtocolContinuationRelated context program candidate
        request.suspension request.boundary
  callbacksRegistered : forall request,
    protocolBoundaryDomain.Admits request ->
      RegisteredNestedCallbackActionsRelated context candidate
        request.suspension
        (program.protocolEnvironment.action request.suspension.request)
        request.boundary.action

/-- Registration sites are ordinary returning sites, but this projection makes
their machine-level callback world effect explicit to downstream consumers. -/
def CheckedWorldNativeProtocolResponseSchedule.registrationResponse
    {context : StaticProofContext} {program : DecodedWorldProgram}
    {candidate : ExactNestedNativeWorldProgram}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {sourceEnvironment : WorldExternalEnvironment}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (schedule : CheckedWorldNativeProtocolResponseSchedule context program
      candidate classified ordinarySites sourceEnvironment mixed frames)
    (classifiedSite : CheckedMachineExternalSite)
    (classifiedMember : classifiedSite ∈ classified)
    (argumentIndex : Nat)
    (registration : classifiedSite.mode.registrationArgument? =
      some argumentIndex)
    (site : OpaqueLockstepCallSite) (siteMember : site ∈ ordinarySites)
    (siteId : site.id = classifiedSite.boundaryId)
    (request : WorldNativeBoundaryRequest)
    (admitted : (schedule.ordinaryResponses site siteMember).boundaryDomain.Admits
      request) :
    WorldNativeRegistrationResult context program site argumentIndex
      request.eventIndex sourceEnvironment candidate.environment
      request.originalEvent request.candidateEvent :=
  schedule.registrationResponses classifiedSite classifiedMember argumentIndex
    registration site siteMember siteId request admitted

/-- Checked data admitting one combined response pair.  The public relation is
`Nonempty` evidence for this certificate, so it includes every environment pair
that can supply the checked reachable-domain schedule. -/
structure AdmittedWorldNativeProtocolResponsePair
    (context : StaticProofContext)
    (classified : List CheckedMachineExternalSite)
    (ordinarySites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (mixed : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract)
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldResponseEnvironment) where
  responseSchedule : CheckedWorldNativeProtocolResponseSchedule context
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).project.worldProgram
    (nativeEnvironment.nestedProgram
      (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
        nativeEnvironment.ordinary).machineAuthority.program)
    classified ordinarySites sourceEnvironment.ordinary mixed frames
  sourceFamily : CheckedNativeSourceLaunchFamily
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).project
  launchRealizable : NativeCompilationLaunchRealizable
    (exactNativeCompilationAtResponseEnvironments compilation sourceEnvironment
      nativeEnvironment.ordinary).machineAuthority

/-- Environment-independent coverage for the admitted response relation.  No
response theorem or canonical schedule is stored here: those are behavioral
facts and must be supplied by a separately checked completion. -/
structure CheckedWorldNativeAdmittedProtocolResponseFamily
    (context : StaticProofContext)
    (classified : List CheckedMachineExternalSite)
    (ordinarySites : List OpaqueLockstepCallSite)
    (compilation : ExactNativeCompilation)
    (mixed : MixedRelationContract)
    (frames : MixedNestedExternalFrameContract) : Prop where
  classificationChecked : exists
      (signatures : List StaticMachineImportSignature)
      (boundaries : List StaticMachineImportBoundary)
      (authority : CheckedMachineExternalSiteInventory context.originalPe
        context.originalImports signatures boundaries),
      authority.sites = classified
  completeCoverage : machineExternalSitesCoverProgram context
    compilation.project.worldProgram classified ordinarySites = true
  ordinaryUnique : opaqueLockstepCallSiteIdsUnique ordinarySites = true
  ordinaryValid : ordinarySites.all
    (OpaqueLockstepCallSite.staticValid context) = true

def CheckedWorldNativeAdmittedProtocolResponseFamily.Related
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (_family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames)
    (sourceEnvironment : SourceWorldResponseEnvironment)
    (nativeEnvironment : NativeWorldResponseEnvironment) : Prop :=
  Nonempty (AdmittedWorldNativeProtocolResponsePair context classified
    ordinarySites compilation mixed frames sourceEnvironment nativeEnvironment)

/-- Constructive nonvacuity is intentionally separate from static coverage.
An inhabitant must contain the complete machine-level response schedule; a
generated site inventory alone cannot manufacture one. -/
structure CheckedWorldNativeAdmittedProtocolResponseFamily.Completion
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    (family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames) where
  canonicalSourceEnvironment : SourceWorldResponseEnvironment
  canonicalNativeEnvironment : NativeWorldResponseEnvironment
  canonical : family.Related canonicalSourceEnvironment
    canonicalNativeEnvironment

theorem CheckedWorldNativeAdmittedProtocolResponseFamily.Completion.realizable
    {context : StaticProofContext}
    {classified : List CheckedMachineExternalSite}
    {ordinarySites : List OpaqueLockstepCallSite}
    {compilation : ExactNativeCompilation}
    {mixed : MixedRelationContract}
    {frames : MixedNestedExternalFrameContract}
    {family : CheckedWorldNativeAdmittedProtocolResponseFamily context classified
      ordinarySites compilation mixed frames}
    (completion : family.Completion) :
    exists sourceEnvironment nativeEnvironment,
      family.Related sourceEnvironment nativeEnvironment := by
  exact ⟨completion.canonicalSourceEnvironment,
    completion.canonicalNativeEnvironment, completion.canonical⟩

end StageA.Relational.NativeSource
