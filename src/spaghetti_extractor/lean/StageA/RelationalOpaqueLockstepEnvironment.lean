import StageA.RelationalEnvironment

namespace StageA.Relational

open StageA.Formal

/-- A machine-level argument source.  This is deliberately below C prototype
recovery: an argument is either a concrete register value or a word read from
the call-boundary stack. -/
inductive OpaqueArgumentSource where
  | register (register : Reg)
  | stackWord (offset : Nat)
  | constant (value : Word)
deriving Repr, DecidableEq

def OpaqueArgumentSource.shapeValid : OpaqueArgumentSource -> Bool
  | OpaqueArgumentSource.register _ => true
  | OpaqueArgumentSource.stackWord offset => offset < 2^32
  | OpaqueArgumentSource.constant _ => true

def OpaqueArgumentSource.eval (source : OpaqueArgumentSource)
    (state : MachineState) : Word :=
  match source with
  | OpaqueArgumentSource.register reg => state.registers.get reg
  | OpaqueArgumentSource.stackWord offset =>
      state.read32 (state.registers.esp + BitVec.ofNat 32 offset)
  | OpaqueArgumentSource.constant value => value

/-- Original and candidate argument locations may differ while denoting the
same event argument. -/
structure OpaqueArgumentSourcePair where
  original : OpaqueArgumentSource
  candidate : OpaqueArgumentSource
deriving Repr, DecidableEq

def OpaqueArgumentSourcePair.shapeValid
    (source : OpaqueArgumentSourcePair) : Bool :=
  source.original.shapeValid && source.candidate.shapeValid

inductive OpaqueMemoryArgumentRelation where
  | exactBytes
  | relatedWords
deriving Repr, DecidableEq

/-- Whether an exact lockstep event resumes in the binary or transfers control
permanently to a terminating external implementation.  Protocol/callback
events use the separate protocol environment until their nested-frame contract
is connected to this profile. -/
inductive OpaqueLockstepDisposition where
  | returns
  | terminates
deriving Repr, DecidableEq

def opaqueLockstepDispositionsMatch
    (opaqueDisposition : OpaqueLockstepDisposition)
    (machine : MachineCallDisposition) : Bool :=
  match opaqueDisposition, machine with
  | .returns, .returns => true
  | .terminates, .terminates => true
  | _, _ => false

theorem opaqueLockstepDispositionsMatch_returns
    (opaqueDisposition : OpaqueLockstepDisposition)
    (machine : MachineCallDisposition)
    (matched : opaqueLockstepDispositionsMatch opaqueDisposition machine = true)
    (returns : machine = .returns) : opaqueDisposition = .returns := by
  cases opaqueDisposition <;> cases machine <;>
    simp_all [opaqueLockstepDispositionsMatch]

theorem opaqueLockstepDispositionsMatch_terminates
    (opaqueDisposition : OpaqueLockstepDisposition)
    (machine : MachineCallDisposition)
    (matched : opaqueLockstepDispositionsMatch opaqueDisposition machine = true)
    (terminates : machine = .terminates) : opaqueDisposition = .terminates := by
  cases opaqueDisposition <;> cases machine <;>
    simp_all [opaqueLockstepDispositionsMatch]

/-- A checked observation through one pointer-valued event argument.  Mixed
structures are represented by several observations, allowing exact byte spans
and address-related word spans to coexist without an API-specific type model. -/
structure OpaqueMemoryArgumentObservation where
  argumentIndex : Nat
  originalOffset : Nat
  candidateOffset : Nat
  bytes : Nat
  relation : OpaqueMemoryArgumentRelation
deriving Repr, DecidableEq

def OpaqueMemoryArgumentObservation.shapeValid (argumentCount : Nat)
    (observation : OpaqueMemoryArgumentObservation) : Bool :=
  observation.argumentIndex < argumentCount &&
    observation.originalOffset < 2^32 &&
    observation.candidateOffset < 2^32 &&
    0 < observation.bytes && observation.bytes < 2^32 &&
    match observation.relation with
    | .exactBytes => true
    | .relatedWords => observation.bytes % 4 == 0

def opaqueExactBytesRelated (original candidate : Memory)
    (originalAddress candidateAddress : Word) (bytes : Nat) : Bool :=
  (List.range bytes).all fun offset =>
    original (originalAddress + BitVec.ofNat 32 offset) ==
      candidate (candidateAddress + BitVec.ofNat 32 offset)

def opaqueRelatedWords (context : StaticProofContext) (world : RelationalWorld)
    (original candidate : Memory) (originalAddress candidateAddress : Word)
    (bytes : Nat) : Bool :=
  (List.range (bytes / 4)).all fun index =>
    wordRelated context.originalPe.imageBase context.candidatePe.imageBase
      context.codeMap.entries.toList (context.relationalValueTargets world)
      (Memory.read32 original
        (originalAddress + BitVec.ofNat 32 (index * 4)))
      (Memory.read32 candidate
        (candidateAddress + BitVec.ofNat 32 (index * 4)))

def OpaqueMemoryArgumentObservation.holds (context : StaticProofContext)
    (world : RelationalWorld) (observation : OpaqueMemoryArgumentObservation)
    (original candidate : WorldExternalEvent) : Bool :=
  match original.arguments[observation.argumentIndex]?,
      candidate.arguments[observation.argumentIndex]? with
  | some originalBase, some candidateBase =>
      let originalAddress :=
        originalBase + BitVec.ofNat 32 observation.originalOffset
      let candidateAddress :=
        candidateBase + BitVec.ofNat 32 observation.candidateOffset
      match observation.relation with
      | .exactBytes => opaqueExactBytesRelated original.state.memory
          candidate.state.memory originalAddress candidateAddress observation.bytes
      | .relatedWords => opaqueRelatedWords context world original.state.memory
          candidate.state.memory originalAddress candidateAddress observation.bytes
  | _, _ => false

/-- Prototype-free external call site.  Import RVAs bind the normalized call
identity to both parsed PE import tables.  Argument locations and pointed-to
memory observations are explicit machine evidence, not inferred C types. -/
structure OpaqueLockstepCallSite where
  id : Nat
  sourceTargetId : Nat
  continuationTargetId : Nat
  disposition : OpaqueLockstepDisposition
  imported : ExternalTarget
  originalIatRva : Nat
  candidateIatRva : Nat
  argumentSources : List OpaqueArgumentSourcePair
  memoryObservations : List OpaqueMemoryArgumentObservation
  boundaryInvariant : StateInvariant
  targetInvariant : StateInvariant
deriving Repr, DecidableEq

def OpaqueLockstepCallSite.importIdentityValid (context : StaticProofContext)
    (site : OpaqueLockstepCallSite) : Bool :=
  match importAtIatRva context.originalImports site.originalIatRva,
      importAtIatRva context.candidateImports site.candidateIatRva with
  | some originalImport, some candidateImport =>
      normalizeImport originalImport == site.imported &&
        normalizeImport candidateImport == site.imported
  | _, _ => false

def OpaqueLockstepCallSite.shapeValid (site : OpaqueLockstepCallSite) : Bool :=
  site.originalIatRva < 2^32 && site.candidateIatRva < 2^32 &&
    site.argumentSources.all OpaqueArgumentSourcePair.shapeValid &&
    site.memoryObservations.all
      (OpaqueMemoryArgumentObservation.shapeValid site.argumentSources.length)

def OpaqueLockstepCallSite.staticValid (context : StaticProofContext)
    (site : OpaqueLockstepCallSite) : Bool :=
  (context.codeMap.get? site.sourceTargetId).isSome &&
    (context.codeMap.get? site.continuationTargetId).isSome &&
    site.shapeValid && site.importIdentityValid context

/-- Bind an opaque call-site contract to the existing decoded-world execution
site.  The latter still selects the operational machine-call transition; this
predicate prevents acceptance evidence from changing its source, continuation,
import identity, or relational invariants. -/
def OpaqueLockstepCallSite.matchesExternalCallSite
    (context : StaticProofContext) (opaqueSite : OpaqueLockstepCallSite)
    (site : ExternalCallSiteContract) : Bool :=
  opaqueSite.id == site.id &&
    opaqueSite.sourceTargetId == site.sourceTargetId &&
    opaqueSite.continuationTargetId == site.continuationTargetId &&
    opaqueSite.boundaryInvariant == site.boundaryInvariant &&
    opaqueSite.targetInvariant == site.targetInvariant &&
    match machineImportCallContractById? context site.machineContractId with
    | some contract =>
        contract.imported == opaqueSite.imported &&
          opaqueLockstepDispositionsMatch opaqueSite.disposition
            contract.disposition
    | none => false

/-- Exact one-to-one coverage in both directions.  In particular, an
ambiguous or unmatched returning/terminating execution site cannot be hidden
by omitting it from the opaque inventory. -/
def opaqueLockstepCallSitesCoverExternalSites
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (opaqueSites : List OpaqueLockstepCallSite) : Bool :=
  (sites.all fun site =>
      (opaqueSites.filter fun opaqueSite =>
        opaqueSite.matchesExternalCallSite context site).length == 1) &&
    (opaqueSites.all fun opaqueSite =>
      (sites.filter fun site =>
        opaqueSite.matchesExternalCallSite context site).length == 1)

/-- Coverage restricted to returning, tail, and terminating external sites
reached by the checked product graph.  The generated running-node proofs use
the same IDs; unreachable execution sites need not be promoted to roots. -/
def opaqueLockstepCallSitesCoverExternalSiteIds
    (context : StaticProofContext) (sites : List ExternalCallSiteContract)
    (opaqueSites : List OpaqueLockstepCallSite) (requiredSiteIds : List Nat) : Bool :=
  (requiredSiteIds.all fun id =>
      (requiredSiteIds.filter (· == id)).length == 1 &&
        (sites.filter fun site => site.id == id).length == 1 &&
        (opaqueSites.filter fun opaqueSite => opaqueSite.id == id).length == 1 &&
        match sites.find? (fun site => site.id == id),
            opaqueSites.find? (fun opaqueSite => opaqueSite.id == id) with
        | some site, some opaqueSite =>
            opaqueSite.matchesExternalCallSite context site
        | _, _ => false) &&
    (opaqueSites.all fun opaqueSite => requiredSiteIds.contains opaqueSite.id)

def opaqueLockstepCallSiteIdsUnique
    (sites : List OpaqueLockstepCallSite) : Bool :=
  sites.all fun site =>
    (sites.filter fun other => other.id == site.id).length == 1

def OpaqueCallArgumentsExtracted (site : OpaqueLockstepCallSite)
    (original candidate : WorldExternalEvent) : Prop :=
  original.arguments = site.argumentSources.map
      (fun source => source.original.eval original.state) ∧
    candidate.arguments = site.argumentSources.map
      (fun source => source.candidate.eval candidate.state)

def OpaqueCallMemoryObservationsHold (context : StaticProofContext)
    (world : RelationalWorld) (site : OpaqueLockstepCallSite)
    (original candidate : WorldExternalEvent) : Prop :=
  site.memoryObservations.all
    (fun observation => observation.holds context world original candidate) = true

/-- The complete machine-level boundary used by the opaque exact-lockstep
profile.  `StateRel` covers registers, flags, x87, concrete flat memory,
relational ranges, imports, TLS, and undefined values; the remaining clauses
anchor the event identity and the exact ABI observations supplied to the
external environment. -/
def OpaqueLockstepBoundaryRelated (context : StaticProofContext)
    (site : OpaqueLockstepCallSite)
    (original candidate : WorldExternalEvent) : Prop :=
  site.staticValid context = true ∧
    original.siteId = site.id ∧ candidate.siteId = site.id ∧
    original.world = candidate.world ∧
    original.imported = site.imported ∧ candidate.imported = site.imported ∧
    StateRel context original.world site.boundaryInvariant
      original.state candidate.state ∧
    OpaqueCallArgumentsExtracted site original candidate ∧
    externalCallArgumentsRelated context original.world
      original.arguments candidate.arguments = true ∧
    OpaqueCallMemoryObservationsHold context original.world site
      original candidate

def OpaqueLockstepResultRelated (context : StaticProofContext)
    (site : OpaqueLockstepCallSite)
    (originalEvent candidateEvent : WorldExternalEvent)
    (originalResult candidateResult : WorldExternalResult) : Prop :=
  originalResult.world = candidateResult.world ∧
    StateRel context originalResult.world site.targetInvariant
      originalResult.state candidateResult.state ∧
    ExternalRuntimeFramesPreserved originalEvent candidateEvent
      originalResult candidateResult

/-- Pointwise paired-environment assumption.  Supplying the same `eventIndex`
to both sides makes event order exact; batching, omission, reordering, and API
substitution cannot satisfy this relation.  No API behavior or C prototype is
defined in the proof core. -/
def OpaqueLockstepEnvironmentRefinesAt (context : StaticProofContext)
    (site : OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment) : Prop :=
  ∀ eventIndex originalEvent candidateEvent,
    OpaqueLockstepBoundaryRelated context site originalEvent candidateEvent ->
      OpaqueLockstepResultRelated context site originalEvent candidateEvent
        (original.result eventIndex originalEvent)
        (candidate.result eventIndex candidateEvent)

def OpaqueLockstepEnvironmentsRefine (context : StaticProofContext)
    (sites : List OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment) : Prop :=
  opaqueLockstepCallSiteIdsUnique sites = true ∧
    sites.all (OpaqueLockstepCallSite.staticValid context) = true ∧
    ∀ site, site ∈ sites ->
      site.disposition = .returns ->
        OpaqueLockstepEnvironmentRefinesAt context site original candidate

theorem OpaqueLockstepEnvironmentsRefine.at
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment)
    (refines : OpaqueLockstepEnvironmentsRefine context sites original candidate)
    (site : OpaqueLockstepCallSite) (member : site ∈ sites)
    (returns : site.disposition = .returns) :
    OpaqueLockstepEnvironmentRefinesAt context site original candidate :=
  refines.2.2 site member returns

/-- A non-returning external transition still consumes the next shared event
index and must establish the complete opaque boundary.  It has no successor
result or continuation state to relate. -/
def OpaqueLockstepTerminalEventRelated (context : StaticProofContext)
    (site : OpaqueLockstepCallSite) (_eventIndex : Nat)
    (original candidate : WorldExternalEvent) : Prop :=
  site.disposition = .terminates ∧
    OpaqueLockstepBoundaryRelated context site original candidate

/-- Acceptance integration API.  This package contains only checked static
call-site data and the paired-environment theorem assumption.  It cannot by
itself authorize whole-program acceptance. -/
structure CheckedOpaqueLockstepEnvironment
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment) : Prop where
  contextValid : context.StructurallyValid
  refines : OpaqueLockstepEnvironmentsRefine context sites original candidate

theorem CheckedOpaqueLockstepEnvironment.at
    (context : StaticProofContext) (sites : List OpaqueLockstepCallSite)
    (original candidate : WorldExternalEnvironment)
    (checked : CheckedOpaqueLockstepEnvironment context sites original candidate)
    (site : OpaqueLockstepCallSite) (member : site ∈ sites)
    (returns : site.disposition = .returns) :
    OpaqueLockstepEnvironmentRefinesAt context site original candidate :=
  checked.refines.at context sites original candidate site member returns

end StageA.Relational
