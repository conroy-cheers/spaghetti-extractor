import StageA.RelationalCertificates
import StageA.RelationalInterpreterNormalization
import StageA.RelationalInterpreterX87
import StageA.RelationalInterpreterKernel
import StageA.RelationalInterpreterKernelData
import StageA.RelationalOpaqueLockstepEnvironment

namespace StageA.Relational.InterpreterAcceptance

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterNormalization
open StageA.Relational.InterpreterX87
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelData

/-! # Round-trip interpreter acceptance

This module is the small trusted assembly boundary for a Stage B interpreter
candidate.  Extraction tools may propose every value below, but only proofs of
the typed propositions can construct an acceptance certificate.

The final field is deliberately a chunked simulation over the exact decoded PE
transition systems.  The component packages record how that simulation was
obtained and keep its proof dependencies explicit; none of them is a Boolean
completion claim and none can replace the chunked simulation. -/

/-- One ordinary original transfer, independently executed from exact decoded
PE instructions and proved equal to the typed semantic transfer. -/
structure ExactOriginalTransferRefinement (context : StaticProofContext) where
  path : ExactNormalizedTransferPath
  transfer : SemanticTransfer
  certificate : ExactProgramRecordNormalizationCertificate context.originalPe
    path transfer

def ExactOriginalTransferRefinementAt (context : StaticProofContext)
    (sourceRva : Nat) : Prop :=
  exists refinement : ExactOriginalTransferRefinement context,
    refinement.path.sourceRva = sourceRva

/-- Reachable ordinary transfer coverage.  Both directions are retained:
`complete` prevents omitted required transfers and `exact` prevents unrelated
certificates from being counted as coverage. -/
structure ExactOriginalTransferInventory (context : StaticProofContext) where
  requiredSourceRvas : List Nat
  certifiedSourceRvas : List Nat
  requiredUnique : requiredSourceRvas.Nodup
  certifiedUnique : certifiedSourceRvas.Nodup
  complete : forall sourceRva, sourceRva ∈ requiredSourceRvas ->
    sourceRva ∈ certifiedSourceRvas
  exact : forall sourceRva, sourceRva ∈ certifiedSourceRvas ->
    sourceRva ∈ requiredSourceRvas
  refined : forall sourceRva, sourceRva ∈ certifiedSourceRvas ->
    ExactOriginalTransferRefinementAt context sourceRva

theorem ExactOriginalTransferInventory.refinementAt
    {context : StaticProofContext}
    (inventory : ExactOriginalTransferInventory context) (sourceRva : Nat)
    (required : sourceRva ∈ inventory.requiredSourceRvas) :
    ExactOriginalTransferRefinementAt context sourceRva :=
  inventory.refined sourceRva (inventory.complete sourceRva required)

/-- Exact mixed ordinary/x87 schedules required by the original transfer
inventory.  The schedule certificate decodes from the original PE and proves
the authoritative and interpreter executions equal. -/
structure ExactOriginalX87Inventory (context : StaticProofContext) where
  requiredSourceRvas : List Nat
  witnesses : List (ExactInterpreterX87ScheduleWitness context.originalPe)
  requiredUnique : requiredSourceRvas.Nodup
  witnessSourcesUnique :
    (witnesses.map fun witness => witness.schedule.sourceRva).Nodup
  complete : forall sourceRva, sourceRva ∈ requiredSourceRvas ->
    exists witness, witness ∈ witnesses ∧ witness.schedule.sourceRva = sourceRva
  exact : forall witness, witness ∈ witnesses ->
    witness.schedule.sourceRva ∈ requiredSourceRvas

theorem ExactOriginalX87Inventory.witnessAt
    {context : StaticProofContext}
    (inventory : ExactOriginalX87Inventory context) (sourceRva : Nat)
    (required : sourceRva ∈ inventory.requiredSourceRvas) :
    exists witness, witness ∈ inventory.witnesses ∧
      witness.schedule.sourceRva = sourceRva :=
  inventory.complete sourceRva required

/-- The semantic program is decoded from immutable candidate PE data and its
relocation inventory, not accepted from the Stage B JSON artifact. -/
structure ExactCompiledProgramTable (context : StaticProofContext) where
  relocations : List BaseRelocation
  tableRva : Nat
  countRva : Nat
  semanticRecords : List ProgramRecord
  certificate : ProgramTableCertificate context.candidatePe
    context.candidateImports relocations tableRva countRva semanticRecords

/-- The four native interpreter entry points refine their authoritative
abstract operations for every request.  The table is a parameter so later
composition cannot accidentally substitute a different semantic program. -/
structure ExactCompiledInterpreterKernel (context : StaticProofContext)
    (table : ExactCompiledProgramTable context) where
  binding : KernelArtifactBinding
  program : CompiledKernelProgram
  nativeEnvironment : NativeEnvironment
  abi : KernelABIRelation
  certificate : CompiledKernelRefinement binding program context.candidatePe
    context.candidateImports nativeEnvironment abi
  semanticProgram : List ProgramRecord
  semanticProgramBound : semanticProgram = table.semanticRecords

def ExactCompiledProgramRecordAt {context : StaticProofContext}
    (table : ExactCompiledProgramTable context) (sourceRva : Nat) : Prop :=
  exists record, record ∈ table.semanticRecords ∧ record.sourceRva = sourceRva

/-- The original ordinary and x87 inventories form an exact, disjoint
partition of the immutable candidate program table.  This prevents an
acceptance package from carrying complete-looking but unrelated inventories. -/
structure ExactRoundTripProgramCoverage (context : StaticProofContext)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context) : Prop where
  tableCovered : forall record, record ∈ programTable.semanticRecords ->
    record.sourceRva ∈ originalTransfers.requiredSourceRvas ∨
      record.sourceRva ∈ originalX87.requiredSourceRvas
  ordinaryPresent : forall sourceRva,
    sourceRva ∈ originalTransfers.requiredSourceRvas ->
      ExactCompiledProgramRecordAt programTable sourceRva
  x87Present : forall sourceRva, sourceRva ∈ originalX87.requiredSourceRvas ->
    ExactCompiledProgramRecordAt programTable sourceRva
  disjoint : forall sourceRva,
    sourceRva ∈ originalTransfers.requiredSourceRvas ->
      sourceRva ∉ originalX87.requiredSourceRvas

/-- The opaque environment inventory covers the operational external sites on
both exact decoded programs.  Omitting a call site therefore cannot make its
environment obligation disappear. -/
structure ExactOpaqueProgramCoverage (context : StaticProofContext)
    (original candidate : DecodedWorldProgram)
    (opaqueSites : List OpaqueLockstepCallSite) : Prop where
  originalCovered : opaqueLockstepCallSitesCoverExternalSites context
    original.externalCallSites opaqueSites = true
  candidateCovered : opaqueLockstepCallSitesCoverExternalSites context
    candidate.externalCallSites opaqueSites = true

/-- Bind the two operational transition systems to the same exact static
context and to their intended original/candidate roles and environments. -/
structure ExactRoundTripProgramBinding (context : StaticProofContext)
    (original candidate : DecodedWorldProgram)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment) : Prop where
  originalContext : original.context = context
  candidateContext : candidate.context = context
  originalRole : original.candidate = false
  candidateRole : candidate.candidate = true
  originalEnvironment : original.environment = originalEnvironment
  candidateEnvironment : candidate.environment = candidateEnvironment

/-- The decoded programs used by the final theorem are the complete,
graph-backed views of the exact PE images.  This closes the gap between merely
binding a program's role/context fields and proving that its region inventory
is the one covered by the static image and reachable product graph. -/
structure ExactRoundTripDecodedProgramSurface (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile)
    (original candidate : DecodedWorldProgram) where
  imageBundle : ProofBundle
  regionsSame : original.regions = candidate.regions
  externalSitesSame : original.externalCallSites = candidate.externalCallSites
  imagesCovered : imageBundle.CoversStaticContext context original.regions
  regionsUseCanonicalContext : RegionsUseStaticContext context original.regions
  regionsMatchGraph : RegionsMatchProductGraph context graph original.regions
  graphValid : graph.IndexedValid context
  reachabilityClosed : reachability.SoundlyClosed context graph
  invariantsValid : invariants.Valid graph
  controlChecked : control.checked = true
  originalInstructionSemantics : original.InstructionSemanticsAdequate
  candidateInstructionSemantics : candidate.InstructionSemanticsAdequate

/-- Launch evidence includes the PE entry root, every declared TLS callback in
image order, and a concrete inhabitant of the launch relation. -/
structure CheckedRoundTripLaunch (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2) where
  valid : launch.Valid context graph invariants
  realizable : launch.Realizable context graph reachability

/-- A generated launch binding must connect target identifiers back to the
exact original RVAs decoded from the PE.  This relation is deliberately stated
over the canonical code map; function names and linker-map labels are not part
of the trusted launch boundary. -/
def TargetIdsMatchOriginalRvas (context : StaticProofContext) :
    List Nat -> List Nat -> Prop
  | [], [] => True
  | targetId :: targetIds, rva :: rvas =>
      (exists target, context.codeMap.get? targetId = some target /\
        target.originalRva = rva) /\
      TargetIdsMatchOriginalRvas context targetIds rvas
  | _, _ => False

/-- Exact entrypoint and TLS-root provenance for a bounded PE32 launch.  PE
parsing supplies the callback order, while the canonical code map supplies the
target identities used by execution and reachability. -/
structure ExactRoundTripLaunchRoots (context : StaticProofContext)
    (launch : PE32ConsoleLaunchV2) : Prop where
  entry : exists target,
    context.codeMap.get? launch.entryTargetId = some target /\
      target.originalRva = context.originalPe.entrypointRva
  tls : exists tlsCallbackRvas,
    parseTlsCallbackRvas context.originalPe = some tlsCallbackRvas /\
      TargetIdsMatchOriginalRvas context launch.tlsCallbackTargetIds tlsCallbackRvas

inductive RoundTripChunkKind where
  | ordinary (sourceRva : Nat)
  | x87 (sourceRva : Nat)
  | opaqueExternal (siteId : Nat)
  | quiescent
deriving Repr, DecidableEq

def WorldExecution.AtOriginalRva (context : StaticProofContext)
    (sourceRva : Nat) : WorldExecution -> Prop
  | .running targetId _ _ _ _ | .callbackRunning targetId _ _ _ _ _ =>
      exists target, context.codeMap.get? targetId = some target ∧
        target.originalRva = sourceRva
  | _ => False

def WorldExecution.AtTargetId (expectedTargetId : Nat) : WorldExecution -> Prop
  | .running targetId _ _ _ _ | .callbackRunning targetId _ _ _ _ _ =>
      targetId = expectedTargetId
  | _ => False

def WorldExecution.QuiescentPair : WorldExecution -> WorldExecution -> Prop
  | .returned _ _, .returned _ _ => True
  | .terminated _, .terminated _ => True
  | .fault originalCause, .fault candidateCause =>
      originalCause = candidateCause
  | _, _ => False

def ContainsExternalObservation (imported : ExternalTarget) :
    List WorldRelationalObservable -> Prop := fun observations =>
  exists observation, observation ∈ observations ∧
    exists world arguments, observation = .external world imported arguments

def ContainsAnyExternalObservation :
    List WorldRelationalObservable -> Prop := fun observations =>
  exists observation, observation ∈ observations ∧
    exists world imported arguments,
      observation = .external world imported arguments

/-- Select the exact lower certificate that authorizes a chunk.  The table and
kernel arguments are value-indexed: a proof assembled for another compiled
table or kernel is not definitionally interchangeable. -/
def RoundTripChunkKind.Authorized (context : StaticProofContext)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (compiledKernel : ExactCompiledInterpreterKernel context programTable)
    (opaqueSites : List OpaqueLockstepCallSite)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment) :
    RoundTripChunkKind -> Prop
  | .ordinary sourceRva =>
      sourceRva ∈ originalTransfers.requiredSourceRvas ∧
        ExactOriginalTransferRefinementAt context sourceRva ∧
        ExactCompiledProgramRecordAt programTable sourceRva ∧
        compiledKernel.semanticProgram = programTable.semanticRecords
  | .x87 sourceRva =>
      sourceRva ∈ originalX87.requiredSourceRvas ∧
        (exists witness, witness ∈ originalX87.witnesses ∧
        witness.schedule.sourceRva = sourceRva) ∧
        ExactCompiledProgramRecordAt programTable sourceRva ∧
        compiledKernel.semanticProgram = programTable.semanticRecords
  | .opaqueExternal siteId =>
      exists site, site ∈ opaqueSites ∧ site.id = siteId ∧
        context.StructurallyValid ∧ (site.disposition = .returns ->
          OpaqueLockstepEnvironmentRefinesAt context site originalEnvironment
            candidateEnvironment)
  | .quiescent => True

/-- A component label is determined by the exact execution shape.  Internal
chunks start at the certified original RVA and cannot swallow an external
event; external chunks name the imported identity they actually emit; only
already-terminal paired executions may take silent quiescent steps. -/
def RoundTripChunkKind.Classifies (context : StaticProofContext)
    (opaqueSites : List OpaqueLockstepCallSite)
    (originalBefore candidateBefore : WorldExecution)
    (originalObservations candidateObservations :
      List WorldRelationalObservable) : RoundTripChunkKind -> Prop
  | .ordinary sourceRva | .x87 sourceRva =>
      WorldExecution.AtOriginalRva context sourceRva originalBefore ∧
        ¬ ContainsAnyExternalObservation originalObservations ∧
        ¬ ContainsAnyExternalObservation candidateObservations
  | .opaqueExternal siteId =>
      exists site, site ∈ opaqueSites ∧ site.id = siteId ∧
        ContainsExternalObservation site.imported originalObservations ∧
        ContainsExternalObservation site.imported candidateObservations
  | .quiescent =>
      WorldExecution.QuiescentPair originalBefore candidateBefore ∧
        originalObservations = [] ∧ candidateObservations = []

/-- Exhaustive classification of every execution pair retained by the
simulation relation.  This is intentionally based on the exact current world
execution, not on a submitted status or a free-form chunk label. -/
inductive RoundTripRelatedSourceCase (context : StaticProofContext)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (opaqueSites : List OpaqueLockstepCallSite)
    (originalBefore candidateBefore : WorldExecution) : Type where
  | ordinary (sourceRva : Nat)
      (atSource : WorldExecution.AtOriginalRva context sourceRva originalBefore)
      (required : sourceRva ∈ originalTransfers.requiredSourceRvas)
  | x87 (sourceRva : Nat)
      (atSource : WorldExecution.AtOriginalRva context sourceRva originalBefore)
      (required : sourceRva ∈ originalX87.requiredSourceRvas)
      (witness : ExactInterpreterX87ScheduleWitness context.originalPe)
      (witnessMember : witness ∈ originalX87.witnesses)
      (witnessSource : witness.schedule.sourceRva = sourceRva)
  | opaqueExternal (site : OpaqueLockstepCallSite)
      (member : site ∈ opaqueSites)
      (atSite : WorldExecution.AtTargetId site.sourceTargetId originalBefore)
  | quiescent
      (paired : WorldExecution.QuiescentPair originalBefore candidateBefore)

/-- One exact pair of nonempty PE paths, with every observation retained and a
checked component certificate identifying why this particular chunk is
available. -/
structure RoundTripComponentChunkRefinement (context : StaticProofContext)
    (original candidate : DecodedWorldProgram)
    (executionRelation : WorldExecution -> WorldExecution -> Prop)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (compiledKernel : ExactCompiledInterpreterKernel context programTable)
    (programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable)
    (opaqueSites : List OpaqueLockstepCallSite)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (opaqueEnvironment : CheckedOpaqueLockstepEnvironment context opaqueSites
      originalEnvironment candidateEnvironment)
    (originalBefore candidateBefore : WorldExecution)
    (kind : RoundTripChunkKind) where
  authorized : kind.Authorized context originalTransfers originalX87 programTable
    compiledKernel opaqueSites originalEnvironment candidateEnvironment
  originalObservations : List WorldRelationalObservable
  candidateObservations : List WorldRelationalObservable
  originalAfter : WorldExecution
  candidateAfter : WorldExecution
  originalPath : NonemptyRelatedPath original.pe32TransitionSystem originalBefore
    originalObservations originalAfter
  candidatePath : NonemptyRelatedPath candidate.pe32TransitionSystem candidateBefore
    candidateObservations candidateAfter
  observationsRelated : RelatedObservationLists
    (worldRelationalObservationsRelated context) originalObservations
    candidateObservations
  classified : kind.Classifies context opaqueSites originalBefore candidateBefore
    originalObservations candidateObservations
  afterRelated : executionRelation originalAfter candidateAfter

/-- The semantic closure assembled from the local transfer, program-table,
kernel, callback/environment, invariant, and launch proofs.  This is not an
inventory bit: it quantifies over every pair of related execution states and
produces nonempty exact PE paths with pointwise-related observations. -/
structure RoundTripChunkComposition (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch)
    (original candidate : DecodedWorldProgram)
    (originalTransfers : ExactOriginalTransferInventory context)
    (originalX87 : ExactOriginalX87Inventory context)
    (programTable : ExactCompiledProgramTable context)
    (compiledKernel : ExactCompiledInterpreterKernel context programTable)
    (programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable)
    (opaqueSites : List OpaqueLockstepCallSite)
    (opaqueCoverage : ExactOpaqueProgramCoverage context original candidate opaqueSites)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (programBinding : ExactRoundTripProgramBinding context original candidate
      originalEnvironment candidateEnvironment)
    (opaqueEnvironment : CheckedOpaqueLockstepEnvironment context opaqueSites
      originalEnvironment candidateEnvironment) where
  executionRelation : WorldExecution -> WorldExecution -> Prop
  rootsRelated : forall world originalState candidateState,
    launch.StatesRelated context graph reachability world originalState candidateState ->
      executionRelation
        (.running launch.rootTargetId originalState launch.continuationTargetIds 0 world)
        (.running launch.rootTargetId candidateState launch.continuationTargetIds 0 world)
  classify : forall originalBefore candidateBefore,
    launch.Valid context graph invariants ->
    launch.Realizable context graph reachability ->
    context.StructurallyValid ->
    ExactRoundTripProgramBinding context original candidate originalEnvironment
      candidateEnvironment ->
    executionRelation originalBefore candidateBefore ->
      RoundTripRelatedSourceCase context originalTransfers originalX87 opaqueSites
        originalBefore candidateBefore
  ordinaryChunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore ->
    forall sourceRva,
      WorldExecution.AtOriginalRva context sourceRva originalBefore ->
      sourceRva ∈ originalTransfers.requiredSourceRvas ->
      ExactOriginalTransferRefinementAt context sourceRva ->
      ExactCompiledProgramRecordAt programTable sourceRva ->
      ProgramTableCertificate context.candidatePe context.candidateImports
        programTable.relocations programTable.tableRva programTable.countRva
        programTable.semanticRecords ->
      CompiledKernelRefinement compiledKernel.binding compiledKernel.program
        context.candidatePe context.candidateImports compiledKernel.nativeEnvironment
        compiledKernel.abi ->
      RoundTripComponentChunkRefinement context original candidate executionRelation
        originalTransfers originalX87 programTable compiledKernel programCoverage
        opaqueSites originalEnvironment candidateEnvironment opaqueEnvironment
        originalBefore candidateBefore (.ordinary sourceRva)
  x87Chunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore ->
    forall sourceRva,
      WorldExecution.AtOriginalRva context sourceRva originalBefore ->
      sourceRva ∈ originalX87.requiredSourceRvas ->
      forall witness,
      witness ∈ originalX87.witnesses ->
      witness.schedule.sourceRva = sourceRva ->
      ExactCompiledProgramRecordAt programTable sourceRva ->
      ProgramTableCertificate context.candidatePe context.candidateImports
        programTable.relocations programTable.tableRva programTable.countRva
        programTable.semanticRecords ->
      CompiledKernelRefinement compiledKernel.binding compiledKernel.program
        context.candidatePe context.candidateImports compiledKernel.nativeEnvironment
        compiledKernel.abi ->
      RoundTripComponentChunkRefinement context original candidate executionRelation
        originalTransfers originalX87 programTable compiledKernel programCoverage
        opaqueSites originalEnvironment candidateEnvironment opaqueEnvironment
        originalBefore candidateBefore (.x87 sourceRva)
  opaqueExternalChunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore ->
    forall site,
      site ∈ opaqueSites ->
      WorldExecution.AtTargetId site.sourceTargetId originalBefore ->
      opaqueLockstepCallSitesCoverExternalSites context original.externalCallSites
        opaqueSites = true ->
      opaqueLockstepCallSitesCoverExternalSites context candidate.externalCallSites
        opaqueSites = true ->
      context.StructurallyValid ->
      (site.disposition = .returns -> OpaqueLockstepEnvironmentRefinesAt context
        site originalEnvironment candidateEnvironment) ->
      RoundTripComponentChunkRefinement context original candidate executionRelation
        originalTransfers originalX87 programTable compiledKernel programCoverage
        opaqueSites originalEnvironment candidateEnvironment opaqueEnvironment
        originalBefore candidateBefore (.opaqueExternal site.id)
  quiescentChunk : forall originalBefore candidateBefore,
    executionRelation originalBefore candidateBefore ->
      WorldExecution.QuiescentPair originalBefore candidateBefore ->
      RoundTripComponentChunkRefinement context original candidate executionRelation
        originalTransfers originalX87 programTable compiledKernel programCoverage
        opaqueSites originalEnvironment candidateEnvironment opaqueEnvironment
        originalBefore candidateBefore .quiescent

def RoundTripChunkComposition.componentChunk
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch}
    {original candidate : DecodedWorldProgram}
    {originalTransfers : ExactOriginalTransferInventory context}
    {originalX87 : ExactOriginalX87Inventory context}
    {programTable : ExactCompiledProgramTable context}
    {compiledKernel : ExactCompiledInterpreterKernel context programTable}
    {programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable}
    {opaqueSites : List OpaqueLockstepCallSite}
    {opaqueCoverage : ExactOpaqueProgramCoverage context original candidate opaqueSites}
    {originalEnvironment candidateEnvironment : WorldExternalEnvironment}
    {programBinding : ExactRoundTripProgramBinding context original candidate
      originalEnvironment candidateEnvironment}
    {opaqueEnvironment : CheckedOpaqueLockstepEnvironment context opaqueSites
      originalEnvironment candidateEnvironment}
    (composition : RoundTripChunkComposition context graph invariants reachability
      control launch launchChecked original candidate originalTransfers originalX87
      programTable compiledKernel programCoverage opaqueSites opaqueCoverage
      originalEnvironment candidateEnvironment programBinding opaqueEnvironment)
    (originalBefore candidateBefore : WorldExecution)
    (related : composition.executionRelation originalBefore candidateBefore) :
    Sigma fun kind => RoundTripComponentChunkRefinement context original candidate
      composition.executionRelation originalTransfers originalX87 programTable
      compiledKernel programCoverage opaqueSites originalEnvironment
      candidateEnvironment opaqueEnvironment originalBefore candidateBefore kind := by
  cases sourceCase : composition.classify originalBefore candidateBefore
      launchChecked.valid launchChecked.realizable opaqueEnvironment.contextValid
      programBinding related with
  | ordinary sourceRva atSource required =>
      exact ⟨.ordinary sourceRva,
        composition.ordinaryChunk originalBefore candidateBefore related sourceRva
          atSource required (originalTransfers.refinementAt sourceRva required)
          (programCoverage.ordinaryPresent sourceRva required)
          programTable.certificate compiledKernel.certificate⟩
  | x87 sourceRva atSource required witness witnessMember witnessSource =>
      exact ⟨.x87 sourceRva,
        composition.x87Chunk originalBefore candidateBefore related sourceRva
          atSource required witness witnessMember witnessSource
          (programCoverage.x87Present sourceRva required)
          programTable.certificate compiledKernel.certificate⟩
  | opaqueExternal site member atSite =>
      exact ⟨.opaqueExternal site.id,
        composition.opaqueExternalChunk originalBefore candidateBefore related site
          member atSite opaqueCoverage.originalCovered opaqueCoverage.candidateCovered
          opaqueEnvironment.contextValid (fun returns =>
            opaqueEnvironment.at context opaqueSites originalEnvironment
              candidateEnvironment site member returns)⟩
  | quiescent paired =>
      exact ⟨.quiescent,
        composition.quiescentChunk originalBefore candidateBefore related paired⟩

theorem RoundTripChunkComposition.chunksRefine
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch}
    {original candidate : DecodedWorldProgram}
    {originalTransfers : ExactOriginalTransferInventory context}
    {originalX87 : ExactOriginalX87Inventory context}
    {programTable : ExactCompiledProgramTable context}
    {compiledKernel : ExactCompiledInterpreterKernel context programTable}
    {programCoverage : ExactRoundTripProgramCoverage context originalTransfers
      originalX87 programTable}
    {opaqueSites : List OpaqueLockstepCallSite}
    {opaqueCoverage : ExactOpaqueProgramCoverage context original candidate opaqueSites}
    {originalEnvironment candidateEnvironment : WorldExternalEnvironment}
    {programBinding : ExactRoundTripProgramBinding context original candidate
      originalEnvironment candidateEnvironment}
    {opaqueEnvironment : CheckedOpaqueLockstepEnvironment context opaqueSites
      originalEnvironment candidateEnvironment}
    (composition : RoundTripChunkComposition context graph invariants reachability
      control launch launchChecked original candidate originalTransfers originalX87 programTable
      compiledKernel programCoverage opaqueSites opaqueCoverage originalEnvironment
      candidateEnvironment programBinding opaqueEnvironment) :
    ChunkedRelationalBisimulation original.pe32TransitionSystem
      candidate.pe32TransitionSystem composition.executionRelation
      (worldRelationalObservationsRelated context) := by
  intro originalBefore candidateBefore related
  obtain ⟨kind, chunk⟩ := composition.componentChunk originalBefore
    candidateBefore related
  exact ⟨chunk.originalObservations, chunk.candidateObservations,
    chunk.originalAfter, chunk.candidateAfter, chunk.originalPath,
    chunk.candidatePath, chunk.observationsRelated, chunk.afterRelated⟩

/-- All independently cacheable proof products required at the round-trip
acceptance boundary.  The component-directed composition is value-indexed by
every preceding product and is converted to the exact chunked simulation only
by `RoundTripChunkComposition.chunksRefine`. -/
structure RoundTripAcceptanceCertificate (context : StaticProofContext)
    (graph : RelationalProductGraph) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment) where
  originalTransfers : ExactOriginalTransferInventory context
  originalX87 : ExactOriginalX87Inventory context
  programTable : ExactCompiledProgramTable context
  compiledKernel : ExactCompiledInterpreterKernel context programTable
  programCoverage : ExactRoundTripProgramCoverage context originalTransfers
    originalX87 programTable
  opaqueSites : List OpaqueLockstepCallSite
  opaqueCoverage : ExactOpaqueProgramCoverage context original candidate opaqueSites
  opaqueEnvironment : CheckedOpaqueLockstepEnvironment context opaqueSites
    originalEnvironment candidateEnvironment
  programBinding : ExactRoundTripProgramBinding context original candidate
    originalEnvironment candidateEnvironment
  programSurface : ExactRoundTripDecodedProgramSurface context graph invariants
    reachability control original candidate
  launchRoots : ExactRoundTripLaunchRoots context launch
  launchChecked : CheckedRoundTripLaunch context graph invariants reachability launch
  composition : RoundTripChunkComposition context graph invariants reachability
    control launch launchChecked original candidate originalTransfers originalX87 programTable
    compiledKernel programCoverage opaqueSites opaqueCoverage originalEnvironment
    candidateEnvironment programBinding opaqueEnvironment

/-- Whole-program equivalence together with checked provenance that the launch
roots are the exact PE entrypoint and TLS callback sequence.  Keeping this in
the theorem result prevents a caller from substituting an otherwise-valid
synthetic graph root for the actual image launch surface. -/
def ExactPE32ProgramsChunkObservationallyEquivalent
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram) : Prop :=
  ExactRoundTripLaunchRoots context launch ∧
    PE32ProgramsChunkObservationallyEquivalent context graph invariants
      reachability control launch original candidate

/-- The sole round-trip acceptance theorem.  It returns the real whole-program
chunked observational-equivalence proposition over exact decoded PE programs
and retains exact PE launch-root provenance. -/
theorem roundTripProgramsEquivalent
    {context : StaticProofContext}
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    {original candidate : DecodedWorldProgram}
    {originalEnvironment candidateEnvironment : WorldExternalEnvironment}
    (certificate : RoundTripAcceptanceCertificate context graph invariants
      reachability control launch original candidate originalEnvironment
      candidateEnvironment) :
    ExactPE32ProgramsChunkObservationallyEquivalent context graph invariants
      reachability control launch original candidate := by
  refine ⟨certificate.launchRoots, ?_⟩
  exact ⟨certificate.launchChecked.realizable,
    certificate.composition.executionRelation,
    certificate.composition.rootsRelated,
    certificate.composition.chunksRefine⟩

end StageA.Relational.InterpreterAcceptance
