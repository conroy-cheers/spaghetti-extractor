import StageA.RelationalCertificates

namespace StageA.Relational

open StageA.Formal

/-- Exact side identity for every mapping component consulted by current PE32
world execution. -/
def PE32WorldMappingsIdentical (context : StaticProofContext) : Prop :=
  context.originalImportCertificate = context.candidateImportCertificate ∧
    context.originalRelocations = context.candidateRelocations ∧
    context.codeMap.originalAddresses = context.codeMap.candidateAddresses ∧
    context.dataMap.originalOrder = context.dataMap.candidateOrder ∧
    (∀ target, target ∈ context.codeMap.entries.toList ->
      target.originalRva = target.candidateRva ∧
        target.originalAliases = target.candidateAliases) ∧
    (∀ target, target ∈ context.dataMap.entries.toList ->
      target.originalValue = target.candidateValue ∧
        target.originalRelocationRva = target.candidateRelocationRva)

def reachableSegmentInventoryCovered
    (decodedSegmentIds reachableSegmentIds : List Nat) : Bool :=
  reachableSegmentIds.all decodedSegmentIds.contains

/-- Segment target identifiers obtained from the current product graph's
reachable node inventory. -/
def RelationalProductReachabilityEvidence.reachableSegmentIds
    (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence) : List Nat :=
  (reachability.reachableNodeIds graph).filterMap fun nodeId =>
    (graph.getNode? nodeId).map (·.targetId)

/-- Kernel evidence that two side-selected `DecodedWorldProgram` values have
the same exact PE32 world semantics.  The final two equalities are typed Lean
facts about the current fetch-and-execute semantics, not Python status fields. -/
structure ExactPE32WorldIdentityEvidence
    (originalPESha256 candidatePESha256 : String)
    (originalPEBytes candidatePEBytes : ByteTree)
    (decodedSegmentIds reachableSegmentIds : List Nat)
    (context : StaticProofContext)
    (original candidate : DecodedWorldProgram)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment) : Prop where
  originalPEBytesBound : context.originalPe.bytes = originalPEBytes
  candidatePEBytesBound : context.candidatePe.bytes = candidatePEBytes
  peHashesIdentical : originalPESha256 = candidatePESha256
  peBytesIdentical : originalPEBytes = candidatePEBytes
  typedPEsIdentical : context.originalPe = context.candidatePe
  mappingsIdentical : PE32WorldMappingsIdentical context
  originalContextBound : original.context = context
  candidateContextBound : candidate.context = context
  originalSide : original.candidate = false
  candidateSide : candidate.candidate = true
  decodedSegmentIdsBound : original.regions.map (·.id) = decodedSegmentIds
  decodedSegmentIdsNonempty : decodedSegmentIds != []
  regionsIdentical : original.regions = candidate.regions
  reachableSegmentsCovered :
    reachableSegmentInventoryCovered decodedSegmentIds reachableSegmentIds = true
  externalCallSitesIdentical :
    original.externalCallSites = candidate.externalCallSites
  originalEnvironmentBound : original.environment = originalEnvironment
  candidateEnvironmentBound : candidate.environment = candidateEnvironment
  worldEnvironmentsIdentical : originalEnvironment = candidateEnvironment
  originalProtocolEnvironmentBound :
    original.protocolEnvironment = originalProtocolEnvironment
  candidateProtocolEnvironmentBound :
    candidate.protocolEnvironment = candidateProtocolEnvironment
  protocolEnvironmentsIdentical :
    originalProtocolEnvironment = candidateProtocolEnvironment
  pe32RegionSemanticsIdentical :
    pe32WorldRegionBehavior original = pe32WorldRegionBehavior candidate
  pe32TransitionSystemsIdentical :
    original.pe32TransitionSystem = candidate.pe32TransitionSystem

/-- The explicit nonvacuous launch relation for exact identity.  It retains the
current checked PE32 launch relation and additionally requires the two machine
states to be literally equal. -/
def ExactIdentityLaunchStatesRelated
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (reachability : RelationalProductReachabilityEvidence)
    (launch : PE32ConsoleLaunchV2) (world : RelationalWorld)
    (original candidate : MachineState) : Prop :=
  launch.StatesRelated context graph reachability world original candidate ∧
    original = candidate

/-- Checked current-model facts retained by the identity result.  This is
intentionally short of `WholeProgramCertificate`: external refinements,
protocol refinements, decoded-control closure, and every reachable product-edge
refinement still have to be supplied by the ordinary acceptance path. -/
structure ExactIdentityPE32CheckedFrontier
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (regions : List RegionRelation) (reachableSegmentIds : List Nat)
    (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram) : Prop where
  executableImagesCovered : ∃ imageBundle : ProofBundle,
    imageBundle.CoversStaticContext context regions
  productGraphValid : graph.IndexedValid context
  regionsUseCanonicalContext : RegionsUseStaticContext context regions
  regionsMatchProductGraph : RegionsMatchProductGraph context graph regions
  invariantTableValid : invariants.Valid graph
  reachabilityClosed : reachability.SoundlyClosed context graph
  reachableSegmentIdsBound :
    reachability.reachableSegmentIds graph = reachableSegmentIds
  launchValid : launch.Valid context graph invariants
  launchControlAllowed : control.Allows launch.rootNodeId
    launch.continuationTargetIds launch.frameOffsets = true
  identityLaunchRealizable : ∃ world state,
    ExactIdentityLaunchStatesRelated context graph reachability launch world state state
  originalInstructionSemanticsAdequate :
    original.InstructionSemanticsAdequate
  candidateInstructionSemanticsAdequate :
    candidate.InstructionSemanticsAdequate

/-- Actual PE32 world-transition reflexivity under exact observation equality.

This is explicitly an intermediate theorem, not current Stage A acceptance.
In particular, exact equality relates identical `proofBlocked` observations,
whereas `worldRelationalObservationsRelated` intentionally relates no blocked
observation.  Consequently this structure cannot be substituted for
`PE32ProgramsObservationallyEquivalent` or `WholeProgramCertificate`. -/
structure ExactIdentityPE32WorldReflexivityIntermediate
    (originalPESha256 candidatePESha256 : String)
    (originalPEBytes candidatePEBytes : ByteTree)
    (decodedSegmentIds reachableSegmentIds : List Nat)
    (context : StaticProofContext) (graph : RelationalProductGraph)
    (regions : List RegionRelation) (invariants : ProductInvariantTable)
    (reachability : RelationalProductReachabilityEvidence)
    (control : ProductControlProfile) (launch : PE32ConsoleLaunchV2)
    (original candidate : DecodedWorldProgram)
    (originalEnvironment candidateEnvironment : WorldExternalEnvironment)
    (originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment) : Prop where
  identityEvidence : ExactPE32WorldIdentityEvidence originalPESha256
    candidatePESha256 originalPEBytes candidatePEBytes decodedSegmentIds
    reachableSegmentIds context original candidate originalEnvironment
    candidateEnvironment originalProtocolEnvironment candidateProtocolEnvironment
  checkedFrontier : ExactIdentityPE32CheckedFrontier context graph regions
    reachableSegmentIds invariants reachability control launch original candidate
  exactWorldReflexivity :
    ∃ executionRelation : WorldExecution -> WorldExecution -> Prop,
    (∀ world originalState candidateState,
      ExactIdentityLaunchStatesRelated context graph reachability launch world
        originalState candidateState ->
      executionRelation
        (.running launch.rootTargetId originalState
          launch.continuationTargetIds 0 world)
        (.running launch.rootTargetId candidateState
          launch.continuationTargetIds 0 world)) ∧
    RelationalWeakBisimulation original.pe32TransitionSystem
      candidate.pe32TransitionSystem executionRelation Eq

theorem ExactPE32WorldIdentityEvidence.worldReflexivityIntermediate
    {originalPESha256 candidatePESha256 : String}
    {originalPEBytes candidatePEBytes : ByteTree}
    {decodedSegmentIds reachableSegmentIds : List Nat}
    {context : StaticProofContext}
    {original candidate : DecodedWorldProgram}
    {originalEnvironment candidateEnvironment : WorldExternalEnvironment}
    {originalProtocolEnvironment candidateProtocolEnvironment :
      WorldExternalProtocolEnvironment}
    (evidence : ExactPE32WorldIdentityEvidence originalPESha256 candidatePESha256
      originalPEBytes candidatePEBytes decodedSegmentIds reachableSegmentIds context
      original candidate originalEnvironment candidateEnvironment
      originalProtocolEnvironment candidateProtocolEnvironment)
    {graph : RelationalProductGraph} {invariants : ProductInvariantTable}
    {reachability : RelationalProductReachabilityEvidence}
    {control : ProductControlProfile} {launch : PE32ConsoleLaunchV2}
    (frontier : ExactIdentityPE32CheckedFrontier context graph original.regions
      reachableSegmentIds invariants reachability control launch original candidate) :
    ExactIdentityPE32WorldReflexivityIntermediate originalPESha256
      candidatePESha256 originalPEBytes candidatePEBytes decodedSegmentIds
      reachableSegmentIds context graph original.regions invariants reachability
      control launch original candidate originalEnvironment candidateEnvironment
      originalProtocolEnvironment candidateProtocolEnvironment := by
  refine ⟨evidence, frontier, Eq, ?_, ?_⟩
  · intro world originalState candidateState launchRelated
    rcases launchRelated with ⟨_, statesIdentical⟩
    subst candidateState
    rfl
  · intro originalExecution candidateExecution executionsIdentical
    subst candidateExecution
    rw [evidence.pe32TransitionSystemsIdentical]
    exact ⟨rfl, rfl⟩

end StageA.Relational
