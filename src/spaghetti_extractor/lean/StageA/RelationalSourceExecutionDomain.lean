import StageA.RelationalOriginalExecutionInvariant
import StageA.RelationalSourceAdmissibility
import StageA.RelationalPEWorldExecution

namespace StageA.Relational.OriginalExecutionInvariant

open StageA.Relational
open StageA.Relational.SourceWorld

/-!
# Original invariant to checked source domain

This module is the stable boundary between one-sided original-execution
invariants and the rooted domain used by source-equivalence proofs.  The
conversion reuses the invariant's exact one-step closure.  It does not infer a
root, exclude proof blocks, or invent raw-EIP mappings.

Those additional facts are explicit certificate inputs.  In particular, raw
concretizability is a checked mapping obligation over every admitted state,
not a consequence of reachability membership alone.
-/

/-- A logical original execution is proof-open exactly when it is not a
proof-blocked state.  Modeled faults and termination remain program behavior. -/
def OriginalExecutionProofOpen : WorldExecution -> Prop
  | .blocked _ => False
  | _ => True

/-- The invariant admits no proof-blocked execution state. -/
def OriginalWorldExecutionInvariant.BlocksExcluded
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program) : Prop :=
  forall reason, ¬ invariant.holds (.blocked reason)

/-- Every state admitted by the invariant is proof-open. -/
def OriginalWorldExecutionInvariant.ProofOpen
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program) : Prop :=
  forall execution, invariant.holds execution ->
    OriginalExecutionProofOpen execution

/-- Explicit mapping evidence for every state admitted by the invariant. -/
def OriginalWorldExecutionInvariant.RawConcretizable
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program) : Prop :=
  forall execution, invariant.holds execution ->
    exists raw, execution.ConcretizesToRawEip program raw

/-- Convert an invariant into the source layer's rooted checked domain.  The
root proof is deliberately an argument rather than an inferred reachability
claim. -/
def OriginalWorldExecutionInvariant.toCheckedExecutionDomain
    {program : DecodedWorldProgram} {root : WorldExecution}
    (invariant : OriginalWorldExecutionInvariant program)
    (rootHolds : invariant.holds root) :
    CheckedExecutionDomain program root where
  holds := invariant.holds
  rootHolds := rootHolds
  stepClosed := invariant.stepClosed

@[simp]
theorem OriginalWorldExecutionInvariant.toCheckedExecutionDomain_holds
    {program : DecodedWorldProgram} {root execution : WorldExecution}
    (invariant : OriginalWorldExecutionInvariant program)
    (rootHolds : invariant.holds root) :
    (invariant.toCheckedExecutionDomain rootHolds).holds execution <->
      invariant.holds execution :=
  Iff.rfl

theorem OriginalWorldExecutionInvariant.proofOpen_of_blocksExcluded
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program)
    (blocksExcluded : invariant.BlocksExcluded) :
    invariant.ProofOpen := by
  intro execution member
  cases execution <;> simp [OriginalExecutionProofOpen]
  case blocked reason =>
    exact blocksExcluded reason member

theorem OriginalWorldExecutionInvariant.blocksExcluded_of_proofOpen
    {program : DecodedWorldProgram}
    (invariant : OriginalWorldExecutionInvariant program)
    (proofOpen : invariant.ProofOpen) :
    invariant.BlocksExcluded := by
  intro reason member
  exact proofOpen (.blocked reason) member

end StageA.Relational.OriginalExecutionInvariant

namespace StageA.Relational.SourceWorld

open StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld.InterpreterKernel

/-!
## Checked one-sided evidence aggregation

Control provenance, carried values, stack facts, and writable-slot facts are
all represented below by the same object: an invariant of the authoritative
original transition system together with a proof that it holds at the root.
The aggregation layer is deliberately ignorant of how each invariant was
proved.  In particular, it cannot project a fact from a candidate relation or
close an obligation from a generated status field.

One foundational invariant owns proof-block exclusion and logical-to-raw
concretization.  Additional invariants may only restrict that domain.  Their
root and exact one-step closure proofs make that restriction inductive.
-/

/-- A one-sided invariant which is established at the declared original
execution root. -/
structure RootedOriginalWorldExecutionInvariant
    (program : DecodedWorldProgram) (root : WorldExecution) where
  invariant : OriginalWorldExecutionInvariant program
  rootHolds : invariant.holds root

/-- Conjoin a finite inventory of independently checked rooted invariants. -/
def RootedOriginalWorldExecutionInvariant.all
    {program : DecodedWorldProgram} {root : WorldExecution}
    (invariants : List (RootedOriginalWorldExecutionInvariant program root)) :
    RootedOriginalWorldExecutionInvariant program root where
  invariant := OriginalWorldExecutionInvariant.all
    (invariants.map (fun invariant => invariant.invariant))
  rootHolds := by
    intro invariant member
    simp only [List.mem_map] at member
    rcases member with ⟨rooted, _member, rfl⟩
    exact rooted.rootHolds

theorem RootedOriginalWorldExecutionInvariant.all_member
    {program : DecodedWorldProgram} {root execution : WorldExecution}
    {invariants : List (RootedOriginalWorldExecutionInvariant program root)}
    (combined :
      (RootedOriginalWorldExecutionInvariant.all invariants).invariant.holds
        execution)
    (rooted : RootedOriginalWorldExecutionInvariant program root)
    (member : rooted ∈ invariants) :
    rooted.invariant.holds execution := by
  apply OriginalWorldExecutionInvariant.all_member combined rooted.invariant
  exact List.mem_map.mpr ⟨rooted, member, rfl⟩

/-- The complete one-sided evidence package used to construct a source proof
domain.  `foundation` supplies structural execution safety.  The remaining
entries supply category-independent value/control facts and are conjoined
without any pairwise candidate premise. -/
structure CheckedOriginalExecutionEvidence
    (program : DecodedWorldProgram) (root : WorldExecution) where
  foundation : RootedOriginalWorldExecutionInvariant program root
  refinements : List (RootedOriginalWorldExecutionInvariant program root)
  foundationBlocksExcluded : foundation.invariant.BlocksExcluded
  foundationRawConcretizable : foundation.invariant.RawConcretizable

/-- Structural one-sided reachability evidence.  The exact transition must
preserve the submitted target inventory, and each target in that inventory
must round-trip through the canonical concrete EIP resolver. -/
structure CheckedOriginalReachabilityEvidence
    (program : DecodedWorldProgram) (root : WorldExecution) where
  targetIds : List Nat
  targetIdsUnique : targetIds.Nodup
  rootReachable : OriginalExecutionReachable targetIds root
  stepClosed : forall before,
    OriginalExecutionReachable targetIds before ->
      OriginalExecutionReachable targetIds
        (program.pe32TransitionSystem.step before).next
  targetRoundTrips : forall targetId,
    targetId ∈ targetIds ->
      exists eip,
        program.canonicalRawEip? targetId = some eip /\
          program.resolveRawEip eip = some targetId

/-- Root-independent reachability evidence for a launch family.  The finite
target inventory, exact one-step closure, and raw-EIP round trips are checked
once; only entry membership varies with the concrete launch state. -/
structure CheckedOriginalReachabilityFamilyEvidence
    (program : DecodedWorldProgram) where
  targetIds : List Nat
  targetIdsUnique : targetIds.Nodup
  entryReachable : forall root,
    WorldExecution.IsProgramEntry program root ->
      OriginalExecutionReachable targetIds root
  stepClosed : forall before,
    OriginalExecutionReachable targetIds before ->
      OriginalExecutionReachable targetIds
        (program.pe32TransitionSystem.step before).next
  targetRoundTrips : forall targetId,
    targetId ∈ targetIds ->
      exists eip,
        program.canonicalRawEip? targetId = some eip /\
          program.resolveRawEip eip = some targetId

/-- A root-independent one-sided invariant family.  The combined invariant is
the only predicate required to be inductive.  Its reachability projection is
used for fail-closed block exclusion and raw-EIP lookup, but need not itself be
closed under the transition system. -/
structure CheckedOriginalInvariantFamilyEvidence
    (program : DecodedWorldProgram) where
  invariant : OriginalWorldExecutionInvariant program
  targetIds : List Nat
  targetIdsUnique : targetIds.Nodup
  reachabilityProjection : forall execution,
    invariant.holds execution -> OriginalExecutionReachable targetIds execution
  targetRoundTrips : forall targetId,
    targetId ∈ targetIds ->
      exists eip,
        program.canonicalRawEip? targetId = some eip /\
          program.resolveRawEip eip = some targetId

/-- The reachability projection remains fail closed for proof-blocked states. -/
theorem CheckedOriginalInvariantFamilyEvidence.blocksExcluded
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program) :
    evidence.invariant.BlocksExcluded := by
  intro reason holds
  have reachable := evidence.reachabilityProjection (.blocked reason) holds
  simpa [OriginalExecutionReachable] using reachable

/-- Every state in the combined invariant has a checked logical-to-raw
concretization.  Running-state target membership comes from the projection;
terminal and modeled fault states round-trip directly. -/
theorem CheckedOriginalInvariantFamilyEvidence.rawConcretizable
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program) :
    evidence.invariant.RawConcretizable := by
  intro execution holds
  have reachable := evidence.reachabilityProjection execution holds
  cases execution with
  | running targetId state calls eventIndex world =>
      rcases evidence.targetRoundTrips targetId reachable.1 with
        ⟨eip, canonical, resolved⟩
      refine ⟨.running eip state calls eventIndex world, ?_⟩
      exact ⟨by
        simp [WorldExecution.concretizeRawEip?, canonical], by
        unfold RawEipWorldExecution.ProjectsTo
        simp only [RawEipWorldExecution.project?]
        rw [resolved]
        rfl⟩
  | callbackRunning targetId state calls eventIndex world callbacks =>
      rcases evidence.targetRoundTrips targetId reachable.1 with
        ⟨eip, canonical, resolved⟩
      refine ⟨.callbackRunning eip state calls eventIndex world callbacks, ?_⟩
      exact ⟨by
        simp [WorldExecution.concretizeRawEip?, canonical], by
        unfold RawEipWorldExecution.ProjectsTo
        simp only [RawEipWorldExecution.project?]
        rw [resolved]
        rfl⟩
  | returned state world =>
      exact ⟨.returned state world, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | terminated world =>
      exact ⟨.terminated world, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | awaitingExternal suspension callbacks =>
      exact ⟨.awaitingExternal suspension callbacks, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | fault cause =>
      exact ⟨.fault cause, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | blocked reason =>
      simp [OriginalExecutionReachable] at reachable

/-- Regard the state-insensitive reachability family as a combined invariant
family.  This retains the existing generated interface while allowing clients
to migrate to the more general boundary. -/
def CheckedOriginalReachabilityFamilyEvidence.toInvariantFamilyEvidence
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalReachabilityFamilyEvidence program) :
    CheckedOriginalInvariantFamilyEvidence program where
  invariant := {
    holds := OriginalExecutionReachable evidence.targetIds
    stepClosed := evidence.stepClosed
  }
  targetIds := evidence.targetIds
  targetIdsUnique := evidence.targetIdsUnique
  reachabilityProjection := by
    intro _ reachable
    exact reachable
  targetRoundTrips := evidence.targetRoundTrips

def CheckedOriginalReachabilityFamilyEvidence.atRoot
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalReachabilityFamilyEvidence program)
    (root : WorldExecution) (entry : WorldExecution.IsProgramEntry program root) :
    CheckedOriginalReachabilityEvidence program root where
  targetIds := evidence.targetIds
  targetIdsUnique := evidence.targetIdsUnique
  rootReachable := evidence.entryReachable root entry
  stepClosed := evidence.stepClosed
  targetRoundTrips := evidence.targetRoundTrips

def CheckedOriginalReachabilityEvidence.rooted
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalReachabilityEvidence program root) :
    RootedOriginalWorldExecutionInvariant program root where
  invariant := {
    holds := OriginalExecutionReachable evidence.targetIds
    stepClosed := evidence.stepClosed
  }
  rootHolds := evidence.rootReachable

theorem CheckedOriginalReachabilityEvidence.blocksExcluded
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalReachabilityEvidence program root) :
    evidence.rooted.invariant.BlocksExcluded := by
  intro reason reachable
  simpa [CheckedOriginalReachabilityEvidence.rooted,
    OriginalExecutionReachable] using reachable

theorem CheckedOriginalReachabilityEvidence.rawConcretizable
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalReachabilityEvidence program root) :
    evidence.rooted.invariant.RawConcretizable := by
  intro execution reachable
  cases execution with
  | running targetId state calls eventIndex world =>
      rcases evidence.targetRoundTrips targetId reachable.1 with
        ⟨eip, canonical, resolved⟩
      refine ⟨.running eip state calls eventIndex world, ?_⟩
      exact ⟨by
        simp [WorldExecution.concretizeRawEip?, canonical], by
        unfold RawEipWorldExecution.ProjectsTo
        simp only [RawEipWorldExecution.project?]
        rw [resolved]
        rfl⟩
  | callbackRunning targetId state calls eventIndex world callbacks =>
      rcases evidence.targetRoundTrips targetId reachable.1 with
        ⟨eip, canonical, resolved⟩
      refine ⟨.callbackRunning eip state calls eventIndex world callbacks, ?_⟩
      exact ⟨by
        simp [WorldExecution.concretizeRawEip?, canonical], by
        unfold RawEipWorldExecution.ProjectsTo
        simp only [RawEipWorldExecution.project?]
        rw [resolved]
        rfl⟩
  | returned state world =>
      exact ⟨.returned state world, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | terminated world =>
      exact ⟨.terminated world, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | awaitingExternal suspension callbacks =>
      exact ⟨.awaitingExternal suspension callbacks, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | fault cause =>
      exact ⟨.fault cause, by
        simp [WorldExecution.ConcretizesToRawEip,
          WorldExecution.concretizeRawEip?, RawEipWorldExecution.ProjectsTo,
          RawEipWorldExecution.project?]⟩
  | blocked reason =>
      simp [CheckedOriginalReachabilityEvidence.rooted,
        OriginalExecutionReachable] at reachable

/-- Use structural reachability as the foundation and conjoin any number of
independently rooted value/control invariants. -/
def CheckedOriginalReachabilityEvidence.withRefinements
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalReachabilityEvidence program root)
    (refinements : List
      (RootedOriginalWorldExecutionInvariant program root)) :
    CheckedOriginalExecutionEvidence program root where
  foundation := evidence.rooted
  refinements := refinements
  foundationBlocksExcluded := evidence.blocksExcluded
  foundationRawConcretizable := evidence.rawConcretizable

def CheckedOriginalExecutionEvidence.rooted
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root) :
    RootedOriginalWorldExecutionInvariant program root :=
  RootedOriginalWorldExecutionInvariant.all
    (evidence.foundation :: evidence.refinements)

def CheckedOriginalExecutionEvidence.invariant
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root) :
    OriginalWorldExecutionInvariant program :=
  evidence.rooted.invariant

theorem CheckedOriginalExecutionEvidence.foundationHolds
    {program : DecodedWorldProgram} {root execution : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root)
    (holds : evidence.invariant.holds execution) :
    evidence.foundation.invariant.holds execution :=
  RootedOriginalWorldExecutionInvariant.all_member holds evidence.foundation
    (List.mem_cons_self)

theorem CheckedOriginalExecutionEvidence.refinementHolds
    {program : DecodedWorldProgram} {root execution : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root)
    (holds : evidence.invariant.holds execution)
    (refinement : RootedOriginalWorldExecutionInvariant program root)
    (member : refinement ∈ evidence.refinements) :
    refinement.invariant.holds execution :=
  RootedOriginalWorldExecutionInvariant.all_member holds refinement
    (List.mem_cons_of_mem evidence.foundation member)

theorem CheckedOriginalExecutionEvidence.blocksExcluded
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root) :
    evidence.invariant.BlocksExcluded := by
  intro reason holds
  exact evidence.foundationBlocksExcluded reason
    (evidence.foundationHolds holds)

theorem CheckedOriginalExecutionEvidence.rawConcretizable
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root) :
    evidence.invariant.RawConcretizable := by
  intro execution holds
  exact evidence.foundationRawConcretizable execution
    (evidence.foundationHolds holds)

/-- All evidence needed to expose an original invariant as an acceptance-side
source domain.  None of the three non-structural obligations is synthesized. -/
structure OriginalInvariantDomainCertificate
    (program : DecodedWorldProgram) (root : WorldExecution) where
  invariant : OriginalWorldExecutionInvariant program
  rootHolds : invariant.holds root
  blocksExcluded : invariant.BlocksExcluded
  rawConcretizable : invariant.RawConcretizable

/-- Specialize a combined invariant family at a launch where its invariant has
been established.  No independent closure theorem for the reachability
projection is needed. -/
def CheckedOriginalInvariantFamilyEvidence.domainCertificateAtLaunch
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program)
    (root : WorldExecution) (invariantAtLaunch : evidence.invariant.holds root) :
    OriginalInvariantDomainCertificate program root where
  invariant := evidence.invariant
  rootHolds := invariantAtLaunch
  blocksExcluded := evidence.blocksExcluded
  rawConcretizable := evidence.rawConcretizable

/-- Package checked one-sided evidence as the source execution-domain
certificate.  Step closure is inherited only from the constituent exact
original invariants. -/
def CheckedOriginalExecutionEvidence.toDomainCertificate
    {program : DecodedWorldProgram} {root : WorldExecution}
    (evidence : CheckedOriginalExecutionEvidence program root) :
    OriginalInvariantDomainCertificate program root where
  invariant := evidence.invariant
  rootHolds := evidence.rooted.rootHolds
  blocksExcluded := evidence.blocksExcluded
  rawConcretizable := evidence.rawConcretizable

def OriginalInvariantDomainCertificate.domain
    {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    CheckedExecutionDomain program root :=
  certificate.invariant.toCheckedExecutionDomain certificate.rootHolds

@[simp]
theorem OriginalInvariantDomainCertificate.domain_holds
    {program : DecodedWorldProgram} {root execution : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    certificate.domain.holds execution <->
      certificate.invariant.holds execution :=
  Iff.rfl

/-- The checked source domain obtained by rooting the combined invariant at one
launch. -/
def CheckedOriginalInvariantFamilyEvidence.domainAtLaunch
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program)
    (root : WorldExecution) (invariantAtLaunch : evidence.invariant.holds root) :
    CheckedExecutionDomain program root :=
  (evidence.domainCertificateAtLaunch root invariantAtLaunch).domain

@[simp]
theorem CheckedOriginalInvariantFamilyEvidence.domainAtLaunch_holds_iff
    {program : DecodedWorldProgram}
    (evidence : CheckedOriginalInvariantFamilyEvidence program)
    (root execution : WorldExecution)
    (invariantAtLaunch : evidence.invariant.holds root) :
    (evidence.domainAtLaunch root invariantAtLaunch).holds execution <->
      evidence.invariant.holds execution :=
  Iff.rfl

theorem OriginalInvariantDomainCertificate.domainBlocksExcluded
    {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    forall reason, ¬ certificate.domain.holds (.blocked reason) :=
  certificate.blocksExcluded

theorem OriginalInvariantDomainCertificate.domainProofOpen
    {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    forall execution, certificate.domain.holds execution ->
      OriginalExecutionProofOpen execution :=
  certificate.invariant.proofOpen_of_blocksExcluded certificate.blocksExcluded

theorem OriginalInvariantDomainCertificate.domainRawConcretizable
    {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    forall execution, certificate.domain.holds execution ->
      exists raw, execution.ConcretizesToRawEip program raw :=
  certificate.rawConcretizable

/-- The exact closure shape required by the domain-restricted raw-EIP lift.
The current concretization is retained in the interface so this theorem can be
passed directly to that layer; successor mapping comes from the explicit
all-domain concretizability certificate after checked one-step closure. -/
theorem OriginalInvariantDomainCertificate.rawEipSuccessorConcretizable
    {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root) :
    forall logical raw,
      certificate.domain.holds logical ->
      logical.ConcretizesToRawEip program raw ->
      exists rawNext,
        (program.pe32TransitionSystem.step logical).next.ConcretizesToRawEip
          program rawNext := by
  intro logical _ member _
  exact certificate.rawConcretizable _
    (certificate.invariant.stepClosed logical member)

/-- Block exclusion also closes the fail-closed observation side condition for
the decoded semantic kernel. -/
theorem OriginalInvariantDomainCertificate.decodedSemanticStepsAdmissible
    {program : DecodedWorldProgram} {root : WorldExecution}
    (certificate : OriginalInvariantDomainCertificate program root)
    (adequate : program.InstructionSemanticsAdequate) :
    DecodedSemanticStepsAdmissible program certificate.domain :=
  certificate.domain.decodedSemanticStepsAdmissible_of_blocksExcluded adequate
    certificate.domainBlocksExcluded

end StageA.Relational.SourceWorld
