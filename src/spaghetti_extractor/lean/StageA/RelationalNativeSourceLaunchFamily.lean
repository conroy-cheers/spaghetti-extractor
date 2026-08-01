import StageA.RelationalNativeSource
import StageA.RelationalSourceExecutionDomain
import StageA.RelationalSourceProgramCertificate

namespace StageA.Relational.NativeSource

open StageA.Relational
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

/-!
# Static source evidence to launch-family acceptance

Generated proof data should not rebuild the source acceptance package for each
argv, environment, or relational-world instance.  This module checks the
root-independent inventory once, then establishes the invariant at each launch.

The adapters contain no compiler or candidate premise.  They establish the
exact-original-PE to source-kernel leg used by native-source acceptance.
-/

/-- Static source evidence backed by one combined original invariant.  Its
launch root may depend on the complete checked PE32 console launch, including
the loaded image, import memory, and external world. -/
structure CheckedNativeSourceInvariantLaunchFamilyEvidence
    (project : NativeSourceProject) where
  exactBinding :
    ExactBinding project.program.worldProgram.context.originalPe project.program
  instructionSemanticsAdequate :
    project.program.worldProgram.InstructionSemanticsAdequate
  original :
    CheckedOriginalInvariantFamilyEvidence project.program.worldProgram
  invariantAtLaunch : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      original.invariant.holds sourceRoot.toWorldExecution
  activeTargets : ActiveTargetTransitionIndex exactBinding
  activeTargetIdsExact :
    activeTargets.certificates.map (fun certificate => certificate.targetId) =
      original.targetIds
  launchRealizable : exists sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot

/-- Root-independent evidence sufficient to certify the source project at
every checked program entry.  The dependent target index is tied to the exact
PE/source binding, while `activeTargetIdsExact` connects its finite semantic
inventory to the independently checked reachability closure. -/
structure StaticNativeSourceLaunchFamilyEvidence
    (project : NativeSourceProject) where
  exactBinding :
    ExactBinding project.program.worldProgram.context.originalPe project.program
  instructionSemanticsAdequate :
    project.program.worldProgram.InstructionSemanticsAdequate
  reachability :
    CheckedOriginalReachabilityFamilyEvidence project.program.worldProgram
  activeTargets : ActiveTargetTransitionIndex exactBinding
  activeTargetIdsExact :
    activeTargets.certificates.map (fun certificate => certificate.targetId) =
      reachability.targetIds
  launchRealizable : exists sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot

/-- Root the combined original invariant using the full checked native-source
launch predicate. -/
def CheckedNativeSourceInvariantLaunchFamilyEvidence.domainCertificateAtLaunch
    {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    OriginalInvariantDomainCertificate project.program.worldProgram
      sourceRoot.toWorldExecution :=
  evidence.original.domainCertificateAtLaunch sourceRoot.toWorldExecution
    (evidence.invariantAtLaunch sourceRoot launch)

def CheckedNativeSourceInvariantLaunchFamilyEvidence.domainAtLaunch
    {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    CheckedExecutionDomain project.program.worldProgram
      sourceRoot.toWorldExecution :=
  (evidence.domainCertificateAtLaunch sourceRoot launch).domain

@[simp]
theorem CheckedNativeSourceInvariantLaunchFamilyEvidence.domainAtLaunch_holds_iff
    {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot)
    (execution : WorldExecution) :
    (evidence.domainAtLaunch sourceRoot launch).holds execution <->
      evidence.original.invariant.holds execution :=
  Iff.rfl

/-- Project the combined invariant to finite target reachability only where the
semantic target inventory needs it. -/
def CheckedNativeSourceInvariantLaunchFamilyEvidence.activeTargetCoverageAtLaunch
    {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    ActiveTargetDomainCoverage evidence.activeTargets
      (evidence.domainAtLaunch sourceRoot launch) :=
  ActiveTargetDomainCoverage.ofTargetMembership evidence.activeTargets
    (evidence.domainAtLaunch sourceRoot launch) evidence.original.targetIds
    evidence.activeTargetIdsExact
    (by
      intro targetId state calls eventIndex world inDomain
      have holds := (evidence.domainAtLaunch_holds_iff sourceRoot launch
        (.running targetId state calls eventIndex world)).mp inDomain
      exact (evidence.original.reachabilityProjection _ holds).1)
    (by
      intro targetId state calls eventIndex world callbacks inDomain
      have holds := (evidence.domainAtLaunch_holds_iff sourceRoot launch
        (.callbackRunning targetId state calls eventIndex world callbacks)).mp
          inDomain
      exact (evidence.original.reachabilityProjection _ holds).1)

/-- Assemble one checked source project from the launch-rooted combined
invariant. -/
def CheckedNativeSourceInvariantLaunchFamilyEvidence.checkedProjectAtLaunch
    {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    CheckedNativeSourceProject project sourceRoot.toWorldExecution
      (evidence.domainAtLaunch sourceRoot launch) :=
  let certificate := evidence.domainCertificateAtLaunch sourceRoot launch
  {
    exactBinding := evidence.exactBinding
    instructionSemanticsAdequate := evidence.instructionSemanticsAdequate
    decodedSemanticStepsAdmissible :=
      certificate.decodedSemanticStepsAdmissible
        evidence.instructionSemanticsAdequate
    programRecordKernelMatchesDecodedSemantics :=
      programRecordKernelMatchesDecodedSemantics_of_checkedTargets
        evidence.activeTargets (evidence.domainAtLaunch sourceRoot launch)
        (evidence.activeTargetCoverageAtLaunch sourceRoot launch)
    rawEipLeftStepClosed := certificate.rawEipSuccessorConcretizable
  }

/-- Adapt the combined invariant to native-source launch-family acceptance. -/
def CheckedNativeSourceInvariantLaunchFamilyEvidence.toCheckedNativeSourceLaunchFamily
    {project : NativeSourceProject}
    (evidence : CheckedNativeSourceInvariantLaunchFamilyEvidence project) :
    CheckedNativeSourceLaunchFamily project where
  realizable := evidence.launchRealizable
  source sourceRoot launch :=
    Nonempty.intro {
      domain := evidence.domainAtLaunch sourceRoot launch
      checkedProject := evidence.checkedProjectAtLaunch sourceRoot launch
    }

/-- Compatibility adapter for generated evidence whose invariant is the
state-insensitive finite reachability predicate. -/
def StaticNativeSourceLaunchFamilyEvidence.toInvariantLaunchFamilyEvidence
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project) :
    CheckedNativeSourceInvariantLaunchFamilyEvidence project where
  exactBinding := evidence.exactBinding
  instructionSemanticsAdequate := evidence.instructionSemanticsAdequate
  original := evidence.reachability.toInvariantFamilyEvidence
  invariantAtLaunch sourceRoot launch :=
    evidence.reachability.entryReachable sourceRoot.toWorldExecution
      launch.isProgramEntry
  activeTargets := evidence.activeTargets
  activeTargetIdsExact := evidence.activeTargetIdsExact
  launchRealizable := evidence.launchRealizable

/-- Specialize the static reachability family at one checked entry. -/
def StaticNativeSourceLaunchFamilyEvidence.reachabilityAtRoot
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (root : WorldExecution)
    (entry : WorldExecution.IsProgramEntry project.program.worldProgram root) :
    CheckedOriginalReachabilityEvidence project.program.worldProgram root :=
  evidence.reachability.atRoot root entry

/-- Package the specialized reachability invariant with its checked proof-open
and raw-EIP evidence. -/
def StaticNativeSourceLaunchFamilyEvidence.domainCertificateAtRoot
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (root : WorldExecution)
    (entry : WorldExecution.IsProgramEntry project.program.worldProgram root) :
    OriginalInvariantDomainCertificate project.program.worldProgram root :=
  let reachability := evidence.reachabilityAtRoot root entry
  {
    invariant := reachability.rooted.invariant
    rootHolds := reachability.rooted.rootHolds
    blocksExcluded := reachability.blocksExcluded
    rawConcretizable := reachability.rawConcretizable
  }

/-- The per-launch domain is definitionally the checked finite reachability
closure, not a submitted root-specific invariant. -/
def StaticNativeSourceLaunchFamilyEvidence.domainAtRoot
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (root : WorldExecution)
    (entry : WorldExecution.IsProgramEntry project.program.worldProgram root) :
    CheckedExecutionDomain project.program.worldProgram root :=
  (evidence.domainCertificateAtRoot root entry).domain

theorem StaticNativeSourceLaunchFamilyEvidence.domainAtRoot_holds_iff
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (root execution : WorldExecution)
    (entry : WorldExecution.IsProgramEntry project.program.worldProgram root) :
    (evidence.domainAtRoot root entry).holds execution <->
      OriginalExecutionReachable evidence.reachability.targetIds execution :=
  Iff.rfl

/-- Reachability membership and the static inventory equality construct the
root-specific active-target coverage required by semantic composition. -/
def StaticNativeSourceLaunchFamilyEvidence.activeTargetCoverageAtRoot
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (root : WorldExecution)
    (entry : WorldExecution.IsProgramEntry project.program.worldProgram root) :
    ActiveTargetDomainCoverage evidence.activeTargets
      (evidence.domainAtRoot root entry) :=
  ActiveTargetDomainCoverage.ofTargetMembership evidence.activeTargets
    (evidence.domainAtRoot root entry) evidence.reachability.targetIds
    evidence.activeTargetIdsExact
    (by
      intro targetId state calls eventIndex world inDomain
      exact (evidence.domainAtRoot_holds_iff root
        (.running targetId state calls eventIndex world) entry).mp inDomain |>.1)
    (by
      intro targetId state calls eventIndex world callbacks inDomain
      exact (evidence.domainAtRoot_holds_iff root
        (.callbackRunning targetId state calls eventIndex world callbacks)
        entry).mp inDomain |>.1)

/-- Assemble all root-specific source-project obligations from the static
evidence and the selected checked entry. -/
def StaticNativeSourceLaunchFamilyEvidence.checkedProjectAtRoot
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project)
    (root : WorldExecution)
    (entry : WorldExecution.IsProgramEntry project.program.worldProgram root) :
    CheckedNativeSourceProject project root (evidence.domainAtRoot root entry) :=
  let certificate := evidence.domainCertificateAtRoot root entry
  {
    exactBinding := evidence.exactBinding
    instructionSemanticsAdequate := evidence.instructionSemanticsAdequate
    decodedSemanticStepsAdmissible :=
      certificate.decodedSemanticStepsAdmissible
        evidence.instructionSemanticsAdequate
    programRecordKernelMatchesDecodedSemantics :=
      programRecordKernelMatchesDecodedSemantics_of_checkedTargets
        evidence.activeTargets (evidence.domainAtRoot root entry)
        (evidence.activeTargetCoverageAtRoot root entry)
    rawEipLeftStepClosed := certificate.rawEipSuccessorConcretizable
  }

/-- Derive source-side acceptance uniformly for every checked program entry. -/
def StaticNativeSourceLaunchFamilyEvidence.toCheckedNativeSourceLaunchFamily
    {project : NativeSourceProject}
    (evidence : StaticNativeSourceLaunchFamilyEvidence project) :
    CheckedNativeSourceLaunchFamily project :=
  evidence.toInvariantLaunchFamilyEvidence.toCheckedNativeSourceLaunchFamily

end StageA.Relational.NativeSource
