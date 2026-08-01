import StageA.RelationalSourceRawEIP
import StageA.RelationalSourceInterpreterKernel
import StageA.RelationalInterpreterNativeWorld

namespace StageA.Relational.NativeSource

open StageA.Formal
open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterTransfer
open StageA.Relational.InterpreterX87
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.InterpreterNativeWorld

abbrev SourceExecution := StageA.Relational.SourceWorld.Execution

/-!
Conditional native-source compilation for the one-sided source-equivalence
lane.

The exact original PE remains governed by `RelationalSourceRawEIP`.  This
module adds two separate layers:

* content and provenance values for the native-interpreter source project,
  pinned lowering stack, and exact compiled PE; and
* one explicitly named, profile-wide correctness hypothesis for every exact
  compilation produced by that complete lowering stack.

The hypothesis covers the renderer, semantic lowering, native runtime,
compiler, assembler, linker, and ABI lowering.  It is parametric in the
source kernel and its external world, so it preserves emitted calls,
callbacks, faults, termination, and world observations without postulating
the behavior of Windows or an imported API.

No generated artifact contains a field asserting original-to-compiled
equivalence.  The final theorem composes the checked original-to-source
simulation with the source-to-compiled simulation supplied by the sole named
toolchain hypothesis.
-/

inductive NativeSourceProfile where
  | checkedInterpreterV1
deriving Repr, DecidableEq

/-- Stable identity for one exact source or build artifact. -/
structure ArtifactIdentity where
  role : String
  sha256 : String
  byteLength : Nat
deriving Repr, DecidableEq

def ArtifactIdentity.Valid (identity : ArtifactIdentity) : Prop :=
  identity.role != "" /\
    identity.sha256.length = 64 /\
    0 < identity.byteLength

/-- Exact source content tied to its reviewed SHA-256 identity. -/
structure ExactSourceArtifact where
  identity : ArtifactIdentity
  bytes : Bytes
  identityValid : identity.Valid
  byteLengthExact : identity.byteLength = bytes.length
  sha256Exact : SHA256.checkedHex bytes identity.sha256 = true

/-- Nix recipe and realized-output identity.  These values are part of the
conditional premise; Nix attestation validates them before Lean generation. -/
structure NixRealizationIdentity where
  derivationPath : String
  derivationSha256 : String
  outputPath : String
  narHash : String
deriving Repr, DecidableEq

def NixRealizationIdentity.Valid (identity : NixRealizationIdentity) : Prop :=
  identity.derivationPath != "" /\
    identity.derivationSha256.length = 64 /\
    identity.outputPath != "" /\
    identity.narHash != ""

/-- Canonical semantic input to the pinned native renderer.  Ordinary records
are typed Lean data, while x87 behavior is represented by exact checked
schedules rather than by an independently supplied function. -/
structure CanonicalNativeProgramIR (worldProgram : DecodedWorldProgram) where
  records : List ProgramRecord
  x87Witnesses : List
    (ExactInterpreterX87ScheduleWitness worldProgram.context.originalPe)

def CanonicalNativeProgramIR.x87SourceRvas
    {worldProgram : DecodedWorldProgram}
    (ir : CanonicalNativeProgramIR worldProgram) : List Nat :=
  ir.x87Witnesses.map fun witness => witness.schedule.sourceRva

/-- Kernel-checked structural properties of the canonical native-program IR.
The rendered C is deliberately not parsed here: correctness of rendering this
typed input is part of the single pinned-stack hypothesis below. -/
structure CheckedNativeProgramInput (worldProgram : DecodedWorldProgram) where
  ir : CanonicalNativeProgramIR worldProgram
  recordsUnique :
    (ir.records.map (fun record : ProgramRecord => record.sourceRva)).Nodup
  x87SourcesUnique : ir.x87SourceRvas.Nodup

/-- The interpreter `Program` is determined definitionally by the checked IR.
In particular, the x87 provider cannot be replaced independently of its exact
witness inventory. -/
def CheckedNativeProgramInput.program
    {worldProgram : DecodedWorldProgram}
    (input : CheckedNativeProgramInput worldProgram) : Program := {
  worldProgram
  records := input.ir.records
  x87SourceRvas := input.ir.x87SourceRvas
  x87Provider := exactX87Provider input.ir.x87Witnesses
}

/-- One exact native source project.  The semantic `Program` is not a field:
it is definitionally derived from `checkedInput`.  Source bytes and Nix
identities remain exact provenance for the renderer/lowering/compiler stack. -/
structure NativeSourceProject where
  profile : NativeSourceProfile
  worldProgram : DecodedWorldProgram
  checkedInput : CheckedNativeProgramInput worldProgram
  bundleManifest : ArtifactIdentity
  rendererInputArtifact : ArtifactIdentity
  sourceArtifacts : List ArtifactIdentity
  nixIdentity : NixRealizationIdentity

def NativeSourceProject.program (project : NativeSourceProject) : Program :=
  project.checkedInput.program

def NativeSourceProject.kernel (project : NativeSourceProject) : Kernel :=
  project.program.kernel

def NativeSourceProject.Valid (project : NativeSourceProject) : Prop :=
  project.profile = .checkedInterpreterV1 /\
    0 < project.checkedInput.ir.records.length +
      project.checkedInput.ir.x87Witnesses.length /\
    project.bundleManifest.Valid /\
    project.rendererInputArtifact.Valid /\
    0 < project.sourceArtifacts.length /\
    (forall artifact, artifact ∈ project.sourceArtifacts -> artifact.Valid) /\
    (project.sourceArtifacts.map fun artifact => artifact.role).Nodup /\
    project.nixIdentity.Valid

/-- Every semantic part of the pinned native lowering stack is explicit. -/
structure PinnedNativeSourceToolchainProfile where
  identifier : String
  sourceProfile : NativeSourceProfile
  nixIdentity : NixRealizationIdentity
  rendererIdentifier : String
  rendererSha256 : String
  loweringIdentifier : String
  loweringSha256 : String
  runtimeIdentifier : String
  runtimeSha256 : String
  compilerIdentifier : String
  compilerSha256 : String
  assemblerIdentifier : String
  assemblerSha256 : String
  linkerIdentifier : String
  linkerSha256 : String
  abiIdentifier : String
  abiSha256 : String
deriving Repr, DecidableEq

def PinnedNativeSourceToolchainProfile.FullStackPinned
    (profile : PinnedNativeSourceToolchainProfile) : Prop :=
  profile.identifier != "" /\
    profile.sourceProfile = .checkedInterpreterV1 /\
    profile.nixIdentity.Valid /\
    profile.rendererIdentifier != "" /\ profile.rendererSha256.length = 64 /\
    profile.loweringIdentifier != "" /\ profile.loweringSha256.length = 64 /\
    profile.runtimeIdentifier != "" /\ profile.runtimeSha256.length = 64 /\
    profile.compilerIdentifier != "" /\ profile.compilerSha256.length = 64 /\
    profile.assemblerIdentifier != "" /\ profile.assemblerSha256.length = 64 /\
    profile.linkerIdentifier != "" /\ profile.linkerSha256.length = 64 /\
    profile.abiIdentifier != "" /\ profile.abiSha256.length = 64

/-- Exact compiled bytes and the PE value re-parsed from that same `ByteTree`.
The external digest is a cache/provenance identifier; semantic authority comes
from the Lean-resident bytes and exact parse, so large binaries are not
flattened and rehashed in every proof consumer. -/
structure CompiledArtifact where
  identity : ArtifactIdentity
  buildIdentity : NixRealizationIdentity
  sourceProjectNarHash : String
  toolchainNarHash : String
  bytes : ByteTree
  pe : PE32
  identityValid : identity.Valid
  byteLengthExact : identity.byteLength = bytes.length
  parsedExactly : parsePE32Tree bytes = some pe
  peBytesExact : pe.bytes = bytes

/-- Static build-attestation binding.  The exact output bytes are tied to the
source-project and toolchain NAR identities selected by the compilation. -/
structure CompiledArtifact.BuiltFrom (artifact : CompiledArtifact)
    (profile : PinnedNativeSourceToolchainProfile)
    (project : NativeSourceProject) : Prop where
  buildIdentityValid : artifact.buildIdentity.Valid
  sourceProjectExact :
    artifact.sourceProjectNarHash = project.nixIdentity.narHash
  toolchainExact : artifact.toolchainNarHash = profile.nixIdentity.narHash

/-- Checked, byte-derived machine execution profile for one compiled artifact.
The executable program below is definitionally built from `artifact.pe`; no
independently supplied decoded-region carrier can stand in for the output
binary. -/
structure ExactCompiledPE32Authority (artifact : CompiledArtifact) where
  importCertificate : ImportTableCertificate
  relocations : List BaseRelocation
  environment : NativeWorldEnvironment
  callableExternal : Option NativeCallableExternalConfig := none
  indirectTargets : NativeIndirectTargetInventory := {}
  importsParsed :
    importTableValid artifact.pe importCertificate = true
  relocationsParsed : parseRelocations artifact.pe = some relocations
  loaderImageValid : preferredBaseLoaderImageValid artifact.pe = true
  callableBound : forall config,
    callableExternal = some config ->
      config.BoundTo artifact.pe importCertificate.imports
  indirectTargetsValid : indirectTargets.valid artifact.pe = true

/-- Canonical exact machine program selected by a compiled-artifact authority. -/
def ExactCompiledPE32Authority.program
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact) : ExactNativeWorldProgram := {
  pe := artifact.pe
  imports := authority.importCertificate.imports
  environment := authority.environment
  callableExternal := authority.callableExternal
  indirectTargets := authority.indirectTargets
}

@[simp]
theorem ExactCompiledPE32Authority.program_pe
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact) :
    authority.program.pe = artifact.pe :=
  rfl

/-- Fixed fail-closed phase relation for the compiler simulation.  Internal
machine states and concrete EIPs may differ, but event position, relational
world, callback phase, faults, and termination phase cannot be forgotten.
Proof-blocked states never correspond. -/
def ExecutionPhaseMatches : SourceExecution -> NativeWorldExecution -> Prop
  | .running _ _ _ sourceEventIndex sourceWorld,
      .running _ _ _ _ compiledEventIndex _ compiledWorld =>
      sourceEventIndex = compiledEventIndex /\ sourceWorld = compiledWorld
  | .returned _ sourceWorld, .returned _ _ compiledWorld =>
      sourceWorld = compiledWorld
  | .terminated sourceWorld, .terminated _ compiledWorld =>
      sourceWorld = compiledWorld
  | .fault sourceCause, .fault compiledCause => sourceCause = compiledCause
  | _, _ => False

/-- Exact checked source-side package used by acceptance.  Each field is tied
to the program definitionally constructed from `project.checkedInput` and its
exact decoded original program by dependent types. -/
structure CheckedNativeSourceProject (project : NativeSourceProject)
    (root : WorldExecution)
    (domain : CheckedExecutionDomain project.program.worldProgram root) where
  exactBinding :
    ExactBinding project.program.worldProgram.context.originalPe project.program
  instructionSemanticsAdequate :
    project.program.worldProgram.InstructionSemanticsAdequate
  decodedSemanticStepsAdmissible :
    DecodedSemanticStepsAdmissible project.program.worldProgram domain
  programRecordKernelMatchesDecodedSemantics :
    ProgramRecordKernelMatchesDecodedSemantics project.program domain
  rawEipLeftStepClosed : RawEipLeftStepClosed project.program.worldProgram root domain

/-- Derive the raw-EIP original-to-source leg from the checked package.  In
particular, callers cannot inject an arbitrary source-equivalence proposition
at the acceptance theorem. -/
theorem CheckedNativeSourceProject.sourceEquivalent
    {project : NativeSourceProject} {root : WorldExecution}
    {domain : CheckedExecutionDomain project.program.worldProgram root}
    (checked : CheckedNativeSourceProject project root domain) :
    ExactRawOriginalPESourceKernelObservationallyEquivalent
      project.program.worldProgram project.kernel root domain := by
  have _binding := checked.exactBinding
  exact chunkedSimulation_rawEipLeft_of_logical
    (programRecordKernelChunkComposition project.program root domain
      checked.instructionSemanticsAdequate
      checked.decodedSemanticStepsAdmissible
      checked.programRecordKernelMatchesDecodedSemantics)
    checked.rawEipLeftStepClosed

/-- Loader-populated IAT words for one exact native PE.  The relational world
supplies paired external addresses, but this predicate deliberately indexes the
candidate side by the compiled PE's own import table rather than by the
historical candidate carried in the original decoded context. -/
def NativeImportAddressesMemoryHold (pe : PE32) (imports : List PEImport)
    (world : RelationalWorld) (memory : Memory) : Prop :=
  forall imported, imported ∈ imports ->
    exists binding, binding ∈ world.importAddresses /\
      binding.imported = normalizeImport imported /\
      Memory.read32 memory
          (BitVec.ofNat 32 (pe.imageBase + imported.iatRva)) =
        binding.candidateAddress /\
      binding.candidateAddress != BitVec.ofNat 32 0 /\
      !(pe.imageBase <= binding.candidateAddress.toNat &&
        binding.candidateAddress.toNat < pe.imageBase + pe.sizeOfImage)

/-- One bounded, one-sided PE32 console launch of the exact original image.
Unlike `WorldExecution.IsProgramEntry`, this binds the loaded image, IAT, and
initial external world as well as the control point. -/
structure CheckedNativeSourcePE32ConsoleLaunch (project : NativeSourceProject)
    (sourceRoot : SourceExecution) : Prop where
  launch : exists targetId state world,
    sourceRoot = .running targetId state [] 0 world /\
      project.program.worldProgram.candidate = false /\
      (exists target,
        project.program.worldProgram.context.codeMap.get? targetId = some target /\
          target.originalRva =
            project.program.worldProgram.context.originalPe.entrypointRva) /\
      PE32ConsoleLaunchWorldV1.Valid project.program.worldProgram.context world /\
      PreferredBaseImageMemory project.program.worldProgram.context.originalPe
        project.program.worldProgram.context.originalImports state.memory /\
      (forall binding, binding ∈ world.importAddresses ->
        Memory.read32 state.memory
            (BitVec.ofNat 32
              (project.program.worldProgram.context.originalPe.imageBase +
                binding.originalIatRva)) = binding.originalAddress)

theorem CheckedNativeSourcePE32ConsoleLaunch.isProgramEntry
    {project : NativeSourceProject} {sourceRoot : SourceExecution}
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    WorldExecution.IsProgramEntry project.program.worldProgram
      sourceRoot.toWorldExecution := by
  rcases launch.launch with
    ⟨targetId, state, world, rfl, originalSide,
      ⟨target, targetFound, targetRva⟩,
      worldValid, imageMapped, importMemory⟩
  change [] = [] /\ 0 = 0 /\ exists selected,
    project.program.worldProgram.context.codeMap.get? targetId = some selected /\
      (if project.program.worldProgram.candidate then selected.candidateRva
        else selected.originalRva) =
      (if project.program.worldProgram.candidate then
        project.program.worldProgram.context.candidatePe.entrypointRva
        else project.program.worldProgram.context.originalPe.entrypointRva)
  refine ⟨rfl, rfl, target, targetFound, ?_⟩
  simp [originalSide, targetRva]

/-- One exact console launch of the compiled artifact.  This predicate contains
no source state: correspondence with a source launch is supplied by the pinned
compiler-correctness premise below.  Keeping the two concerns separate avoids
quantifying compiler correctness over arbitrary, unrelated machine states. -/
structure CheckedCompiledPE32ConsoleLaunch
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact)
    (compiledRoot : NativeWorldExecution) : Prop where
  launch : exists compiledState compiledWorld,
    compiledRoot = .running artifact.pe.entrypointRva 0
      compiledState [] 0 [] compiledWorld /\
    PreferredBaseImageMemory artifact.pe authority.importCertificate.imports
      compiledState.memory /\
    NativeImportAddressesMemoryHold artifact.pe
      authority.importCertificate.imports compiledWorld compiledState.memory

/-- A source/compiled launch pair selected by the pinned lowering theorem.
Both roots are independently exact launches; `phaseMatches` rules out relating
different callback, fault, termination, world, or event phases. -/
structure CheckedNativeCompilationLaunch (project : NativeSourceProject)
    (sourceRoot : SourceExecution)
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact)
    (compiledRoot : NativeWorldExecution) : Prop where
  sourceLaunch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot
  compiledLaunch : CheckedCompiledPE32ConsoleLaunch authority compiledRoot
  phaseMatches : ExecutionPhaseMatches sourceRoot compiledRoot

/-- The exact compiled launch profile is inhabited.  This is checked
independently of the compiler hypothesis, so that hypothesis cannot authorize
acceptance by choosing an empty source/compiled correspondence. -/
def NativeCompilationLaunchRealizable
    {artifact : CompiledArtifact}
    (authority : ExactCompiledPE32Authority artifact) : Prop :=
  exists compiledRoot,
    CheckedCompiledPE32ConsoleLaunch authority compiledRoot

/-- Semantic consequence required from a correct pinned lowering stack.

One source macro-path may execute as many compiled x86 instructions.  The
compiled path must retain exactly the same `WorldRelationalObservable` list.
This quantifies over the kernel's external world rather than specifying API
results inside the compiler premise. -/
structure NativeCompilationSimulation (kernel : Kernel)
    (compiledProgram : ExactNativeWorldProgram)
    (sourceRoot : SourceExecution) (compiledRoot : NativeWorldExecution) where
  relation : SourceExecution -> NativeWorldExecution -> Prop
  rootRelated : relation sourceRoot compiledRoot
  phaseMatches : forall source compiled,
    relation source compiled -> ExecutionPhaseMatches source compiled
  compilePath : forall sourceBefore compiledBefore observations sourceAfter,
    relation sourceBefore compiledBefore ->
      NonemptyRelatedPath kernel.transitionSystem sourceBefore observations
        sourceAfter ->
      exists compiledAfter,
        NonemptyRelatedPath compiledProgram.transitionSystem
          compiledBefore observations compiledAfter /\
        relation sourceAfter compiledAfter

/-- One exact output of a pinned native source toolchain.  Static source,
build, and parsed-program authority are retained here; launch states are
quantified separately so acceptance cannot silently specialize the compiled
artifact to one command line or external-world instance. -/
structure ExactNativeCompilation where
  profile : PinnedNativeSourceToolchainProfile
  project : NativeSourceProject
  artifact : CompiledArtifact
  machineAuthority : ExactCompiledPE32Authority artifact
  projectValid : project.Valid
  profilePinned : profile.FullStackPinned
  profileMatches : project.profile = profile.sourceProfile
  builtFrom : artifact.BuiltFrom profile project

/-- The sole semantic hypothesis admitted by native-source acceptance.

The pinned stack must relate every exact compiled launch to a checked source
launch, and every checked source launch to an exact compiled launch.  The
simulation itself covers rendering, lowering, compilation, linking, ABI
lowering, and runtime execution.  It never asserts original-to-compiled
equivalence: the original-to-source leg remains Lean-checked independently.

The bidirectional launch clauses are essential.  A weak predicate over an
arbitrary source/compiled pair is generally false, while an existential-only
predicate could omit real compiled launches. -/
structure CorrectPinnedNativeSourceStackHypothesis
    (compilation : ExactNativeCompilation) : Prop where
  compiledLaunch : forall compiledRoot,
    CheckedCompiledPE32ConsoleLaunch compilation.machineAuthority compiledRoot ->
      exists sourceRoot,
        CheckedNativeCompilationLaunch compilation.project sourceRoot
            compilation.machineAuthority compiledRoot /\
          Nonempty (NativeCompilationSimulation compilation.project.kernel
            compilation.machineAuthority.program sourceRoot compiledRoot)
  sourceLaunch : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch compilation.project sourceRoot ->
      exists compiledRoot,
        CheckedNativeCompilationLaunch compilation.project sourceRoot
            compilation.machineAuthority compiledRoot /\
          Nonempty (NativeCompilationSimulation compilation.project.kernel
            compilation.machineAuthority.program sourceRoot compiledRoot)

/-- Checked original-to-source evidence for one source launch.  The execution
domain is retained existentially because different launch profiles may use
different inductive invariants while sharing the same exact source project. -/
structure CheckedNativeSourceLaunch (project : NativeSourceProject)
    (sourceRoot : SourceExecution) where
  domain : CheckedExecutionDomain project.program.worldProgram
    sourceRoot.toWorldExecution
  checkedProject : CheckedNativeSourceProject project
    sourceRoot.toWorldExecution domain

/-- Source-side proof coverage for every checked program entry.  This is the
acceptance boundary which prevents a whole-program claim from being silently
specialized to one argv/environment/world instance. -/
structure CheckedNativeSourceLaunchFamily (project : NativeSourceProject) where
  realizable : exists sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot
  source : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      Nonempty (CheckedNativeSourceLaunch project sourceRoot)

/-- The fixed mediated state relation used by the final theorem.  The checked
domain remains in the original-to-source leg and the compiler relation is the
only second leg. -/
def OriginalCompiledExecutionsMatch
    (original : DecodedWorldProgram) (root : WorldExecution)
    (domain : CheckedExecutionDomain original root)
    (compiledRelation : SourceExecution -> NativeWorldExecution -> Prop) :
    RawEipWorldExecution -> NativeWorldExecution -> Prop :=
  fun originalExecution compiledExecution =>
    exists sourceExecution,
      RawEipSourceExecutionsMatch original root domain originalExecution
          sourceExecution /\
        compiledRelation sourceExecution compiledExecution

/-- Direct, rooted exact-original-to-compiled-artifact observational
equivalence.  The mediated relation is existential proof evidence rather than
trusted computational data.  The exact artifact binding is retained in the
result, while the transition theorem remains about the exact parsed PE
semantics. -/
def ExactRawOriginalPECompiledArtifactObservationalEquivalence
    (original : DecodedWorldProgram) (root : WorldExecution)
    (domain : CheckedExecutionDomain original root)
    (profile : PinnedNativeSourceToolchainProfile)
    (project : NativeSourceProject) (artifact : CompiledArtifact)
    (machineAuthority : ExactCompiledPE32Authority artifact)
    (compiledRoot : NativeWorldExecution) : Prop :=
  project.Valid /\ profile.FullStackPinned /\
    project.profile = profile.sourceProfile /\
    artifact.BuiltFrom profile project /\
    exists executionRelation :
        RawEipWorldExecution -> NativeWorldExecution -> Prop,
      (forall originalRaw,
        root.ConcretizesToRawEip original originalRaw ->
          executionRelation originalRaw compiledRoot) /\
      (forall originalRaw compiledRaw,
        executionRelation originalRaw compiledRaw ->
          exists sourceExecution,
            RawEipSourceExecutionsMatch original root domain originalRaw
                sourceExecution /\
              ExecutionPhaseMatches sourceExecution compiledRaw) /\
      ChunkedRelationalBisimulation
        original.pe32RawEipTransitionSystem
        machineAuthority.program.transitionSystem executionRelation
        sourceObservationsRelated

/-- Acceptance-facing composition.  Source equivalence is derived from the
checked project fields; the only separate semantic assumption is universal
correctness of the selected pinned renderer/lowering/runtime/toolchain/ABI
profile. -/
theorem compiledArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
    (compilation : ExactNativeCompilation)
    (sourceRoot : SourceExecution) (compiledRoot : NativeWorldExecution)
    (launchChecked : CheckedNativeCompilationLaunch compilation.project
      sourceRoot compilation.machineAuthority compiledRoot)
    {domain : CheckedExecutionDomain compilation.project.program.worldProgram
      sourceRoot.toWorldExecution}
    (checkedProject : CheckedNativeSourceProject compilation.project
      sourceRoot.toWorldExecution domain)
    (simulation : NativeCompilationSimulation compilation.project.kernel
      compilation.machineAuthority.program sourceRoot compiledRoot) :
    ExactRawOriginalPECompiledArtifactObservationalEquivalence
      compilation.project.program.worldProgram
      sourceRoot.toWorldExecution domain compilation.profile
      compilation.project
      compilation.artifact compilation.machineAuthority
      compiledRoot := by
  let sourceEquivalent := checkedProject.sourceEquivalent
  let relation := OriginalCompiledExecutionsMatch
    compilation.project.program.worldProgram
    sourceRoot.toWorldExecution domain simulation.relation
  refine ⟨compilation.projectValid, compilation.profilePinned,
    compilation.profileMatches, compilation.builtFrom,
    relation, ?_, ?_, ?_⟩
  · intro originalRaw originalConcrete
    refine ⟨sourceRoot, ?_, simulation.rootRelated⟩
    exact ⟨sourceRoot.toWorldExecution, originalConcrete,
      by simpa using ExecutionsMatch.root domain⟩
  · intro originalRaw compiledRaw related
    rcases related with ⟨sourceExecution, originalSource, sourceCompiled⟩
    exact ⟨sourceExecution, originalSource,
      simulation.phaseMatches sourceExecution compiledRaw sourceCompiled⟩
  · intro originalBefore compiledBefore beforeRelated
    rcases beforeRelated with
      ⟨sourceBefore, originalSourceBefore, sourceCompiledBefore⟩
    rcases sourceEquivalent originalBefore sourceBefore originalSourceBefore with
      ⟨originalObservations, sourceObservations, originalAfter, sourceAfter,
        originalPath, sourcePath, observationsRelated, originalSourceAfter⟩
    rcases simulation.compilePath sourceBefore compiledBefore
        sourceObservations sourceAfter sourceCompiledBefore sourcePath with
      ⟨compiledAfter, compiledPath, sourceCompiledAfter⟩
    exact ⟨originalObservations, sourceObservations, originalAfter,
      compiledAfter, originalPath, compiledPath, observationsRelated,
      ⟨sourceAfter, originalSourceAfter, sourceCompiledAfter⟩⟩

/-- Launch-universal acceptance statement for one exact source compilation.
Every source/compiled root pair satisfying the checked launch relation obtains
an exact original-to-compiled theorem and the particular checked source domain
which justifies it. -/
def ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence
    (compilation : ExactNativeCompilation) : Prop :=
  NativeCompilationLaunchRealizable compilation.machineAuthority /\
    forall compiledRoot,
      CheckedCompiledPE32ConsoleLaunch compilation.machineAuthority compiledRoot ->
        exists sourceRoot,
          exists sourceLaunch : CheckedNativeSourceLaunch compilation.project
              sourceRoot,
            ExactRawOriginalPECompiledArtifactObservationalEquivalence
              compilation.project.program.worldProgram
              sourceRoot.toWorldExecution sourceLaunch.domain
              compilation.profile compilation.project compilation.artifact
              compilation.machineAuthority compiledRoot

/-- Final launch-family composition.  Static artifact authority, source
semantics, and compiler correctness remain separate inputs, but no concrete
launch is selected by the theorem. -/
theorem compiledArtifactLaunchFamilyEquivalentUnderPinnedNativeSourceStackHypothesis
    (compilation : ExactNativeCompilation)
    (sourceFamily : CheckedNativeSourceLaunchFamily compilation.project)
    (launchRealizable : NativeCompilationLaunchRealizable
      compilation.machineAuthority)
    (toolchainCorrect : CorrectPinnedNativeSourceStackHypothesis compilation) :
    ExactRawOriginalPECompiledArtifactLaunchFamilyEquivalence compilation := by
  refine ⟨launchRealizable, ?_⟩
  intro compiledRoot compiledLaunch
  rcases toolchainCorrect.compiledLaunch compiledRoot compiledLaunch with
    ⟨sourceRoot, launchChecked, ⟨simulation⟩⟩
  rcases sourceFamily.source sourceRoot launchChecked.sourceLaunch with
    ⟨sourceLaunch⟩
  refine ⟨sourceRoot, sourceLaunch, ?_⟩
  exact compiledArtifactEquivalentUnderPinnedNativeSourceStackHypothesis
    compilation sourceRoot compiledRoot launchChecked
      sourceLaunch.checkedProject simulation

end StageA.Relational.NativeSource
