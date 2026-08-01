import StageA.RelationalNativeSourceLaunchFamily
import StageA.RelationalOriginalCombinedTargetStepIndex

namespace StageA.Relational.OriginalSourceLaunchContext

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.NativeSource
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalCombinedTargetStepIndex
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.SourceWorld
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.SourceWorld.ProgramCertificate

/-!
# Exact original-source launch context

This module is the stable, program-independent boundary between static PE32
launch facts and whole-program original execution preservation.  It separates
two responsibilities which must not be conflated:

* `OriginalCombinedPE32ConsoleLaunchSeed` proves that every exact bounded
  console launch establishes each component of the submitted combined
  invariant; and
* `OriginalSourceAwaitingExternalHook` supplies preservation for an external
  suspension without changing, weakening, or reinterpreting that invariant.

The static context can therefore be checked before any API-specific protocol
semantics exists.  Supplying the external hook closes the invariant and exposes
the exact `ProgramRecord`/decoded-kernel compatibility theorem used by source
acceptance.  No field is a status bit or a declaration name.
-/

/-- Component-wise launch evidence for one exact PE32 source project.  Keeping
the six inventory components plus the runtime-memory partition explicit gives
generators precise fail-closed obligations instead of allowing a monolithic
`inventory.Holds` assertion to hide a missing launch fact. -/
structure OriginalCombinedPE32ConsoleLaunchSeed
    (project : NativeSourceProject)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext) : Prop where
  reachable : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      OriginalExecutionReachable inventory.reachableTargets.targetIds
        sourceRoot.toWorldExecution
  staticWords : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      inventory.staticWords.Holds project.program.worldProgram.context
        sourceRoot.toWorldExecution
  callFrames : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      OriginalCallFrameExecutionHolds project.program.worldProgram.context
        sourceRoot.toWorldExecution
  valueFlows : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      inventory.valueFlows.Holds sourceRoot.toWorldExecution
  registerTargets : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      OriginalRegisterTargetsHold inventory.registerTargets
        sourceRoot.toWorldExecution
  stackDynamicTargets : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      OriginalStackDynamicTargetsHold inventory.stackDynamicTargets
        sourceRoot.toWorldExecution
  runtimeMemory : forall sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot ->
      OriginalRuntimeMemoryPartition.ExecutionHolds
        project.program.worldProgram.context sourceRoot.toWorldExecution

/-- The component seed establishes the authoritative conjunction at every
checked launch. -/
theorem OriginalCombinedPE32ConsoleLaunchSeed.holds
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (seed : OriginalCombinedPE32ConsoleLaunchSeed project originalContext
      inventory)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    inventory.Holds sourceRoot.toWorldExecution :=
  ⟨seed.reachable sourceRoot launch, seed.staticWords sourceRoot launch,
    seed.callFrames sourceRoot launch, seed.valueFlows sourceRoot launch,
    seed.registerTargets sourceRoot launch,
    seed.stackDynamicTargets sourceRoot launch,
    seed.runtimeMemory sourceRoot launch⟩

/-- API-independent static context.  Every declaration is indexed by the exact
project program, source binding, combined inventory, and checked target index.
External responses are deliberately absent. -/
structure CheckedOriginalSourceStaticLaunchContext
    (project : NativeSourceProject)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext) where
  exactBinding : ExactBinding project.program.worldProgram.context.originalPe
    project.program
  instructionSemanticsAdequate :
    project.program.worldProgram.InstructionSemanticsAdequate
  activeTargets : ActiveTargetTransitionIndex exactBinding
  activeTargetIdsExact :
    activeTargets.certificates.map (fun certificate => certificate.targetId) =
      inventory.reachableTargets.targetIds
  launchSeed : OriginalCombinedPE32ConsoleLaunchSeed project originalContext
    inventory
  launchRealizable : exists sourceRoot,
    CheckedNativeSourcePE32ConsoleLaunch project sourceRoot

/-- The only external interface needed to close the one-sided invariant.
Constructors for concrete machine protocols live outside this static context. -/
structure OriginalSourceAwaitingExternalHook
    {project : NativeSourceProject}
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext) where
  preservation : OriginalCombinedAwaitingExternalPreservation originalContext
    inventory

/-- Closed context after a separately checked environment implementation has
provided the typed external-preservation hook. -/
structure CheckedOriginalSourceLaunchContext
    (project : NativeSourceProject)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext) where
  static : CheckedOriginalSourceStaticLaunchContext project originalContext
    inventory
  targetStepIndex : OriginalCombinedTargetStepIndex static.exactBinding
    originalContext inventory
  targetStepIndexExact : targetStepIndex.transitions = static.activeTargets
  external : OriginalSourceAwaitingExternalHook originalContext inventory

def CheckedOriginalSourceLaunchContext.checkedCombinedInvariant
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory) :
    CheckedOriginalCombinedExecutionInvariant project.program.worldProgram
      originalContext inventory :=
  originalCombinedInvariant_of_indexedTargets context.targetStepIndex
    context.external.preservation

abbrev CheckedOriginalSourceLaunchContext.combinedInvariant
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory) : OriginalWorldExecutionInvariant project.program.worldProgram :=
  CheckedOriginalCombinedExecutionInvariant.toOriginalInvariant
    (CheckedOriginalSourceLaunchContext.checkedCombinedInvariant context)

def CheckedOriginalSourceLaunchContext.invariantFamilyEvidence
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory) : CheckedOriginalInvariantFamilyEvidence
      project.program.worldProgram :=
  CheckedOriginalCombinedExecutionInvariant.toInvariantFamilyEvidence
    (CheckedOriginalSourceLaunchContext.checkedCombinedInvariant context)

theorem CheckedOriginalSourceLaunchContext.combinedInvariantAtLaunch
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    context.combinedInvariant.holds sourceRoot.toWorldExecution :=
  context.static.launchSeed.holds sourceRoot launch

def CheckedOriginalSourceLaunchContext.launchFamilyEvidence
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory) : CheckedNativeSourceInvariantLaunchFamilyEvidence project where
  exactBinding := context.static.exactBinding
  instructionSemanticsAdequate := context.static.instructionSemanticsAdequate
  original := context.invariantFamilyEvidence
  invariantAtLaunch := context.combinedInvariantAtLaunch
  activeTargets := context.static.activeTargets
  activeTargetIdsExact := context.static.activeTargetIdsExact
  launchRealizable := context.static.launchRealizable

/-- Exact `ProgramRecord`/decoded-kernel compatibility at every checked launch.
This is derived from the checked target index and launch domain; it is not a
separately submitted compatibility theorem. -/
theorem CheckedOriginalSourceLaunchContext.programRecordKernelCompatibility
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    ProgramRecordKernelMatchesDecodedSemantics project.program
      (context.launchFamilyEvidence.domainAtLaunch sourceRoot launch) :=
  (context.launchFamilyEvidence.checkedProjectAtLaunch sourceRoot launch).programRecordKernelMatchesDecodedSemantics

/-- Non-circular compatibility interface for preservation producers.  The
static launch artifact exports this theorem before target preservation exists;
the eventual target index and external hook are explicit arguments. -/
theorem CheckedOriginalSourceStaticLaunchContext.programRecordKernelCompatibility
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (static : CheckedOriginalSourceStaticLaunchContext project originalContext
      inventory)
    (targetStepIndex : OriginalCombinedTargetStepIndex static.exactBinding
      originalContext inventory)
    (targetStepIndexExact : targetStepIndex.transitions = static.activeTargets)
    (external : OriginalSourceAwaitingExternalHook originalContext inventory)
    (sourceRoot : SourceExecution)
    (launch : CheckedNativeSourcePE32ConsoleLaunch project sourceRoot) :
    let context : CheckedOriginalSourceLaunchContext project originalContext
        inventory := {
      static := static
      targetStepIndex := targetStepIndex
      targetStepIndexExact := targetStepIndexExact
      external := external
    }
    ProgramRecordKernelMatchesDecodedSemantics project.program
      (context.launchFamilyEvidence.domainAtLaunch sourceRoot launch) := by
  let context : CheckedOriginalSourceLaunchContext project originalContext
      inventory := {
    static := static
    targetStepIndex := targetStepIndex
    targetStepIndexExact := targetStepIndexExact
    external := external
  }
  exact context.programRecordKernelCompatibility sourceRoot launch

def CheckedOriginalSourceLaunchContext.toCheckedNativeSourceLaunchFamily
    {project : NativeSourceProject}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory
      project.program.worldProgram originalContext}
    (context : CheckedOriginalSourceLaunchContext project originalContext
      inventory) : CheckedNativeSourceLaunchFamily project :=
  context.launchFamilyEvidence.toCheckedNativeSourceLaunchFamily

#print axioms OriginalCombinedPE32ConsoleLaunchSeed.holds
#print axioms CheckedOriginalSourceLaunchContext.checkedCombinedInvariant
#print axioms CheckedOriginalSourceLaunchContext.combinedInvariantAtLaunch
#print axioms CheckedOriginalSourceLaunchContext.programRecordKernelCompatibility
#print axioms CheckedOriginalSourceStaticLaunchContext.programRecordKernelCompatibility
#print axioms CheckedOriginalSourceLaunchContext.toCheckedNativeSourceLaunchFamily

end StageA.Relational.OriginalSourceLaunchContext
