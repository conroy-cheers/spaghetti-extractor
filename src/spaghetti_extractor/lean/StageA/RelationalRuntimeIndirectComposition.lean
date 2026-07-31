import StageA.RelationalGuardedRuntimeCut
import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalInterpreterNativeLaunch
import StageA.RelationalNullableCodePointerRootedUnreachability
import StageA.RelationalRuntimeIndirectEffects
import StageA.RelationalRuntimeValueCarrySemantics

namespace StageA.Relational.RuntimeIndirectComposition

open StageA.Formal StageA.Relational
open StageA.Relational.GuardedRuntimeCut
open StageA.Relational.InternalDirectCallComposition
open StageA.Relational.InternalDirectCallMixedOriginalIntegration
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.MixedExecutionInvariantExtension
open StageA.Relational.NullableCodePointerRootedUnreachability
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.RuntimeValueCarry
open StageA.Relational.RuntimeValueCarrySemantics
open StageA.Relational.RuntimeIndirectEffects
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

/-!
# One typed runtime-indirect composition certificate

This module consolidates the three common rooted runtime-indirect outcomes:

* a finite stack-carried code target;
* a guarded indexed source which is unreachable;
* a guarded dynamic source which is unreachable.

The inventory is diagnostic data only until Lean checks its exact stable IDs
and source identities. The exported closures are derived from one combined
inductive invariant and cannot be replaced by a zero blocker count.
-/

inductive FrontierKind where
  | stackFinite
  | indexedGuarded
  | dynamicGuarded
deriving Repr, DecidableEq, BEq

structure FrontierDescriptor where
  stableId : String
  kind : FrontierKind
  sourceTargetId : Nat
deriving Repr, DecidableEq, BEq

structure FrontierInventory where
  frontiers : List FrontierDescriptor
deriving Repr, DecidableEq

def FrontierInventory.checked
    (inventory : FrontierInventory)
    (stackStableId constructorStableId dynamicStableId : String)
    (stackSource constructorSource dynamicSource : Nat) : Bool :=
  match inventory.frontiers with
  | [stack, constructor, dynamic] =>
      stack.stableId == stackStableId &&
        stack.kind == .stackFinite &&
        stack.sourceTargetId == stackSource &&
        constructor.stableId == constructorStableId &&
        constructor.kind == .indexedGuarded &&
        constructor.sourceTargetId == constructorSource &&
        dynamic.stableId == dynamicStableId &&
        dynamic.kind == .dynamicGuarded &&
        dynamic.sourceTargetId == dynamicSource &&
        inventory.frontiers.all (fun frontier => frontier.stableId != "") &&
        noDuplicates (inventory.frontiers.map (·.stableId)) &&
        noDuplicates (inventory.frontiers.map (·.sourceTargetId))
  | _ => false

/-! ## Canonical selected-component strengthening

Runtime-indirect facts are established over the exact component selected by
the checked mixed-kernel source classifier.  Quantifying over an arbitrary
`MixedWorldComponentChunkRefinement` is both unnecessarily strong and loses
the semantic witness retained by the classifier's component producer.

This interface keeps the original and candidate paths authoritative while
making the induction premise refer to exactly one executable component.  It
cannot be inhabited by a detached theorem about a submitted path.
-/

structure SelectedMixedComponentInvariantExtension
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot :
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva}
    (composition : MixedWorldChunkComposition originalContext
      originalAuthority original candidate candidateAuthority programBinding
      contract launch originalRoot reachability candidateRootRva
      candidateRoot) where
  holds : WorldExecution ->
    StageA.Relational.InterpreterNativeWorld.NativeWorldExecution -> Prop
  componentClosed : forall originalBefore candidateBefore,
    (related :
      composition.invariant.holds originalBefore candidateBefore) ->
      (_extensionHolds : holds originalBefore candidateBefore) ->
      let selected :=
        composition.component originalBefore candidateBefore
          related
      holds selected.originalAfter selected.candidateAfter

def SelectedMixedComponentInvariantExtension.strengthenedInvariant
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot :
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva}
    {composition : MixedWorldChunkComposition originalContext
      originalAuthority original candidate candidateAuthority programBinding
      contract launch originalRoot reachability candidateRootRva
      candidateRoot}
    (extension : SelectedMixedComponentInvariantExtension composition) :
    MixedExecutionInvariant reachability.targetIds contract where
  holds originalExecution candidateExecution :=
    composition.invariant.holds originalExecution candidateExecution /\
      extension.holds originalExecution candidateExecution
  originalReachable originalExecution candidateExecution related :=
    composition.invariant.originalReachable originalExecution
      candidateExecution related.1
  candidateProofOpen originalExecution candidateExecution related :=
    composition.invariant.candidateProofOpen originalExecution
      candidateExecution related.1
  worldsRelated originalExecution candidateExecution originalWorld
      candidateWorld related originalWorldExact candidateWorldExact :=
    composition.invariant.worldsRelated originalExecution candidateExecution
      originalWorld candidateWorld related.1 originalWorldExact
      candidateWorldExact
  machineStatesRelated originalExecution candidateExecution originalWorld
      candidateWorld originalState candidateState related originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact :=
    composition.invariant.machineStatesRelated originalExecution
      candidateExecution originalWorld candidateWorld originalState
      candidateState related.1 originalWorldExact candidateWorldExact
      originalStateExact candidateStateExact

def SelectedMixedComponentInvariantExtension.strengthen
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot :
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva}
    {composition : MixedWorldChunkComposition originalContext
      originalAuthority original candidate candidateAuthority programBinding
      contract launch originalRoot reachability candidateRootRva
      candidateRoot}
    (extension : SelectedMixedComponentInvariantExtension composition) :
    MixedWorldChunkComposition originalContext originalAuthority original
      candidate candidateAuthority programBinding contract launch originalRoot
      reachability candidateRootRva candidateRoot where
  invariant := extension.strengthenedInvariant
  component originalBefore candidateBefore related := by
    let selected :=
      composition.component originalBefore candidateBefore related.1
    exact {
      beforeRelated := related
      originalObservations := selected.originalObservations
      candidateObservations := selected.candidateObservations
      originalAfter := selected.originalAfter
      candidateAfter := selected.candidateAfter
      originalPath := selected.originalPath
      candidatePath := selected.candidatePath
      observationsRelated := selected.observationsRelated
      afterRelated := {
        left := selected.afterRelated
        right := extension.componentClosed originalBefore candidateBefore
          related.1 related.2
      }
    }

/-! ## Classifier-selected invariant closure

The common component interface intentionally exposes only paths and endpoint
relatedness.  Invariant synthesis needs the stronger checked certificate while
proving preservation.  These callbacks are invoked while the exact classifier
arm and its semantic certificate are still in scope, before the component is
erased to the common interface.
-/

structure CheckedMixedKernelSelectedInvariantClosure
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {program : CompiledKernelProgram}
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation}
    {invariant : MixedExecutionInvariant reachability.targetIds contract}
    (cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability candidateRootRva program abi dispatches invariant) where
  holds : WorldExecution ->
    StageA.Relational.InterpreterNativeWorld.NativeWorldExecution -> Prop
  semanticClosed : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry : nativeExecutionAtRva entryRva candidateBefore)
      (candidateWorld : RelationalWorld)
      (candidateWorldExact :
        nativeExecutionWorld? candidateBefore = some candidateWorld)
      (entryExact : program.functionEntry? operation.role = some entryRva)
      (classified :
        cases.classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .semanticTransfer source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    holds originalBefore candidateBefore ->
      let certificate :=
        cases.semanticChunk originalBefore candidateBefore source operation
          entryRva beforeRelated originalAtSource candidateAtEntry candidateWorld
          candidateWorldExact entryExact classified
      holds certificate.paths.originalAfter certificate.paths.candidateAfter
  externalOperationClosed : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtEntry : nativeExecutionAtRva entryRva candidateBefore)
      (candidateWorld : RelationalWorld)
      (candidateWorldExact :
        nativeExecutionWorld? candidateBefore = some candidateWorld)
      (entryExact : program.functionEntry? operation.role = some entryRva)
      (classified :
        cases.classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .externalOperation source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    holds originalBefore candidateBefore ->
      let certificate :=
        cases.externalOperationChunk originalBefore candidateBefore source
          operation entryRva beforeRelated originalAtSource candidateAtEntry
          candidateWorld candidateWorldExact entryExact classified
      holds certificate.paths.originalAfter certificate.paths.candidateAfter
  externalBoundaryClosed : forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource originalContext originalAuthority
        launch originalRoot reachability candidate candidateAuthority)
      (candidateRva : Nat)
      (beforeRelated : invariant.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtSource : nativeExecutionAtRva candidateRva candidateBefore)
      (classified :
        cases.classifier.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .externalBoundary source candidateRva originalAtSource
            candidateAtSource),
    holds originalBefore candidateBefore ->
      let paths :=
        cases.externalBoundaryChunk originalBefore candidateBefore source
          candidateRva beforeRelated originalAtSource candidateAtSource
          classified
      holds paths.originalAfter paths.candidateAfter

def CheckedMixedKernelSelectedInvariantClosure.strengthenedInvariant
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {program : CompiledKernelProgram}
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation}
    {invariant : MixedExecutionInvariant reachability.targetIds contract}
    {cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability candidateRootRva program abi dispatches invariant}
    (closure : CheckedMixedKernelSelectedInvariantClosure cases) :
    MixedExecutionInvariant reachability.targetIds contract where
  holds originalExecution candidateExecution :=
    invariant.holds originalExecution candidateExecution /\
      closure.holds originalExecution candidateExecution
  originalReachable originalExecution candidateExecution related :=
    invariant.originalReachable originalExecution candidateExecution related.1
  candidateProofOpen originalExecution candidateExecution related :=
    invariant.candidateProofOpen originalExecution candidateExecution related.1
  worldsRelated originalExecution candidateExecution originalWorld
      candidateWorld related originalWorldExact candidateWorldExact :=
    invariant.worldsRelated originalExecution candidateExecution originalWorld
      candidateWorld related.1 originalWorldExact candidateWorldExact
  machineStatesRelated originalExecution candidateExecution originalWorld
      candidateWorld originalState candidateState related originalWorldExact
      candidateWorldExact originalStateExact candidateStateExact :=
    invariant.machineStatesRelated originalExecution candidateExecution
      originalWorld candidateWorld originalState candidateState related.1
      originalWorldExact candidateWorldExact originalStateExact
      candidateStateExact

private def strengthenedComponentOfPaths
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {program : CompiledKernelProgram}
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation}
    {invariant : MixedExecutionInvariant reachability.targetIds contract}
    {cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability candidateRootRva program abi dispatches invariant}
    (closure : CheckedMixedKernelSelectedInvariantClosure cases)
    (paths : MixedKernelChunkPaths original candidate contract invariant
      originalBefore candidateBefore)
    (beforeRelated :
      closure.strengthenedInvariant.holds originalBefore candidateBefore)
    (afterHolds :
      closure.holds paths.originalAfter paths.candidateAfter) :
    MixedWorldComponentChunkRefinement original candidate contract
      closure.strengthenedInvariant originalBefore candidateBefore := {
  beforeRelated
  originalObservations := paths.originalObservations
  candidateObservations := paths.candidateObservations
  originalAfter := paths.originalAfter
  candidateAfter := paths.candidateAfter
  originalPath := paths.originalPath
  candidatePath := paths.candidatePath
  observationsRelated := paths.observationsChecked.related
  afterRelated := ⟨paths.afterRelated, afterHolds⟩
}

def CheckedMixedKernelSelectedInvariantClosure.toMixedWorldChunkComposition
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot :
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva}
    {program : CompiledKernelProgram}
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation}
    {invariant : MixedExecutionInvariant reachability.targetIds contract}
    {cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability candidateRootRva program abi dispatches invariant}
    (closure : CheckedMixedKernelSelectedInvariantClosure cases) :
    MixedWorldChunkComposition originalContext originalAuthority original
      candidate candidateAuthority programBinding contract launch originalRoot
      reachability candidateRootRva candidateRoot where
  invariant := closure.strengthenedInvariant
  component originalBefore candidateBefore beforeRelated := by
    have runtimeOnly :=
      cases.classifier.runtimeOnly originalBefore candidateBefore
        beforeRelated.1
    cases classified : cases.classifier.classifier.classify originalBefore
        candidateBefore beforeRelated.1 with
    | launchDispatch source sourceIsRoot originalAtSource candidateAtRoot =>
        rw [classified] at runtimeOnly
        exact False.elim runtimeOnly
    | semanticTransfer source operation entryRva originalAtSource
        candidateAtEntry entryExact =>
        let candidateRunning := exactNativeRunningWorldAtRva candidateAtEntry
        let certificate :=
          cases.semanticChunk originalBefore candidateBefore source operation
            entryRva beforeRelated.1 originalAtSource candidateAtEntry
            candidateRunning.world candidateRunning.worldExact entryExact classified
        exact strengthenedComponentOfPaths closure certificate.paths
          beforeRelated
          (closure.semanticClosed originalBefore candidateBefore source operation
            entryRva beforeRelated.1 originalAtSource candidateAtEntry
            candidateRunning.world candidateRunning.worldExact entryExact
            classified beforeRelated.2)
    | externalOperation source operation entryRva originalAtSource
        candidateAtEntry entryExact =>
        let candidateRunning := exactNativeRunningWorldAtRva candidateAtEntry
        let certificate :=
          cases.externalOperationChunk originalBefore candidateBefore source
            operation entryRva beforeRelated.1 originalAtSource candidateAtEntry
            candidateRunning.world candidateRunning.worldExact entryExact
            classified
        exact strengthenedComponentOfPaths closure certificate.paths
          beforeRelated
          (closure.externalOperationClosed originalBefore candidateBefore source
            operation entryRva beforeRelated.1 originalAtSource candidateAtEntry
            candidateRunning.world candidateRunning.worldExact entryExact
            classified beforeRelated.2)
    | externalBoundary source candidateRva originalAtSource candidateAtSource =>
        let paths :=
          cases.externalBoundaryChunk originalBefore candidateBefore source
            candidateRva beforeRelated.1 originalAtSource candidateAtSource
            classified
        exact strengthenedComponentOfPaths closure paths beforeRelated
          (closure.externalBoundaryClosed originalBefore candidateBefore source
            candidateRva beforeRelated.1 originalAtSource candidateAtSource
            classified beforeRelated.2)
    | returned originalState candidateState originalWorld candidateWorld
        candidateEvents =>
        refine {
          beforeRelated
          originalObservations := []
          candidateObservations := []
          originalAfter := .returned originalState originalWorld
          candidateAfter := .returned candidateState candidateEvents candidateWorld
          originalPath := ?_
          candidatePath := ?_
          observationsRelated := by trivial
          afterRelated := beforeRelated
        }
        · simpa [DecodedWorldProgram.pe32TransitionSystem,
            stepPE32WorldExecution] using
            (nonemptyRelatedPath_one original.pe32TransitionSystem
              (.returned originalState originalWorld))
        · simpa [StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram.transitionSystem,
            StageA.Relational.InterpreterNativeWorld.stepPE32NativeWorldExecution] using
            (nonemptyRelatedPath_one candidate.transitionSystem
              (.returned candidateState candidateEvents candidateWorld))
    | terminated originalWorld candidateWorld candidateEvents =>
        refine {
          beforeRelated
          originalObservations := []
          candidateObservations := []
          originalAfter := .terminated originalWorld
          candidateAfter := .terminated candidateEvents candidateWorld
          originalPath := ?_
          candidatePath := ?_
          observationsRelated := by trivial
          afterRelated := beforeRelated
        }
        · simpa [DecodedWorldProgram.pe32TransitionSystem,
            stepPE32WorldExecution] using
            (nonemptyRelatedPath_one original.pe32TransitionSystem
              (.terminated originalWorld))
        · simpa [StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram.transitionSystem,
            StageA.Relational.InterpreterNativeWorld.stepPE32NativeWorldExecution] using
            (nonemptyRelatedPath_one candidate.transitionSystem
              (.terminated candidateEvents candidateWorld))
    | fault cause =>
        refine {
          beforeRelated
          originalObservations := []
          candidateObservations := []
          originalAfter := .fault cause
          candidateAfter := .fault cause
          originalPath := ?_
          candidatePath := ?_
          observationsRelated := by trivial
          afterRelated := beforeRelated
        }
        · simpa [DecodedWorldProgram.pe32TransitionSystem,
            stepPE32WorldExecution] using
            (nonemptyRelatedPath_one original.pe32TransitionSystem (.fault cause))
        · simpa [StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram.transitionSystem,
            StageA.Relational.InterpreterNativeWorld.stepPE32NativeWorldExecution] using
            (nonemptyRelatedPath_one candidate.transitionSystem (.fault cause))

/-- The exact adapter required to turn a rooted scanner SCC certificate into a
mixed source-exclusion result. The rooted certificate proves that its source is
absent from `RootedScannerOperationalReachable`; this projection ties that
operational reachability to the classifier-selected invariant. It cannot be
constructed from graph reachability or a report status. -/
structure CheckedRootedScannerSelectedSourceProjection
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {program : CompiledKernelProgram}
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation}
    {invariant : MixedExecutionInvariant reachability.targetIds contract}
    {cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability candidateRootRva program abi dispatches invariant}
    (closure : CheckedMixedKernelSelectedInvariantClosure cases)
    {site : OriginalIndirectControlSite}
    (rooted :
      CheckedRootedScannerSccExecution originalContext site) : Prop where
  project : forall originalExecution candidateExecution,
    closure.holds originalExecution candidateExecution ->
      originalExecutionAtTargetId site.sourceTargetId originalExecution ->
      RootedScannerOperationalReachable rooted site.sourceTargetId

theorem CheckedRootedScannerSelectedSourceProjection.sourceUninhabited
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {program : CompiledKernelProgram}
    {abi : KernelABIRelation}
    {dispatches : RelationalWorld -> KernelDispatchRelation}
    {invariant : MixedExecutionInvariant reachability.targetIds contract}
    {cases : CheckedMixedKernelComponentCases originalContext originalAuthority
      original candidate candidateAuthority contract launch originalRoot
      reachability candidateRootRva program abi dispatches invariant}
    {closure : CheckedMixedKernelSelectedInvariantClosure cases}
    {site : OriginalIndirectControlSite}
    {rooted : CheckedRootedScannerSccExecution originalContext site}
    (projection :
      CheckedRootedScannerSelectedSourceProjection closure rooted) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      closure.strengthenedInvariant site.sourceTargetId := by
  rintro ⟨world, state, reached⟩
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · exact rooted.sourceUnreachable
      (projection.project
        (.running site.sourceTargetId state calls eventIndex world)
        candidateExecution related.2 rfl)
  · exact rooted.sourceUnreachable
      (projection.project
        (.callbackRunning site.sourceTargetId state calls eventIndex world
          callbacks)
        candidateExecution related.2 rfl)

/-! ## Paired chunk invariant assembly

The route crosses internal call/return components, so it cannot be represented
soundly as a one-instruction `OriginalWorldExecutionInvariant`.  The exact
mixed component graph is the induction unit used by whole-program composition.
-/

inductive CheckedRouteTransferAuthority
    (originalContext : OriginalDecodedStaticContext)
    (carrierContext : StaticProofContext) (route : Route) where
  | decoded
      {behavior : NormalizedSymbolicBehavior}
      (authority :
        CheckedDecodedLocalRouteTransfer (carrierContext := carrierContext)
          route behavior)
  | directRegister
      {contract :
        CheckedDirectCallRegisterControlContract carrierContext}
      (authority : CheckedDirectCallRegisterRouteTransfer route contract)
  | finiteResult
      {contract :
        CheckedFiniteOriginCallRegisterControlContract carrierContext}
      (authority :
        CheckedFiniteOriginCallResultRouteTransfer originalContext route
          contract)
  | directFrame
      {contract :
        CheckedDirectCallCallerFrameWordControlContract carrierContext}
      (authority :
        CheckedDirectCallCallerFrameWordRouteTransfer route contract)
  | finiteFrame
      {contract :
        CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
      (authority :
        CheckedFiniteOriginCallCallerFrameWordRouteTransfer route contract)

def CheckedRouteTransferAuthority.transfer :
    CheckedRouteTransferAuthority originalContext carrierContext route ->
      Transfer
  | .decoded authority => authority.transfer
  | .directRegister authority => authority.transfer
  | .finiteResult authority => authority.transfer
  | .directFrame authority => authority.transfer
  | .finiteFrame authority => authority.transfer

/-- The source fact required by one route authority. A finite-origin call
constructs its result from the checked target provenance and therefore has no
pre-existing source location. Every preservation authority names its exact
source location instead. -/
def CheckedRouteTransferAuthority.SourceFactHolds
    (authority :
      CheckedRouteTransferAuthority originalContext carrierContext route)
    (state : MachineState) : Prop :=
  match authority with
  | .decoded authority =>
      route.FactHolds originalContext {
        targetId := authority.transfer.sourceTargetId
        locationId := authority.sourceLocationId
      } state
  | .directRegister authority =>
      route.FactHolds originalContext {
        targetId := authority.transfer.sourceTargetId
        locationId := authority.sourceLocationId
      } state
  | .finiteResult _ => True
  | .directFrame authority =>
      route.FactHolds originalContext {
        targetId := authority.transfer.sourceTargetId
        locationId := authority.sourceLocationId
      } state
  | .finiteFrame authority =>
      route.FactHolds originalContext {
        targetId := authority.transfer.sourceTargetId
        locationId := authority.sourceLocationId
      } state

def CheckedRouteTransferAuthority.TargetFactHolds
    (authority :
      CheckedRouteTransferAuthority originalContext carrierContext route)
    (state : MachineState) : Prop :=
  Route.FactHolds originalContext route
    { targetId := authority.transfer.targetTargetId
      locationId := authority.transfer.targetLocationId }
    state

/-- Exact executable evidence paired with the authority that checks the route
edge. The constructors retain the computed endpoints from the decoded behavior
or call/return certificate; no caller supplies an endpoint equality. -/
inductive CheckedRouteTransferExecution
    (originalContext : OriginalDecodedStaticContext)
    (carrierContext : StaticProofContext) (route : Route) :
    (authority :
      CheckedRouteTransferAuthority originalContext carrierContext route) ->
      MachineState -> MachineState -> Prop where
  | decoded
      {behavior : NormalizedSymbolicBehavior}
      (authority :
        CheckedDecodedLocalRouteTransfer (carrierContext := carrierContext)
          route behavior)
      (state : MachineState) :
      CheckedRouteTransferExecution originalContext carrierContext route
        (.decoded authority) state
        ((behavior.eval state).nextMachineState state)
  | directRegister
      {contract :
        CheckedDirectCallRegisterControlContract carrierContext}
      (authority : CheckedDirectCallRegisterRouteTransfer route contract)
      {entryBinding : ExactDirectCallEntryBinding carrierContext contract.tree}
      {originalProgram candidateProgram : DecodedWorldProgram}
      (actual : ActualDirectCallReturnExecution carrierContext contract.tree
        entryBinding originalProgram candidateProgram) :
      CheckedRouteTransferExecution originalContext carrierContext route
        (.directRegister authority) actual.source.original.state
        actual.originalExit.state
  | finiteResult
      {contract :
        CheckedFiniteOriginCallRegisterControlContract carrierContext}
      (authority :
        CheckedFiniteOriginCallResultRouteTransfer originalContext route contract)
      {originalProgram candidateProgram : DecodedWorldProgram}
      (actual : ActualFiniteOriginCallReturnExecution contract.entry
        originalProgram candidateProgram) :
      CheckedRouteTransferExecution originalContext carrierContext route
        (.finiteResult authority) actual.sourceOriginal.state
        actual.originalExit.state
  | directFrame
      {contract :
        CheckedDirectCallCallerFrameWordControlContract carrierContext}
      (authority :
        CheckedDirectCallCallerFrameWordRouteTransfer route contract)
      {entryBinding : ExactDirectCallEntryBinding carrierContext contract.tree}
      {originalProgram candidateProgram : DecodedWorldProgram}
      (actual : ActualDirectCallReturnExecution carrierContext contract.tree
        entryBinding originalProgram candidateProgram) :
      CheckedRouteTransferExecution originalContext carrierContext route
        (.directFrame authority) actual.source.original.state
        actual.originalExit.state
  | finiteFrame
      {contract :
        CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
      (authority :
        CheckedFiniteOriginCallCallerFrameWordRouteTransfer route contract)
      {originalProgram candidateProgram : DecodedWorldProgram}
      (actual : ActualFiniteOriginCallReturnExecution contract.entry
        originalProgram candidateProgram) :
      CheckedRouteTransferExecution originalContext carrierContext route
        (.finiteFrame authority) actual.sourceOriginal.state
        actual.originalExit.state

/-- One generic preservation theorem for all route authority classes. This is
the route-level adapter consumed by selected mixed components after their exact
decoded or call/return execution has been recovered. -/
theorem CheckedRouteTransferExecution.preservesOriginal
    {authority :
      CheckedRouteTransferAuthority originalContext carrierContext route}
    {sourceState targetState : MachineState}
    (execution : CheckedRouteTransferExecution originalContext carrierContext
      route authority sourceState targetState)
    (sourceFact : authority.SourceFactHolds sourceState) :
    authority.TargetFactHolds targetState := by
  cases execution with
  | decoded authority =>
      exact authority.preservesOriginal sourceState sourceFact
  | directRegister authority actual =>
      exact authority.preservesOriginal actual sourceFact
  | finiteResult authority actual =>
      exact authority.preservesOriginal actual
  | directFrame authority actual =>
      rcases sourceFact with
        ⟨sourceLocation, target, sourceLocationExact, targetExact, valueMatches⟩
      rw [authority.sourceLocationExact] at sourceLocationExact
      have sourceLocationMatches :
          sourceLocation = authority.sourceLocation :=
        (Option.some.inj sourceLocationExact).symm
      subst sourceLocation
      refine ⟨authority.targetLocation, target,
        authority.targetLocationExact, targetExact, ?_⟩
      rw [authority.preservesOriginal actual]
      exact valueMatches
  | finiteFrame authority actual =>
      rcases sourceFact with
        ⟨sourceLocation, target, sourceLocationExact, targetExact, valueMatches⟩
      rw [authority.sourceLocationExact] at sourceLocationExact
      have sourceLocationMatches :
          sourceLocation = authority.sourceLocation :=
        (Option.some.inj sourceLocationExact).symm
      subst sourceLocation
      refine ⟨authority.targetLocation, target,
        authority.targetLocationExact, targetExact, ?_⟩
      rw [authority.preservesOriginal actual]
      exact valueMatches

/-- The list is intentionally ordered. The route checker has already checked
the graph edges; this checker additionally requires one semantic authority for
every transfer, with no omitted, duplicated, or silently reordered chunk. -/
def checkedRouteTransferInventory
    (route : Route)
    (authorities :
      List (CheckedRouteTransferAuthority originalContext carrierContext
        route)) : Bool :=
  authorities.map CheckedRouteTransferAuthority.transfer == route.transfers

structure CheckedRouteTransferInventory
    (originalContext : OriginalDecodedStaticContext)
    (carrierContext : StaticProofContext) (route : Route) where
  authorities :
    List (CheckedRouteTransferAuthority originalContext carrierContext route)
  checked : checkedRouteTransferInventory route authorities = true

theorem CheckedRouteTransferInventory.exact
    (inventory :
      CheckedRouteTransferInventory originalContext carrierContext route) :
    inventory.authorities.map CheckedRouteTransferAuthority.transfer =
      route.transfers :=
  beq_iff_eq.mp inventory.checked

/-- One route authority applied to the exact original path selected by mixed
component composition.  The selected chunk owns both endpoints; generated
evidence may only identify their machine states and supply the corresponding
checked decoded or call/return execution. -/
structure CheckedSelectedRouteTransferExecution
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    {base : MixedExecutionInvariant reachabilityTargetIds contract}
    (inventory :
      CheckedRouteTransferInventory originalContext carrierContext route)
    (originalBefore : WorldExecution)
    (candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution)
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore) : Type where
  authorityIndex : Nat
  authority :
    CheckedRouteTransferAuthority originalContext carrierContext route
  authorityExact :
    inventory.authorities[authorityIndex]? = some authority
  sourceState : MachineState
  targetState : MachineState
  sourceAt :
    originalExecutionAtTargetId authority.transfer.sourceTargetId
      originalBefore
  targetAt :
    originalExecutionAtTargetId authority.transfer.targetTargetId
      chunk.originalAfter
  sourceMachineExact :
    originalExecutionMachine? originalBefore = some sourceState
  targetMachineExact :
    originalExecutionMachine? chunk.originalAfter = some targetState
  sourceFact : authority.SourceFactHolds sourceState
  execution :
    CheckedRouteTransferExecution originalContext carrierContext route
      authority sourceState targetState

/-- Checked constructor for an ordinary decoded route edge. -/
def CheckedSelectedRouteTransferExecution.ofDecoded
    {inventory :
      CheckedRouteTransferInventory originalContext carrierContext route}
    (authorityIndex : Nat)
    {behavior : NormalizedSymbolicBehavior}
    (authority :
      CheckedDecodedLocalRouteTransfer (carrierContext := carrierContext)
        route behavior)
    (authorityExact :
      inventory.authorities[authorityIndex]? =
        some (.decoded authority))
    {originalBefore : WorldExecution}
    {candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (state : MachineState)
    (sourceAt :
      originalExecutionAtTargetId authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore = some state)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter =
        some ((behavior.eval state).nextMachineState state))
    (sourceFact :
      CheckedRouteTransferAuthority.SourceFactHolds
        (originalContext := originalContext) (.decoded authority) state) :
    CheckedSelectedRouteTransferExecution inventory originalBefore
      candidateBefore chunk := {
  authorityIndex
  authority := .decoded authority
  authorityExact
  sourceState := state
  targetState := (behavior.eval state).nextMachineState state
  sourceAt
  targetAt
  sourceMachineExact
  targetMachineExact
  sourceFact
  execution := .decoded authority state
}

/-- Checked constructor for a direct-call register-preservation edge. -/
def CheckedSelectedRouteTransferExecution.ofDirectRegister
    {inventory :
      CheckedRouteTransferInventory originalContext carrierContext route}
    (authorityIndex : Nat)
    {callContract :
      CheckedDirectCallRegisterControlContract carrierContext}
    (authority :
      CheckedDirectCallRegisterRouteTransfer route callContract)
    (authorityExact :
      inventory.authorities[authorityIndex]? =
        some (.directRegister authority))
    {entryBinding : ExactDirectCallEntryBinding carrierContext callContract.tree}
    {originalProgram summaryCandidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution carrierContext callContract.tree
      entryBinding originalProgram summaryCandidateProgram)
    {originalBefore : WorldExecution}
    {candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (sourceAt :
      originalExecutionAtTargetId authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore =
        some actual.source.original.state)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter =
        some actual.originalExit.state)
    (sourceFact :
      CheckedRouteTransferAuthority.SourceFactHolds
        (originalContext := originalContext) (.directRegister authority)
        actual.source.original.state) :
    CheckedSelectedRouteTransferExecution inventory originalBefore
      candidateBefore chunk := {
  authorityIndex
  authority := .directRegister authority
  authorityExact
  sourceState := actual.source.original.state
  targetState := actual.originalExit.state
  sourceAt
  targetAt
  sourceMachineExact
  targetMachineExact
  sourceFact
  execution := .directRegister authority actual
}

/-- Checked constructor for a finite-origin call result edge. -/
def CheckedSelectedRouteTransferExecution.ofFiniteResult
    {inventory :
      CheckedRouteTransferInventory originalContext carrierContext route}
    (authorityIndex : Nat)
    {callContract :
      CheckedFiniteOriginCallRegisterControlContract carrierContext}
    (authority :
      CheckedFiniteOriginCallResultRouteTransfer originalContext route
        callContract)
    (authorityExact :
      inventory.authorities[authorityIndex]? =
        some (.finiteResult authority))
    {originalProgram summaryCandidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution callContract.entry
      originalProgram summaryCandidateProgram)
    {originalBefore : WorldExecution}
    {candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (sourceAt :
      originalExecutionAtTargetId authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore =
        some actual.sourceOriginal.state)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter =
        some actual.originalExit.state) :
    CheckedSelectedRouteTransferExecution inventory originalBefore
      candidateBefore chunk := {
  authorityIndex
  authority := .finiteResult authority
  authorityExact
  sourceState := actual.sourceOriginal.state
  targetState := actual.originalExit.state
  sourceAt
  targetAt
  sourceMachineExact
  targetMachineExact
  sourceFact := trivial
  execution := .finiteResult authority actual
}

/-- Checked constructor for a direct caller-frame preservation edge. -/
def CheckedSelectedRouteTransferExecution.ofDirectFrame
    {inventory :
      CheckedRouteTransferInventory originalContext carrierContext route}
    (authorityIndex : Nat)
    {callContract :
      CheckedDirectCallCallerFrameWordControlContract carrierContext}
    (authority :
      CheckedDirectCallCallerFrameWordRouteTransfer route callContract)
    (authorityExact :
      inventory.authorities[authorityIndex]? =
        some (.directFrame authority))
    {entryBinding : ExactDirectCallEntryBinding carrierContext callContract.tree}
    {originalProgram summaryCandidateProgram : DecodedWorldProgram}
    (actual : ActualDirectCallReturnExecution carrierContext callContract.tree
      entryBinding originalProgram summaryCandidateProgram)
    {originalBefore : WorldExecution}
    {candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (sourceAt :
      originalExecutionAtTargetId authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore =
        some actual.source.original.state)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter =
        some actual.originalExit.state)
    (sourceFact :
      CheckedRouteTransferAuthority.SourceFactHolds
        (originalContext := originalContext) (.directFrame authority)
        actual.source.original.state) :
    CheckedSelectedRouteTransferExecution inventory originalBefore
      candidateBefore chunk := {
  authorityIndex
  authority := .directFrame authority
  authorityExact
  sourceState := actual.source.original.state
  targetState := actual.originalExit.state
  sourceAt
  targetAt
  sourceMachineExact
  targetMachineExact
  sourceFact
  execution := .directFrame authority actual
}

/-- Checked constructor for a finite-origin caller-frame preservation edge. -/
def CheckedSelectedRouteTransferExecution.ofFiniteFrame
    {inventory :
      CheckedRouteTransferInventory originalContext carrierContext route}
    (authorityIndex : Nat)
    {callContract :
      CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
    (authority :
      CheckedFiniteOriginCallCallerFrameWordRouteTransfer route callContract)
    (authorityExact :
      inventory.authorities[authorityIndex]? =
        some (.finiteFrame authority))
    {originalProgram summaryCandidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution callContract.entry
      originalProgram summaryCandidateProgram)
    {originalBefore : WorldExecution}
    {candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution}
    (chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore)
    (sourceAt :
      originalExecutionAtTargetId authority.transfer.sourceTargetId
        originalBefore)
    (targetAt :
      originalExecutionAtTargetId authority.transfer.targetTargetId
        chunk.originalAfter)
    (sourceMachineExact :
      originalExecutionMachine? originalBefore =
        some actual.sourceOriginal.state)
    (targetMachineExact :
      originalExecutionMachine? chunk.originalAfter =
        some actual.originalExit.state)
    (sourceFact :
      CheckedRouteTransferAuthority.SourceFactHolds
        (originalContext := originalContext) (.finiteFrame authority)
        actual.sourceOriginal.state) :
    CheckedSelectedRouteTransferExecution inventory originalBefore
      candidateBefore chunk := {
  authorityIndex
  authority := .finiteFrame authority
  authorityExact
  sourceState := actual.sourceOriginal.state
  targetState := actual.originalExit.state
  sourceAt
  targetAt
  sourceMachineExact
  targetMachineExact
  sourceFact
  execution := .finiteFrame authority actual
}

/-- The selected component establishes the route fact at its computed target.
No endpoint, route status, or independently supplied path is consumed. -/
theorem CheckedSelectedRouteTransferExecution.targetFactAt
    {inventory :
      CheckedRouteTransferInventory originalContext carrierContext route}
    {originalBefore : WorldExecution}
    {candidateBefore :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution}
    {chunk : MixedWorldComponentChunkRefinement original candidate contract
      base originalBefore candidateBefore}
    (selected :
      CheckedSelectedRouteTransferExecution inventory originalBefore
        candidateBefore chunk) :
    OriginalSourceFactAt selected.authority.transfer.targetTargetId
      (fun _world state =>
        selected.authority.TargetFactHolds state)
      chunk.originalAfter := by
  have targetFact :=
    selected.execution.preservesOriginal selected.sourceFact
  cases afterExact : chunk.originalAfter with
  | running targetId state calls eventIndex world =>
      have stateExact := selected.targetMachineExact
      rw [afterExact] at stateExact
      simp only [originalExecutionMachine?, Option.some.injEq] at stateExact
      simp only [OriginalSourceFactAt]
      intro _targetExact
      rw [stateExact]
      exact targetFact
  | callbackRunning targetId state calls eventIndex world callbacks =>
      have stateExact := selected.targetMachineExact
      rw [afterExact] at stateExact
      simp only [originalExecutionMachine?, Option.some.injEq] at stateExact
      simp only [OriginalSourceFactAt]
      intro _targetExact
      rw [stateExact]
      exact targetFact
  | returned state world =>
      have impossible := selected.targetAt
      simpa [afterExact, originalExecutionAtTargetId] using impossible
  | awaitingExternal suspension externalIndex =>
      have impossible := selected.targetAt
      simpa [afterExact, originalExecutionAtTargetId] using impossible
  | terminated world =>
      have impossible := selected.targetAt
      simpa [afterExact, originalExecutionAtTargetId] using impossible
  | fault cause =>
      have impossible := selected.targetAt
      simpa [afterExact, originalExecutionAtTargetId] using impossible
  | blocked reason =>
      have impossible := selected.targetAt
      simpa [afterExact, originalExecutionAtTargetId] using impossible

structure CheckedRouteChunkInvariant
    (context : OriginalDecodedStaticContext)
    (original : DecodedWorldProgram)
    (candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram)
    (contract : MixedRelationContract)
    (reachabilityTargetIds : List Nat)
    (base : MixedExecutionInvariant reachabilityTargetIds contract)
    (authority : CheckedRoute context) where
  programBinding : ExactMixedProgramBinding context original
  chunkClosed : forall originalBefore candidateBefore,
    RouteFactsHoldAt context authority.route originalBefore ->
      (chunk : MixedWorldComponentChunkRefinement original candidate contract
        base originalBefore candidateBefore) ->
      RouteFactsHoldAt context authority.route chunk.originalAfter

def CheckedRouteChunkInvariant.toExtension
    (invariant :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base authority) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base where
  holds originalExecution _candidateExecution :=
    RouteFactsHoldAt context authority.route originalExecution
  chunkClosed := invariant.chunkClosed

def CheckedRouteChunkInvariant.projection
    (invariant :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base authority)
    (fact : Fact) (member : fact ∈ authority.route.facts) :
    OriginalSourceFactMixedProjection invariant.toExtension fact.targetId
      (fun _world state => authority.route.FactHolds context fact state) where
  project _ _ holds := holds fact member

def combinedExtension
    (route :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base routeAuthority)
    (constructor :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base constructorCut)
    (dynamic :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base dynamicCut) :
    MixedWorldExecutionInvariantExtension original candidate contract
      reachabilityTargetIds base :=
  MixedWorldExecutionInvariantExtension.all [
    route.toExtension,
    constructor.toExtension,
    dynamic.toExtension
  ]

def combinedMixedInvariant
    (route :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base routeAuthority)
    (constructor :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base constructorCut)
    (dynamic :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base dynamicCut) :
    MixedExecutionInvariant reachabilityTargetIds contract :=
  (combinedExtension route constructor dynamic).strengthen

/-! ## Exact root establishment

The canonical extensions are vacuous at a launch root which is not one of the
tracked route targets or guarded sources. This finite Boolean check prevents a
generated module from replacing that fact with an unconstrained root theorem.
-/

def rootExclusionChecked
    (routeAuthority : CheckedRoute context)
    (constructorCut dynamicCut : CheckedCertificate context)
    (rootTargetId : Nat) : Bool :=
  routeAuthority.route.facts.all
      (fun fact => fact.targetId != rootTargetId) &&
    (constructorCut.certificate.sourceTargetId != rootTargetId &&
      dynamicCut.certificate.sourceTargetId != rootTargetId)

theorem combinedExtension_holds_at_root_of_checked
    (route :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base routeAuthority)
    (constructor :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base constructorCut)
    (dynamic :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base dynamicCut)
    (checked :
      rootExclusionChecked routeAuthority constructorCut dynamicCut
        rootTargetId = true)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld)
    (candidateExecution :
      StageA.Relational.InterpreterNativeWorld.NativeWorldExecution) :
    (combinedExtension route constructor dynamic).holds
      (.running rootTargetId state calls eventIndex world)
      candidateExecution := by
  unfold rootExclusionChecked at checked
  simp only [Bool.and_eq_true] at checked
  have routeChecked := checked.1
  have constructorChecked := checked.2.1
  have dynamicChecked := checked.2.2
  simp only [List.all_eq_true, bne_iff_ne] at routeChecked
  simp only [bne_iff_ne] at constructorChecked dynamicChecked
  intro extension member
  simp only [List.mem_cons, List.not_mem_nil, or_false] at member
  rcases member with routeExact | constructorExact | dynamicExact
  · subst extension
    intro fact factMember rootExact
    exact ((routeChecked fact factMember) rootExact.symm).elim
  · subst extension
    intro rootExact
    exact constructorChecked rootExact.symm
  · subst extension
    intro rootExact
    exact dynamicChecked rootExact.symm

def projectionFromCombined
    (route :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base routeAuthority)
    (constructor :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base constructorCut)
    (dynamic :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base dynamicCut)
    (memberExtension :
      MixedWorldExecutionInvariantExtension original candidate contract
        reachabilityTargetIds base)
    (member : memberExtension ∈ [
      route.toExtension,
      constructor.toExtension,
      dynamic.toExtension
    ])
    (projection :
      OriginalSourceFactMixedProjection memberExtension sourceTargetId fact) :
    OriginalSourceFactMixedProjection
      (combinedExtension route constructor dynamic) sourceTargetId fact where
  project originalExecution candidateExecution holds :=
    projection.project originalExecution candidateExecution
      (MixedWorldExecutionInvariantExtension.all_member holds memberExtension
        member)

def StackRangeSlotHolds
    (binding :
      CheckedStackCarryRouteSeedValue context graph route authority fact)
    (world : RelationalWorld) (state : MachineState) : Prop :=
  exists stackRange : DynamicAddressRangePair,
    stackRange ∈ world.stackRanges /\
      stackRange.originalBase.toNat <=
        ((binding.adjustment.expression binding.stackRegister).eval state).toNat /\
      ((binding.adjustment.expression binding.stackRegister).eval state).toNat +
          4 <=
        stackRange.originalBase.toNat + stackRange.size

/-- A range-relative stack-address origin supplies the runtime membership and
slot bounds omitted by a value-carry fact.  This is the bridge used by checked
stack-pointer provenance; it does not infer allocation membership from the
syntactic shape `ESP + k`. -/
theorem stackRangeSlotHolds_of_canonicalRangeOffset
    (binding :
      CheckedStackCarryRouteSeedValue context graph route authority fact)
    (related :
      CanonicalMixedWorldsRelated context candidate anchors world
        candidateWorld)
    (stackRange : DynamicAddressRangePair)
    (rangeMember : stackRange ∈ world.stackRanges)
    (offset : Nat)
    (offsetFits : offset + 4 <= stackRange.size)
    (addressExact :
      (binding.adjustment.expression binding.stackRegister).eval state =
        stackRange.originalBase + BitVec.ofNat 32 offset) :
    StackRangeSlotHolds binding world state := by
  have combinedMember :
      stackRange ∈ world.dynamicRanges ++ world.stackRanges := by
    simp [rangeMember]
  have rangeDisjoint :=
    canonicalMixedWorldsRelated_range_disjoint related combinedMember
  have contained :=
    originalRangeOffsetAccessContained rangeDisjoint offsetFits
  refine ⟨stackRange, rangeMember, ?_, ?_⟩
  · rw [addressExact]
    exact contained.2.2.2.1
  · rw [addressExact]
    exact contained.2.2.2.2

def RuntimeIndirectOperationalFacts
    (context : OriginalDecodedStaticContext)
    (routeAuthority : CheckedRoute context)
    (constructorCut dynamicCut : CheckedCertificate context)
    (stackAuthority : CheckedStackCarryAuthority context)
    (stackSeed :
      CheckedStackCarryRouteSeedValue context routeAuthority.graph
        routeAuthority.route stackAuthority routeAuthority.route.targetFact) :
    WorldExecution -> Prop :=
  fun originalExecution =>
    RouteFactsHoldAt context routeAuthority.route originalExecution /\
      OriginalSourceFactAt constructorCut.certificate.sourceTargetId
        (fun _world _state => False) originalExecution /\
      OriginalSourceFactAt dynamicCut.certificate.sourceTargetId
        (fun _world _state => False) originalExecution /\
      OriginalSourceFactAt stackAuthority.static.claim.site.sourceTargetId
        (StackRangeSlotHolds stackSeed) originalExecution

def selectedRuntimeIndirectExtension
    {originalContext : OriginalDecodedStaticContext}
    {originalAuthority : ExactOriginalDecodedAuthority originalContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {candidateAuthority : ExactNativeCandidateAuthority candidate}
    {programBinding : ExactMixedProgramBinding originalContext original}
    {contract : MixedRelationContract}
    {launch : PE32ConsoleLaunchV2}
    {originalRoot :
      DirectExactOriginalDecodedLaunchRoot originalContext launch}
    {reachability : ExactOriginalDecodedReachability originalContext
      originalAuthority launch originalRoot}
    {candidateRootRva : Nat}
    {candidateRoot :
      DirectExactCandidateNativeLaunchRoot candidate launch candidateRootRva}
    {composition : MixedWorldChunkComposition originalContext
      originalAuthority original candidate candidateAuthority programBinding
      contract launch originalRoot reachability candidateRootRva candidateRoot}
    (routeAuthority : CheckedRoute originalContext)
    (constructorCut dynamicCut : CheckedCertificate originalContext)
    (stackAuthority : CheckedStackCarryAuthority originalContext)
    (stackSeed :
      CheckedStackCarryRouteSeedValue originalContext routeAuthority.graph
        routeAuthority.route stackAuthority routeAuthority.route.targetFact)
    (componentClosed : forall originalBefore candidateBefore,
      (related :
        composition.invariant.holds originalBefore candidateBefore) ->
        (_facts : RuntimeIndirectOperationalFacts originalContext
          routeAuthority constructorCut dynamicCut stackAuthority stackSeed
          originalBefore) ->
        let selected :=
          composition.component originalBefore candidateBefore related
        RuntimeIndirectOperationalFacts originalContext routeAuthority
          constructorCut dynamicCut stackAuthority stackSeed
          selected.originalAfter) :
    SelectedMixedComponentInvariantExtension composition where
  holds originalExecution _candidateExecution :=
    RuntimeIndirectOperationalFacts originalContext routeAuthority
      constructorCut dynamicCut stackAuthority stackSeed originalExecution
  componentClosed := componentClosed

theorem runtimeIndirectOperationalFacts_at_root_of_checked
    (routeAuthority : CheckedRoute context)
    (constructorCut dynamicCut : CheckedCertificate context)
    (stackAuthority : CheckedStackCarryAuthority context)
    (stackSeed :
      CheckedStackCarryRouteSeedValue context routeAuthority.graph
        routeAuthority.route stackAuthority routeAuthority.route.targetFact)
    (checked :
      rootExclusionChecked routeAuthority constructorCut dynamicCut
        rootTargetId = true)
    (state : MachineState) (calls : List Nat) (eventIndex : Nat)
    (world : RelationalWorld) :
    RuntimeIndirectOperationalFacts context routeAuthority constructorCut
      dynamicCut stackAuthority stackSeed
      (.running rootTargetId state calls eventIndex world) := by
  unfold rootExclusionChecked at checked
  simp only [Bool.and_eq_true] at checked
  have routeChecked := checked.1
  have constructorChecked := checked.2.1
  have dynamicChecked := checked.2.2
  simp only [List.all_eq_true, bne_iff_ne] at routeChecked
  simp only [bne_iff_ne] at constructorChecked dynamicChecked
  refine ⟨?_, ?_, ?_, ?_⟩
  · intro fact factMember rootExact
    exact ((routeChecked fact factMember) rootExact.symm).elim
  · intro rootExact
    exact constructorChecked rootExact.symm
  · intro rootExact
    exact dynamicChecked rootExact.symm
  · intro rootExact
    have targetMember : routeAuthority.route.targetFact ∈
        routeAuthority.route.facts := by
      have known := stackSeed.factKnown
      simp only [Route.factKnown, Bool.and_eq_true] at known
      exact List.contains_iff_mem.mp known.1
    exact ((routeChecked _ targetMember)
      (stackSeed.factTargetExact.trans rootExact.symm)).elim

def stackWindowSlotChecked
    (window : StackWindowPair) (register : Reg) (amount : Nat) : Bool :=
  window.originalRegister == register &&
    decide (amount + 4 <= window.bytesAbove)

/-- A checked stack window is the authoritative source of stack-slot bounds.
This theorem does not infer stack membership from an address shape alone:
`StateRel` supplies both the concrete range member and the no-wrap facts. -/
theorem stackRangeSlotHolds_of_stateRel_window_add
    (binding :
      CheckedStackCarryRouteSeedValue context graph route authority fact)
    (window : StackWindowPair) (amount : Nat)
    (stackRegisterExact :
      window.originalRegister = binding.stackRegister)
    (adjustmentExact : binding.adjustment = .add amount)
    (windowMember : window ∈ invariant.stackWindows)
    (slotInside : amount + 4 <= window.bytesAbove)
    (related : StateRel carrierContext world invariant original candidate) :
    StackRangeSlotHolds binding world original := by
  have windows := related.stackWindowsHold carrierContext world invariant
    original candidate
  simp only [stackWindowsRelated, List.all_eq_true] at windows
  have windowHolds := windows window windowMember
  cases found : world.stackRanges.find? (fun range =>
      range.id == window.rangeId) with
  | none =>
      simp [StackWindowPair.holds, found] at windowHolds
  | some stackRange =>
      have stackRangeMember : stackRange ∈ world.stackRanges :=
        List.mem_of_find?_eq_some found
      simp only [StackWindowPair.holds, found, Bool.and_eq_true,
        beq_iff_eq, decide_eq_true_eq] at windowHolds
      rcases windowHolds with
        ⟨⟨⟨⟨⟨originalLower, originalUpper⟩, _candidateLower⟩,
          _candidateUpper⟩, _pairedOffset⟩, _alignment⟩
      have rangesValid :=
        related.stackRangesValid carrierContext world invariant original candidate
      simp only [RelationalWorld.stackRangesValid, Bool.and_eq_true,
        List.all_eq_true] at rangesValid
      have stackRangeValid :
          stackRange.disjointFromImages carrierContext = true :=
        (rangesValid.1.1.2 stackRange stackRangeMember).1.1.1
      have noWrap :
          stackRange.originalBase.toNat + stackRange.size < 2 ^ 32 := by
        simpa [DynamicAddressRangePair.sideBase] using
          DynamicAddressRangePair.sideBase_noWrap_of_disjoint carrierContext false
            stackRange stackRangeValid
      have amountSmall : amount < 2 ^ 32 := by
        omega
      have addressBefore :
          (original.registers.get binding.stackRegister).toNat + amount <
            2 ^ 32 := by
        rw [← stackRegisterExact]
        omega
      refine ⟨stackRange, stackRangeMember, ?_, ?_⟩
      · rw [adjustmentExact]
        simp [StackAdjustment.expression, Expr.eval, BitVec.toNat_add,
          BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall,
          Nat.mod_eq_of_lt addressBefore]
        rw [← stackRegisterExact]
        omega
      · rw [adjustmentExact]
        simp [StackAdjustment.expression, Expr.eval, BitVec.toNat_add,
          BitVec.toNat_ofNat, Nat.mod_eq_of_lt amountSmall,
          Nat.mod_eq_of_lt addressBefore]
        rw [← stackRegisterExact]
        omega

theorem stackRangeSlotHolds_of_stateRel_window_add_checked
    (binding :
      CheckedStackCarryRouteSeedValue context graph route authority fact)
    (window : StackWindowPair) (amount : Nat)
    (adjustmentExact : binding.adjustment = .add amount)
    (windowMember : window ∈ invariant.stackWindows)
    (slotChecked :
      stackWindowSlotChecked window binding.stackRegister amount = true)
    (related : StateRel carrierContext world invariant original candidate) :
    StackRangeSlotHolds binding world original := by
  simp only [stackWindowSlotChecked, Bool.and_eq_true, beq_iff_eq,
    decide_eq_true_eq] at slotChecked
  exact stackRangeSlotHolds_of_stateRel_window_add binding window amount
    slotChecked.1 adjustmentExact windowMember slotChecked.2 related

/-- Canonical range evidence for a caller-frame slot carried through a checked
finite-origin call.  The range identifier and bounds come from the exact
source invariant used by the call-entry authority. -/
structure CheckedFiniteOriginCallerFrameStackRangeWitness
    {originalContext : OriginalDecodedStaticContext}
    {carrierContext : StaticProofContext}
    {route : Route}
    {contract :
      CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
    (authority :
      CheckedFiniteOriginCallCallerFrameWordRouteTransfer route contract)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution contract.entry
      originalProgram candidateProgram)
    {graph : CutpointGraph}
    {stackAuthority : CheckedStackCarryAuthority originalContext}
    {fact : Fact}
    (binding :
      CheckedStackCarryRouteSeedValue originalContext graph route
        stackAuthority fact) : Type where
  window : StackWindowPair
  amount : Nat
  adjustmentExact : binding.adjustment = .add amount
  windowMember :
    window ∈ contract.entry.sourceInvariant.stackWindows
  slotChecked :
    stackWindowSlotChecked window binding.stackRegister amount = true

def finiteOriginCallerFrameStackRangeChecked
    {originalContext : OriginalDecodedStaticContext}
    {carrierContext : StaticProofContext}
    {route : Route}
    {contract :
      CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
    (_authority :
      CheckedFiniteOriginCallCallerFrameWordRouteTransfer route contract)
    {graph : CutpointGraph}
    {stackAuthority : CheckedStackCarryAuthority originalContext}
    {fact : Fact}
    (binding :
      CheckedStackCarryRouteSeedValue originalContext graph route
        stackAuthority fact)
    (window : StackWindowPair) (amount : Nat) : Bool :=
  contract.entry.sourceInvariant.stackWindows.contains window &&
    decide (binding.adjustment = .add amount) &&
    stackWindowSlotChecked window binding.stackRegister amount

def checkedFiniteOriginCallerFrameStackRangeWitness_of_checked
    {originalContext : OriginalDecodedStaticContext}
    {carrierContext : StaticProofContext}
    {route : Route}
    {contract :
      CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
    (authority :
      CheckedFiniteOriginCallCallerFrameWordRouteTransfer route contract)
    {graph : CutpointGraph}
    {stackAuthority : CheckedStackCarryAuthority originalContext}
    {fact : Fact}
    (binding :
      CheckedStackCarryRouteSeedValue originalContext graph route
        stackAuthority fact)
    (window : StackWindowPair) (amount : Nat)
    (checked :
      finiteOriginCallerFrameStackRangeChecked authority binding window amount =
        true)
    {originalProgram candidateProgram : DecodedWorldProgram}
    (actual : ActualFiniteOriginCallReturnExecution contract.entry
      originalProgram candidateProgram) :
    CheckedFiniteOriginCallerFrameStackRangeWitness authority actual binding := by
  simp only [finiteOriginCallerFrameStackRangeChecked, Bool.and_eq_true,
    List.contains_iff_mem, decide_eq_true_eq] at checked
  exact {
    window
    amount
    adjustmentExact := checked.1.2
    windowMember := checked.1.1
    slotChecked := checked.2
  }

theorem CheckedFiniteOriginCallerFrameStackRangeWitness.holds
    {originalContext : OriginalDecodedStaticContext}
    {carrierContext : StaticProofContext}
    {route : Route}
    {contract :
      CheckedFiniteOriginCallCallerFrameWordControlContract carrierContext}
    {authority :
      CheckedFiniteOriginCallCallerFrameWordRouteTransfer route contract}
    {originalProgram candidateProgram : DecodedWorldProgram}
    {actual : ActualFiniteOriginCallReturnExecution contract.entry
      originalProgram candidateProgram}
    {graph : CutpointGraph}
    {stackAuthority : CheckedStackCarryAuthority originalContext}
    {fact : Fact}
    {binding :
      CheckedStackCarryRouteSeedValue originalContext graph route
        stackAuthority fact}
    (witness :
      CheckedFiniteOriginCallerFrameStackRangeWitness authority actual binding) :
    StackRangeSlotHolds binding actual.sourceOriginal.world
      actual.sourceOriginal.state :=
  stackRangeSlotHolds_of_stateRel_window_add_checked binding witness.window
    witness.amount witness.adjustmentExact witness.windowMember
    witness.slotChecked actual.sourceRelated

structure StrengthenedOriginalSourceFactProjection
    (extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base)
    (sourceTargetId : Nat)
    (fact : RelationalWorld -> MachineState -> Prop) : Prop where
  project : forall originalExecution candidateExecution,
    extension.strengthen.holds originalExecution candidateExecution ->
      OriginalSourceFactAt sourceTargetId fact originalExecution

theorem originalSourceFact_of_strengthenedProjection
    {extension : MixedWorldExecutionInvariantExtension original candidate
      contract reachabilityTargetIds base}
    (projection :
      StrengthenedOriginalSourceFactProjection extension sourceTargetId fact)
    {world : RelationalWorld} {state : MachineState}
    (reached : ActualMixedOriginalStackDynamicSource extension.strengthen
      sourceTargetId world state) :
    fact world state := by
  rcases reached with
    ⟨calls, eventIndex, candidateExecution, related⟩ |
    ⟨calls, eventIndex, callbacks, candidateExecution, related⟩
  · exact projection.project _ _ related rfl
  · exact projection.project _ _ related rfl

structure Aggregate
    {context : OriginalDecodedStaticContext}
    {original : DecodedWorldProgram}
    {candidate :
      StageA.Relational.InterpreterNativeWorld.ExactNativeWorldProgram}
    {contract : MixedRelationContract}
    {reachabilityTargetIds : List Nat}
    (base : MixedExecutionInvariant reachabilityTargetIds contract)
    {stackAuthority : CheckedStackCarryAuthority context}
    {routeAuthority : CheckedRoute context}
    {constructorAuthority : CheckedEmptyIndexedSourceAuthority context}
    {constructorCut : CheckedCertificate context}
    {dynamicSite : CheckedOriginalIndirectControlSite context}
    {dynamicCut : CheckedCertificate context}
    (routeInvariant :
      CheckedRouteChunkInvariant context original candidate contract
        reachabilityTargetIds base routeAuthority)
    (constructorOperational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base constructorCut)
    (dynamicOperational :
      CheckedMixedOperationalCut context original candidate contract
        reachabilityTargetIds base dynamicCut) where
  inventory : FrontierInventory
  inventoryChecked :
    inventory.checked routeAuthority.route.stableId
      constructorCut.certificate.frontierId
      dynamicCut.certificate.frontierId
      stackAuthority.static.claim.site.sourceTargetId
      constructorAuthority.site.sourceTargetId
      dynamicSite.site.sourceTargetId = true
  constructorSourceExact :
    constructorCut.certificate.sourceTargetId =
      constructorAuthority.site.sourceTargetId
  dynamicSourceExact :
    dynamicCut.certificate.sourceTargetId =
      dynamicSite.site.sourceTargetId
  stackSeed :
    CheckedStackCarryRouteSeedValue context routeAuthority.graph
      routeAuthority.route stackAuthority routeAuthority.route.targetFact
  stackRangeProjection :
    StrengthenedOriginalSourceFactProjection
      (combinedExtension routeInvariant constructorOperational
        dynamicOperational)
      stackAuthority.static.claim.site.sourceTargetId
      (StackRangeSlotHolds stackSeed)

def Aggregate.stackProjection
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    OriginalSourceFactMixedProjection
      (combinedExtension routeInvariant constructorOperational
        dynamicOperational)
      routeAuthority.route.targetFact.targetId
      (fun _world state =>
        routeAuthority.route.FactHolds context
          routeAuthority.route.targetFact state) := by
  have known := aggregate.stackSeed.factKnown
  rw [Route.factKnown] at known
  simp only [Bool.and_eq_true] at known
  have member :
      routeAuthority.route.targetFact ∈ routeAuthority.route.facts :=
    List.contains_iff_mem.mp known.1
  exact projectionFromCombined routeInvariant constructorOperational
    dynamicOperational routeInvariant.toExtension (by simp)
    (routeInvariant.projection routeAuthority.route.targetFact member)

noncomputable def Aggregate.stackComplete
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    CompleteStackCarryPremise context stackAuthority
      (ActualMixedOriginalStackDynamicSource
        (combinedMixedInvariant routeInvariant constructorOperational
          dynamicOperational)
        stackAuthority.static.claim.site.sourceTargetId) :=
  completeStackCarryPremise_of_checkedRoute aggregate.stackSeed _ (by
    intro world state reached
    apply originalSourceFact_of_mixedProjection aggregate.stackProjection
    rw [aggregate.stackSeed.factTargetExact]
    exact reached) {
      everyReachableSlotBound := by
        intro world state reached
        exact originalSourceFact_of_strengthenedProjection
          aggregate.stackRangeProjection reached
    }

def Aggregate.stackComposition
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    StackCarryMixedOriginalComposition stackAuthority
      (combinedMixedInvariant routeInvariant constructorOperational
        dynamicOperational) :=
  .finite aggregate.stackComplete

def Aggregate.constructorProjection
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    OriginalSourceFactMixedProjection
      (combinedExtension routeInvariant constructorOperational
        dynamicOperational)
      constructorCut.certificate.sourceTargetId
      (fun _world _state => False) :=
  projectionFromCombined routeInvariant constructorOperational
    dynamicOperational constructorOperational.toExtension (by simp)
    constructorOperational.sourceFalseProjection

theorem Aggregate.constructorSourceUninhabited
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      (combinedMixedInvariant routeInvariant constructorOperational
        dynamicOperational)
      constructorAuthority.site.sourceTargetId := by
  have uninhabited :=
    actualMixedOriginalStackDynamicSourceUninhabited_of_mixedProjection
      aggregate.constructorProjection
  rw [aggregate.constructorSourceExact] at uninhabited
  exact uninhabited

def Aggregate.constructorComposition
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    IndexedTableMixedOriginalComposition constructorAuthority
      (combinedMixedInvariant routeInvariant constructorOperational
        dynamicOperational) :=
  .unreachable aggregate.constructorSourceUninhabited

def Aggregate.dynamicProjection
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    OriginalSourceFactMixedProjection
      (combinedExtension routeInvariant constructorOperational
        dynamicOperational)
      dynamicCut.certificate.sourceTargetId
      (fun _world _state => False) :=
  projectionFromCombined routeInvariant constructorOperational
    dynamicOperational dynamicOperational.toExtension (by simp)
    dynamicOperational.sourceFalseProjection

theorem Aggregate.dynamicSourceUninhabited
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    ActualMixedOriginalStackDynamicSourceUninhabited
      (combinedMixedInvariant routeInvariant constructorOperational
        dynamicOperational)
      dynamicSite.site.sourceTargetId := by
  have uninhabited :=
    actualMixedOriginalStackDynamicSourceUninhabited_of_mixedProjection
      aggregate.dynamicProjection
  rw [aggregate.dynamicSourceExact] at uninhabited
  exact uninhabited

def Aggregate.dynamicComposition
    (aggregate :
      Aggregate (context := context) (original := original)
        (candidate := candidate)
        (stackAuthority := stackAuthority)
        (routeAuthority := routeAuthority)
        (constructorAuthority := constructorAuthority)
        (constructorCut := constructorCut)
        (dynamicSite := dynamicSite)
        (dynamicCut := dynamicCut)
        base routeInvariant constructorOperational dynamicOperational) :
    DynamicSourceMixedOriginalComposition dynamicSite
      (combinedMixedInvariant routeInvariant constructorOperational
        dynamicOperational) where
  complete := {
    sourceUninhabited := aggregate.dynamicSourceUninhabited
  }

#print axioms Aggregate.stackComposition
#print axioms Aggregate.constructorComposition
#print axioms Aggregate.dynamicComposition
#print axioms CheckedMixedKernelSelectedInvariantClosure.toMixedWorldChunkComposition
#print axioms
  CheckedRootedScannerSelectedSourceProjection.sourceUninhabited
#print axioms combinedExtension_holds_at_root_of_checked
#print axioms CheckedRouteTransferExecution.preservesOriginal
#print axioms CheckedRouteTransferInventory.exact
#print axioms stackRangeSlotHolds_of_stateRel_window_add_checked
#print axioms stackRangeSlotHolds_of_canonicalRangeOffset
#print axioms originalSourceFact_of_strengthenedProjection

end StageA.Relational.RuntimeIndirectComposition
