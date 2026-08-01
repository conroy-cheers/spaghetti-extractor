import StageA.RelationalOriginalStaticWordExecutionInvariant
import StageA.RelationalOriginalRuntimeMemoryPartition
import StageA.RelationalOriginalValueFlowExecutionInvariant
import StageA.RelationalRegisterIndirectMixedOriginalComposition
import StageA.RelationalStackDynamicIndirectMixedOriginalComposition
import StageA.RelationalSourceExecutionDomain

namespace StageA.Relational.OriginalCombinedExecutionInvariant

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalExecutionInvariant
open StageA.Relational.OriginalIndirectControlAuthority
open StageA.Relational.OriginalRuntimeMemoryPartition
open StageA.Relational.OriginalStackDynamicControlClosure
open StageA.Relational.OriginalStaticWordExecutionInvariant
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.SourceWorld
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition

/-!
# Combined one-sided original execution invariant

This module is the root-independent acceptance boundary for finite original
control and value facts.  It combines exact reachable-target membership,
static-word provenance, relational call frames, register target inventories,
stack/dynamic target facts, and the checked runtime-memory partition into one
predicate over concrete `WorldExecution` values.

The finite facts are retained directly at their source states.  In particular,
register membership is stated as `RuntimeTargetMember`, while stack/dynamic
membership retains an `OriginalResolvedCodeTarget`.  Neither fact is inferred
from the existence of an analysis history.  A program adapter must prove one
exact step-closure theorem for the complete conjunction.
-/

/-- Exact finite target inventory used by the acceptance-side reachability
projection.  The round-trip proof binds every admitted logical target to the
program's canonical raw EIP. -/
structure ExactOriginalReachableTargetInventory
    (program : DecodedWorldProgram) where
  targetIds : List Nat
  targetIdsUnique : targetIds.Nodup
  targetRoundTrips : forall targetId,
    targetId ∈ targetIds ->
      exists eip,
        program.canonicalRawEip? targetId = some eip /\
          program.resolveRawEip eip = some targetId

/-- One register-mediated indirect source.  The checked static certificate
supplies the finite inventory; this predicate requires membership for the
concrete register value whenever execution is at that source.  Runtime
membership is part of the combined invariant itself, rather than hidden behind
the circular `CheckedAuthority.reachable` premise. -/
structure OriginalRegisterTargetRequirement
    (context : OriginalDecodedStaticContext) where
  certificate : CheckedCertificate context

def OriginalRegisterTargetRequirement.Holds
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalRegisterTargetRequirement context) :
    WorldExecution -> Prop
  | .running targetId state _calls _eventIndex world =>
      targetId =
          requirement.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember context world
          (state.registers.get
            requirement.certificate.certificate.register)
          requirement.certificate.certificate.inventory
  | .callbackRunning targetId state _calls _eventIndex world _callbacks =>
      targetId =
          requirement.certificate.certificate.site.sourceTargetId ->
        RuntimeTargetMember context world
          (state.registers.get
            requirement.certificate.certificate.register)
          requirement.certificate.certificate.inventory
  | _ => True

theorem OriginalRegisterTargetRequirement.targetMemberAtRunningSource
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalRegisterTargetRequirement context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (holds : requirement.Holds
      (.running targetId state calls eventIndex world))
    (atSource :
      targetId = requirement.certificate.certificate.site.sourceTargetId) :
    RuntimeTargetMember context world
      (state.registers.get requirement.certificate.certificate.register)
      requirement.certificate.certificate.inventory :=
  holds atSource

theorem OriginalRegisterTargetRequirement.targetMemberAtCallbackSource
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalRegisterTargetRequirement context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (callbacks : List WorldExternalCallbackRuntime)
    (holds : requirement.Holds
      (.callbackRunning targetId state calls eventIndex world callbacks))
    (atSource :
      targetId = requirement.certificate.certificate.site.sourceTargetId) :
    RuntimeTargetMember context world
      (state.registers.get requirement.certificate.certificate.register)
      requirement.certificate.certificate.inventory :=
  holds atSource

/-- A stack-, table-, or dynamic-memory-derived target requirement.  Proposal
logic may choose the source fact, but the checked requirement must turn it into
a resolved target in a finite, statically checked code inventory. -/
structure OriginalStackDynamicTargetRequirement
    (context : OriginalDecodedStaticContext) where
  site : OriginalIndirectControlSite
  allowedTargetIds : List Nat
  allowedTargetsChecked :
    codeTargetInventoryChecked context allowedTargetIds = true
  sourceFact : RelationalWorld -> MachineState -> Prop
  sourceFactResolves : forall world state,
    sourceFact world state ->
      exists resolved : OriginalResolvedCodeTarget context site state,
        resolved.targetId ∈ allowedTargetIds

def OriginalStackDynamicTargetRequirement.Holds
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalStackDynamicTargetRequirement context)
    (execution : WorldExecution) : Prop :=
  OriginalSourceFactAt requirement.site.sourceTargetId requirement.sourceFact
    execution

theorem OriginalStackDynamicTargetRequirement.targetMemberAtSource
    {context : OriginalDecodedStaticContext}
    (requirement : OriginalStackDynamicTargetRequirement context)
    (targetId : Nat) (state : MachineState) (calls : List Nat)
    (eventIndex : Nat) (world : RelationalWorld)
    (holds : requirement.Holds
      (.running targetId state calls eventIndex world))
    (atSource : targetId = requirement.site.sourceTargetId) :
    exists resolved : OriginalResolvedCodeTarget context requirement.site state,
      resolved.targetId ∈ requirement.allowedTargetIds :=
  requirement.sourceFactResolves world state (holds atSource)

def OriginalRegisterTargetsHold
    {context : OriginalDecodedStaticContext}
    (requirements : List (OriginalRegisterTargetRequirement context))
    (execution : WorldExecution) : Prop :=
  forall requirement, requirement ∈ requirements -> requirement.Holds execution

def OriginalStackDynamicTargetsHold
    {context : OriginalDecodedStaticContext}
    (requirements : List (OriginalStackDynamicTargetRequirement context))
    (execution : WorldExecution) : Prop :=
  forall requirement, requirement ∈ requirements -> requirement.Holds execution

/-- All finite one-sided facts required by one original program. -/
structure OriginalCombinedExecutionInventory
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext) where
  reachableTargets : ExactOriginalReachableTargetInventory program
  staticWords : OriginalStaticWordInventory := {}
  valueFlows : OriginalValueFlowInventory program.context := {
    facts := []
    factIdsUnique := List.nodup_nil
  }
  registerTargets : List (OriginalRegisterTargetRequirement originalContext) := []
  stackDynamicTargets :
    List (OriginalStackDynamicTargetRequirement originalContext) := []

/-- The authoritative combined predicate.  Reachability and both memory/frame
components reject proof-blocked states.  Target facts remain explicit finite
witnesses at their corresponding concrete source states. -/
def OriginalCombinedExecutionInventory.Holds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (execution : WorldExecution) : Prop :=
  OriginalExecutionReachable inventory.reachableTargets.targetIds execution /\
    inventory.staticWords.Holds program.context execution /\
    OriginalCallFrameExecutionHolds program.context execution /\
    inventory.valueFlows.Holds execution /\
    OriginalRegisterTargetsHold inventory.registerTargets execution /\
    OriginalStackDynamicTargetsHold inventory.stackDynamicTargets execution /\
    OriginalRuntimeMemoryPartition.ExecutionHolds program.context execution

theorem OriginalCombinedExecutionInventory.reachable
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution) :
    OriginalExecutionReachable inventory.reachableTargets.targetIds execution :=
  holds.1

theorem OriginalCombinedExecutionInventory.staticWordsHold
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution) :
    inventory.staticWords.Holds program.context execution :=
  holds.2.1

theorem OriginalCombinedExecutionInventory.callFramesHold
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution) :
    OriginalCallFrameExecutionHolds program.context execution :=
  holds.2.2.1

theorem OriginalCombinedExecutionInventory.registerTargetHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution)
    (requirement : OriginalRegisterTargetRequirement originalContext)
    (member : requirement ∈ inventory.registerTargets) :
    requirement.Holds execution :=
  holds.2.2.2.2.1 requirement member

theorem OriginalCombinedExecutionInventory.valueFlowHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution)
    (fact : OriginalFiniteValueFlowFact program.context)
    (member : fact ∈ inventory.valueFlows.facts) :
    fact.Holds execution :=
  holds.2.2.2.1 fact member

theorem OriginalCombinedExecutionInventory.stackDynamicTargetHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution)
    (requirement : OriginalStackDynamicTargetRequirement originalContext)
    (member : requirement ∈ inventory.stackDynamicTargets) :
    requirement.Holds execution :=
  holds.2.2.2.2.2.1 requirement member

theorem OriginalCombinedExecutionInventory.runtimeMemoryHolds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {execution : WorldExecution} (holds : inventory.Holds execution) :
    OriginalRuntimeMemoryPartition.ExecutionHolds program.context execution :=
  holds.2.2.2.2.2.2

theorem OriginalCombinedExecutionInventory.blockedFalse
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (reason : ExecutionBlock) :
    Not (inventory.Holds (.blocked reason)) := by
  intro holds
  simpa [OriginalExecutionReachable] using holds.1

/-- The single whole-program adapter.  Static extraction and local transfer
lemmas may help prove this field, but only exact closure of the complete
predicate can construct the acceptance invariant. -/
structure CheckedOriginalCombinedExecutionInvariant
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext) :
    Prop where
  stepClosed : forall before,
    inventory.Holds before ->
      inventory.Holds (program.pe32TransitionSystem.step before).next

/-- Cache-friendly decomposition of the single inductive closure theorem.
Every family sees the same complete pre-state invariant, so a value-flow proof
may consume static-word or call-frame facts without introducing independently
rooted proof regimes.  The constructor below is the only authority-producing
use of these fields. -/
structure CheckedOriginalCombinedExecutionStepFamilies
    (program : DecodedWorldProgram)
    (originalContext : OriginalDecodedStaticContext)
    (inventory : OriginalCombinedExecutionInventory program originalContext) :
    Prop where
  reachabilityClosed : forall before,
    inventory.Holds before ->
      OriginalExecutionReachable inventory.reachableTargets.targetIds
        (program.pe32TransitionSystem.step before).next
  staticWordsClosed : forall before,
    inventory.Holds before ->
      inventory.staticWords.Holds program.context
        (program.pe32TransitionSystem.step before).next
  callFramesClosed : forall before,
    inventory.Holds before ->
      OriginalCallFrameExecutionHolds program.context
        (program.pe32TransitionSystem.step before).next
  valueFlowsClosed : forall before,
    inventory.Holds before ->
      inventory.valueFlows.Holds
        (program.pe32TransitionSystem.step before).next
  registerTargetsClosed : forall before,
    inventory.Holds before ->
      OriginalRegisterTargetsHold inventory.registerTargets
        (program.pe32TransitionSystem.step before).next
  stackDynamicTargetsClosed : forall before,
    inventory.Holds before ->
      OriginalStackDynamicTargetsHold inventory.stackDynamicTargets
        (program.pe32TransitionSystem.step before).next
  runtimeMemoryClosed : forall before,
    inventory.Holds before ->
      OriginalRuntimeMemoryPartition.ExecutionHolds program.context
        (program.pe32TransitionSystem.step before).next

def CheckedOriginalCombinedExecutionStepFamilies.toCheckedInvariant
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (families : CheckedOriginalCombinedExecutionStepFamilies program
      originalContext inventory) :
    CheckedOriginalCombinedExecutionInvariant program originalContext
      inventory where
  stepClosed before holds :=
    ⟨families.reachabilityClosed before holds,
      families.staticWordsClosed before holds,
      families.callFramesClosed before holds,
      families.valueFlowsClosed before holds,
      families.registerTargetsClosed before holds,
      families.stackDynamicTargetsClosed before holds,
      families.runtimeMemoryClosed before holds⟩

def CheckedOriginalCombinedExecutionInvariant.toOriginalInvariant
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (checked : CheckedOriginalCombinedExecutionInvariant program
      originalContext inventory) :
    OriginalWorldExecutionInvariant program where
  holds := inventory.Holds
  stepClosed := checked.stepClosed

@[simp]
theorem CheckedOriginalCombinedExecutionInvariant.toOriginalInvariant_holds
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (checked : CheckedOriginalCombinedExecutionInvariant program
      originalContext inventory)
    (execution : WorldExecution) :
    checked.toOriginalInvariant.holds execution <-> inventory.Holds execution :=
  Iff.rfl

/-- The combined invariant exposes exactly the finite target inventory carried
by its predicate.  This is the direct bridge to source-domain acceptance. -/
def CheckedOriginalCombinedExecutionInvariant.toInvariantFamilyEvidence
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (checked : CheckedOriginalCombinedExecutionInvariant program
      originalContext inventory) :
    StageA.Relational.SourceWorld.CheckedOriginalInvariantFamilyEvidence program
      where
  invariant := checked.toOriginalInvariant
  targetIds := inventory.reachableTargets.targetIds
  targetIdsUnique := inventory.reachableTargets.targetIdsUnique
  reachabilityProjection _execution holds := holds.1
  targetRoundTrips := inventory.reachableTargets.targetRoundTrips

theorem CheckedOriginalCombinedExecutionInvariant.registerTargetMember
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (checked : CheckedOriginalCombinedExecutionInvariant program
      originalContext inventory)
    {execution : WorldExecution}
    (holds : checked.toInvariantFamilyEvidence.invariant.holds execution)
    (requirement : OriginalRegisterTargetRequirement originalContext)
    (member : requirement ∈ inventory.registerTargets) :
    requirement.Holds execution :=
  inventory.registerTargetHolds holds requirement member

theorem CheckedOriginalCombinedExecutionInvariant.stackDynamicTargetMember
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    (checked : CheckedOriginalCombinedExecutionInvariant program
      originalContext inventory)
    {execution : WorldExecution}
    (holds : checked.toInvariantFamilyEvidence.invariant.holds execution)
    (requirement : OriginalStackDynamicTargetRequirement originalContext)
    (member : requirement ∈ inventory.stackDynamicTargets) :
    requirement.Holds execution :=
  inventory.stackDynamicTargetHolds holds requirement member

#print axioms OriginalStackDynamicTargetRequirement.targetMemberAtSource
#print axioms OriginalRegisterTargetRequirement.targetMemberAtRunningSource
#print axioms OriginalRegisterTargetRequirement.targetMemberAtCallbackSource
#print axioms OriginalCombinedExecutionInventory.blockedFalse
#print axioms CheckedOriginalCombinedExecutionInvariant.toOriginalInvariant
#print axioms CheckedOriginalCombinedExecutionStepFamilies.toCheckedInvariant
#print axioms CheckedOriginalCombinedExecutionInvariant.toInvariantFamilyEvidence
#print axioms CheckedOriginalCombinedExecutionInvariant.registerTargetMember
#print axioms CheckedOriginalCombinedExecutionInvariant.stackDynamicTargetMember
#print axioms OriginalCombinedExecutionInventory.runtimeMemoryHolds

end StageA.Relational.OriginalCombinedExecutionInvariant
