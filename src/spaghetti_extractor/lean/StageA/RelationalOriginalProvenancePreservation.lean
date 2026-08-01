import StageA.RelationalOriginalTargetPreservation
import StageA.RelationalValueProvenance

namespace StageA.Relational.ValueProvenance

open StageA.Formal StageA.Relational

/-! ## One-sided projections of normalized transition effects

The paired effect language is also the canonical normalized effect language for
the original-only execution invariant.  These projections retain the exact
ordered writes and register expressions for the original side without inventing
a second summary format.
-/

def TransitionEffects.OriginalMemoryImplements
    (effects : TransitionEffects) (before after : MachineState) : Prop :=
  after.memory = applyConcreteWrites before.memory
    (effects.originalConcreteWrites before)

def TransitionEffects.OriginalRegistersImplement
    (effects : TransitionEffects) (before after : MachineState) : Prop :=
  forall register,
    match effects.originalRegisterEffect? register with
    | none => after.registers.get register = before.registers.get register
    | some effect =>
        after.registers.get register = effect.originalValue.eval before

def TransitionEffects.OriginalRuntimeImplements
    (effects : TransitionEffects) (before after : MachineState) : Prop :=
  effects.OriginalMemoryImplements before after /\
    effects.OriginalRegistersImplement before after

theorem TransitionEffects.OriginalRegistersImplement.preserved
    (effects : TransitionEffects) (before after : MachineState) (register : Reg)
    (implemented : effects.OriginalRegistersImplement before after)
    (missing : effects.originalRegisterEffect? register = none) :
    after.registers.get register = before.registers.get register := by
  simpa [missing] using implemented register

theorem TransitionEffects.RuntimeMemoryImplements.original
    (effects : TransitionEffects)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (implemented : effects.RuntimeMemoryImplements originalBefore candidateBefore
      originalAfter candidateAfter) :
    effects.OriginalMemoryImplements originalBefore originalAfter :=
  implemented.1

theorem TransitionEffects.RuntimeRegistersImplement.original
    (effects : TransitionEffects)
    (originalBefore candidateBefore originalAfter candidateAfter : MachineState)
    (implemented : effects.RuntimeRegistersImplement originalBefore candidateBefore
      originalAfter candidateAfter) :
    effects.OriginalRegistersImplement originalBefore originalAfter :=
  implemented.1

end StageA.Relational.ValueProvenance

namespace StageA.Relational.OriginalProvenancePreservation

open StageA.Formal StageA.Relational
open StageA.Relational.ControlValueProvenance
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.OriginalCallFrameExecutionInvariant
open StageA.Relational.OriginalCombinedExecutionInvariant
open StageA.Relational.OriginalTargetPreservation
open StageA.Relational.OriginalValueFlowExecutionInvariant
open StageA.Relational.RegisterIndirectControlAuthority
open StageA.Relational.SourceWorld.InterpreterKernel
open StageA.Relational.StackDynamicIndirectMixedOriginalComposition
open StageA.Relational.ValueProvenance

/-!
# Generic original provenance preservation

This module derives the value-flow and indirect-target postcondition families
from one checked normalized effect summary.  It does not authorize the machine
step: callers must bind the summary to a `CheckedOriginalTargetTransition`.
Every state-bearing successor is tied to the exact ordered writes and register
expressions in that summary.

Finite joins are inherited from `OriginalFiniteValueFlowFact`: every introduced
or transported origin must be a member of its nonempty, duplicate-free,
budget-bounded alternative list.  There is deliberately no unknown or widening
case.
-/

/-- One normalized effect summary implemented by the concrete original
successor.  Terminal and fault states have no machine state to constrain, but
still require a structurally checked summary. -/
structure CheckedOriginalNormalizedTransitionEffects
    (before : MachineState) (successor : OriginalNormalizedSuccessor) where
  effects : TransitionEffects
  effectsChecked : effects.checked = true
  implements :
    match successor with
    | .running _ state _ _ _ => effects.OriginalRuntimeImplements before state
    | .callbackRunning _ state _ _ _ _ =>
        effects.OriginalRuntimeImplements before state
    | .awaitingExternal suspension _ =>
        effects.OriginalRuntimeImplements before suspension.state
    | .returned state _ => effects.OriginalRuntimeImplements before state
    | .terminated _ | .fault _ => True

/-- The normalized effects and the exact PE transition share one successor.
This is the adapter consumed by generated target-preservation shards. -/
structure CheckedOriginalTargetProvenanceEffects
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {reachableTargetIds : List Nat}
    {invocation : OriginalTargetInvocation targetId}
    (transition : CheckedOriginalTargetTransition checked originalContext
      reachableTargetIds invocation) where
  normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
    transition.successor

theorem activeValueFlowAt
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (before : inventory.Holds invocation.execution)
    (fact : OriginalFiniteValueFlowFact program.context)
    (factMember : fact ∈ inventory.valueFlows.facts)
    (targetMember : targetId ∈ fact.targetIds) :
    fact.HoldsAt invocation.state invocation.world := by
  have holds := inventory.valueFlowHolds before fact factMember
  cases callbackCase : invocation.callbacks with
  | none =>
      have active : targetId ∈ fact.targetIds ->
          fact.HoldsAt invocation.state invocation.world := by
        simpa [OriginalTargetInvocation.execution, callbackCase] using holds
      exact active targetMember
  | some callbacks =>
      have active : targetId ∈ fact.targetIds ->
          fact.HoldsAt invocation.state invocation.world := by
        simpa [OriginalTargetInvocation.execution, callbackCase] using holds
      exact active targetMember

theorem activeRegisterTargetMember
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (before : inventory.Holds invocation.execution)
    (requirement : OriginalRegisterTargetRequirement originalContext)
    (requirementMember : requirement ∈ inventory.registerTargets)
    (atSource : targetId =
      requirement.certificate.certificate.site.sourceTargetId) :
    RuntimeTargetMember originalContext invocation.world
      (invocation.state.registers.get
        requirement.certificate.certificate.register)
      requirement.certificate.certificate.inventory := by
  have holds := inventory.registerTargetHolds before requirement requirementMember
  cases callbackCase : invocation.callbacks with
  | none =>
      have active : targetId =
            requirement.certificate.certificate.site.sourceTargetId ->
          RuntimeTargetMember originalContext invocation.world
            (invocation.state.registers.get
              requirement.certificate.certificate.register)
            requirement.certificate.certificate.inventory := by
        simpa [OriginalTargetInvocation.execution, callbackCase,
          OriginalRegisterTargetRequirement.Holds] using holds
      exact active atSource
  | some callbacks =>
      have active : targetId =
            requirement.certificate.certificate.site.sourceTargetId ->
          RuntimeTargetMember originalContext invocation.world
            (invocation.state.registers.get
              requirement.certificate.certificate.register)
            requirement.certificate.certificate.inventory := by
        simpa [OriginalTargetInvocation.execution, callbackCase,
          OriginalRegisterTargetRequirement.Holds] using holds
      exact active atSource

/-- Explicit transport for one value-flow endpoint.  Register framing is
derived from the normalized effect summary.  General value framing carries an
exact value equality.  A related update must name a concrete finite origin, and
a decoded transfer must retain its exact checked transfer object. -/
inductive OriginalValueFlowEndpointTransfer
    {program : DecodedWorldProgram}
    (fact : OriginalFiniteValueFlowFact program.context)
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (effects : TransitionEffects) (afterState : MachineState)
    (afterWorld : RelationalWorld) : Prop where
  | registerFrame (register : Reg)
      (sourceTargetMember : targetId ∈ fact.targetIds)
      (locationExact : fact.location = .register register)
      (registerUnwritten : effects.originalRegisterEffect? register = none)
      (worldFrame : OriginalValueFlowWorldFrame program.context invocation.world
        afterWorld fact.alternatives) :
      OriginalValueFlowEndpointTransfer fact invocation effects afterState
        afterWorld
  | valueFrame
      (sourceTargetMember : targetId ∈ fact.targetIds)
      (valueExact : originalLocationValue fact.location afterState =
        originalLocationValue fact.location invocation.state)
      (worldFrame : OriginalValueFlowWorldFrame program.context invocation.world
        afterWorld fact.alternatives) :
      OriginalValueFlowEndpointTransfer fact invocation effects afterState
        afterWorld
  | relatedUpdate (selected : ValueOriginAtom)
      (selectedMember : selected ∈ fact.alternatives)
      (selectedHolds : OriginalValueOriginAtomHolds program.context afterWorld
        (originalLocationValue fact.location afterState) selected) :
      OriginalValueFlowEndpointTransfer fact invocation effects afterState
        afterWorld
  | decodedTransfer
      (sourceLocation : ControlValueProvenance.Location)
      (selected : ValueOriginAtom) (selectedMember : selected ∈ fact.alternatives)
      (sourceHolds : OriginalValueOriginAtomHolds program.context afterWorld
        (originalLocationValue sourceLocation invocation.state) selected)
      (transfer : CheckedOriginalDecodedLocationTransfer program sourceLocation
        fact.location)
      (stateExact : afterState =
        (transfer.behavior.eval invocation.state).nextMachineState
          invocation.state) :
      OriginalValueFlowEndpointTransfer fact invocation effects afterState
        afterWorld

theorem OriginalValueFlowEndpointTransfer.toAtEvidence
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {fact : OriginalFiniteValueFlowFact program.context}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {effects : TransitionEffects} {afterState : MachineState}
    {afterWorld : RelationalWorld}
    (transfer : OriginalValueFlowEndpointTransfer fact invocation effects
      afterState afterWorld)
    (before : inventory.Holds invocation.execution)
    (factMember : fact ∈ inventory.valueFlows.facts)
    (registersImplement : effects.OriginalRegistersImplement invocation.state
      afterState) : OriginalValueFlowAtEvidence program fact afterState afterWorld := by
  cases transfer with
  | registerFrame register sourceTargetMember locationExact registerUnwritten
      worldFrame =>
      have beforeAt := activeValueFlowAt invocation before fact factMember
        sourceTargetMember
      apply OriginalValueFlowAtEvidence.afterFrame invocation.state invocation.world
        beforeAt
      · rw [locationExact]
        simpa [originalLocationValue, ControlValueProvenance.Location.inputExpr,
          Expr.eval] using
          TransitionEffects.OriginalRegistersImplement.preserved effects
            invocation.state afterState register registersImplement
            registerUnwritten
      · exact worldFrame
  | valueFrame sourceTargetMember valueExact worldFrame =>
      have beforeAt := activeValueFlowAt invocation before fact factMember
        sourceTargetMember
      exact .afterFrame invocation.state invocation.world beforeAt valueExact
        worldFrame
  | relatedUpdate selected selectedMember selectedHolds =>
      exact .origin selected selectedMember selectedHolds
  | decodedTransfer sourceLocation selected selectedMember sourceHolds checked
      stateExact =>
      exact .decodedTransfer sourceLocation invocation.state selected selectedMember
        sourceHolds checked stateExact

/-- Runtime target membership may survive a world update only through an
explicit frame for the exact finite target inventory. -/
structure OriginalRuntimeTargetWorldFrame
    (context : OriginalDecodedStaticContext)
    (before after : RelationalWorld) (inventory : RegisterTargetInventory) : Prop where
  preserves : forall value,
    RuntimeTargetMember context before value inventory ->
      RuntimeTargetMember context after value inventory

/-- A finite value-flow fact resolves a register target origin-by-origin.  The
resolver must cover every selected member of the fact's bounded alternatives. -/
structure OriginalRegisterValueFlowResolver
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (fact : OriginalFiniteValueFlowFact program.context)
    (requirement : OriginalRegisterTargetRequirement originalContext) : Prop where
  sourceTargetMember :
    requirement.certificate.certificate.site.sourceTargetId ∈ fact.targetIds
  locationExact : fact.location =
    .register requirement.certificate.certificate.register
  resolveOrigin : forall (world : RelationalWorld) (state : MachineState)
      (origin : ValueOriginAtom),
    origin ∈ fact.alternatives ->
      OriginalValueOriginAtomHolds program.context world
        (state.registers.get requirement.certificate.certificate.register) origin ->
      RuntimeTargetMember originalContext world
        (state.registers.get requirement.certificate.certificate.register)
        requirement.certificate.certificate.inventory

theorem OriginalRegisterValueFlowResolver.resolve
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {fact : OriginalFiniteValueFlowFact program.context}
    {requirement : OriginalRegisterTargetRequirement originalContext}
    (resolver : OriginalRegisterValueFlowResolver fact requirement)
    (state : MachineState) (world : RelationalWorld)
    (holds : fact.HoldsAt state world) :
    RuntimeTargetMember originalContext world
      (state.registers.get requirement.certificate.certificate.register)
      requirement.certificate.certificate.inventory := by
  rcases holds with ⟨origin, member, originHolds⟩
  exact resolver.resolveOrigin world state origin member (by
    simpa [resolver.locationExact, originalLocationValue,
      ControlValueProvenance.Location.inputExpr, Expr.eval] using originHolds)

/-- Register-target preservation uses either an exact unwritten-register frame,
an origin-by-origin finite value-flow resolver, or an explicit related update. -/
inductive OriginalRegisterTargetTransfer
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (effects : TransitionEffects)
    (requirement : OriginalRegisterTargetRequirement originalContext)
    (afterState : MachineState) (afterWorld : RelationalWorld) : Prop where
  | preserved
      (beforeAtSource : targetId =
        requirement.certificate.certificate.site.sourceTargetId)
      (registerUnwritten : effects.originalRegisterEffect?
        requirement.certificate.certificate.register = none)
      (worldFrame : OriginalRuntimeTargetWorldFrame originalContext
        invocation.world afterWorld requirement.certificate.certificate.inventory) :
      OriginalRegisterTargetTransfer inventory invocation effects requirement
        afterState afterWorld
  | fromFiniteValueFlow (fact : OriginalFiniteValueFlowFact program.context)
      (factMember : fact ∈ inventory.valueFlows.facts)
      (resolver : OriginalRegisterValueFlowResolver fact requirement) :
      OriginalRegisterTargetTransfer inventory invocation effects requirement
        afterState afterWorld
  | relatedUpdate
      (member : RuntimeTargetMember originalContext afterWorld
        (afterState.registers.get requirement.certificate.certificate.register)
        requirement.certificate.certificate.inventory) :
      OriginalRegisterTargetTransfer inventory invocation effects requirement
        afterState afterWorld

theorem OriginalRegisterTargetTransfer.toMember
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {effects : TransitionEffects}
    {requirement : OriginalRegisterTargetRequirement originalContext}
    {afterState : MachineState} {afterWorld : RelationalWorld}
    (transfer : OriginalRegisterTargetTransfer inventory invocation effects
      requirement afterState afterWorld)
    (before : inventory.Holds invocation.execution)
    (requirementMember : requirement ∈ inventory.registerTargets)
    (registersImplement : effects.OriginalRegistersImplement invocation.state
      afterState)
    (valueAt : forall fact,
      fact ∈ inventory.valueFlows.facts ->
      requirement.certificate.certificate.site.sourceTargetId ∈ fact.targetIds ->
        fact.HoldsAt afterState afterWorld) :
    RuntimeTargetMember originalContext afterWorld
      (afterState.registers.get requirement.certificate.certificate.register)
      requirement.certificate.certificate.inventory := by
  cases transfer with
  | preserved beforeAtSource registerUnwritten worldFrame =>
      have beforeMember := activeRegisterTargetMember invocation before requirement
        requirementMember beforeAtSource
      have registerExact :=
        TransitionEffects.OriginalRegistersImplement.preserved effects
          invocation.state afterState
          requirement.certificate.certificate.register registersImplement
          registerUnwritten
      rw [registerExact]
      exact worldFrame.preserves _ beforeMember
  | fromFiniteValueFlow fact factMember resolver =>
      exact resolver.resolve afterState afterWorld
        (valueAt fact factMember resolver.sourceTargetMember)
  | relatedUpdate member => exact member

theorem activeStackDynamicSource
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (before : inventory.Holds invocation.execution)
    (requirement : OriginalStackDynamicTargetRequirement originalContext)
    (requirementMember : requirement ∈ inventory.stackDynamicTargets)
    (atSource : targetId = requirement.site.sourceTargetId) :
    requirement.sourceFact invocation.world invocation.state := by
  have holds := inventory.stackDynamicTargetHolds before requirement
    requirementMember
  cases callbackCase : invocation.callbacks with
  | none =>
      have active : targetId = requirement.site.sourceTargetId ->
          requirement.sourceFact invocation.world invocation.state := by
        simpa [OriginalTargetInvocation.execution, callbackCase,
          OriginalStackDynamicTargetRequirement.Holds, OriginalSourceFactAt]
          using holds
      exact active atSource
  | some callbacks =>
      have active : targetId = requirement.site.sourceTargetId ->
          requirement.sourceFact invocation.world invocation.state := by
        simpa [OriginalTargetInvocation.execution, callbackCase,
          OriginalStackDynamicTargetRequirement.Holds, OriginalSourceFactAt]
          using holds
      exact active atSource

/-- A stack/dynamic source fact is recovered from a finite value-flow fact one
origin at a time. -/
structure OriginalStackDynamicValueFlowResolver
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (fact : OriginalFiniteValueFlowFact program.context)
    (requirement : OriginalStackDynamicTargetRequirement originalContext) : Prop where
  sourceTargetMember : requirement.site.sourceTargetId ∈ fact.targetIds
  resolveOrigin : forall (world : RelationalWorld) (state : MachineState)
      (origin : ValueOriginAtom),
    origin ∈ fact.alternatives ->
      OriginalValueOriginAtomHolds program.context world
        (originalLocationValue fact.location state) origin ->
      requirement.sourceFact world state

theorem OriginalStackDynamicValueFlowResolver.resolve
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {fact : OriginalFiniteValueFlowFact program.context}
    {requirement : OriginalStackDynamicTargetRequirement originalContext}
    (resolver : OriginalStackDynamicValueFlowResolver fact requirement)
    (state : MachineState) (world : RelationalWorld)
    (holds : fact.HoldsAt state world) : requirement.sourceFact world state := by
  rcases holds with ⟨origin, member, originHolds⟩
  exact resolver.resolveOrigin world state origin member originHolds

/-- Stack/dynamic target preservation uses an explicit source-fact frame, a
finite value-flow resolver, or an explicit related update. -/
inductive OriginalStackDynamicTargetTransfer
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (requirement : OriginalStackDynamicTargetRequirement originalContext)
    (afterState : MachineState) (afterWorld : RelationalWorld) : Prop where
  | preserved (beforeAtSource : targetId = requirement.site.sourceTargetId)
      (sourceFrame : requirement.sourceFact invocation.world invocation.state ->
        requirement.sourceFact afterWorld afterState) :
      OriginalStackDynamicTargetTransfer inventory invocation requirement
        afterState afterWorld
  | fromFiniteValueFlow (fact : OriginalFiniteValueFlowFact program.context)
      (factMember : fact ∈ inventory.valueFlows.facts)
      (resolver : OriginalStackDynamicValueFlowResolver fact requirement) :
      OriginalStackDynamicTargetTransfer inventory invocation requirement
        afterState afterWorld
  | relatedUpdate (source : requirement.sourceFact afterWorld afterState) :
      OriginalStackDynamicTargetTransfer inventory invocation requirement
        afterState afterWorld

theorem OriginalStackDynamicTargetTransfer.toSourceFact
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {requirement : OriginalStackDynamicTargetRequirement originalContext}
    {afterState : MachineState} {afterWorld : RelationalWorld}
    (transfer : OriginalStackDynamicTargetTransfer inventory invocation
      requirement afterState afterWorld)
    (before : inventory.Holds invocation.execution)
    (requirementMember : requirement ∈ inventory.stackDynamicTargets)
    (valueAt : forall fact,
      fact ∈ inventory.valueFlows.facts ->
      requirement.site.sourceTargetId ∈ fact.targetIds ->
        fact.HoldsAt afterState afterWorld) :
    requirement.sourceFact afterWorld afterState := by
  cases transfer with
  | preserved beforeAtSource sourceFrame =>
      exact sourceFrame (activeStackDynamicSource invocation before requirement
        requirementMember beforeAtSource)
  | fromFiniteValueFlow fact factMember resolver =>
      exact resolver.resolve afterState afterWorld
        (valueAt fact factMember resolver.sourceTargetMember)
  | relatedUpdate source => exact source

def OriginalValueFlowEndpointObligation
    {program : DecodedWorldProgram}
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (effects : TransitionEffects) (successor : OriginalNormalizedSuccessor)
    (fact : OriginalFiniteValueFlowFact program.context) : Prop :=
  match successor with
  | .running nextTarget state _ _ world =>
      nextTarget ∈ fact.targetIds ->
        OriginalValueFlowEndpointTransfer fact invocation effects state world
  | .callbackRunning nextTarget state _ _ world _ =>
      nextTarget ∈ fact.targetIds ->
        OriginalValueFlowEndpointTransfer fact invocation effects state world
  | .awaitingExternal suspension _ =>
      (suspension.sourceTargetId ∈ fact.targetIds \/
          suspension.continuationTargetId ∈ fact.targetIds) ->
        OriginalValueFlowEndpointTransfer fact invocation effects suspension.state
          suspension.world
  | .returned _ _ | .terminated _ | .fault _ => True

def OriginalRegisterTargetEndpointObligation
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (effects : TransitionEffects) (successor : OriginalNormalizedSuccessor)
    (requirement : OriginalRegisterTargetRequirement originalContext) : Prop :=
  match successor with
  | .running nextTarget state _ _ world =>
      nextTarget = requirement.certificate.certificate.site.sourceTargetId ->
        OriginalRegisterTargetTransfer inventory invocation effects requirement
          state world
  | .callbackRunning nextTarget state _ _ world _ =>
      nextTarget = requirement.certificate.certificate.site.sourceTargetId ->
        OriginalRegisterTargetTransfer inventory invocation effects requirement
          state world
  | .awaitingExternal _ _ | .returned _ _ | .terminated _ | .fault _ => True

def OriginalStackDynamicTargetEndpointObligation
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (successor : OriginalNormalizedSuccessor)
    (requirement : OriginalStackDynamicTargetRequirement originalContext) : Prop :=
  match successor with
  | .running nextTarget state _ _ world =>
      nextTarget = requirement.site.sourceTargetId ->
        OriginalStackDynamicTargetTransfer inventory invocation requirement state
          world
  | .callbackRunning nextTarget state _ _ world _ =>
      nextTarget = requirement.site.sourceTargetId ->
        OriginalStackDynamicTargetTransfer inventory invocation requirement state
          world
  | .awaitingExternal _ _ | .returned _ _ | .terminated _ | .fault _ => True

/-- The complete explicit witness inventory for the three provenance families.
It is indexed by the complete pre-invariant and one checked effect summary. -/
structure CheckedOriginalProvenancePostWitness
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    {targetId : Nat} (invocation : OriginalTargetInvocation targetId)
    (successor : OriginalNormalizedSuccessor)
    (normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor) : Prop where
  valueFlows : forall fact, fact ∈ inventory.valueFlows.facts ->
    OriginalValueFlowEndpointObligation invocation normalized.effects
      successor fact
  registerTargets : forall requirement,
    requirement ∈ inventory.registerTargets ->
      OriginalRegisterTargetEndpointObligation inventory invocation
        normalized.effects successor requirement
  stackDynamicTargets : forall requirement,
    requirement ∈ inventory.stackDynamicTargets ->
      OriginalStackDynamicTargetEndpointObligation inventory invocation successor
        requirement

theorem CheckedOriginalProvenancePostWitness.valueFlowPost
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      normalized)
    (before : inventory.Holds invocation.execution) :
    OriginalValueFlowPostInventoryEvidence program inventory.valueFlows
      successor := by
  cases successor with
  | running nextTarget state calls eventIndex world =>
      refine { facts := fun fact factMember =>
        .running nextTarget state calls eventIndex world ?_ }
      intro endpoint
      exact (witness.valueFlows fact factMember endpoint).toAtEvidence
        before factMember
        normalized.implements.2
  | callbackRunning nextTarget state calls eventIndex world callbacks =>
      refine { facts := fun fact factMember =>
        .callbackRunning nextTarget state calls eventIndex world callbacks ?_ }
      intro endpoint
      exact (witness.valueFlows fact factMember endpoint).toAtEvidence
        before factMember
        normalized.implements.2
  | awaitingExternal suspension callbacks =>
      refine { facts := fun fact factMember =>
        .awaitingExternal suspension callbacks ?_ }
      intro endpoint
      exact (witness.valueFlows fact factMember endpoint).toAtEvidence
        before factMember
        normalized.implements.2
  | returned state world =>
      exact { facts := fun fact factMember => .returned state world }
  | terminated world =>
      exact { facts := fun fact factMember => .terminated world }
  | fault cause =>
      exact { facts := fun fact factMember => .fault cause }

theorem CheckedOriginalProvenancePostWitness.registerTargetPost
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      normalized)
    (before : inventory.Holds invocation.execution)
    (requirement : OriginalRegisterTargetRequirement originalContext)
    (requirementMember : requirement ∈ inventory.registerTargets) :
    OriginalRegisterTargetPostEvidence requirement successor := by
  have valuePost := witness.valueFlowPost before
  cases successor with
  | running nextTarget state calls eventIndex world =>
      apply OriginalRegisterTargetPostEvidence.running nextTarget state calls
        eventIndex world
      intro atSource
      have transfer := witness.registerTargets requirement requirementMember atSource
      exact transfer.toMember before requirementMember normalized.implements.2
        (by
          intro fact factMember sourceMember
          exact (valuePost.facts fact factMember).holds
            (by simpa [atSource] using sourceMember))
  | callbackRunning nextTarget state calls eventIndex world callbacks =>
      apply OriginalRegisterTargetPostEvidence.callbackRunning nextTarget state calls
        eventIndex world callbacks
      intro atSource
      have transfer := witness.registerTargets requirement requirementMember atSource
      exact transfer.toMember before requirementMember normalized.implements.2
        (by
          intro fact factMember sourceMember
          exact (valuePost.facts fact factMember).holds
            (by simpa [atSource] using sourceMember))
  | awaitingExternal suspension callbacks => exact .awaitingExternal suspension callbacks
  | returned state world => exact .returned state world
  | terminated world => exact .terminated world
  | fault cause => exact .fault cause

theorem CheckedOriginalProvenancePostWitness.stackDynamicTargetPost
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      normalized)
    (before : inventory.Holds invocation.execution)
    (requirement : OriginalStackDynamicTargetRequirement originalContext)
    (requirementMember : requirement ∈ inventory.stackDynamicTargets) :
    OriginalStackDynamicTargetPostEvidence requirement successor := by
  have valuePost := witness.valueFlowPost before
  cases successor with
  | running nextTarget state calls eventIndex world =>
      apply OriginalStackDynamicTargetPostEvidence.running nextTarget state calls
        eventIndex world
      intro atSource
      have transfer := witness.stackDynamicTargets requirement requirementMember
        atSource
      exact transfer.toSourceFact before requirementMember (by
        intro fact factMember sourceMember
        exact (valuePost.facts fact factMember).holds
          (by simpa [atSource] using sourceMember))
  | callbackRunning nextTarget state calls eventIndex world callbacks =>
      apply OriginalStackDynamicTargetPostEvidence.callbackRunning nextTarget state
        calls eventIndex world callbacks
      intro atSource
      have transfer := witness.stackDynamicTargets requirement requirementMember
        atSource
      exact transfer.toSourceFact before requirementMember (by
        intro fact factMember sourceMember
        exact (valuePost.facts fact factMember).holds
          (by simpa [atSource] using sourceMember))
  | awaitingExternal suspension callbacks => exact .awaitingExternal suspension callbacks
  | returned state world => exact .returned state world
  | terminated world => exact .terminated world
  | fault cause => exact .fault cause

structure OriginalProvenancePostFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    (inventory : OriginalCombinedExecutionInventory program originalContext)
    (successor : OriginalNormalizedSuccessor) : Prop where
  valueFlows : OriginalValueFlowPostInventoryEvidence program inventory.valueFlows
    successor
  registerTargets : forall requirement,
    requirement ∈ inventory.registerTargets ->
      OriginalRegisterTargetPostEvidence requirement successor
  stackDynamicTargets : forall requirement,
    requirement ∈ inventory.stackDynamicTargets ->
      OriginalStackDynamicTargetPostEvidence requirement successor

def CheckedOriginalProvenancePostWitness.toPostFamilies
    {program : DecodedWorldProgram}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program originalContext}
    {targetId : Nat} {invocation : OriginalTargetInvocation targetId}
    {successor : OriginalNormalizedSuccessor}
    {normalized : CheckedOriginalNormalizedTransitionEffects invocation.state
      successor}
    (witness : CheckedOriginalProvenancePostWitness inventory invocation successor
      normalized)
    (before : inventory.Holds invocation.execution) :
    OriginalProvenancePostFamilies inventory successor where
  valueFlows := witness.valueFlowPost before
  registerTargets requirement member :=
    witness.registerTargetPost before requirement member
  stackDynamicTargets requirement member :=
    witness.stackDynamicTargetPost before requirement member

/-- Exact-transition-bound form used by target shards. -/
structure CheckedOriginalTargetProvenancePost
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    (transition : CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation) where
  effects : CheckedOriginalTargetProvenanceEffects transition
  witness : CheckedOriginalProvenancePostWitness inventory invocation
    transition.successor effects.normalized

def CheckedOriginalTargetProvenancePost.toPostFamilies
    {program : Program} {targetId : Nat}
    {checked : CheckedOriginalTargetEffect program targetId}
    {originalContext : OriginalDecodedStaticContext}
    {inventory : OriginalCombinedExecutionInventory program.worldProgram
      originalContext}
    {invocation : OriginalTargetInvocation targetId}
    {transition : CheckedOriginalTargetTransition checked originalContext
      inventory.reachableTargets.targetIds invocation}
    (post : CheckedOriginalTargetProvenancePost transition)
    (before : inventory.Holds invocation.execution) :
    OriginalProvenancePostFamilies inventory transition.successor :=
  post.witness.toPostFamilies before

#print axioms TransitionEffects.OriginalRegistersImplement.preserved
#print axioms OriginalValueFlowEndpointTransfer.toAtEvidence
#print axioms OriginalRegisterValueFlowResolver.resolve
#print axioms OriginalRegisterTargetTransfer.toMember
#print axioms OriginalStackDynamicTargetTransfer.toSourceFact
#print axioms CheckedOriginalProvenancePostWitness.valueFlowPost
#print axioms CheckedOriginalProvenancePostWitness.registerTargetPost
#print axioms CheckedOriginalProvenancePostWitness.stackDynamicTargetPost
#print axioms CheckedOriginalTargetProvenancePost.toPostFamilies

end StageA.Relational.OriginalProvenancePreservation
