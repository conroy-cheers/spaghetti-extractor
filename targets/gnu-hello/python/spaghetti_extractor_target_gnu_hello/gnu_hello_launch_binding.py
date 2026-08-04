"""Bind GNU hello's exact native launch graph to the canonical mixed core.

The generated module proves launch-wrapper replay and engine-state capture from
the exact candidate PE graph.  Its acceptance-facing refinement accepts no
replay-success, runtime-relation, report, count, or caller-supplied path
premise.  The lower-level endpoint bridge consumes the replay equality produced
by that checked runtime when constructing the one-time prefix's runtime-only
endpoint.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.util import write_json
from .gnu_hello_acceptance_requirements import (
    GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA,
)


GNU_HELLO_LAUNCH_BINDING_FORMAT = "stage-a-gnu-hello-launch-binding-v1"
GNU_HELLO_LAUNCH_BINDING_MODULE = "GeneratedGnuHelloLaunchBinding"
GNU_HELLO_LAUNCH_BINDING_MANIFEST = "gnu-hello-launch-binding.json"

GNU_HELLO_ENTRY_RVA = 5152
GNU_HELLO_TLS_CALLBACK_RVAS = (41712, 41632)
GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID = 73
GNU_HELLO_ORIGINAL_TLS_TARGET_IDS = (2611, 2606)
GNU_HELLO_ACTIVE_BRIDGE_RVA = 0x981000

_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


@dataclass(frozen=True)
class GnuHelloLaunchBindingSpec:
    module_name: str = GNU_HELLO_LAUNCH_BINDING_MODULE
    namespace: str = "StageA.GeneratedRelational.GnuHelloLaunchBinding"
    native_graph_module: str = (
        "StageA.GeneratedRelationalInterpreterNativeLaunchGraph"
    )
    native_graph_namespace: str = (
        "StageA.GeneratedRelational.InterpreterNativeLaunchGraph"
    )
    core_bindings_module: str = (
        "StageA.GeneratedGnuHelloCanonicalRelationCoreBindings"
    )
    core_bindings_namespace: str = (
        "StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings"
    )
    core_module: str = "StageA.GeneratedGnuHelloCanonicalRelationCore"
    core_namespace: str = (
        "StageA.GeneratedRelational.GnuHelloCanonicalRelationCore"
    )
    original_namespace: str = (
        "StageA.GeneratedRelational.InterpreterMixedOriginal"
    )
    reachability_module: str = (
        "StageA.GeneratedRelationalInterpreterMixedOriginalStaticReachability"
    )
    reachability_namespace: str = (
        "StageA.GeneratedRelational."
        "InterpreterMixedOriginalStaticReachability"
    )
    acceptance_requirements_module: str = (
        "StageA.GeneratedGnuHelloAcceptanceRequirements"
    )
    acceptance_requirements_namespace: str = (
        "StageA.GeneratedRelational.GnuHelloAcceptanceRequirements"
    )
    runtime_foundation_module: str = (
        "StageA.GeneratedGnuHelloRuntimeFoundation"
    )
    runtime_foundation_namespace: str = (
        "StageA.GeneratedRelational.GnuHelloRuntimeFoundation"
    )

    def validate(self) -> None:
        if _LOCAL_NAME.fullmatch(self.module_name) is None:
            raise StageAInputError(
                "GNU hello launch binding module_name must be a local Lean name"
            )
        for label, value in (
            ("namespace", self.namespace),
            ("native_graph_module", self.native_graph_module),
            ("native_graph_namespace", self.native_graph_namespace),
            ("core_bindings_module", self.core_bindings_module),
            ("core_bindings_namespace", self.core_bindings_namespace),
            ("core_module", self.core_module),
            ("core_namespace", self.core_namespace),
            ("original_namespace", self.original_namespace),
            ("reachability_module", self.reachability_module),
            ("reachability_namespace", self.reachability_namespace),
            (
                "acceptance_requirements_module",
                self.acceptance_requirements_module,
            ),
            (
                "acceptance_requirements_namespace",
                self.acceptance_requirements_namespace,
            ),
            ("runtime_foundation_module", self.runtime_foundation_module),
            (
                "runtime_foundation_namespace",
                self.runtime_foundation_namespace,
            ),
        ):
            if _LEAN_NAME.fullmatch(value) is None:
                raise StageAInputError(
                    f"GNU hello launch binding {label} must be a Lean name"
                )


@dataclass(frozen=True)
class GnuHelloLaunchBindingPlan:
    spec: GnuHelloLaunchBindingSpec

    @property
    def complete(self) -> bool:
        return True

    def payload(self) -> dict[str, object]:
        return {
            "format": GNU_HELLO_LAUNCH_BINDING_FORMAT,
            "phase": "gnu-hello-launch-binding",
            "complete": True,
            "status": "source-ready",
            "acceptance_authority": False,
            "lean_check_required": True,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "failure_mode": "fail-closed",
            "outputs": {
                "lean_module": f"StageA/{self.spec.module_name}.lean",
            },
            "exact_roots": {
                "entry_rva": GNU_HELLO_ENTRY_RVA,
                "tls_callback_rvas": list(GNU_HELLO_TLS_CALLBACK_RVAS),
                "original_entry_target_id": (
                    GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID
                ),
                "original_tls_target_ids": list(
                    GNU_HELLO_ORIGINAL_TLS_TARGET_IDS
                ),
            },
            "constructed_terms": {
                "candidate_pe_exact": "generatedCandidatePeExact",
                "candidate_imports_exact": "generatedCandidateImportsExact",
                "candidate_launch_roots_exact": (
                    "generatedCandidateLaunchRootsExact"
                ),
                "canonical_root_route": "generatedCanonicalRootRoute",
                "exact_replay_runtime": "generatedExactNativeLaunchRuntime",
                "entry_replay_capture": "generatedEntryReplayCapture",
                "tls0_replay_capture": "generatedTls0ReplayCapture",
                "tls1_replay_capture": "generatedTls1ReplayCapture",
                "root_frame_facts": "generatedCanonicalRootFrameFacts",
                "launch_root_phase_state_facts": (
                    "generatedLaunchRootPhaseStateFacts"
                ),
                "launch_carrier_projection": (
                    "generatedLaunchCarrierCanonicalExecutions"
                ),
                "acceptance_launch_wrapper_refinements": (
                    "generatedAcceptanceLaunchWrapperRefinements"
                ),
                "acceptance_launch_prefix_endpoint": (
                    "generatedAcceptanceLaunchPrefixEndpoint"
                ),
                "acceptance_launch_prefix": (
                    "generatedAcceptanceLaunchPrefix"
                ),
            },
            "public_terms": {
                "launch_realizable": (
                    "RuntimeFoundation.generatedLaunchRealizable"
                ),
                "launch_wrapper_refinements": (
                    "generatedAcceptanceLaunchWrapperRefinements"
                ),
                "launch_prefix": "generatedAcceptanceLaunchPrefix",
                "exact_binding": (
                    "generatedExactCanonicalLaunchWrapperBinding"
                ),
            },
            "dynamic_evidence_fields": {
                "launch_realizable": {
                    "status": "constructed",
                    "term": "RuntimeFoundation.generatedLaunchRealizable",
                },
                "launch_wrapper_refinements": {
                    "status": "constructed",
                    "term": "generatedAcceptanceLaunchWrapperRefinements",
                },
                "launch_prefix": {
                    "status": "constructed",
                    "term": "generatedAcceptanceLaunchPrefix",
                },
            },
            "phase_policy": {
                "root_relation": "launchStatesRelated",
                "root_classifier": (
                    "ConstructiveMixedKernelSourceEvidence.launch"
                ),
                "root_carrier": "ExactConstructiveMixedLaunchCarrier",
                "root_carrier_projection": (
                    "ExactConstructiveMixedLaunchCarrier.canonicalExecutions"
                ),
                "wrapper_endpoint_relation": "runtimeStatesRelated",
                "wrapper_endpoint_constructor": (
                    "ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact"
                ),
                "classifier_wide_policy_owned_by": (
                    "constructive-mixed-source-classifier"
                ),
            },
            "blocking_obligations": [],
        }


def build_gnu_hello_launch_binding_plan(
    spec: GnuHelloLaunchBindingSpec | None = None,
) -> GnuHelloLaunchBindingPlan:
    selected = spec or GnuHelloLaunchBindingSpec()
    selected.validate()
    return GnuHelloLaunchBindingPlan(selected)


def gnu_hello_launch_binding_source(
    plan: GnuHelloLaunchBindingPlan,
) -> str:
    """Emit the complete exact GNU launch binding."""

    spec = plan.spec
    spec.validate()
    entry_rva = GNU_HELLO_ENTRY_RVA
    tls0_rva, tls1_rva = GNU_HELLO_TLS_CALLBACK_RVAS
    entry_target = GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID
    tls0_target, tls1_target = GNU_HELLO_ORIGINAL_TLS_TARGET_IDS
    active_bridge_rva = GNU_HELLO_ACTIVE_BRIDGE_RVA
    runtime_boundary_rva = GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA

    return f"""import {spec.native_graph_module}
import {spec.core_bindings_module}
import {spec.core_module}
import {spec.reachability_module}
import {spec.acceptance_requirements_module}
import {spec.runtime_foundation_module}
import StageA.RelationalInterpreterMixedConstructiveSourceClassifier

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Engine
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedLaunchRefinement
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

namespace NativeLaunchGraph := {spec.native_graph_namespace}
namespace CoreBindings := {spec.core_bindings_namespace}
namespace Core := {spec.core_namespace}
namespace Original := {spec.original_namespace}
namespace Reachability := {spec.reachability_namespace}
namespace Acceptance := {spec.acceptance_requirements_namespace}
namespace RuntimeFoundation := {spec.runtime_foundation_namespace}
namespace SourceCoverage :=
  StageA.GeneratedRelational.InterpreterMixedSourceCoverage
namespace SourceRules :=
  StageA.GeneratedRelational.GnuHelloConstructiveSourceRules

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

def generatedCandidate
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    ExactNativeWorldProgram :=
  exactNativeWorldProgramWithEnvironment requirements.candidate
    candidateEnvironment

def generatedCandidateAuthority
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    ExactNativeCandidateAuthority
      (generatedCandidate requirements candidateEnvironment) :=
  exactNativeCandidateAuthorityWithEnvironment requirements.candidateAuthority
    candidateEnvironment

def generatedCore (requirements : CoreBindings.Requirements) :=
  Core.generatedCanonicalMixedRelationCore requirements

/-- Public root constructor for the `phaseStateFacts` field.  Its result index
is definitionally the exact `.launch` classifier evidence. -/
abbrev generatedLaunchRootPhaseStateFacts :=
  @ConstructiveMixedKernelPhaseStateFacts.ofLaunchExact

/-- Public elimination rule for the proof-carrying launch classifier.  It
projects the exact original and candidate launch executions, loader-derived
call frames, zero event index, and empty event history. -/
abbrev generatedLaunchCarrierCanonicalExecutions :=
  @ExactConstructiveMixedLaunchCarrier.canonicalExecutions

/-- Both definitions re-parse the same exact candidate PE bytes. -/
theorem generatedCandidatePeExact
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    NativeLaunchGraph.generatedNativeLaunchGraphCandidatePe =
      (generatedCandidate requirements candidateEnvironment).pe := by
  decide +kernel

/-- Imports are recovered from the same exact candidate PE on both sides. -/
theorem generatedCandidateImportsExact
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    NativeLaunchGraph.generatedNativeLaunchGraphImports =
      (generatedCandidate requirements candidateEnvironment).imports := by
  decide +kernel

/-- The exact PE parser fixes the only canonical roots accepted below. -/
theorem generatedCandidateLaunchRootsExact
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    candidatePELaunchRoots?
        (generatedCandidate requirements candidateEnvironment).pe =
      some {{
        entryRva := {entry_rva}
        tlsCallbackRvas := [{tls0_rva}, {tls1_rva}]
      }} := by
  decide +kernel

/-- Route existence is derived from the checked expected-source inventory; the
GNU binding does not submit a second root list. -/
theorem generatedCanonicalRootRoute
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    forall root rootRva,
      root.rva? (generatedCandidate requirements candidateEnvironment).pe =
          some rootRva ->
        exists route,
          route ∈
              NativeLaunchGraph.generatedCheckedNativeLaunchGraph.certificate.routes /\\
            route.source = .canonicalRoot root :=
  NativeLaunchGraph.generatedCheckedNativeLaunchGraph.canonicalRootRoute
    (generatedCandidate requirements candidateEnvironment)
    (generatedCandidatePeExact requirements candidateEnvironment)

/-- Exact replay authority with no replay-success premise in its public
signature.  Admissibility remains the exact replay predicate internally. -/
def generatedExactNativeLaunchRuntime
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    ExactNativeLaunchGraphRuntime
      NativeLaunchGraph.generatedCheckedNativeLaunchGraph
      (generatedCandidate requirements candidateEnvironment) :=
  ExactNativeLaunchGraphRuntime.ofExactReplay
    (generatedCandidatePeExact requirements candidateEnvironment)
    (generatedCandidateImportsExact requirements candidateEnvironment)
    (generatedCanonicalRootRoute requirements candidateEnvironment)

def generatedEntryOriginalSource :=
  (Original.generatedOriginalStaticContext.source? {entry_target}).get
    (by decide +kernel)

def generatedTls0OriginalSource :=
  (Original.generatedOriginalStaticContext.source? {tls0_target}).get
    (by decide +kernel)

def generatedTls1OriginalSource :=
  (Original.generatedOriginalStaticContext.source? {tls1_target}).get
    (by decide +kernel)

theorem generatedEntryOriginalSourceExact :
    Original.generatedOriginalStaticContext.source? {entry_target} =
      some generatedEntryOriginalSource := by
  decide +kernel

theorem generatedTls0OriginalSourceExact :
    Original.generatedOriginalStaticContext.source? {tls0_target} =
      some generatedTls0OriginalSource := by
  decide +kernel

theorem generatedTls1OriginalSourceExact :
    Original.generatedOriginalStaticContext.source? {tls1_target} =
      some generatedTls1OriginalSource := by
  decide +kernel

theorem generatedEntryOriginalSourceRvaExact :
    generatedEntryOriginalSource.target.rva = {entry_rva} := by
  decide +kernel

theorem generatedTls0OriginalSourceRvaExact :
    generatedTls0OriginalSource.target.rva = {tls0_rva} := by
  decide +kernel

theorem generatedTls1OriginalSourceRvaExact :
    generatedTls1OriginalSource.target.rva = {tls1_rva} := by
  decide +kernel

theorem generatedEntryOriginalReachable :
    {entry_target} ∈
      Reachability.generatedExactOriginalDecodedStaticReachability.targetIds := by
  decide +kernel

theorem generatedTls0OriginalReachable :
    {tls0_target} ∈
      Reachability.generatedExactOriginalDecodedStaticReachability.targetIds := by
  decide +kernel

theorem generatedTls1OriginalReachable :
    {tls1_target} ∈
      Reachability.generatedExactOriginalDecodedStaticReachability.targetIds := by
  decide +kernel

/-- The checked source inventory contains exactly one route for each parsed
canonical root.  Stable return and termination routes cannot satisfy this
predicate. -/
private theorem generatedCanonicalRootRouteCases
    (root : CanonicalNativeLaunchRoot)
    (route : ReflectedNativeLaunchGraphRoute)
    (member :
      route ∈
        NativeLaunchGraph.generatedCheckedNativeLaunchGraph.certificate.routes)
    (sourceExact : route.source = .canonicalRoot root) :
    (root = .entry /\\
        route = NativeLaunchGraph.generatedNativeLaunchGraphRoute0000) \\/
      (root = .tlsCallback 0 /\\
        route = NativeLaunchGraph.generatedNativeLaunchGraphRoute0001) \\/
      (root = .tlsCallback 1 /\\
        route = NativeLaunchGraph.generatedNativeLaunchGraphRoute0002) := by
  simp [NativeLaunchGraph.generatedCheckedNativeLaunchGraph,
    NativeLaunchGraph.generatedNativeLaunchGraphCertificate] at member
  rcases member with rfl | rfl | rfl | rfl | rfl | rfl | rfl <;>
    simp [NativeLaunchGraph.generatedNativeLaunchGraphRoute0000,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0001,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0002,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0003,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0004,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0005,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0006] at sourceExact ⊢

/-- Concrete reduction of the exact entry wrapper.  The theorem quantifies
over the launch machine, stack frames, world, and environment; its only memory
fact is the checked Win32 `fs:[0x18]` self pointer. -/
theorem generatedEntryReplayCapture
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    (candidateState : MachineState) (calls : List NativeCallFrame)
    (candidateWorld : RelationalWorld)
    (fsSelf : Memory.read32 candidateState.memory
      (candidateState.fsBase + BitVec.ofNat 32 0x18) =
        candidateState.fsBase) :
    exists result candidateAfter,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0000.replay?
          (generatedCandidate requirements candidateEnvironment)
          NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
          (.running {entry_rva} 0 candidateState calls 0 [] candidateWorld) =
        some result /\\
      result.observations = [] /\\
      result.after.machine? = some candidateAfter /\\
      OriginalEngineStateHolds
        (CoreBindings.Requirements.concreteABI requirements).engineLayout
        (CoreBindings.Requirements.concreteABI requirements).parameters.inputAddress
        {entry_rva} candidateState candidateAfter := by
  simp [ReflectedNativeLaunchGraphRoute.replay?,
    ReflectedNativeLaunchGraphRoute.additionalFuel?,
    runRelatedSteps, ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, transitionFromNativeWorldOutcome,
    generatedCandidate, NativeLaunchGraph.generatedNativeLaunchGraphRoute0000,
    NativeLaunchGraph.generatedNativeLaunchGraphCutpoints,
    OriginalEngineStateHolds, engineRepAt, EngineFieldHolds, readBytes,
    Memory.read32, fsSelf]

/-- Concrete reduction of the first exact TLS root wrapper. -/
theorem generatedTls0ReplayCapture
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    (candidateState : MachineState) (calls : List NativeCallFrame)
    (candidateWorld : RelationalWorld)
    (fsSelf : Memory.read32 candidateState.memory
      (candidateState.fsBase + BitVec.ofNat 32 0x18) =
        candidateState.fsBase)
    (activeBridgeZero : candidateState.memory
      (BitVec.ofNat 32
        ((generatedCandidate requirements candidateEnvironment).pe.imageBase +
          {active_bridge_rva})) = BitVec.ofNat 8 0) :
    exists result candidateAfter,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0001.replay?
          (generatedCandidate requirements candidateEnvironment)
          NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
          (.running {tls0_rva} 0 candidateState calls 0 [] candidateWorld) =
        some result /\\
      result.observations = [] /\\
      result.after.machine? = some candidateAfter /\\
      OriginalEngineStateHolds
        (CoreBindings.Requirements.concreteABI requirements).engineLayout
        (CoreBindings.Requirements.concreteABI requirements).parameters.inputAddress
        {tls0_rva} candidateState candidateAfter := by
  simp [ReflectedNativeLaunchGraphRoute.replay?,
    ReflectedNativeLaunchGraphRoute.additionalFuel?,
    runRelatedSteps, ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, transitionFromNativeWorldOutcome,
    generatedCandidate, NativeLaunchGraph.generatedNativeLaunchGraphRoute0001,
    NativeLaunchGraph.generatedNativeLaunchGraphCutpoints,
    OriginalEngineStateHolds, engineRepAt, EngineFieldHolds, readBytes,
    Memory.read32, fsSelf, activeBridgeZero]

/-- Exact TLS0 replay preserves the relational world.  This is reduced from
the same checked native route as the engine-state capture; it is not a
submitted post-state fact. -/
theorem generatedTls0ReplayWorldExact
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    (candidateState : MachineState) (calls : List NativeCallFrame)
    (candidateWorld : RelationalWorld)
    (result : NativeLaunchGraphReplay)
    (fsSelf : Memory.read32 candidateState.memory
      (candidateState.fsBase + BitVec.ofNat 32 0x18) =
        candidateState.fsBase)
    (activeBridgeZero : candidateState.memory
      (BitVec.ofNat 32
        ((generatedCandidate requirements candidateEnvironment).pe.imageBase +
          {active_bridge_rva})) = BitVec.ofNat 8 0)
    (replayed :
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0001.replay?
          (generatedCandidate requirements candidateEnvironment)
          NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
          (.running {tls0_rva} 0 candidateState calls 0 [] candidateWorld) =
        some result) :
    nativeExecutionWorld? result.after = some candidateWorld := by
  simp [ReflectedNativeLaunchGraphRoute.replay?,
    ReflectedNativeLaunchGraphRoute.additionalFuel?,
    runRelatedSteps, ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, transitionFromNativeWorldOutcome,
    generatedCandidate, NativeLaunchGraph.generatedNativeLaunchGraphRoute0001,
    NativeLaunchGraph.generatedNativeLaunchGraphCutpoints,
    OriginalEngineStateHolds, engineRepAt, EngineFieldHolds, readBytes,
    Memory.read32, fsSelf, activeBridgeZero] at replayed
  subst result
  rfl

/-- The destination encoded by TLS0's exact reflected route is the first
runtime callback boundary. -/
theorem generatedTls0ReplayAtRuntimeBoundary
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    (candidateState : MachineState) (calls : List NativeCallFrame)
    (candidateWorld : RelationalWorld)
    (result : NativeLaunchGraphReplay)
    (replayed :
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0001.replay?
          (generatedCandidate requirements candidateEnvironment)
          NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
          (.running {tls0_rva} 0 candidateState calls 0 [] candidateWorld) =
        some result) :
    nativeExecutionAtRva {runtime_boundary_rva} result.after := by
  have destination :=
    (NativeLaunchGraph.generatedNativeLaunchGraphRoute0001.replay?_sound
      (generatedCandidate requirements candidateEnvironment)
      NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
      (.running {tls0_rva} 0 candidateState calls 0 [] candidateWorld)
      result replayed).2.1
  simpa [NativeLaunchGraph.generatedNativeLaunchGraphRoute0001,
    NativeLaunchGraph.generatedNativeLaunchGraphCutpoints,
    NativeLaunchPathDestination.matches, nativeExecutionAtRva] using destination

/-- Concrete reduction of the second exact TLS root wrapper. -/
theorem generatedTls1ReplayCapture
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    (candidateState : MachineState) (calls : List NativeCallFrame)
    (candidateWorld : RelationalWorld)
    (fsSelf : Memory.read32 candidateState.memory
      (candidateState.fsBase + BitVec.ofNat 32 0x18) =
        candidateState.fsBase)
    (activeBridgeZero : candidateState.memory
      (BitVec.ofNat 32
        ((generatedCandidate requirements candidateEnvironment).pe.imageBase +
          {active_bridge_rva})) = BitVec.ofNat 8 0) :
    exists result candidateAfter,
      NativeLaunchGraph.generatedNativeLaunchGraphRoute0002.replay?
          (generatedCandidate requirements candidateEnvironment)
          NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
          (.running {tls1_rva} 0 candidateState calls 0 [] candidateWorld) =
        some result /\\
      result.observations = [] /\\
      result.after.machine? = some candidateAfter /\\
      OriginalEngineStateHolds
        (CoreBindings.Requirements.concreteABI requirements).engineLayout
        (CoreBindings.Requirements.concreteABI requirements).parameters.inputAddress
        {tls1_rva} candidateState candidateAfter := by
  simp [ReflectedNativeLaunchGraphRoute.replay?,
    ReflectedNativeLaunchGraphRoute.additionalFuel?,
    runRelatedSteps, ExactNativeWorldProgram.transitionSystem,
    stepPE32NativeWorldExecution, transitionFromNativeWorldOutcome,
    generatedCandidate, NativeLaunchGraph.generatedNativeLaunchGraphRoute0002,
    NativeLaunchGraph.generatedNativeLaunchGraphCutpoints,
    OriginalEngineStateHolds, engineRepAt, EngineFieldHolds, readBytes,
    Memory.read32, fsSelf, activeBridgeZero]

abbrev GeneratedCanonicalRootFrameFacts
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) : Prop :=
  CanonicalMixedLaunchRootFrameFacts
    NativeLaunchGraph.generatedCheckedNativeLaunchGraph
    (generatedExactNativeLaunchRuntime requirements candidateEnvironment)
    Original.generatedOriginalStaticContext
    (generatedCandidate requirements candidateEnvironment)
    (generatedCore requirements).contract Original.generatedOriginalLaunch

private theorem generatedCandidateFsSelf
    (pair : CanonicalMixedPE32ConsoleLaunchStatePair original candidate anchors
      profile originalWorld candidateWorld originalState candidateState) :
    Memory.read32 candidateState.memory
        (candidateState.fsBase + BitVec.ofNat 32 0x18) =
      candidateState.fsBase := by
  rw [pair.candidateFsBase]
  exact pair.candidateTebSelf

private theorem generatedActiveBridgeZero
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    (pair : CanonicalMixedPE32ConsoleLaunchStatePair
      Original.generatedOriginalStaticContext
      (generatedCandidate requirements candidateEnvironment)
      (generatedCore requirements).anchors
      (generatedCore requirements).launchMemoryProfile
      originalWorld candidateWorld originalState candidateState) :
    candidateState.memory
        (BitVec.ofNat 32
          ((generatedCandidate requirements candidateEnvironment).pe.imageBase +
            {active_bridge_rva})) =
      BitVec.ofNat 8 0 :=
  pair.candidateLoaderZeroFill {active_bridge_rva}
    (by decide +kernel) (by decide +kernel) (by decide +kernel)

/-- Exact root replay starts from the launch relation and establishes the
runtime engine relation at the concrete replay endpoint. -/
def generatedCanonicalRootFrameFacts
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment) :
    GeneratedCanonicalRootFrameFacts requirements candidateEnvironment := {{
  rootReady := by
    intro root rootRva originalWorld candidateWorld originalState
      candidateState calls route rootExact launchRelated _callsExact
      routeMember routeSource
    rcases launchRelated.2.2.2 with ⟨pair⟩
    have fsSelf := generatedCandidateFsSelf pair
    rcases generatedCanonicalRootRouteCases root route routeMember routeSource with
      ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · have rootRvaExact : rootRva = {entry_rva} := by
        simpa [CanonicalNativeLaunchRoot.rva?,
          generatedCandidateLaunchRootsExact requirements candidateEnvironment]
          using rootExact.symm
      subst rootRva
      refine ⟨by simp [NativeLaunchPathSource.matches, rootExact], ?_⟩
      obtain ⟨result, _candidateAfter, replayed, _⟩ :=
        generatedEntryReplayCapture requirements candidateEnvironment
          candidateState calls candidateWorld fsSelf
      rw [replayed]
      rfl
    · have rootRvaExact : rootRva = {tls0_rva} := by
        simpa [CanonicalNativeLaunchRoot.rva?,
          generatedCandidateLaunchRootsExact requirements candidateEnvironment]
          using rootExact.symm
      subst rootRva
      refine ⟨by simp [NativeLaunchPathSource.matches, rootExact], ?_⟩
      obtain ⟨result, _candidateAfter, replayed, _⟩ :=
        generatedTls0ReplayCapture requirements candidateEnvironment
          candidateState calls candidateWorld fsSelf
          (generatedActiveBridgeZero requirements candidateEnvironment pair)
      rw [replayed]
      rfl
    · have rootRvaExact : rootRva = {tls1_rva} := by
        simpa [CanonicalNativeLaunchRoot.rva?,
          generatedCandidateLaunchRootsExact requirements candidateEnvironment]
          using rootExact.symm
      subst rootRva
      refine ⟨by simp [NativeLaunchPathSource.matches, rootExact], ?_⟩
      obtain ⟨result, _candidateAfter, replayed, _⟩ :=
        generatedTls1ReplayCapture requirements candidateEnvironment
          candidateState calls candidateWorld fsSelf
          (generatedActiveBridgeZero requirements candidateEnvironment pair)
      rw [replayed]
      rfl
  replayEstablishesRuntime := by
    intro root rootRva originalWorld candidateWorld originalState
      candidateState calls route result rootExact launchRelated _callsExact
      routeMember routeSource replayed
    rcases launchRelated.2.2.2 with ⟨pair⟩
    have fsSelf := generatedCandidateFsSelf pair
    rcases generatedCanonicalRootRouteCases root route routeMember routeSource with
      ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩ | ⟨rfl, rfl⟩
    · have rootRvaExact : rootRva = {entry_rva} := by
        simpa [CanonicalNativeLaunchRoot.rva?,
          generatedCandidateLaunchRootsExact requirements candidateEnvironment]
          using rootExact.symm
      subst rootRva
      obtain ⟨expected, candidateAfter, expectedReplay, observations,
          afterMachine, capturedCandidate⟩ :=
        generatedEntryReplayCapture requirements candidateEnvironment
          candidateState calls candidateWorld fsSelf
      rw [replayed] at expectedReplay
      cases Option.some.inj expectedReplay
      refine ⟨observations, candidateAfter, afterMachine, ?_⟩
      exact canonicalMixedRuntimeStatesRelated_of_inputEngine
        pair.worldsRelated generatedEntryOriginalReachable
        generatedEntryOriginalSourceExact
        (OriginalEngineStateHolds.of_launch_exact
          (CoreBindings.Requirements.concreteABI requirements).engineLayout
          (CoreBindings.Requirements.concreteABI requirements).parameters.inputAddress
          {entry_rva} originalState candidateState candidateAfter
          pair.registersExact pair.flagsExact pair.x87Exact pair.fsBaseExact
          (by simpa [generatedEntryOriginalSourceRvaExact] using capturedCandidate))
    · have rootRvaExact : rootRva = {tls0_rva} := by
        simpa [CanonicalNativeLaunchRoot.rva?,
          generatedCandidateLaunchRootsExact requirements candidateEnvironment]
          using rootExact.symm
      subst rootRva
      obtain ⟨expected, candidateAfter, expectedReplay, observations,
          afterMachine, capturedCandidate⟩ :=
        generatedTls0ReplayCapture requirements candidateEnvironment
          candidateState calls candidateWorld fsSelf
          (generatedActiveBridgeZero requirements candidateEnvironment pair)
      rw [replayed] at expectedReplay
      cases Option.some.inj expectedReplay
      refine ⟨observations, candidateAfter, afterMachine, ?_⟩
      exact canonicalMixedRuntimeStatesRelated_of_inputEngine
        pair.worldsRelated generatedTls0OriginalReachable
        generatedTls0OriginalSourceExact
        (OriginalEngineStateHolds.of_launch_exact
          (CoreBindings.Requirements.concreteABI requirements).engineLayout
          (CoreBindings.Requirements.concreteABI requirements).parameters.inputAddress
          {tls0_rva} originalState candidateState candidateAfter
          pair.registersExact pair.flagsExact pair.x87Exact pair.fsBaseExact
          (by simpa [generatedTls0OriginalSourceRvaExact] using capturedCandidate))
    · have rootRvaExact : rootRva = {tls1_rva} := by
        simpa [CanonicalNativeLaunchRoot.rva?,
          generatedCandidateLaunchRootsExact requirements candidateEnvironment]
          using rootExact.symm
      subst rootRva
      obtain ⟨expected, candidateAfter, expectedReplay, observations,
          afterMachine, capturedCandidate⟩ :=
        generatedTls1ReplayCapture requirements candidateEnvironment
          candidateState calls candidateWorld fsSelf
          (generatedActiveBridgeZero requirements candidateEnvironment pair)
      rw [replayed] at expectedReplay
      cases Option.some.inj expectedReplay
      refine ⟨observations, candidateAfter, afterMachine, ?_⟩
      exact canonicalMixedRuntimeStatesRelated_of_inputEngine
        pair.worldsRelated generatedTls1OriginalReachable
        generatedTls1OriginalSourceExact
        (OriginalEngineStateHolds.of_launch_exact
          (CoreBindings.Requirements.concreteABI requirements).engineLayout
          (CoreBindings.Requirements.concreteABI requirements).parameters.inputAddress
          {tls1_rva} originalState candidateState candidateAfter
          pair.registersExact pair.flagsExact pair.x87Exact pair.fsBaseExact
          (by simpa [generatedTls1OriginalSourceRvaExact] using capturedCandidate))
}}

/-- Wrapper replay constructs the phase-indexed runtime facts consumed by the
post-wrapper residual.  A `.launch` endpoint evidence cannot satisfy
`runtimeEvidence`, so this theorem cannot propagate launch relatedness beyond
the wrapper. -/
theorem generatedReplayEstablishesRuntimePhaseStateFacts
    (requirements : CoreBindings.Requirements)
    (candidateEnvironment : NativeWorldEnvironment)
    {{program : CompiledKernelProgram}}
    {{candidateRootRva : Nat}}
    {{originalAfter : WorldExecution}}
    (root : CanonicalNativeLaunchRoot) (rootRva : Nat)
    (originalWorld candidateWorld : RelationalWorld)
    (originalState candidateState : MachineState)
    (calls : List NativeCallFrame)
    (route : ReflectedNativeLaunchGraphRoute)
    (result : NativeLaunchGraphReplay)
    (evidence : ConstructiveMixedKernelSourceEvidence
      Original.generatedOriginalStaticContext
      Original.generatedExactOriginalDecodedAuthority
      Original.generatedOriginalLaunch
      Original.generatedDirectExactOriginalDecodedLaunchRoot
      Reachability.generatedExactOriginalDecodedStaticReachability
      (generatedCandidate requirements candidateEnvironment)
      (generatedCandidateAuthority requirements candidateEnvironment)
      program candidateRootRva originalAfter result.after)
    (runtimeEvidence : ConstructiveMixedKernelRuntimeEvidence evidence)
    (rootExact :
      root.rva? (generatedCandidate requirements candidateEnvironment).pe =
        some rootRva)
    (launchRelated : MixedLaunchStatesRelated
      Original.generatedOriginalStaticContext
      (generatedCandidate requirements candidateEnvironment)
      (generatedCore requirements).contract originalWorld candidateWorld
      originalState candidateState)
    (callsExact : candidateNativeLaunchCallFrames?
      (generatedCandidate requirements candidateEnvironment)
      Original.generatedOriginalLaunch candidateState = some calls)
    (routeMember :
      route ∈
        NativeLaunchGraph.generatedCheckedNativeLaunchGraph.certificate.routes)
    (routeSource : route.source = .canonicalRoot root)
    (replayed : route.replay?
      (generatedCandidate requirements candidateEnvironment)
      NativeLaunchGraph.generatedCheckedNativeLaunchGraph.certificate.cutpoints
      (.running rootRva 0 candidateState calls 0 [] candidateWorld) =
        some result)
    (originalWorldExact :
      originalExecutionWorld? originalAfter = some originalWorld)
    (candidateWorldExact :
      nativeExecutionWorld? result.after = some candidateWorld)
    (originalStateExact :
      originalExecutionMachine? originalAfter = some originalState) :
    result.observations = [] /\\
      exists candidateAfter,
        result.after.machine? = some candidateAfter /\\
          ConstructiveMixedKernelPhaseStateFacts
            (generatedCore requirements).contract evidence := by
  obtain ⟨observations, candidateAfter, afterMachine, runtimeRelated⟩ :=
    (generatedCanonicalRootFrameFacts requirements candidateEnvironment).
      replayEstablishesRuntime root rootRva originalWorld candidateWorld
        originalState candidateState calls route result rootExact launchRelated
        callsExact routeMember routeSource replayed
  exact ⟨observations, candidateAfter, afterMachine,
    ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact evidence
      runtimeEvidence
      originalWorldExact candidateWorldExact originalStateExact afterMachine
      runtimeRelated⟩

/-- The acceptance-facing family is total for every environment pair.  The
environment-refinement argument is part of the whole-program protocol
contract; launch-wrapper execution itself reaches the internal dispatch
cutpoint before consulting that environment. -/
def generatedLaunchWrapperRefinements
    (requirements : CoreBindings.Requirements)
    (externalFrames : MixedExternalFrameContract) :
    forall originalEnvironment candidateEnvironment,
      ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment
          requirements.originalProgram originalEnvironment)
        (generatedCandidate requirements candidateEnvironment)
        (generatedCore requirements).contract externalFrames ->
      CanonicalMixedLaunchWrapperRefinement
        Original.generatedOriginalStaticContext
        (generatedCandidate requirements candidateEnvironment)
        (generatedCore requirements).contract
        Original.generatedOriginalLaunch := by
  intro _originalEnvironment candidateEnvironment _environmentRefines
  exact CanonicalMixedLaunchWrapperRefinement.ofCheckedRuntime
    (generatedExactNativeLaunchRuntime requirements candidateEnvironment)
    (generatedCanonicalRootFrameFacts requirements candidateEnvironment)

/-- Exact inhabitant of `DynamicEvidence.launch_wrapper_refinements`.  The
environment premise selects the acceptance profile but contributes no launch
execution fact: wrapper replay remains the exact checked native graph above. -/
def generatedAcceptanceLaunchWrapperRefinements
    (parameters : Acceptance.Parameters) :
    forall originalEnvironment candidateEnvironment,
      ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment
          (Acceptance.generatedOriginalProgram parameters)
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment
          (Acceptance.generatedCandidateProgram parameters)
          candidateEnvironment)
        (Acceptance.generatedRelationCore parameters).contract
        (RuntimeFoundation.generatedExternalFrames parameters) ->
      CanonicalMixedLaunchWrapperRefinement
        Acceptance.generatedOriginalContext
        (exactNativeWorldProgramWithEnvironment
          (Acceptance.generatedCandidateProgram parameters)
          candidateEnvironment)
        (Acceptance.generatedRelationCore parameters).contract
        Acceptance.generatedLaunch := by
  intro _originalEnvironment candidateEnvironment _environmentRefines
  rw [Acceptance.generatedRelationCoreContractExact]
  simpa [Acceptance.generatedCandidateProgram,
    Acceptance.generatedPlainRelationCore, generatedCandidate, generatedCore]
    using
      CanonicalMixedLaunchWrapperRefinement.ofCheckedRuntime
        (generatedExactNativeLaunchRuntime parameters.coreRequirements
          candidateEnvironment)
        (generatedCanonicalRootFrameFacts parameters.coreRequirements
          candidateEnvironment)

/-- The exact candidate PE has TLS callbacks, so the loader-selected initial
root is TLS callback zero. -/
theorem generatedAcceptanceInitialRootExact
    (parameters : Acceptance.Parameters)
    (candidateEnvironment : NativeWorldEnvironment) :
    canonicalNativeInitialLaunchRoot
        (exactNativeWorldProgramWithEnvironment
          (Acceptance.generatedCandidateProgram parameters)
          candidateEnvironment) =
      .tlsCallback 0 := by
  simp [canonicalNativeInitialLaunchRoot,
    candidatePELaunchRoots?,
    Acceptance.generatedCandidateProgram,
    generatedCandidateLaunchRootsExact]

noncomputable def generatedRuntimeRootSource
    (parameters : Acceptance.Parameters) :=
  (SourceCoverage.generatedExactOriginalSemanticSourceCoverage
      parameters.sourceRequirements).source
    Acceptance.generatedLaunch.rootTargetId
    (by
      simpa [Acceptance.generatedLaunch] using generatedTls0OriginalReachable)

noncomputable def generatedRuntimeBoundaryEvidence
    (parameters : Acceptance.Parameters)
    (originalWorld : RelationalWorld)
    (originalState : MachineState)
    (candidateAfter : NativeWorldExecution)
    (candidateAtBoundary :
      nativeExecutionAtRva {runtime_boundary_rva} candidateAfter) :
    ConstructiveMixedKernelSourceEvidence
      Acceptance.generatedOriginalContext
      Acceptance.generatedOriginalAuthority Acceptance.generatedLaunch
      Acceptance.generatedOriginalRoot Acceptance.generatedReachability
      (Acceptance.generatedCandidateProgram parameters)
      (Acceptance.generatedCandidateAuthority parameters)
      Acceptance.generatedCompiledProgram Acceptance.generatedCandidateRootRva
      (.running Acceptance.generatedLaunch.rootTargetId originalState
        Acceptance.generatedLaunch.continuationTargetIds 0 originalWorld)
      candidateAfter :=
  .externalBoundary (generatedRuntimeRootSource parameters)
    SourceRules.generatedInterpreterStepEntry {runtime_boundary_rva}
    (by
      simp [generatedRuntimeRootSource, originalExecutionAtBoundarySource,
        ExactOriginalSemanticSourceCoverage.source])
    candidateAtBoundary

/-- The finite runtime inventory classifies the launch endpoint by its unique
root-boundary rule.  Every other generated rule has a distinct original target
ID and therefore cannot match the unchanged original root execution. -/
theorem generatedRuntimeBoundaryClassified
    (parameters : Acceptance.Parameters)
    (originalWorld : RelationalWorld)
    (originalState : MachineState)
    (candidateAfter : NativeWorldExecution)
    (candidateAtBoundary :
      nativeExecutionAtRva {runtime_boundary_rva} candidateAfter) :
    constructiveMixedKernelSourceEvidence?
        (Acceptance.generatedRuntimeRules parameters)
        (.running Acceptance.generatedLaunch.rootTargetId originalState
          Acceptance.generatedLaunch.continuationTargetIds 0 originalWorld)
        candidateAfter =
      some (generatedRuntimeBoundaryEvidence parameters originalWorld
        originalState candidateAfter candidateAtBoundary) := by
  simp [Acceptance.generatedRuntimeRules,
    constructiveSemanticRulesWithRootBoundary,
    constructiveMixedKernelSourceEvidence?,
    uniqueConstructiveMixedKernelActiveEvidence?,
    constructiveMixedKernelActiveEvidence,
    ConstructiveMixedKernelSourceRule.evidence?,
    generatedRuntimeBoundaryEvidence, generatedRuntimeRootSource,
    ExactOriginalSemanticSourceCoverage.sources,
    ExactOriginalSemanticSourceCoverage.source,
    originalExecutionAtBoundarySource, nativeExecutionAtRva,
    candidateAtBoundary]

/-- Exact checked runtime endpoint for the unique one-time launch prefix. -/
noncomputable def generatedAcceptanceLaunchPrefixEndpoint
    (parameters : Acceptance.Parameters)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentRefines :
      ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment
          (Acceptance.generatedOriginalProgram parameters)
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment
          (Acceptance.generatedCandidateProgram parameters)
          candidateEnvironment)
        (Acceptance.generatedRelationCore parameters).contract
        (RuntimeFoundation.generatedExternalFrames parameters)) :
    CanonicalMixedLaunchPrefixEndpoint Acceptance.generatedOriginalContext
      (exactNativeWorldProgramWithEnvironment
        (Acceptance.generatedCandidateProgram parameters)
        candidateEnvironment)
      (Acceptance.generatedRelationCore parameters).contract
      Acceptance.generatedLaunch
      (generatedAcceptanceLaunchWrapperRefinements parameters
        originalEnvironment candidateEnvironment environmentRefines).reflected
      (canonicalNativeInitialLaunchRoot
        (exactNativeWorldProgramWithEnvironment
          (Acceptance.generatedCandidateProgram parameters)
          candidateEnvironment))
      Acceptance.generatedCandidateRootRva
      (Acceptance.generatedInvariant parameters) := {{
  afterRelated := by
    intro originalWorld candidateWorld originalState candidateState calls route
      result candidateAfterState rootExact launchRelated callsExact routeMember
      routeSource replayed observationsExact candidateAfterMachine runtimeRelated
    have rootIsTls0 :=
      generatedAcceptanceInitialRootExact parameters candidateEnvironment
    have routeSourceTls0 :
        route.source = .canonicalRoot (.tlsCallback 0) := by
      simpa [rootIsTls0] using routeSource
    have routeExact :
        route = NativeLaunchGraph.generatedNativeLaunchGraphRoute0001 := by
      rcases generatedCanonicalRootRouteCases (.tlsCallback 0) route routeMember
          routeSourceTls0 with
        ⟨rootImpossible, _⟩ | ⟨_, routeExact⟩ | ⟨rootImpossible, _⟩
      · contradiction
      · exact routeExact
      · contradiction
    subst route
    have rootRvaExact : Acceptance.generatedCandidateRootRva = {tls0_rva} := by
      decide +kernel
    have replayedTls0 :
        NativeLaunchGraph.generatedNativeLaunchGraphRoute0001.replay?
            (generatedCandidate parameters.coreRequirements candidateEnvironment)
            NativeLaunchGraph.generatedNativeLaunchGraphCutpoints
            (.running {tls0_rva} 0 candidateState calls 0 [] candidateWorld) =
          some result := by
      simpa [Acceptance.generatedCandidateProgram, generatedCandidate,
        rootRvaExact] using replayed
    rcases launchRelated.2.2.2 with ⟨pair⟩
    have fsSelf := generatedCandidateFsSelf pair
    have activeBridgeZero :=
      generatedActiveBridgeZero parameters.coreRequirements candidateEnvironment
        pair
    have candidateWorldExact :
        nativeExecutionWorld? result.after = some candidateWorld :=
      generatedTls0ReplayWorldExact parameters.coreRequirements
        candidateEnvironment candidateState calls candidateWorld result fsSelf
        activeBridgeZero replayedTls0
    have candidateAtBoundary :
        nativeExecutionAtRva {runtime_boundary_rva} result.after :=
      generatedTls0ReplayAtRuntimeBoundary parameters.coreRequirements
        candidateEnvironment candidateState calls candidateWorld result
        replayedTls0
    let evidence := generatedRuntimeBoundaryEvidence parameters originalWorld
      originalState result.after candidateAtBoundary
    have stateFacts :
        ConstructiveMixedKernelStateFacts
          Acceptance.generatedReachability.targetIds
          (Acceptance.generatedRelationCore parameters).contract
          (.running Acceptance.generatedLaunch.rootTargetId originalState
            Acceptance.generatedLaunch.continuationTargetIds 0 originalWorld)
          result.after := {{
      originalReachable := exactOriginalLaunchExecutionReachable
        Acceptance.generatedOriginalRoot Acceptance.generatedReachability
        originalState originalWorld
      candidateProofOpen := by
        cases result.after <;>
          simp_all [nativeExecutionAtRva, NativeExecutionProofOpen]
      worldsRelated := by
        intro selectedOriginalWorld selectedCandidateWorld originalWorldExact
          selectedCandidateWorldExact
        simp only [originalExecutionWorld?, Option.some.injEq]
          at originalWorldExact
        subst selectedOriginalWorld
        have candidateWorldEquality : candidateWorld = selectedCandidateWorld :=
          Option.some.inj
            (candidateWorldExact.symm.trans selectedCandidateWorldExact)
        subst selectedCandidateWorld
        exact launchRelated.2.2.1
    }}
    have phaseFacts :
        ConstructiveMixedKernelPhaseStateFacts
          (Acceptance.generatedRelationCore parameters).contract evidence :=
      ConstructiveMixedKernelPhaseStateFacts.ofRuntimeExact evidence (by rfl)
        (by rfl) candidateWorldExact (by rfl) candidateAfterMachine
        runtimeRelated
    exact constructiveMixedKernelRuntimeInvariant_holds stateFacts phaseFacts
      (generatedRuntimeBoundaryClassified parameters originalWorld originalState
        result.after candidateAtBoundary)
      (by rfl)
}}

/-- Exact inhabitant intended for `DynamicEvidence.launch_prefix`.  It contains
the zero-step original identity path, the checked nonempty silent TLS wrapper
replay, and the runtime-only endpoint invariant. -/
noncomputable def generatedAcceptanceLaunchPrefix
    (parameters : Acceptance.Parameters)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentRefines :
      ExactOneToOneMixedExternalEnvironmentsRefine
        (decodedWorldProgramWithProtocolEnvironment
          (Acceptance.generatedOriginalProgram parameters)
          originalEnvironment)
        (exactNativeWorldProgramWithEnvironment
          (Acceptance.generatedCandidateProgram parameters)
          candidateEnvironment)
        (Acceptance.generatedRelationCore parameters).contract
        (RuntimeFoundation.generatedExternalFrames parameters)) :
    MixedWorldLaunchPrefixCertificate Acceptance.generatedOriginalContext
      (decodedWorldProgramWithProtocolEnvironment
        (Acceptance.generatedOriginalProgram parameters) originalEnvironment)
      (exactNativeWorldProgramWithEnvironment
        (Acceptance.generatedCandidateProgram parameters) candidateEnvironment)
      (Acceptance.generatedRelationCore parameters).contract
      Acceptance.generatedLaunch Acceptance.generatedCandidateRootRva
      (Acceptance.generatedInvariant parameters) := by
  let candidateWithEnvironment :=
    exactNativeWorldProgramWithEnvironment
      (Acceptance.generatedCandidateProgram parameters) candidateEnvironment
  let root := canonicalNativeInitialLaunchRoot candidateWithEnvironment
  have rootExact : root.rva? candidateWithEnvironment.pe =
      some Acceptance.generatedCandidateRootRva :=
    directExactCandidateNativeLaunchRoot_canonicalRootExact
      (directExactCandidateNativeLaunchRootWithEnvironment
        (Acceptance.generatedCandidateRoot parameters) candidateEnvironment)
  exact canonicalMixedLaunchPrefixCertificate
    (generatedAcceptanceLaunchWrapperRefinements parameters originalEnvironment
      candidateEnvironment environmentRefines)
    root rootExact
    (Acceptance.generatedCandidateLaunchCalls parameters)
    (Acceptance.generatedCandidateLaunchCallsExact parameters)
    (generatedAcceptanceLaunchPrefixEndpoint parameters originalEnvironment
      candidateEnvironment environmentRefines)

def generatedExactCanonicalLaunchWrapperBinding
    (requirements : CoreBindings.Requirements)
    (externalFrames : MixedExternalFrameContract)
    (originalEnvironment : WorldExternalProtocolEnvironment)
    (candidateEnvironment : NativeWorldEnvironment)
    (environmentRefines : ExactOneToOneMixedExternalEnvironmentsRefine
      (decodedWorldProgramWithProtocolEnvironment
        requirements.originalProgram originalEnvironment)
      (generatedCandidate requirements candidateEnvironment)
      (generatedCore requirements).contract externalFrames) :
    ExactCanonicalMixedLaunchWrapperRefinementBinding
      NativeLaunchGraph.generatedCheckedNativeLaunchGraph
      Original.generatedOriginalStaticContext
      (generatedCandidate requirements candidateEnvironment)
      (generatedCore requirements).contract Original.generatedOriginalLaunch
      (generatedLaunchWrapperRefinements requirements externalFrames
        originalEnvironment candidateEnvironment environmentRefines) := by
  simpa [generatedLaunchWrapperRefinements] using
    ExactCanonicalMixedLaunchWrapperRefinementBinding.ofCheckedRuntime
      (generatedExactNativeLaunchRuntime requirements candidateEnvironment)
      (generatedCanonicalRootFrameFacts requirements candidateEnvironment)

#print axioms generatedCandidatePeExact
#print axioms generatedCandidateImportsExact
#print axioms generatedCandidateLaunchRootsExact
#print axioms generatedCanonicalRootRoute
#print axioms generatedEntryReplayCapture
#print axioms generatedTls0ReplayCapture
#print axioms generatedTls0ReplayWorldExact
#print axioms generatedTls0ReplayAtRuntimeBoundary
#print axioms generatedTls1ReplayCapture
#print axioms generatedLaunchRootPhaseStateFacts
#print axioms generatedLaunchCarrierCanonicalExecutions
#print axioms generatedCanonicalRootFrameFacts
#print axioms generatedReplayEstablishesRuntimePhaseStateFacts
#print axioms generatedLaunchWrapperRefinements
#print axioms generatedAcceptanceLaunchWrapperRefinements
#print axioms generatedRuntimeBoundaryClassified
#print axioms generatedAcceptanceLaunchPrefixEndpoint
#print axioms generatedAcceptanceLaunchPrefix
#print axioms generatedExactCanonicalLaunchWrapperBinding

end {spec.namespace}
"""


def write_gnu_hello_launch_binding(
    out: Path | str,
    spec: GnuHelloLaunchBindingSpec | None = None,
) -> GnuHelloLaunchBindingPlan:
    plan = build_gnu_hello_launch_binding_plan(spec)
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{plan.spec.module_name}.lean").write_text(
        gnu_hello_launch_binding_source(plan), encoding="utf-8"
    )
    write_json(output / GNU_HELLO_LAUNCH_BINDING_MANIFEST, plan.payload())
    return plan


__all__ = [
    "GNU_HELLO_ACTIVE_BRIDGE_RVA",
    "GNU_HELLO_ENTRY_RVA",
    "GNU_HELLO_LAUNCH_BINDING_FORMAT",
    "GNU_HELLO_LAUNCH_BINDING_MANIFEST",
    "GNU_HELLO_LAUNCH_BINDING_MODULE",
    "GNU_HELLO_ORIGINAL_ENTRY_TARGET_ID",
    "GNU_HELLO_ORIGINAL_TLS_TARGET_IDS",
    "GNU_HELLO_TLS_CALLBACK_RVAS",
    "GnuHelloLaunchBindingPlan",
    "GnuHelloLaunchBindingSpec",
    "build_gnu_hello_launch_binding_plan",
    "gnu_hello_launch_binding_source",
    "write_gnu_hello_launch_binding",
]
