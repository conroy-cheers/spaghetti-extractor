"""Generate GNU hello's exact root-boundary operation bridge.

The acceptance runtime inventory has one real ``externalBoundary`` rule at
candidate RVA 278423.  This generator therefore does not reuse the no-case
theorem for the older launch-plus-semantic inventory.  It exports the exact
acceptance-shaped bridge and chunk-factory types, together with the only sound
generic constructor: a silent nonempty native prefix to a checked operation
certificate.

No current generated artifact proves that native prefix.  The manifest and
Lean API keep that proof object explicit and fail closed until it is supplied,
or until launch replay is extended to the operation entry and the runtime rule
inventory is changed accordingly.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.util import write_json


GNU_HELLO_EXTERNAL_COMPONENT_FORMAT = (
    "stage-a-gnu-hello-external-component-v3"
)
GNU_HELLO_EXTERNAL_COMPONENT_MANIFEST = "gnu-hello-external-component.json"
GNU_HELLO_EXTERNAL_COMPONENT_MODULE = "GeneratedGnuHelloExternalComponent"
GNU_HELLO_CANDIDATE_ROOT_RVA = 41712
GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA = 278423

_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


@dataclass(frozen=True)
class GnuHelloExternalComponentSpec:
    module_name: str = GNU_HELLO_EXTERNAL_COMPONENT_MODULE
    namespace: str = "StageA.GeneratedRelational.GnuHelloExternalComponent"
    original_module: str = "StageA.GeneratedRelationalInterpreterMixedOriginal"
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
    reachability: str = "generatedExactOriginalDecodedStaticReachability"
    source_bindings_module: str = (
        "StageA.GeneratedGnuHelloConstructiveSourceCoverageBindings"
    )
    source_bindings_namespace: str = (
        "StageA.GeneratedRelational."
        "GnuHelloConstructiveSourceCoverageBindings"
    )
    source_rules_module: str = (
        "StageA.GeneratedGnuHelloConstructiveSourceRules"
    )
    source_rules_namespace: str = (
        "StageA.GeneratedRelational.GnuHelloConstructiveSourceRules"
    )
    source_coverage_module: str = (
        "StageA.GeneratedRelationalInterpreterMixedSourceCoverage"
    )
    source_coverage_namespace: str = (
        "StageA.GeneratedRelational.InterpreterMixedSourceCoverage"
    )
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel"
    kernel_namespace: str = "StageA.GeneratedRelational.InterpreterKernel"
    candidate_root_rva: int = GNU_HELLO_CANDIDATE_ROOT_RVA
    runtime_boundary_rva: int = GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA

    def validate(self) -> None:
        if _LOCAL_NAME.fullmatch(self.module_name) is None:
            raise StageAInputError(
                "GNU hello external component module_name must be a local "
                "Lean name"
            )
        modules = {
            "original_module",
            "reachability_module",
            "source_bindings_module",
            "source_rules_module",
            "source_coverage_module",
            "kernel_module",
        }
        for label, value in (
            ("namespace", self.namespace),
            ("original_module", self.original_module),
            ("original_namespace", self.original_namespace),
            ("reachability_module", self.reachability_module),
            ("reachability_namespace", self.reachability_namespace),
            ("source_bindings_module", self.source_bindings_module),
            ("source_bindings_namespace", self.source_bindings_namespace),
            ("source_rules_module", self.source_rules_module),
            ("source_rules_namespace", self.source_rules_namespace),
            ("source_coverage_module", self.source_coverage_module),
            ("source_coverage_namespace", self.source_coverage_namespace),
            ("kernel_module", self.kernel_module),
            ("kernel_namespace", self.kernel_namespace),
        ):
            pattern = _STAGE_A_MODULE if label in modules else _LEAN_NAME
            if pattern.fullmatch(value) is None:
                raise StageAInputError(
                    f"GNU hello external component {label} must be a Lean name"
                )
        if _LOCAL_NAME.fullmatch(self.reachability) is None:
            raise StageAInputError(
                "GNU hello external component reachability must be a local "
                "Lean name"
            )
        for label, value in (
            ("candidate_root_rva", self.candidate_root_rva),
            ("runtime_boundary_rva", self.runtime_boundary_rva),
        ):
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or not 0 <= value < 2**32
            ):
                raise StageAInputError(
                    f"GNU hello external component {label} must be a PE32 RVA"
                )


@dataclass(frozen=True)
class GnuHelloExternalComponentPlan:
    spec: GnuHelloExternalComponentSpec

    @property
    def complete(self) -> bool:
        return False

    def payload(self) -> dict[str, object]:
        return {
            "format": GNU_HELLO_EXTERNAL_COMPONENT_FORMAT,
            "phase": "gnu-hello-external-component",
            "complete": False,
            "acceptance_authority": False,
            "proof_authority": False,
            "executes_original_binary": False,
            "executes_candidate_binary": False,
            "outputs": {
                "lean_module": f"StageA/{self.spec.module_name}.lean",
            },
            "constructed_terms": {
                "runtime_rules": "generatedRuntimeRules",
                "runtime_invariant": "generatedRuntimeInvariant",
                "runtime_classifier": "generatedRuntimeClassifier",
                "bridge_type": "GeneratedRootBoundaryToOperationBridge",
                "bridge_factory_type": (
                    "GeneratedRootBoundaryToOperationBridgeFactory"
                ),
                "chunk_factory_type": (
                    "GeneratedExternalBoundaryChunkFactory"
                ),
                "chunk_constructor": (
                    "generatedExternalBoundaryChunkFactoryOfOperationBridge"
                ),
            },
            "public_terms": {
                "bridge_factory_type": (
                    "GeneratedRootBoundaryToOperationBridgeFactory"
                ),
                "chunk_constructor": (
                    "generatedExternalBoundaryChunkFactoryOfOperationBridge"
                ),
            },
            "external_boundary_classification": {
                "separate_classifier_cases": 1,
                "candidate_rva": self.spec.runtime_boundary_rva,
                "owner": "generatedInterpreterStepEntry",
                "operation": "interpreterStep",
                "rules": "constructiveSemanticRulesWithRootBoundary",
            },
            "remaining_premises": [
                (
                    "GeneratedRootBoundaryToOperationBridgeFactory: a silent "
                    "nonempty candidate path from the classified root boundary "
                    "to generatedInterpreterStepEntry, followed by a checked "
                    "MixedKernelOperationComponentCertificate"
                )
            ],
            "blocking_obligations": [
                (
                    "no generated theorem proves callback-wrapper execution "
                    f"from RVA {self.spec.runtime_boundary_rva} to the first "
                    "checked interpreterStep operation state for every state "
                    "admitted by generatedRuntimeInvariant"
                )
            ],
        }


def build_gnu_hello_external_component_plan(
    spec: GnuHelloExternalComponentSpec | None = None,
) -> GnuHelloExternalComponentPlan:
    selected = spec or GnuHelloExternalComponentSpec()
    selected.validate()
    return GnuHelloExternalComponentPlan(selected)


def gnu_hello_external_component_source(
    plan: GnuHelloExternalComponentPlan,
) -> str:
    """Emit the exact root-boundary bridge interface and constructor."""

    spec = plan.spec
    spec.validate()
    return f"""import StageA.RelationalInterpreterMixedBoundaryOperation
import {spec.original_module}
import {spec.reachability_module}
import {spec.source_bindings_module}
import {spec.source_rules_module}
import {spec.source_coverage_module}
import {spec.kernel_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedBoundaryOperation
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeWorld

noncomputable section

abbrev generatedOriginalContext :=
  {spec.original_namespace}.generatedOriginalStaticContext

abbrev generatedOriginalAuthority :=
  {spec.original_namespace}.generatedExactOriginalDecodedAuthority

abbrev generatedLaunch :=
  {spec.original_namespace}.generatedOriginalLaunch

abbrev generatedOriginalRoot :=
  {spec.original_namespace}.generatedDirectExactOriginalDecodedLaunchRoot

abbrev generatedReachability :=
  {spec.reachability_namespace}.{spec.reachability}

abbrev generatedCompiledProgram :=
  {spec.kernel_namespace}.generatedCompiledKernelProgram

def generatedSourceRequirements
    (candidateEnvironment : NativeWorldEnvironment) :
    {spec.source_bindings_namespace}.Requirements := {{
  candidateEnvironment
}}

abbrev generatedCandidate
    (candidateEnvironment : NativeWorldEnvironment) :=
  (generatedSourceRequirements candidateEnvironment).candidate

abbrev generatedCandidateAuthority
    (candidateEnvironment : NativeWorldEnvironment) :=
  (generatedSourceRequirements candidateEnvironment).candidateAuthority

abbrev generatedInterpreterStepEntry :=
  {spec.source_rules_namespace}.generatedInterpreterStepEntry

/-- This is the exact recurring inventory used by GNU hello acceptance after
the one-time native launch prefix.  Its original root is a real boundary case
at RVA {spec.runtime_boundary_rva}; it is not the older launch rule. -/
noncomputable def generatedRuntimeRules
    (candidateEnvironment : NativeWorldEnvironment) :=
  constructiveSemanticRulesWithRootBoundary
    (candidateRootRva := {spec.candidate_root_rva})
    ({spec.source_coverage_namespace}.generatedExactOriginalSemanticSourceCoverage
        (generatedSourceRequirements candidateEnvironment))
    generatedInterpreterStepEntry
    {spec.runtime_boundary_rva}

noncomputable def generatedRuntimeInvariant
    (candidateEnvironment : NativeWorldEnvironment)
    (contract : MixedRelationContract) :=
  constructiveMixedKernelRuntimeInvariant generatedOriginalContext
    generatedOriginalAuthority generatedLaunch generatedOriginalRoot
    generatedReachability (generatedCandidate candidateEnvironment)
    (generatedCandidateAuthority candidateEnvironment)
    generatedCompiledProgram {spec.candidate_root_rva} contract
    (generatedRuntimeRules candidateEnvironment)

noncomputable def generatedRuntimeClassifier
    (candidateEnvironment : NativeWorldEnvironment)
    (contract : MixedRelationContract) :=
  constructiveMixedKernelRuntimeSourceClassifier generatedOriginalContext
    generatedOriginalAuthority generatedLaunch generatedOriginalRoot
    generatedReachability (generatedCandidate candidateEnvironment)
    (generatedCandidateAuthority candidateEnvironment)
    generatedCompiledProgram {spec.candidate_root_rva} contract
    (generatedRuntimeRules candidateEnvironment)

abbrev GeneratedRootBoundaryToOperationBridge
    (candidateEnvironment : NativeWorldEnvironment)
    (original : DecodedWorldProgram)
    (contract : MixedRelationContract)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (source : ExactOriginalSemanticSource generatedOriginalContext
      generatedOriginalAuthority generatedLaunch generatedOriginalRoot
      generatedReachability (generatedCandidate candidateEnvironment)
      (generatedCandidateAuthority candidateEnvironment))
    (originalBefore : WorldExecution)
    (candidateBefore : NativeWorldExecution) :=
  ExactMixedKernelBoundaryToOperationBridge original
    (generatedCandidate candidateEnvironment) contract
    (generatedRuntimeInvariant candidateEnvironment contract)
    generatedCompiledProgram abi dispatches
    (generatedCandidateAuthority candidateEnvironment)
    source.source.target.rva generatedInterpreterStepEntry originalBefore
    candidateBefore

/-- Exact missing proof object for the one real root-boundary branch.
`classified` pins every request to the runtime classifier above.  The returned
bridge must contain the actual silent nonempty wrapper path and a checked
interpreter-step operation certificate at its derived endpoint. -/
def GeneratedRootBoundaryToOperationBridgeFactory
    (candidateEnvironment : NativeWorldEnvironment)
    (original : DecodedWorldProgram)
    (contract : MixedRelationContract)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation) : Type :=
  forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource generatedOriginalContext
        generatedOriginalAuthority generatedLaunch generatedOriginalRoot
        generatedReachability (generatedCandidate candidateEnvironment)
        (generatedCandidateAuthority candidateEnvironment))
      (candidateRva : Nat)
      (beforeRelated :
        (generatedRuntimeInvariant candidateEnvironment contract).holds
          originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtSource :
        nativeExecutionAtRva candidateRva candidateBefore)
      (classified :
        (generatedRuntimeClassifier candidateEnvironment contract).classifier.classify
            originalBefore candidateBefore beforeRelated =
          MixedKernelRelatedSourceCase.externalBoundary source candidateRva
            originalAtSource candidateAtSource),
    GeneratedRootBoundaryToOperationBridge candidateEnvironment original
      contract abi dispatches source originalBefore candidateBefore

def GeneratedExternalBoundaryChunkFactory
    (candidateEnvironment : NativeWorldEnvironment)
    (original : DecodedWorldProgram)
    (contract : MixedRelationContract) : Type :=
  forall originalBefore candidateBefore
      (source : ExactOriginalSemanticSource generatedOriginalContext
        generatedOriginalAuthority generatedLaunch generatedOriginalRoot
        generatedReachability (generatedCandidate candidateEnvironment)
        (generatedCandidateAuthority candidateEnvironment))
      (candidateRva : Nat)
      (beforeRelated :
        (generatedRuntimeInvariant candidateEnvironment contract).holds
          originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtSource :
        nativeExecutionAtRva candidateRva candidateBefore)
      (classified :
        (generatedRuntimeClassifier candidateEnvironment contract).classifier.classify
            originalBefore candidateBefore beforeRelated =
          MixedKernelRelatedSourceCase.externalBoundary source candidateRva
            originalAtSource candidateAtSource),
    MixedKernelChunkPaths original (generatedCandidate candidateEnvironment)
      contract (generatedRuntimeInvariant candidateEnvironment contract)
      originalBefore candidateBefore

/-- Sound closure constructor for `external_boundary_chunk`.  It cannot be
called until the exact root-boundary-to-operation bridge factory exists. -/
def generatedExternalBoundaryChunkFactoryOfOperationBridge
    (candidateEnvironment : NativeWorldEnvironment)
    (original : DecodedWorldProgram)
    (contract : MixedRelationContract)
    (abi : KernelABIRelation)
    (dispatches : KernelDispatchRelation)
    (bridges : GeneratedRootBoundaryToOperationBridgeFactory
      candidateEnvironment original contract abi dispatches) :
    GeneratedExternalBoundaryChunkFactory candidateEnvironment original
      contract := by
  intro originalBefore candidateBefore source candidateRva beforeRelated
    originalAtSource candidateAtSource classified
  exact
    (bridges originalBefore candidateBefore source candidateRva beforeRelated
      originalAtSource candidateAtSource classified).toChunk

#print axioms generatedRuntimeRules
#print axioms generatedRuntimeInvariant
#print axioms generatedRuntimeClassifier
#print axioms generatedExternalBoundaryChunkFactoryOfOperationBridge

end
end {spec.namespace}
"""


def write_gnu_hello_external_component(
    out: Path | str,
    spec: GnuHelloExternalComponentSpec | None = None,
) -> GnuHelloExternalComponentPlan:
    plan = build_gnu_hello_external_component_plan(spec)
    output = Path(out)
    stage_a = output / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    (stage_a / f"{plan.spec.module_name}.lean").write_text(
        gnu_hello_external_component_source(plan), encoding="ascii"
    )
    write_json(output / GNU_HELLO_EXTERNAL_COMPONENT_MANIFEST, plan.payload())
    return plan


__all__ = [
    "GNU_HELLO_CANDIDATE_ROOT_RVA",
    "GNU_HELLO_EXTERNAL_COMPONENT_FORMAT",
    "GNU_HELLO_EXTERNAL_COMPONENT_MANIFEST",
    "GNU_HELLO_EXTERNAL_COMPONENT_MODULE",
    "GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA",
    "GnuHelloExternalComponentPlan",
    "GnuHelloExternalComponentSpec",
    "build_gnu_hello_external_component_plan",
    "gnu_hello_external_component_source",
    "write_gnu_hello_external_component",
]
