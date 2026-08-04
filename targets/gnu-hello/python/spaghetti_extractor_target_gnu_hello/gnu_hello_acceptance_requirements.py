"""Generate the concrete static half of GNU hello final acceptance."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.util import write_json
from spaghetti_extractor.relational.lean.interpreter_mixed_kernel_binding import (
    REQUIRED_INHABITANTS,
    relational_interpreter_mixed_kernel_requirements_source,
)


GNU_HELLO_ACCEPTANCE_REQUIREMENTS_FORMAT = (
    "stage-a-gnu-hello-acceptance-requirements-v1"
)
GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MANIFEST = (
    "gnu-hello-acceptance-requirements.json"
)
GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MODULE = (
    "GeneratedGnuHelloAcceptanceRequirements"
)
GNU_HELLO_CANDIDATE_ROOT_RVA = 41712
GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA = 278423

GNU_HELLO_STATIC_REQUIREMENT_KEYS = (
    "original_context",
    "original_authority",
    "original_program",
    "candidate_program",
    "candidate_authority",
    "program_binding",
    "launch",
    "original_root",
    "reachability",
    "concrete_abi",
    "relation_core",
    "launch_anchors_complete",
    "candidate_root_rva",
    "candidate_root",
    "compiled_program",
    "invariant",
    "classify_source",
    "candidate_launch_calls",
    "candidate_launch_calls_exact",
)

GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS = (
    "external_frames",
    "launch_realizable",
    "launch_wrapper_refinements",
    "dispatch_family",
    "program_lookup_refines",
    "interpreter_step_refines",
    "run_function_refines",
    "invoke_call_refines",
    "launch_prefix",
    "semantic_chunk_factory",
    "external_operation_chunk_factory",
    "external_boundary_chunk",
    "environment_compositions",
)

_LEAN_NAME = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")


class GnuHelloAcceptanceRequirementsGenerationError(StageAInputError):
    """The requested GNU acceptance requirements module is malformed."""


@dataclass(frozen=True)
class GnuHelloAcceptanceRequirementsSpec:
    module_name: str = GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MODULE
    namespace: str = (
        "StageA.GeneratedRelational.GnuHelloAcceptanceRequirements"
    )
    candidate_root_rva: int = GNU_HELLO_CANDIDATE_ROOT_RVA
    original_module: str = "StageA.GeneratedRelationalInterpreterMixedOriginal"
    reachability_module: str = (
        "StageA.GeneratedRelationalInterpreterMixedOriginalStaticReachability"
    )
    original_carrier_module: str = (
        "StageA.GeneratedRelationalInterpreterOriginalCarrierBinding"
    )
    callable_module: str = "StageA.GeneratedCallableExternalProgram"
    candidate_module: str = (
        "StageA.GeneratedRelationalInterpreterMixedAuthority"
    )
    kernel_abi_module: str = "StageA.GeneratedRelationalInterpreterKernelABI"
    kernel_module: str = "StageA.GeneratedRelationalInterpreterKernel"
    core_bindings_module: str = (
        "StageA.GeneratedGnuHelloCanonicalRelationCoreBindings"
    )
    core_module: str = "StageA.GeneratedGnuHelloCanonicalRelationCore"
    source_bindings_module: str = (
        "StageA.GeneratedGnuHelloConstructiveSourceCoverageBindings"
    )
    source_rules_module: str = (
        "StageA.GeneratedGnuHelloConstructiveSourceRules"
    )
    candidate_root_checked_term: str | None = None
    emit_axiom_audit: bool = True

    def validate(self) -> None:
        if _LOCAL_NAME.fullmatch(self.module_name) is None:
            raise GnuHelloAcceptanceRequirementsGenerationError(
                "GNU acceptance module_name must be a local Lean name"
            )
        for field in (
            "namespace",
            "original_module",
            "reachability_module",
            "original_carrier_module",
            "callable_module",
            "candidate_module",
            "kernel_abi_module",
            "kernel_module",
            "core_bindings_module",
            "core_module",
            "source_bindings_module",
            "source_rules_module",
        ):
            if _LEAN_NAME.fullmatch(getattr(self, field)) is None:
                raise GnuHelloAcceptanceRequirementsGenerationError(
                    f"GNU acceptance {field} must be a Lean name"
                )
        if (
            isinstance(self.candidate_root_rva, bool)
            or not isinstance(self.candidate_root_rva, int)
            or not 0 <= self.candidate_root_rva < 2**32
        ):
            raise GnuHelloAcceptanceRequirementsGenerationError(
                "GNU acceptance candidate_root_rva must be a PE32 RVA"
            )
        if (
            self.candidate_root_checked_term is not None
            and _LEAN_NAME.fullmatch(self.candidate_root_checked_term) is None
        ):
            raise GnuHelloAcceptanceRequirementsGenerationError(
                "GNU acceptance candidate_root_checked_term must be a Lean name"
            )
        if not isinstance(self.emit_axiom_audit, bool):
            raise GnuHelloAcceptanceRequirementsGenerationError(
                "GNU acceptance emit_axiom_audit must be Boolean"
            )
        _validate_requirement_partition()


@dataclass(frozen=True)
class GnuHelloAcceptanceRequirementsPlan:
    spec: GnuHelloAcceptanceRequirementsSpec

    def payload(self) -> dict[str, object]:
        dynamic_types = _dynamic_requirement_types(_static_terms())
        return {
            "format": GNU_HELLO_ACCEPTANCE_REQUIREMENTS_FORMAT,
            "acceptance_authority": False,
            "report_authority": False,
            "lean_check_required": True,
            "output_module": f"StageA/{self.spec.module_name}.lean",
            "candidate_root_rva": self.spec.candidate_root_rva,
            "constructed_static_fields": list(
                GNU_HELLO_STATIC_REQUIREMENT_KEYS
            ),
            "dynamic_evidence_fields": [
                {"field": key, "lean_type": dynamic_types[key]}
                for key in GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS
            ],
        }


def _validate_requirement_partition() -> None:
    required = tuple(requirement.key for requirement in REQUIRED_INHABITANTS)
    configured = set(GNU_HELLO_STATIC_REQUIREMENT_KEYS) | set(
        GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS
    )
    if len(configured) != (
        len(GNU_HELLO_STATIC_REQUIREMENT_KEYS)
        + len(GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS)
    ):
        raise GnuHelloAcceptanceRequirementsGenerationError(
            "GNU acceptance static and dynamic requirement fields overlap"
        )
    if configured != set(required):
        missing = sorted(set(required) - configured)
        unknown = sorted(configured - set(required))
        raise GnuHelloAcceptanceRequirementsGenerationError(
            "GNU acceptance requirement partition disagrees with "
            f"REQUIRED_INHABITANTS; missing={missing}, unknown={unknown}"
        )


def _substitute_requirement_type(
    lean_type: str, terms: Mapping[str, str]
) -> str:
    result = lean_type
    for requirement in REQUIRED_INHABITANTS:
        result = result.replace(
            f"${requirement.key}",
            terms.get(requirement.key, f"${requirement.key}"),
        )
    if "$" in result:
        raise GnuHelloAcceptanceRequirementsGenerationError(
            f"unresolved dependent requirement type: {result}"
        )
    return result


def _static_terms() -> dict[str, str]:
    return {
        "original_context": "generatedOriginalContext",
        "original_authority": "generatedOriginalAuthority",
        "original_program": "(generatedOriginalProgram parameters)",
        "candidate_program": "(generatedCandidateProgram parameters)",
        "candidate_authority": "(generatedCandidateAuthority parameters)",
        "program_binding": "(generatedProgramBinding parameters)",
        "launch": "generatedLaunch",
        "original_root": "generatedOriginalRoot",
        "reachability": "generatedReachability",
        "concrete_abi": "(generatedConcreteABI parameters)",
        "relation_core": "(generatedRelationCore parameters)",
        "launch_anchors_complete": (
            "(generatedLaunchAnchorsComplete parameters)"
        ),
        "candidate_root_rva": "generatedCandidateRootRva",
        "candidate_root": "(generatedCandidateRoot parameters)",
        "compiled_program": "generatedCompiledProgram",
        "invariant": "(generatedInvariant parameters)",
        "classify_source": "(generatedClassifySource parameters)",
        "candidate_launch_calls": (
            "(generatedCandidateLaunchCalls parameters)"
        ),
        "candidate_launch_calls_exact": (
            "(generatedCandidateLaunchCallsExact parameters)"
        ),
    }


def _dynamic_requirement_types(
    static_terms: Mapping[str, str],
) -> dict[str, str]:
    terms = dict(static_terms)
    result: dict[str, str] = {}
    for requirement in REQUIRED_INHABITANTS:
        if requirement.key in GNU_HELLO_STATIC_REQUIREMENT_KEYS:
            continue
        if requirement.key not in GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS:
            raise GnuHelloAcceptanceRequirementsGenerationError(
                f"unclassified GNU acceptance field: {requirement.key}"
            )
        result[requirement.key] = _substitute_requirement_type(
            requirement.lean_type, terms
        )
        terms[requirement.key] = requirement.key
    return result


def _dynamic_evidence_source() -> str:
    rows = [
        f"  {key} : {lean_type}"
        for key, lean_type in _dynamic_requirement_types(
            _static_terms()
        ).items()
    ]
    return "\n".join(rows)


def _requirements_assignments() -> str:
    static_terms = _static_terms()
    rows = []
    for requirement in REQUIRED_INHABITANTS:
        value = static_terms.get(
            requirement.key, f"evidence.{requirement.key}"
        )
        rows.append(f"  {requirement.key} := {value}")
    return "\n".join(rows)


def build_gnu_hello_acceptance_requirements_plan(
    spec: GnuHelloAcceptanceRequirementsSpec | None = None,
) -> GnuHelloAcceptanceRequirementsPlan:
    selected = spec or GnuHelloAcceptanceRequirementsSpec()
    selected.validate()
    return GnuHelloAcceptanceRequirementsPlan(selected)


def gnu_hello_acceptance_requirements_source(
    plan: GnuHelloAcceptanceRequirementsPlan,
) -> str:
    """Emit concrete static terms and typed dynamic acceptance premises."""

    spec = plan.spec
    spec.validate()
    requirements = relational_interpreter_mixed_kernel_requirements_source(
        spec.namespace
    )
    imports = "\n".join(
        f"import {module}"
        for module in (
            spec.original_module,
            spec.reachability_module,
            spec.original_carrier_module,
            spec.callable_module,
            spec.candidate_module,
            spec.kernel_abi_module,
            spec.kernel_module,
            spec.core_bindings_module,
            spec.core_module,
            spec.source_bindings_module,
            spec.source_rules_module,
            "StageA.RelationalCallableExternalMixedBridge",
            "StageA.RelationalInterpreterMixedExternalComponent",
            "StageA.RelationalInterpreterNativeLaunch",
        )
    )
    candidate_root_checked_proof = (
        "  decide +kernel"
        if spec.candidate_root_checked_term is None
        else (
            f"  exact {spec.candidate_root_checked_term} "
            "parameters.candidateEnvironment"
        )
    )
    axiom_audit = (
        """#print axioms generatedOriginalCallableBinding
#print axioms generatedRelationCore
#print axioms generatedCandidateRoot
#print axioms generatedRuntimeRulesHaveNoExternalOperations
#print axioms generatedInvariant
#print axioms generatedClassifySource
#print axioms generatedCandidateLaunchCallsExact
#print axioms generatedRequirements
"""
        if spec.emit_axiom_audit
        else ""
    )
    return f"""{imports}
{requirements}
namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.CallableExternalExecution
open StageA.Relational.CallableExternalMixedBridge
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedConstructiveSourceClassifier
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedExternalComponent
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

set_option maxHeartbeats 0
set_option maxRecDepth 1000000

noncomputable section

/-- Concrete carrier parameters.  They select environments but carry no proof
authority; all static authority below comes from imported Lean declarations. -/
structure Parameters where
  originalEnvironment : WorldExternalEnvironment
  originalProtocolEnvironment : WorldExternalProtocolEnvironment
  originalExternalCallSites : List ExternalCallSiteContract
  originalCallableEnvironment : OriginalCallableExternalEnvironment
  candidateEnvironment : NativeWorldEnvironment

def Parameters.coreRequirements (parameters : Parameters) :
    StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings.Requirements := {{
  originalEnvironment := parameters.originalEnvironment
  originalProtocolEnvironment := parameters.originalProtocolEnvironment
  originalExternalCallSites := parameters.originalExternalCallSites
  candidateEnvironment := parameters.candidateEnvironment
}}

def Parameters.sourceRequirements (parameters : Parameters) :
    StageA.GeneratedRelational.GnuHelloConstructiveSourceCoverageBindings.Requirements := {{
  candidateEnvironment := parameters.candidateEnvironment
}}

abbrev generatedOriginalContext :=
  StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalStaticContext

abbrev generatedOriginalAuthority :=
  StageA.GeneratedRelational.InterpreterMixedOriginal.generatedExactOriginalDecodedAuthority

abbrev generatedLaunch :=
  StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalLaunch

abbrev generatedOriginalRoot :=
  StageA.GeneratedRelational.InterpreterMixedOriginal.generatedDirectExactOriginalDecodedLaunchRoot

abbrev generatedReachability :=
  StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability.generatedExactOriginalDecodedStaticReachability

abbrev generatedCompiledProgram :=
  StageA.GeneratedRelational.InterpreterKernel.generatedCompiledKernelProgram

def generatedOriginalProgram (parameters : Parameters) : DecodedWorldProgram :=
  decodedWorldProgramWithCallable
    parameters.coreRequirements.originalProgram
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgram
    parameters.originalCallableEnvironment

def generatedProgramBinding (parameters : Parameters) :
    ExactMixedProgramBinding generatedOriginalContext
      (generatedOriginalProgram parameters) :=
  parameters.coreRequirements.programBinding.withCallable
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgram
    parameters.originalCallableEnvironment

def generatedOriginalCallableBinding (parameters : Parameters) :
    ExactDecodedOriginalCallableProgramBinding
      (generatedOriginalProgram parameters)
      StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgram
      parameters.originalCallableEnvironment :=
  ExactDecodedOriginalCallableProgramBinding.ofWithCallable
    parameters.coreRequirements.originalProgram
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgram
    parameters.originalCallableEnvironment rfl rfl
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgramValid

def generatedCandidateProgram (parameters : Parameters) :
    ExactNativeWorldProgram :=
  parameters.coreRequirements.candidate

def generatedCandidateAuthority (parameters : Parameters) :
    ExactNativeCandidateAuthority (generatedCandidateProgram parameters) :=
  parameters.coreRequirements.candidateAuthority

def generatedConcreteABI (parameters : Parameters) :
    ConcreteKernelABI (generatedCandidateProgram parameters).pe
      (generatedCandidateProgram parameters).imports
      (generatedCandidateAuthority parameters).relocations
      (generatedCandidateAuthority parameters).tableRva
      (generatedCandidateAuthority parameters).countRva
      (generatedCandidateAuthority parameters).semanticRecords :=
  parameters.coreRequirements.concreteABI

def generatedPlainRelationCore (parameters : Parameters) :=
  StageA.GeneratedRelational.GnuHelloCanonicalRelationCore.generatedCanonicalMixedRelationCore
    parameters.coreRequirements

def generatedRelationCore (parameters : Parameters) :
    CanonicalMixedRelationCore generatedOriginalContext generatedOriginalAuthority
      (generatedOriginalProgram parameters) (generatedCandidateProgram parameters)
      (generatedCandidateAuthority parameters) (generatedProgramBinding parameters)
      (generatedConcreteABI parameters) generatedReachability.targetIds :=
  (generatedPlainRelationCore parameters).withCallable
    StageA.GeneratedRelational.CallableExternalProgram.originalCallableProgram
    parameters.originalCallableEnvironment

theorem generatedRelationCoreContractExact (parameters : Parameters) :
    (generatedRelationCore parameters).contract =
      (generatedPlainRelationCore parameters).contract := by
  rfl

theorem generatedLaunchAnchorsComplete (parameters : Parameters) :
    MixedNativeLaunchAnchorsComplete (generatedCandidateProgram parameters)
      generatedLaunch (generatedRelationCore parameters).anchors = true := by
  simpa [generatedRelationCore, generatedPlainRelationCore] using
    StageA.GeneratedRelational.GnuHelloCanonicalRelationCore.generatedCanonicalMixedLaunchAnchorsComplete
      parameters.coreRequirements

def generatedCandidateRootRva : Nat := {spec.candidate_root_rva}

theorem generatedCandidateRootChecked (parameters : Parameters) :
    directExactCandidateNativeLaunchRootChecked
      (generatedCandidateProgram parameters) generatedLaunch
      generatedCandidateRootRva = true := by
{candidate_root_checked_proof}

def generatedCandidateRoot (parameters : Parameters) :
    DirectExactCandidateNativeLaunchRoot
      (generatedCandidateProgram parameters) generatedLaunch
      generatedCandidateRootRva :=
  (directExactCandidateNativeLaunchRootChecked_iff
    (generatedCandidateProgram parameters) generatedLaunch
    generatedCandidateRootRva).mp
      (generatedCandidateRootChecked parameters)

/-- Recurring composition uses a runtime-only source inventory.  The initial
original TLS source is paired with the exact native callback boundary reached
by launch replay; every subsequent source enters through the checked
interpreter-step operation. -/
noncomputable def generatedRuntimeRules (parameters : Parameters) :=
  constructiveSemanticRulesWithRootBoundary
    (candidateRootRva := generatedCandidateRootRva)
    (StageA.GeneratedRelational.InterpreterMixedSourceCoverage.generatedExactOriginalSemanticSourceCoverage
        parameters.sourceRequirements)
    StageA.GeneratedRelational.GnuHelloConstructiveSourceRules.generatedInterpreterStepEntry
    {GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA}

theorem generatedRuntimeRulesHaveNoExternalOperations
    (parameters : Parameters) :
    ConstructiveMixedKernelClassificationHasNoExternalOperations
      (generatedRuntimeRules parameters) := by
  exact constructiveSemanticRulesWithRootBoundary_hasNoExternalOperations
    (StageA.GeneratedRelational.InterpreterMixedSourceCoverage.generatedExactOriginalSemanticSourceCoverage
        parameters.sourceRequirements)
    StageA.GeneratedRelational.GnuHelloConstructiveSourceRules.generatedInterpreterStepEntry
    {GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA}

noncomputable def generatedInvariant (parameters : Parameters) :
    MixedExecutionInvariant generatedReachability.targetIds
      (generatedRelationCore parameters).contract :=
  constructiveMixedKernelRuntimeInvariant generatedOriginalContext
    generatedOriginalAuthority generatedLaunch generatedOriginalRoot
    generatedReachability (generatedCandidateProgram parameters)
    (generatedCandidateAuthority parameters) generatedCompiledProgram
    generatedCandidateRootRva (generatedRelationCore parameters).contract
    (generatedRuntimeRules parameters)

noncomputable def generatedClassifySource (parameters : Parameters) :
    MixedKernelRuntimeSourceClassifier generatedOriginalContext
      generatedOriginalAuthority generatedLaunch generatedOriginalRoot
      generatedReachability (generatedCandidateProgram parameters)
      (generatedCandidateAuthority parameters) generatedCompiledProgram
      generatedCandidateRootRva (generatedInvariant parameters) :=
  constructiveMixedKernelRuntimeSourceClassifier generatedOriginalContext
    generatedOriginalAuthority generatedLaunch generatedOriginalRoot
    generatedReachability (generatedCandidateProgram parameters)
    (generatedCandidateAuthority parameters) generatedCompiledProgram
    generatedCandidateRootRva (generatedRelationCore parameters).contract
    (generatedRuntimeRules parameters)

noncomputable def generatedCandidateLaunchCalls
    (parameters : Parameters) (state : MachineState) : List NativeCallFrame :=
  Classical.choose
    (candidateNativeLaunchCallFrames?_exists
      (generatedCandidateRoot parameters)
      StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalLaunchFrameCountChecked
      state)

theorem generatedCandidateLaunchCallsExact
    (parameters : Parameters) :
    forall state,
      candidateNativeLaunchCallFrames? (generatedCandidateProgram parameters)
          generatedLaunch state =
        some (generatedCandidateLaunchCalls parameters state) := by
  intro state
  exact Classical.choose_spec
    (candidateNativeLaunchCallFrames?_exists
      (generatedCandidateRoot parameters)
      StageA.GeneratedRelational.InterpreterMixedOriginal.generatedOriginalLaunchFrameCountChecked
      state)

/-- The only remaining acceptance premises are semantic/runtime evidence. -/
structure DynamicEvidence (parameters : Parameters) where
{_dynamic_evidence_source()}

/-- Full final-acceptance requirements with every closed static field fixed to
the exact GNU hello generated authority. -/
noncomputable def generatedRequirements
    (parameters : Parameters) (evidence : DynamicEvidence parameters) :
    MixedKernelBindingRequirements := {{
{_requirements_assignments()}
}}

{axiom_audit}
end
end {spec.namespace}
"""


def write_gnu_hello_acceptance_requirements(
    out: Path | str,
    spec: GnuHelloAcceptanceRequirementsSpec | None = None,
) -> GnuHelloAcceptanceRequirementsPlan:
    plan = build_gnu_hello_acceptance_requirements_plan(spec)
    root = Path(out)
    stage_a = root / "StageA"
    stage_a.mkdir(parents=True, exist_ok=True)
    source = stage_a / f"{plan.spec.module_name}.lean"
    source.write_text(
        gnu_hello_acceptance_requirements_source(plan), encoding="ascii"
    )
    write_json(
        root / GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MANIFEST,
        plan.payload(),
    )
    return plan


__all__ = [
    "GNU_HELLO_ACCEPTANCE_REQUIREMENTS_FORMAT",
    "GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MANIFEST",
    "GNU_HELLO_ACCEPTANCE_REQUIREMENTS_MODULE",
    "GNU_HELLO_CANDIDATE_ROOT_RVA",
    "GNU_HELLO_INITIAL_RUNTIME_BOUNDARY_RVA",
    "GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS",
    "GNU_HELLO_STATIC_REQUIREMENT_KEYS",
    "GnuHelloAcceptanceRequirementsGenerationError",
    "GnuHelloAcceptanceRequirementsPlan",
    "GnuHelloAcceptanceRequirementsSpec",
    "build_gnu_hello_acceptance_requirements_plan",
    "gnu_hello_acceptance_requirements_source",
    "write_gnu_hello_acceptance_requirements",
]
