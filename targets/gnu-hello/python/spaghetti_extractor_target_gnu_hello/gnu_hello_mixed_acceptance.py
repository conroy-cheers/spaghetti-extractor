"""Aggregate the fixed GNU hello components into closed mixed acceptance.

This generator has no manifest or caller-supplied Lean names.  Component
declarations are fixed here and are admitted to the final module only after
every ``DynamicEvidence`` field has a concrete expression.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from spaghetti_extractor.errors import StageAInputError
from spaghetti_extractor.util import write_json
from .gnu_hello_acceptance_requirements import (
    GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS,
    _dynamic_requirement_types,
    _static_terms,
)
from spaghetti_extractor.relational.lean.interpreter_mixed_kernel_binding import (
    REQUIRED_INHABITANTS,
    InterpreterMixedKernelBindingSpec,
    plan_interpreter_mixed_kernel_binding,
    relational_interpreter_mixed_kernel_binding_source,
)


GNU_HELLO_MIXED_ACCEPTANCE_FORMAT = (
    "stage-a-gnu-hello-mixed-acceptance-v1"
)
GNU_HELLO_MIXED_ACCEPTANCE_MANIFEST = "gnu-hello-mixed-acceptance.json"
GNU_HELLO_MIXED_ACCEPTANCE_MODULE = "GeneratedGnuHelloMixedAcceptance"
GNU_HELLO_MIXED_ACCEPTANCE_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloMixedAcceptance"
)
GNU_HELLO_MIXED_ACCEPTANCE_PROFILE = (
    f"{GNU_HELLO_MIXED_ACCEPTANCE_NAMESPACE}."
    "candidatePE32CanonicalMixedRelationProfile"
)
GNU_HELLO_MIXED_ACCEPTANCE_SOURCE_THEOREM = (
    f"{GNU_HELLO_MIXED_ACCEPTANCE_NAMESPACE}."
    "generatedGNUHelloMixedWorldProgramsEquivalent"
)

_REQUIREMENTS_MODULE = "StageA.GeneratedGnuHelloAcceptanceRequirements"
_REQUIREMENTS_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloAcceptanceRequirements"
)
_REQUIREMENTS_TYPE = f"{_REQUIREMENTS_NAMESPACE}.MixedKernelBindingRequirements"

_RUNTIME_FOUNDATION_MODULE = "StageA.GeneratedGnuHelloRuntimeFoundation"
_RUNTIME_FOUNDATION_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloRuntimeFoundation"
)
_LAUNCH_BINDING_MODULE = "StageA.GeneratedGnuHelloLaunchBinding"
_LAUNCH_BINDING_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloLaunchBinding"
)
_EXTERNAL_COMPONENT_MODULE = "StageA.GeneratedGnuHelloExternalComponent"
_EXTERNAL_COMPONENT_NAMESPACE = (
    "StageA.GeneratedRelational.GnuHelloExternalComponent"
)
_RUNTIME_INDIRECT_MODULE = (
    "StageA.GeneratedRelationalGNUHelloRuntimeIndirectComposition"
)
_RUNTIME_INDIRECT_NAMESPACE = (
    "StageA.GeneratedRelational.GNUHelloRuntimeIndirectComposition"
)
_PROGRAM_LOOKUP_NATIVE_WORLD_MODULE = (
    "StageA.GeneratedRelationalInterpreterKernelProgramLookupNativeWorldBridge"
)
_PROGRAM_LOOKUP_NATIVE_WORLD_NAMESPACE = (
    "StageA.GeneratedRelational."
    "InterpreterKernelProgramLookupNativeWorldBridge"
)

_FIXED_IMPORTS = (
    _RUNTIME_FOUNDATION_MODULE,
    _LAUNCH_BINDING_MODULE,
    _EXTERNAL_COMPONENT_MODULE,
    _RUNTIME_INDIRECT_MODULE,
    _PROGRAM_LOOKUP_NATIVE_WORLD_MODULE,
    "StageA.RelationalInterpreterKernelOperationInstantiation",
)

# These expressions are source-controlled integration points, not user input.
# Missing workers must add their exact checked declarations here; the writer
# remains fail closed until every dynamic field has an expression.
_DYNAMIC_EVIDENCE_EXPRESSIONS: Mapping[str, str | None] = {
    "external_frames": (
        "RuntimeFoundation.generatedExternalFrames parameters.acceptance"
    ),
    "launch_realizable": (
        "RuntimeFoundation.generatedLaunchRealizable parameters.acceptance"
    ),
    "launch_wrapper_refinements": (
        "LaunchBinding.generatedAcceptanceLaunchWrapperRefinements "
        "parameters.acceptance"
    ),
    "dispatch_family": (
        "StageA.Relational.InterpreterKernelOperationInstantiation."
        "checkedNativeWorldKernelOperationDispatchFamily "
        "(Acceptance.generatedCandidateProgram parameters.acceptance)"
    ),
    "program_lookup_refines": (
        "(fun world => by "
        "simpa [Acceptance.generatedCandidateProgram, "
        "Acceptance.Parameters.coreRequirements, "
        "StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings."
        "Requirements.candidate, "
        "StageA.GeneratedRelational.InterpreterMixedAuthority."
        "generatedCandidateNativeWorldProgram, "
        "Acceptance.generatedConcreteABI, "
        "StageA.GeneratedRelational.GnuHelloCanonicalRelationCoreBindings."
        "Requirements.concreteABI, "
        "StageA.GeneratedRelational.InterpreterKernelABI."
        "generatedInterpreterKernelABIRelation] using "
        "ProgramLookupNativeWorld."
        "generatedProgramLookupNativeWorldRefines "
        "parameters.candidateEnvironment world)"
    ),
    "interpreter_step_refines": None,
    "run_function_refines": None,
    "invoke_call_refines": None,
    # The checked base prefix is not final evidence.  It must be transported
    # to the same runtime-indirect strengthened invariant as the composition.
    "launch_prefix": None,
    "semantic_chunk_factory": None,
    "external_operation_chunk_factory": (
        "StageA.Relational.InterpreterMixedExternalComponent."
        "constructiveRuntimeExternalOperationComponentOfNoCases "
        "(Acceptance.generatedRuntimeRules parameters.acceptance) "
        "(Acceptance.generatedRuntimeRulesHaveNoExternalOperations "
        "parameters.acceptance)"
    ),
    "external_boundary_chunk": None,
    "environment_compositions": None,
}

_AVAILABLE_CHECKED_COMPONENTS = {
    "external_frames": (
        f"{_RUNTIME_FOUNDATION_NAMESPACE}.generatedExternalFrames"
    ),
    "launch_realizable": (
        f"{_RUNTIME_FOUNDATION_NAMESPACE}.generatedLaunchRealizable"
    ),
    "launch_wrapper_refinements": (
        f"{_LAUNCH_BINDING_NAMESPACE}."
        "generatedAcceptanceLaunchWrapperRefinements"
    ),
    "base_launch_prefix": (
        f"{_LAUNCH_BINDING_NAMESPACE}.generatedAcceptanceLaunchPrefix"
    ),
    "external_boundary_no_case_factory": (
        f"{_EXTERNAL_COMPONENT_NAMESPACE}."
        "generatedExternalBoundaryEvidenceFactory"
    ),
    "component_composition_constructor": (
        "StageA.Relational.InterpreterMixedKernelComposition."
        "CheckedMixedKernelComponentCases.toMixedWorldChunkComposition"
    ),
    "runtime_indirect_extension_constructor": (
        "StageA.Relational.RuntimeIndirectComposition.combinedExtension"
    ),
    "runtime_indirect_root_theorem": (
        f"{_RUNTIME_INDIRECT_NAMESPACE}.generatedCombinedRootHolds"
    ),
    "launch_prefix_extension_transport": (
        "StageA.Relational.MixedExecutionInvariantExtension."
        "mixedWorldLaunchPrefixCertificateWithInvariantExtension"
    ),
}

_DYNAMIC_EVIDENCE_BLOCKERS = {
    "interpreter_step_refines": (
        "missing closed InterpreterStep native endpoint evidence"
    ),
    "run_function_refines": (
        "missing closed RunFunction native endpoint evidence"
    ),
    "invoke_call_refines": (
        "missing closed InvokeCall native endpoint evidence, including x87 "
        "and indirect continuations"
    ),
    "launch_prefix": (
        "generatedAcceptanceLaunchPrefix is for the base invariant; it must "
        "be transported with "
        "mixedWorldLaunchPrefixCertificateWithInvariantExtension"
    ),
    "semantic_chunk_factory": (
        "no exported generic constructor returns the required "
        "MixedKernelOperationComponentCertificate"
    ),
    "external_operation_chunk_factory": (
        "no exported generic constructor returns the required external "
        "MixedKernelOperationComponentCertificate"
    ),
    "external_boundary_chunk": (
        "the checked no-case factory requires beforeRelated and the exact "
        "classifier equation, but this field's current type receives neither"
    ),
    "environment_compositions": (
        "no closed environment-indexed CheckedOperationalBundle is exported "
        "for targets 292, 2595, and 2792; the final term must compose cases "
        "with toMixedWorldChunkComposition and then combinedExtension"
    ),
}

_REQUIRED_STRENGTHENED_EXPRESSION_MARKERS = {
    "environment_compositions": (
        "toMixedWorldChunkComposition",
        "combinedExtension",
        "withInvariantExtension",
    ),
    "launch_prefix": (
        "mixedWorldLaunchPrefixCertificateWithInvariantExtension",
    ),
}


class GnuHelloMixedAcceptanceGenerationError(StageAInputError):
    """The fixed concrete component set is not yet closed."""


@dataclass(frozen=True)
class MissingDynamicEvidence:
    field: str
    lean_type: str
    blocker: str

    def payload(self) -> dict[str, str]:
        return {
            "field": self.field,
            "lean_type": self.lean_type,
            "blocker": self.blocker,
        }


@dataclass(frozen=True)
class GnuHelloMixedAcceptancePlan:
    missing: tuple[MissingDynamicEvidence, ...]

    @property
    def complete(self) -> bool:
        return not self.missing

    def payload(self) -> dict[str, object]:
        return {
            "format": GNU_HELLO_MIXED_ACCEPTANCE_FORMAT,
            "status": (
                "ready_for_lean_check" if self.complete else "incomplete"
            ),
            "acceptance_authority": False,
            "proof_authority": False,
            "report_authority": False,
            "lean_check_required": True,
            "accepts_manifest": False,
            "accepts_proof_inputs": False,
            "accepts_lean_name_inputs": False,
            "environment_scope": (
                "universal_carrier_parameters_and_paired_refinement"
            ),
            "source_theorem_parameterization": (
                "forall parameters : Parameters"
            ),
            "fixed_profile_wrapper_compatible": True,
            "fixed_profile_wrapper_mode": (
                "universal_proof_free_carrier_family"
            ),
            "requires_strengthened_runtime_indirect_invariant": True,
            "required_runtime_indirect_targets": [292, 2595, 2792],
            "output_module": (
                f"StageA/{GNU_HELLO_MIXED_ACCEPTANCE_MODULE}.lean"
                if self.complete
                else None
            ),
            "profile": (
                GNU_HELLO_MIXED_ACCEPTANCE_PROFILE
                if self.complete
                else None
            ),
            "source_theorem": (
                GNU_HELLO_MIXED_ACCEPTANCE_SOURCE_THEOREM
                if self.complete
                else None
            ),
            "available_checked_components": dict(
                _AVAILABLE_CHECKED_COMPONENTS
            ),
            "missing_dynamic_evidence": [
                item.payload() for item in self.missing
            ],
        }


def build_gnu_hello_mixed_acceptance_plan() -> GnuHelloMixedAcceptancePlan:
    """Audit the fixed aggregation table against the exact dynamic interface."""

    dynamic_types = _dynamic_requirement_types(_static_terms())
    configured = set(_DYNAMIC_EVIDENCE_EXPRESSIONS)
    expected = set(GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS)
    if configured != expected:
        missing = sorted(expected - configured)
        unknown = sorted(configured - expected)
        raise GnuHelloMixedAcceptanceGenerationError(
            "fixed DynamicEvidence table disagrees with acceptance "
            f"requirements; missing={missing}, unknown={unknown}"
        )
    for field, markers in _REQUIRED_STRENGTHENED_EXPRESSION_MARKERS.items():
        expression = _DYNAMIC_EVIDENCE_EXPRESSIONS[field]
        if expression is None:
            continue
        absent = [marker for marker in markers if marker not in expression]
        if absent:
            raise GnuHelloMixedAcceptanceGenerationError(
                f"fixed {field} expression omits required checked "
                f"constructors: {', '.join(absent)}"
            )
    unresolved = tuple(
        MissingDynamicEvidence(
            field,
            dynamic_types[field],
            _DYNAMIC_EVIDENCE_BLOCKERS[field],
        )
        for field in GNU_HELLO_DYNAMIC_REQUIREMENT_KEYS
        if _DYNAMIC_EVIDENCE_EXPRESSIONS[field] is None
    )
    return GnuHelloMixedAcceptancePlan(unresolved)


def _generic_binding_source() -> str:
    terms = {
        requirement.key: f"requirements.{requirement.key}"
        for requirement in REQUIRED_INHABITANTS
    }
    plan = plan_interpreter_mixed_kernel_binding(
        InterpreterMixedKernelBindingSpec(
            binding_module=_REQUIREMENTS_MODULE,
            namespace=GNU_HELLO_MIXED_ACCEPTANCE_NAMESPACE,
            output_module=GNU_HELLO_MIXED_ACCEPTANCE_MODULE,
            terms=terms,
            requirement_parameter="requirements",
            requirement_type=_REQUIREMENTS_TYPE,
        )
    )
    if not plan.complete:
        raise GnuHelloMixedAcceptanceGenerationError(
            "internal generic mixed-kernel binding is incomplete"
        )
    return relational_interpreter_mixed_kernel_binding_source(plan)


def _carrier_and_closure_source() -> str:
    dynamic_fields = _dynamic_requirement_types(_static_terms())
    assignments = "\n".join(
        f"  {field} := {_DYNAMIC_EVIDENCE_EXPRESSIONS[field]}"
        for field in dynamic_fields
    )
    return f"""
namespace Acceptance := {_REQUIREMENTS_NAMESPACE}
namespace RuntimeFoundation := {_RUNTIME_FOUNDATION_NAMESPACE}
namespace LaunchBinding := {_LAUNCH_BINDING_NAMESPACE}
namespace ExternalComponent := {_EXTERNAL_COMPONENT_NAMESPACE}
namespace ProgramLookupNativeWorld := {_PROGRAM_LOOKUP_NATIVE_WORLD_NAMESPACE}

/-- Carrier data only.  No field has type `Prop` and no checked evidence can
enter through this interface. -/
structure Parameters where
  originalEnvironment : WorldExternalEnvironment
  originalProtocolEnvironment : WorldExternalProtocolEnvironment
  originalExternalCallSites : List ExternalCallSiteContract
  originalCallableEnvironment : OriginalCallableExternalEnvironment
  candidateEnvironment : NativeWorldEnvironment

def Parameters.acceptance (parameters : Parameters) :
    Acceptance.Parameters := {{
  originalEnvironment := parameters.originalEnvironment
  originalProtocolEnvironment := parameters.originalProtocolEnvironment
  originalExternalCallSites := parameters.originalExternalCallSites
  originalCallableEnvironment := parameters.originalCallableEnvironment
  candidateEnvironment := parameters.candidateEnvironment
}}

/-- Every proof-bearing field is supplied by a fixed checked component. -/
noncomputable def generatedDynamicEvidence
    (parameters : Parameters) :
    Acceptance.DynamicEvidence parameters.acceptance := {{
{assignments}
}}

noncomputable def generatedGNUHelloRequirements
    (parameters : Parameters) :
    Acceptance.MixedKernelBindingRequirements :=
  Acceptance.generatedRequirements parameters.acceptance
    (generatedDynamicEvidence parameters)

abbrev candidatePE32CanonicalMixedRelationProfile
    (parameters : Parameters) :=
  generatedCanonicalMixedRelationProfile
    (generatedGNUHelloRequirements parameters)

/-- Proof-closed source theorem for arbitrary carrier environments.  Its
canonical proposition separately ranges over every protocol/candidate
environment pair satisfying the checked one-to-one refinement. -/
theorem generatedGNUHelloMixedWorldProgramsEquivalent :
    forall parameters : Parameters,
      CanonicalMixedWorldProgramsChunkObservationallyEquivalent
        (candidatePE32CanonicalMixedRelationProfile parameters) := by
  intro parameters
  exact generatedMixedWorldProgramsEquivalent
    (generatedGNUHelloRequirements parameters)

#print axioms generatedDynamicEvidence
#print axioms generatedGNUHelloRequirements
#print axioms candidatePE32CanonicalMixedRelationProfile
#print axioms generatedGNUHelloMixedWorldProgramsEquivalent
"""


def gnu_hello_mixed_acceptance_source() -> str:
    """Emit the closed module, refusing any unresolved dynamic field."""

    selected = build_gnu_hello_mixed_acceptance_plan()
    if not selected.complete:
        detail = "; ".join(
            f"{item.field} : {item.lean_type}" for item in selected.missing
        )
        raise GnuHelloMixedAcceptanceGenerationError(
            "refusing to emit GNU hello mixed acceptance with missing "
            f"checked terms: {detail}"
        )

    source = _generic_binding_source()
    end_marker = f"\nend {GNU_HELLO_MIXED_ACCEPTANCE_NAMESPACE}\n"
    if source.count(end_marker) != 1:
        raise GnuHelloMixedAcceptanceGenerationError(
            "generic mixed-kernel binding namespace layout changed"
        )
    imports = "".join(f"import {module}\n" for module in _FIXED_IMPORTS)
    return (
        imports
        + source.replace(
            end_marker,
            _carrier_and_closure_source() + end_marker,
        )
    )


def write_gnu_hello_mixed_acceptance(
    out: Path | str,
) -> GnuHelloMixedAcceptancePlan:
    """Persist exact blockers, or the closed source once all terms exist."""

    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    plan = build_gnu_hello_mixed_acceptance_plan()
    write_json(root / GNU_HELLO_MIXED_ACCEPTANCE_MANIFEST, plan.payload())
    source = root / "StageA" / f"{GNU_HELLO_MIXED_ACCEPTANCE_MODULE}.lean"
    if not plan.complete:
        if source.exists():
            source.unlink()
        return plan
    source.parent.mkdir(parents=True, exist_ok=True)
    source.write_text(
        gnu_hello_mixed_acceptance_source(), encoding="ascii"
    )
    return plan


__all__ = [
    "GNU_HELLO_MIXED_ACCEPTANCE_FORMAT",
    "GNU_HELLO_MIXED_ACCEPTANCE_MANIFEST",
    "GNU_HELLO_MIXED_ACCEPTANCE_MODULE",
    "GNU_HELLO_MIXED_ACCEPTANCE_NAMESPACE",
    "GNU_HELLO_MIXED_ACCEPTANCE_PROFILE",
    "GNU_HELLO_MIXED_ACCEPTANCE_SOURCE_THEOREM",
    "GnuHelloMixedAcceptanceGenerationError",
    "GnuHelloMixedAcceptancePlan",
    "MissingDynamicEvidence",
    "build_gnu_hello_mixed_acceptance_plan",
    "gnu_hello_mixed_acceptance_source",
    "write_gnu_hello_mixed_acceptance",
]
