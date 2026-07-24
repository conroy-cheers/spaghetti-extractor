"""Generate the exact mixed-kernel component binding and acceptance term.

The JSON input names Lean inhabitants; it never supplies proof results.  A
diagnostic artifact may veto generation by reporting a concrete unresolved
frontier, but its status or verdict fields are deliberately ignored.  Lean is
the only authority that can accept the emitted terms.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping, Sequence

from ...errors import StageAInputError


INTERPRETER_MIXED_KERNEL_BINDING_FORMAT = (
    "stage-a-relational-interpreter-mixed-kernel-binding-v2"
)
INTERPRETER_MIXED_KERNEL_BINDING_MODULE = (
    "GeneratedRelationalInterpreterMixedKernelBinding"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_CATEGORY = re.compile(r"[a-z][a-z0-9_]*\Z")


class InterpreterMixedKernelBindingGenerationError(StageAInputError):
    """The binding manifest is malformed or cannot safely emit Lean."""


@dataclass(frozen=True)
class RequiredInhabitant:
    key: str
    category: str
    lean_type: str
    dependencies: tuple[str, ...]
    remediation: str


@dataclass(frozen=True)
class DiagnosticArtifact:
    category: str
    path: Path


@dataclass(frozen=True)
class UnresolvedInhabitant:
    identifier: str
    category: str
    key: str
    reason_code: str
    lean_type: str
    dependencies: tuple[str, ...]
    remediation: str
    source: str
    location: object | None = None
    detail: str | None = None

    def to_json(self) -> dict[str, object]:
        result: dict[str, object] = {
            "id": self.identifier,
            "category": self.category,
            "key": self.key,
            "reason_code": self.reason_code,
            "lean_type": self.lean_type,
            "dependencies": list(self.dependencies),
            "remediation": self.remediation,
            "source": self.source,
        }
        if self.location is not None:
            result["location"] = self.location
        if self.detail is not None:
            result["detail"] = self.detail
        return result


@dataclass(frozen=True)
class InterpreterMixedKernelBindingSpec:
    binding_module: str
    namespace: str
    terms: Mapping[str, str]
    diagnostic_artifacts: tuple[DiagnosticArtifact, ...] = ()
    output_module: str = INTERPRETER_MIXED_KERNEL_BINDING_MODULE
    requirement_parameter: str | None = None
    requirement_type: str | None = None

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterMixedKernelBindingGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if _LEAN_IDENTIFIER.fullmatch(self.namespace) is None:
            raise InterpreterMixedKernelBindingGenerationError(
                "namespace must be a canonical Lean namespace"
            )
        if _LOCAL_NAME.fullmatch(self.output_module) is None:
            raise InterpreterMixedKernelBindingGenerationError(
                "output_module must be a local Lean module name"
            )
        if (self.requirement_parameter is None) != (self.requirement_type is None):
            raise InterpreterMixedKernelBindingGenerationError(
                "requirement_parameter and requirement_type must be supplied together"
            )
        if self.requirement_parameter is not None:
            if _LOCAL_NAME.fullmatch(self.requirement_parameter) is None:
                raise InterpreterMixedKernelBindingGenerationError(
                    "requirement_parameter must be a local Lean identifier"
                )
            if _LEAN_IDENTIFIER.fullmatch(self.requirement_type or "") is None:
                raise InterpreterMixedKernelBindingGenerationError(
                    "requirement_type must be a canonical Lean identifier"
                )
        unknown = sorted(set(self.terms) - {item.key for item in REQUIRED_INHABITANTS})
        if unknown:
            raise InterpreterMixedKernelBindingGenerationError(
                "unknown binding term keys: " + ", ".join(unknown)
            )
        for key, value in self.terms.items():
            if _LEAN_IDENTIFIER.fullmatch(value) is None:
                raise InterpreterMixedKernelBindingGenerationError(
                    f"terms.{key} must be a canonical Lean identifier"
                )
        for index, artifact in enumerate(self.diagnostic_artifacts):
            if _CATEGORY.fullmatch(artifact.category) is None:
                raise InterpreterMixedKernelBindingGenerationError(
                    f"diagnostic_artifacts[{index}].category is malformed"
                )


def _type(text: str) -> str:
    return " ".join(text.split())


REQUIRED_INHABITANTS: tuple[RequiredInhabitant, ...] = (
    RequiredInhabitant(
        "original_context",
        "original_authority",
        "OriginalDecodedStaticContext",
        (),
        "emit the exact one-sided original static context",
    ),
    RequiredInhabitant(
        "original_authority",
        "original_authority",
        "ExactOriginalDecodedAuthority $original_context",
        ("original_context",),
        "close exact original parsing, decoding, source indexing, and import contracts",
    ),
    RequiredInhabitant(
        "original_program",
        "original_authority",
        "DecodedWorldProgram",
        (),
        "emit the decoded original operational carrier",
    ),
    RequiredInhabitant(
        "candidate_program",
        "candidate_semantic_record_authority",
        "ExactNativeWorldProgram",
        (),
        "emit the exact native candidate transition system",
    ),
    RequiredInhabitant(
        "candidate_authority",
        "candidate_semantic_record_authority",
        "ExactNativeCandidateAuthority $candidate_program",
        ("candidate_program",),
        "bind candidate PE bytes, imports, relocations, and semantic records",
    ),
    RequiredInhabitant(
        "program_binding",
        "original_authority",
        "ExactMixedProgramBinding $original_context $original_program",
        ("original_context", "original_program"),
        "prove the decoded carrier projects exactly to original authority",
    ),
    RequiredInhabitant(
        "launch",
        "launch_evidence",
        "PE32ConsoleLaunchV2",
        (),
        "provide the checked bounded console launch profile",
    ),
    RequiredInhabitant(
        "original_root",
        "launch_evidence",
        _type(
            "DirectExactOriginalDecodedLaunchRoot $original_context $launch"
        ),
        ("original_context", "launch"),
        "derive original entry and TLS roots from the exact PE",
    ),
    RequiredInhabitant(
        "reachability",
        "original_reachability",
        _type(
            "ExactOriginalDecodedReachability $original_context "
            "$original_authority $launch $original_root"
        ),
        ("original_context", "original_authority", "launch", "original_root"),
        "close the decoded rooted successor closure",
    ),
    RequiredInhabitant(
        "concrete_abi",
        "concrete_abi",
        _type(
            "ConcreteKernelABI $candidate_program.pe $candidate_program.imports "
            "$candidate_authority.relocations $candidate_authority.tableRva "
            "$candidate_authority.countRva $candidate_authority.semanticRecords"
        ),
        (
            "candidate_program",
            "candidate_authority",
        ),
        "extract the checked concrete candidate ABI, layout, and table certificate",
    ),
    RequiredInhabitant(
        "relation_core",
        "mixed_relation",
        _type(
            "CanonicalMixedRelationCore $original_context $original_authority "
            "$original_program $candidate_program $candidate_authority "
            "$program_binding $concrete_abi $reachability.targetIds"
        ),
        (
            "original_context",
            "original_authority",
            "original_program",
            "candidate_program",
            "candidate_authority",
            "program_binding",
            "concrete_abi",
            "reachability",
        ),
        "bind the exact engine-state relation and the small executable anchor map",
    ),
    RequiredInhabitant(
        "external_frames",
        "external_environment_refinement",
        "MixedExternalFrameContract",
        (),
        "provide checked internal/external continuation-frame correspondence",
    ),
    RequiredInhabitant(
        "launch_anchors_complete",
        "launch_evidence",
        _type(
            "MixedNativeLaunchAnchorsComplete $candidate_program $launch "
            "$relation_core.anchors = true"
        ),
        ("candidate_program", "launch", "relation_core"),
        "prove that the small checked anchor map covers the parsed entry and TLS roots",
    ),
    RequiredInhabitant(
        "launch_realizable",
        "launch_evidence",
        _type(
            "MixedLaunchRealizable $original_context $candidate_program "
            "$relation_core.contract"
        ),
        ("original_context", "candidate_program", "relation_core"),
        "inhabit the bounded PE32 console launch relation without pre-populating "
        "the candidate engine buffer",
    ),
    RequiredInhabitant(
        "launch_wrapper_refinements",
        "launch_wrapper_refinement",
        _type(
            "forall originalEnvironment candidateEnvironment, "
            "ExactOneToOneMixedExternalEnvironmentsRefine "
            "(decodedWorldProgramWithProtocolEnvironment $original_program "
            "originalEnvironment) (exactNativeWorldProgramWithEnvironment "
            "$candidate_program candidateEnvironment) $relation_core.contract "
            "$external_frames -> CanonicalMixedLaunchWrapperRefinement "
            "$original_context (exactNativeWorldProgramWithEnvironment "
            "$candidate_program candidateEnvironment) $relation_core.contract $launch"
        ),
        (
            "original_context",
            "original_program",
            "candidate_program",
            "relation_core",
            "external_frames",
            "launch",
        ),
        "replay exact nonempty entry/TLS, return, and termination wrapper paths and "
        "prove each launch root establishes the runtime engine relation for every "
        "environment pair satisfying exact 1:1 refinement",
    ),
    RequiredInhabitant(
        "candidate_root_rva",
        "launch_evidence",
        "Nat",
        (),
        "name the candidate root selected by exact PE launch parsing",
    ),
    RequiredInhabitant(
        "candidate_root",
        "launch_evidence",
        _type(
            "DirectExactCandidateNativeLaunchRoot $candidate_program $launch "
            "$candidate_root_rva"
        ),
        ("candidate_program", "launch", "candidate_root_rva"),
        "derive the candidate root from exact candidate PE launch data",
    ),
    RequiredInhabitant(
        "compiled_program",
        "compiled_kernel",
        "CompiledKernelProgram",
        (),
        "bind the checked candidate kernel CFG and operation entry inventory",
    ),
    RequiredInhabitant(
        "dispatch_family",
        "compiled_kernel",
        "KernelOperationDispatchFamily",
        (),
        "provide the exact operation-indexed native dispatch relations",
    ),
    RequiredInhabitant(
        "program_lookup_refines",
        "operation_refinement_program_lookup",
        _type(
            "KernelOperationRefinesUsing $compiled_program $concrete_abi.relation "
            "($dispatch_family .programLookup) "
            ".programLookup"
        ),
        ("compiled_program", "concrete_abi", "dispatch_family"),
        "prove programLookup from checked local kernel operations",
    ),
    RequiredInhabitant(
        "interpreter_step_refines",
        "operation_refinement_interpreter_step",
        _type(
            "KernelOperationRefinesUsing $compiled_program $concrete_abi.relation "
            "($dispatch_family .interpreterStep) "
            ".interpreterStep"
        ),
        ("compiled_program", "concrete_abi", "dispatch_family"),
        "prove interpreterStep from checked local kernel operations",
    ),
    RequiredInhabitant(
        "run_function_refines",
        "operation_refinement_run_function",
        _type(
            "KernelOperationRefinesUsing $compiled_program $concrete_abi.relation "
            "($dispatch_family .runFunction) "
            ".runFunction"
        ),
        ("compiled_program", "concrete_abi", "dispatch_family"),
        "prove runFunction from checked local kernel operations and loop invariants",
    ),
    RequiredInhabitant(
        "invoke_call_refines",
        "operation_refinement_invoke_call",
        _type(
            "KernelOperationRefinesUsing $compiled_program $concrete_abi.relation "
            "($dispatch_family .invokeCall) "
            ".invokeCall"
        ),
        ("compiled_program", "concrete_abi", "dispatch_family"),
        "prove invokeCall including exact internal and external dispatch",
    ),
    RequiredInhabitant(
        "invariant",
        "mixed_invariant",
        "MixedExecutionInvariant $reachability.targetIds $relation_core.contract",
        ("reachability", "relation_core"),
        "define the authoritative reachable mixed execution invariant",
    ),
    RequiredInhabitant(
        "classify_source",
        "source_classifier",
        _type(
            "forall originalBefore candidateBefore, $invariant.holds originalBefore "
            "candidateBefore -> MixedKernelRelatedSourceCase $original_context "
            "$original_authority $launch $original_root $reachability "
            "$candidate_program $candidate_authority $compiled_program "
            "$candidate_root_rva originalBefore candidateBefore"
        ),
        (
            "original_context",
            "original_authority",
            "launch",
            "original_root",
            "reachability",
            "candidate_program",
            "candidate_authority",
            "compiled_program",
            "candidate_root_rva",
            "invariant",
        ),
        "classify every related state without blocked or unclassified fallback",
    ),
    RequiredInhabitant(
        "launch_chunk",
        "launch_component",
        _type(
            "forall originalBefore candidateBefore (source : "
            "ExactOriginalSemanticSource $original_context $original_authority "
            "$launch $original_root $reachability $candidate_program "
            "$candidate_authority), source.targetId = $launch.rootTargetId -> "
            "originalExecutionAtTargetId source.targetId originalBefore -> "
            "nativeExecutionAtRva $candidate_root_rva candidateBefore -> "
            "MixedKernelChunkPaths $original_program $candidate_program "
            "$relation_core.contract "
            "$invariant originalBefore candidateBefore"
        ),
        ("classify_source", "relation_core", "invariant"),
        "prove the exact nonempty launch-wrapper paths",
    ),
    RequiredInhabitant(
        "semantic_chunk_factory",
        "semantic_component",
        _type(
            "forall originalBefore candidateBefore (source : "
            "ExactOriginalSemanticSource $original_context $original_authority "
            "$launch $original_root $reachability $candidate_program "
            "$candidate_authority) (operation : KernelOperation) (entryRva : Nat), "
            "originalExecutionAtTargetId source.targetId originalBefore -> "
            "nativeExecutionAtRva entryRva candidateBefore -> "
            "$compiled_program.functionEntry? operation.role = some entryRva -> "
            "KernelOperationRefinesUsing $compiled_program $concrete_abi.relation "
            "(combinedKernelDispatchRelation $dispatch_family) operation -> "
            "MixedKernelOperationComponentCertificate $original_program "
            "$candidate_program $relation_core.contract $invariant $compiled_program "
            "$concrete_abi.relation "
            "(combinedKernelDispatchRelation $dispatch_family) $candidate_authority "
            "source.source.target.rva operation "
            "entryRva originalBefore candidateBefore"
        ),
        (
            "classify_source",
            "relation_core",
            "concrete_abi",
            "dispatch_family",
        ),
        "construct exact semantic paths while consuming the selected operation proof",
    ),
    RequiredInhabitant(
        "external_operation_chunk_factory",
        "external_operation_component",
        _type(
            "forall originalBefore candidateBefore (source : "
            "ExactOriginalSemanticSource $original_context $original_authority "
            "$launch $original_root $reachability $candidate_program "
            "$candidate_authority) (operation : KernelOperation) (entryRva : Nat), "
            "originalExecutionAtBoundarySource source.targetId originalBefore -> "
            "nativeExecutionAtRva entryRva candidateBefore -> "
            "$compiled_program.functionEntry? operation.role = some entryRva -> "
            "KernelOperationRefinesUsing $compiled_program $concrete_abi.relation "
            "(combinedKernelDispatchRelation $dispatch_family) operation -> "
            "MixedKernelOperationComponentCertificate $original_program "
            "$candidate_program $relation_core.contract $invariant $compiled_program "
            "$concrete_abi.relation "
            "(combinedKernelDispatchRelation $dispatch_family) $candidate_authority "
            "source.source.target.rva operation "
            "entryRva originalBefore candidateBefore"
        ),
        (
            "classify_source",
            "relation_core",
            "concrete_abi",
            "dispatch_family",
        ),
        "construct exact external-operation paths and consume invoke-call refinement",
    ),
    RequiredInhabitant(
        "external_boundary_chunk",
        "external_boundary_bridge",
        _type(
            "forall originalBefore candidateBefore (source : "
            "ExactOriginalSemanticSource $original_context $original_authority "
            "$launch $original_root $reachability $candidate_program "
            "$candidate_authority) (candidateRva : Nat), "
            "originalExecutionAtBoundarySource source.targetId originalBefore -> "
            "nativeExecutionAtRva candidateRva candidateBefore -> "
            "MixedKernelChunkPaths $original_program $candidate_program "
            "$relation_core.contract "
            "$invariant originalBefore candidateBefore"
        ),
        ("classify_source", "relation_core", "invariant"),
        "prove the exact ordered pointwise external-event and callback bridge",
    ),
    RequiredInhabitant(
        "candidate_launch_calls",
        "launch_evidence",
        "MachineState -> List NativeCallFrame",
        ("candidate_program", "launch"),
        "provide candidate launch call frames",
    ),
    RequiredInhabitant(
        "candidate_launch_calls_exact",
        "launch_evidence",
        _type(
            "forall candidateState, candidateNativeLaunchCallFrames? "
            "$candidate_program $launch candidateState = "
            "some ($candidate_launch_calls candidateState)"
        ),
        ("candidate_program", "launch", "candidate_launch_calls"),
        "prove launch frames are exactly derived from candidate PE data",
    ),
    RequiredInhabitant(
        "roots_related",
        "launch_evidence",
        _type(
            "forall originalWorld candidateWorld originalState candidateState, "
            "MixedLaunchStatesRelated $original_context $candidate_program "
            "$relation_core.contract "
            "originalWorld candidateWorld originalState candidateState -> "
            "$invariant.holds (.running $launch.rootTargetId originalState "
            "$launch.continuationTargetIds 0 originalWorld) "
            "(.running $candidate_root_rva 0 candidateState "
            "($candidate_launch_calls candidateState) 0 [] candidateWorld)"
        ),
        ("relation_core", "invariant", "candidate_launch_calls"),
        "establish the mixed invariant at both exact launch roots",
    ),
    RequiredInhabitant(
        "environment_compositions",
        "whole_program_composition",
        _type(
            "forall originalEnvironment candidateEnvironment, "
            "ExactOneToOneMixedExternalEnvironmentsRefine "
            "(decodedWorldProgramWithProtocolEnvironment $original_program "
            "originalEnvironment) (exactNativeWorldProgramWithEnvironment "
            "$candidate_program candidateEnvironment) $relation_core.contract "
            "$external_frames -> MixedWorldChunkComposition $original_context "
            "$original_authority (decodedWorldProgramWithProtocolEnvironment "
            "$original_program originalEnvironment) "
            "(exactNativeWorldProgramWithEnvironment $candidate_program "
            "candidateEnvironment) "
            "(exactNativeCandidateAuthorityWithEnvironment $candidate_authority "
            "candidateEnvironment) "
            "(exactMixedProgramBindingWithProtocolEnvironment $program_binding "
            "originalEnvironment) "
            "$relation_core.contract $launch $original_root $reachability "
            "$candidate_root_rva "
            "(directExactCandidateNativeLaunchRootWithEnvironment "
            "$candidate_root candidateEnvironment)"
        ),
        (
            "original_context",
            "original_authority",
            "original_program",
            "candidate_program",
            "candidate_authority",
            "program_binding",
            "relation_core",
            "external_frames",
            "launch",
            "original_root",
            "reachability",
            "candidate_root_rva",
            "candidate_root",
        ),
        "compose exact chunks for every original/candidate environment pair "
        "satisfying exact 1:1 machine-level refinement",
    ),
)


@dataclass(frozen=True)
class InterpreterMixedKernelBindingPlan:
    spec: InterpreterMixedKernelBindingSpec
    unresolved: tuple[UnresolvedInhabitant, ...]
    diagnostic_statuses: tuple[dict[str, object], ...]

    @property
    def complete(self) -> bool:
        return not self.unresolved

    def to_json(self) -> dict[str, object]:
        category_counts: dict[str, int] = {}
        category_work_items: dict[str, int] = {}
        for item in self.unresolved:
            category_counts[item.category] = category_counts.get(item.category, 0) + 1
            weight = 1
            if (
                item.reason_code == "upstream_unresolved_count"
                and isinstance(item.location, Mapping)
                and isinstance(item.location.get("count"), int)
            ):
                weight = item.location["count"]
            category_work_items[item.category] = (
                category_work_items.get(item.category, 0) + weight
            )
        generated = {
            "relation_profile": "generatedCanonicalMixedRelationProfile",
            "source_classifier": "generatedMixedKernelSourceClassifier",
            "operation_refinements": "generatedKernelOperationRefinements",
            "component_cases": "generatedCheckedMixedKernelComponentCases",
            "composition": "generatedMixedWorldChunkComposition",
            "selected_acceptance_certificate": (
                "generatedSelectedMixedWorldAcceptanceCertificate"
            ),
            "universal_acceptance_certificate": (
                "generatedUniversalMixedWorldAcceptanceCertificate"
            ),
            "acceptance_theorem": "generatedMixedWorldProgramsEquivalent",
        }
        return {
            "format": INTERPRETER_MIXED_KERNEL_BINDING_FORMAT,
            "status": "ready_for_lean_check" if self.complete else "incomplete",
            "acceptance_authority": False,
            "lean_check_required": True,
            "observation_trace_contract": {
                "cardinality": "arbitrary_finite",
                "ordering": "exact_pointwise_order",
                "relation": "RelatedObservationLists",
                "proof_blocked_observations": "uninhabited",
            },
            "output_module": self.spec.output_module if self.complete else None,
            "generated_terms": generated if self.complete else {},
            "counts": {
                "required_inhabitants": len(REQUIRED_INHABITANTS),
                "named_inhabitants": len(self.spec.terms),
                "unresolved_inhabitants": len(self.unresolved),
                "reported_unresolved_work_items": sum(category_work_items.values()),
                "unresolved_by_category": dict(sorted(category_counts.items())),
                "reported_unresolved_work_items_by_category": dict(
                    sorted(category_work_items.items())
                ),
                "reported_work_items_may_overlap_across_artifacts": True,
            },
            "unresolved_inhabitants": [item.to_json() for item in self.unresolved],
            "diagnostic_artifacts": list(self.diagnostic_statuses),
            "ignored_untrusted_fields": [
                "acceptance",
                "complete",
                "pass",
                "proof_status",
                "status",
                "verdict",
            ],
        }


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InterpreterMixedKernelBindingGenerationError(
            f"{context} must be a JSON object"
        )
    return value


def _string(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InterpreterMixedKernelBindingGenerationError(
            f"{context} must be a non-empty string"
        )
    return value


def _identifier(parts: Sequence[object]) -> str:
    encoded = json.dumps(list(parts), sort_keys=True, separators=(",", ":"))
    return "mixed-kernel-" + hashlib.sha256(encoded.encode("utf-8")).hexdigest()[:20]


def _substitute_type(requirement: RequiredInhabitant, terms: Mapping[str, str]) -> str:
    result = requirement.lean_type
    for item in REQUIRED_INHABITANTS:
        result = result.replace(f"${item.key}", terms.get(item.key, f"${item.key}"))
    return result


def load_interpreter_mixed_kernel_binding_spec(
    path: Path | str,
) -> InterpreterMixedKernelBindingSpec:
    manifest = Path(path)
    try:
        payload = _mapping(json.loads(manifest.read_text(encoding="utf-8")), "manifest")
    except (OSError, json.JSONDecodeError) as error:
        raise InterpreterMixedKernelBindingGenerationError(
            f"unable to read binding manifest: {manifest}"
        ) from error
    allowed = {
        "format",
        "binding_module",
        "namespace",
        "output_module",
        "terms",
        "diagnostic_artifacts",
        "requirement_parameter",
        "requirement_type",
    }
    unknown = sorted(set(payload) - allowed)
    if unknown:
        raise InterpreterMixedKernelBindingGenerationError(
            "unknown manifest fields: " + ", ".join(unknown)
        )
    if payload.get("format") != INTERPRETER_MIXED_KERNEL_BINDING_FORMAT:
        raise InterpreterMixedKernelBindingGenerationError(
            f"manifest.format must be {INTERPRETER_MIXED_KERNEL_BINDING_FORMAT}"
        )
    terms_payload = _mapping(payload.get("terms"), "terms")
    terms = {
        _string(key, "terms key"): _string(value, f"terms.{key}")
        for key, value in terms_payload.items()
    }
    artifact_rows = payload.get("diagnostic_artifacts", [])
    if not isinstance(artifact_rows, list):
        raise InterpreterMixedKernelBindingGenerationError(
            "diagnostic_artifacts must be a JSON array"
        )
    artifacts: list[DiagnosticArtifact] = []
    for index, value in enumerate(artifact_rows):
        row = _mapping(value, f"diagnostic_artifacts[{index}]")
        if set(row) != {"category", "path"}:
            raise InterpreterMixedKernelBindingGenerationError(
                f"diagnostic_artifacts[{index}] requires exactly category and path"
            )
        artifact_path = Path(_string(row.get("path"), f"diagnostic_artifacts[{index}].path"))
        if not artifact_path.is_absolute():
            artifact_path = manifest.parent / artifact_path
        artifacts.append(
            DiagnosticArtifact(
                _string(row.get("category"), f"diagnostic_artifacts[{index}].category"),
                artifact_path,
            )
        )
    requirement_parameter = payload.get("requirement_parameter")
    requirement_type = payload.get("requirement_type")
    if requirement_parameter is not None:
        requirement_parameter = _string(requirement_parameter, "requirement_parameter")
    if requirement_type is not None:
        requirement_type = _string(requirement_type, "requirement_type")
    spec = InterpreterMixedKernelBindingSpec(
        binding_module=_string(payload.get("binding_module"), "binding_module"),
        namespace=_string(payload.get("namespace"), "namespace"),
        output_module=_string(
            payload.get("output_module", INTERPRETER_MIXED_KERNEL_BINDING_MODULE),
            "output_module",
        ),
        terms=terms,
        diagnostic_artifacts=tuple(artifacts),
        requirement_parameter=requirement_parameter,
        requirement_type=requirement_type,
    )
    spec.validate()
    return spec


def _artifact_unresolved(
    artifact: DiagnosticArtifact,
) -> tuple[list[UnresolvedInhabitant], dict[str, object]]:
    try:
        raw = artifact.path.read_bytes()
        payload = _mapping(
            json.loads(raw),
            f"diagnostic artifact {artifact.path}",
        )
    except (OSError, json.JSONDecodeError) as error:
        unresolved = UnresolvedInhabitant(
            _identifier((artifact.category, str(artifact.path), "unreadable")),
            artifact.category,
            "diagnostic_artifact",
            "diagnostic_artifact_unreadable",
            "upstream diagnostic artifact",
            (),
            "regenerate or provide the named diagnostic artifact",
            str(artifact.path),
            detail=str(error),
        )
        return [unresolved], {
            "category": artifact.category,
            "path": str(artifact.path),
            "sha256": None,
            "format": None,
            "reported_status": None,
        }

    result: list[UnresolvedInhabitant] = []
    inventories = (
        ("remaining_uninhabited_fields", "upstream_uninhabited_field"),
        ("remaining_inhabitants", "upstream_uninhabited_field"),
    )
    for field, reason in inventories:
        rows = payload.get(field, [])
        if not isinstance(rows, list):
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, str) or not row:
                continue
            result.append(
                UnresolvedInhabitant(
                    _identifier((artifact.category, str(artifact.path), field, index, row)),
                    artifact.category,
                    row,
                    reason,
                    "upstream proof inhabitant",
                    (),
                    "close the upstream Lean inhabitant and bind its checked term",
                    str(artifact.path),
                    detail=row,
                )
            )
    for field in ("blockers", "issues"):
        rows = payload.get(field, [])
        if not isinstance(rows, list):
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, Mapping):
                continue
            reason_value = row.get(
                "reason_code", row.get("code", row.get("category", field[:-1]))
            )
            reason = reason_value if isinstance(reason_value, str) else field[:-1]
            detail_value = row.get("detail", row.get("message", reason))
            detail = detail_value if isinstance(detail_value, str) else reason
            location = row.get("location")
            if location is None:
                location = {
                    key: row[key]
                    for key in (
                        "target_id",
                        "source_rva",
                        "instruction_rva",
                        "rva",
                        "rva_start",
                        "rva_end",
                        "function_role",
                    )
                    if key in row
                } or None
            result.append(
                UnresolvedInhabitant(
                    _identifier((artifact.category, str(artifact.path), field, index, row)),
                    artifact.category,
                    reason,
                    "upstream_" + field[:-1],
                    "upstream proof frontier",
                    (),
                    "resolve the reported frontier and regenerate its checked Lean term",
                    str(artifact.path),
                    location=location,
                    detail=detail,
                )
            )
    counts = payload.get("counts")
    if isinstance(counts, Mapping):
        for key, value in sorted(counts.items()):
            unresolved_count = (
                isinstance(value, int)
                and not isinstance(value, bool)
                and value > 0
                and not key.startswith(("closed_", "resolved_"))
                and (
                    key.startswith(("pending_", "remaining_", "unresolved_"))
                    or key.endswith(("_blockers", "_frontiers"))
                )
            )
            if not unresolved_count:
                continue
            result.append(
                UnresolvedInhabitant(
                    _identifier(
                        (artifact.category, str(artifact.path), "counts", key, value)
                    ),
                    artifact.category,
                    key,
                    "upstream_unresolved_count",
                    "upstream proof frontier inventory",
                    (),
                    "emit itemized Lean premises for this unresolved upstream count",
                    str(artifact.path),
                    location={"count": value},
                    detail=f"{value} unresolved items reported by {key}",
                )
            )
    metadata = {
        "category": artifact.category,
        "path": str(artifact.path),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "format": payload.get("format") if isinstance(payload.get("format"), str) else None,
        "reported_status": (
            payload.get("status")
            if isinstance(payload.get("status"), str)
            else None
        ),
        "status_is_proof_authority": False,
        "frontiers": len(result),
    }
    return result, metadata


def plan_interpreter_mixed_kernel_binding(
    spec: InterpreterMixedKernelBindingSpec,
) -> InterpreterMixedKernelBindingPlan:
    spec.validate()
    unresolved: list[UnresolvedInhabitant] = []
    for requirement in REQUIRED_INHABITANTS:
        if requirement.key in spec.terms:
            continue
        unresolved.append(
            UnresolvedInhabitant(
                _identifier(("missing", requirement.category, requirement.key)),
                requirement.category,
                requirement.key,
                "missing_lean_term",
                _substitute_type(requirement, spec.terms),
                requirement.dependencies,
                requirement.remediation,
                "binding_manifest",
            )
        )
    diagnostic_statuses: list[dict[str, object]] = []
    for artifact in spec.diagnostic_artifacts:
        artifact_unresolved, metadata = _artifact_unresolved(artifact)
        unresolved.extend(artifact_unresolved)
        diagnostic_statuses.append(metadata)
    unresolved.sort(
        key=lambda item: (item.category, item.reason_code, item.key, item.identifier)
    )
    return InterpreterMixedKernelBindingPlan(
        spec,
        tuple(unresolved),
        tuple(diagnostic_statuses),
    )


def relational_interpreter_mixed_kernel_requirements_source(
    namespace: str,
    structure_name: str = "MixedKernelBindingRequirements",
) -> str:
    """Emit the exact dependent premise interface used by a binding provider.

    This interface is useful while independent proof phases are still being
    implemented: their eventual aggregate value must inhabit this structure.
    It contains no status fields and proves nothing by itself.
    """

    if _LEAN_IDENTIFIER.fullmatch(namespace) is None:
        raise InterpreterMixedKernelBindingGenerationError(
            "requirements namespace must be a canonical Lean namespace"
        )
    if _LOCAL_NAME.fullmatch(structure_name) is None:
        raise InterpreterMixedKernelBindingGenerationError(
            "requirements structure_name must be a local Lean identifier"
        )
    field_terms: dict[str, str] = {}
    rows: list[str] = []
    for requirement in REQUIRED_INHABITANTS:
        lean_type = requirement.lean_type
        for prior in REQUIRED_INHABITANTS:
            replacement = field_terms.get(prior.key, f"${prior.key}")
            lean_type = lean_type.replace(f"${prior.key}", replacement)
        rows.append(f"  {requirement.key} : {lean_type}")
        field_terms[requirement.key] = requirement.key
    fields = "\n".join(rows)
    return f"""import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalInterpreterMixedProfile

namespace {namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

/-- Exact premises that a concrete generated binding must inhabit. -/
structure {structure_name} where
{fields}

end {namespace}
"""


def relational_interpreter_mixed_kernel_binding_source(
    plan: InterpreterMixedKernelBindingPlan,
) -> str:
    if not plan.complete:
        categories = sorted({item.category for item in plan.unresolved})
        raise InterpreterMixedKernelBindingGenerationError(
            "refusing to emit mixed-kernel binding with unresolved inhabitants: "
            + ", ".join(categories)
        )
    spec = plan.spec
    terms = spec.terms
    parameter = (
        f"variable ({spec.requirement_parameter} : {spec.requirement_type})\n\n"
        if spec.requirement_parameter is not None
        else ""
    )
    argument = f" {spec.requirement_parameter}" if spec.requirement_parameter else ""
    return f"""import StageA.RelationalInterpreterMixedKernelComposition
import StageA.RelationalInterpreterMixedProfile
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterMixedContext
open StageA.Relational.InterpreterMixedEnvironment
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedProfile
open StageA.Relational.InterpreterMixedWorldBridge
open StageA.Relational.InterpreterNativeLaunch
open StageA.Relational.InterpreterNativeWorld

{parameter}def generatedCanonicalMixedRelationProfile :
    CanonicalMixedRelationProfile {terms['original_context']}
      {terms['original_authority']} {terms['original_program']}
      {terms['candidate_program']} {terms['candidate_authority']}
      {terms['program_binding']} {terms['concrete_abi']} {terms['launch']}
      {terms['original_root']} {terms['reachability']} := {{
  core := {terms['relation_core']}
  launchAnchorsComplete := {terms['launch_anchors_complete']}
  externalFrames := {terms['external_frames']}
  launchRealizable := {terms['launch_realizable']}
  launchWrapperRefines := {terms['launch_wrapper_refinements']}
}}

def generatedKernelOperationRefinements :
    forall operation,
      KernelOperationRefinesUsing {terms['compiled_program']}
        {terms['concrete_abi']}.relation
        (combinedKernelDispatchRelation {terms['dispatch_family']}) operation := by
  intro operation
  cases operation with
  | programLookup =>
      exact kernelOperationRefinesUsing_combined {terms['dispatch_family']}
        {terms['program_lookup_refines']}
  | interpreterStep =>
      exact kernelOperationRefinesUsing_combined {terms['dispatch_family']}
        {terms['interpreter_step_refines']}
  | runFunction =>
      exact kernelOperationRefinesUsing_combined {terms['dispatch_family']}
        {terms['run_function_refines']}
  | invokeCall =>
      exact kernelOperationRefinesUsing_combined {terms['dispatch_family']}
        {terms['invoke_call_refines']}

def generatedMixedKernelSourceClassifier :
    MixedKernelSourceClassifier {terms['original_context']}
      {terms['original_authority']} {terms['launch']} {terms['original_root']}
      {terms['reachability']} {terms['candidate_program']}
      {terms['candidate_authority']} {terms['compiled_program']}
      {terms['candidate_root_rva']} {terms['invariant']} := {{
  classify := {terms['classify_source']}
}}

def generatedCheckedMixedKernelComponentCases :
    CheckedMixedKernelComponentCases {terms['original_context']}
      {terms['original_authority']} {terms['original_program']}
      {terms['candidate_program']} {terms['candidate_authority']}
      {terms['relation_core']}.contract
      {terms['launch']} {terms['original_root']} {terms['reachability']}
      {terms['candidate_root_rva']} {terms['compiled_program']}
      {terms['concrete_abi']}.relation
      (combinedKernelDispatchRelation {terms['dispatch_family']})
      {terms['invariant']} := {{
  classifier := generatedMixedKernelSourceClassifier{argument}
  launchChunk := {terms['launch_chunk']}
  semanticChunk := fun originalBefore candidateBefore source operation entryRva
      originalAtSource candidateAtEntry entryExact =>
    {terms['semantic_chunk_factory']} originalBefore candidateBefore source operation
      entryRva originalAtSource candidateAtEntry entryExact
      (generatedKernelOperationRefinements{argument} operation)
  externalOperationChunk := fun originalBefore candidateBefore source operation
      entryRva originalAtSource candidateAtEntry entryExact =>
    {terms['external_operation_chunk_factory']} originalBefore candidateBefore source
      operation entryRva originalAtSource candidateAtEntry entryExact
      (generatedKernelOperationRefinements{argument} operation)
  externalBoundaryChunk := {terms['external_boundary_chunk']}
}}

def generatedMixedWorldChunkComposition :
    MixedWorldChunkComposition {terms['original_context']} {terms['original_authority']}
      {terms['original_program']} {terms['candidate_program']}
      {terms['candidate_authority']} {terms['program_binding']}
      {terms['relation_core']}.contract
      {terms['launch']} {terms['original_root']} {terms['reachability']}
      {terms['candidate_root_rva']} {terms['candidate_root']} :=
  (generatedCheckedMixedKernelComponentCases{argument}).toMixedWorldChunkComposition
    {terms['candidate_launch_calls']} {terms['candidate_launch_calls_exact']}
    {terms['roots_related']}

def generatedSelectedMixedWorldAcceptanceCertificate :
    MixedWorldAcceptanceCertificate {terms['original_context']}
      {terms['original_program']} {terms['candidate_program']}
      {terms['relation_core']}.contract {terms['launch']} := {{
  originalAuthority := {terms['original_authority']}
  candidateAuthority := {terms['candidate_authority']}
  programBinding := {terms['program_binding']}
  originalRoot := {terms['original_root']}
  reachability := {terms['reachability']}
  candidateRootRva := {terms['candidate_root_rva']}
  candidateRoot := {terms['candidate_root']}
  launchRealizable := {terms['launch_realizable']}
  composition := generatedMixedWorldChunkComposition{argument}
}}

def generatedUniversalMixedWorldAcceptanceCertificate :
    CanonicalMixedWorldAcceptanceCertificate {terms['original_context']}
      {terms['original_program']} {terms['candidate_program']}
      {terms['relation_core']}.contract {terms['external_frames']}
      {terms['launch']} := {{
  certificates := fun originalEnvironment candidateEnvironment
      environmentRefines => {{
    originalAuthority := {terms['original_authority']}
    candidateAuthority := exactNativeCandidateAuthorityWithEnvironment
      {terms['candidate_authority']} candidateEnvironment
    programBinding := exactMixedProgramBindingWithProtocolEnvironment
      {terms['program_binding']} originalEnvironment
    originalRoot := {terms['original_root']}
    reachability := {terms['reachability']}
    candidateRootRva := {terms['candidate_root_rva']}
    candidateRoot := directExactCandidateNativeLaunchRootWithEnvironment
      {terms['candidate_root']} candidateEnvironment
    launchRealizable := mixedLaunchRealizableWithEnvironment
      {terms['launch_realizable']} candidateEnvironment
    composition := {terms['environment_compositions']} originalEnvironment
      candidateEnvironment environmentRefines
  }}
}}

theorem generatedMixedWorldProgramsEquivalent :
    CanonicalMixedWorldProgramsChunkObservationallyEquivalent
      (generatedCanonicalMixedRelationProfile{argument}) := by
  intro originalEnvironment candidateEnvironment environmentRefines
  exact canonicalMixedWorldProgramsEquivalent
    (generatedCanonicalMixedRelationProfile{argument})
    (generatedUniversalMixedWorldAcceptanceCertificate{argument})
    originalEnvironment candidateEnvironment environmentRefines

#print axioms generatedCanonicalMixedRelationProfile
#print axioms generatedKernelOperationRefinements
#print axioms generatedCheckedMixedKernelComponentCases
#print axioms generatedMixedWorldChunkComposition
#print axioms generatedSelectedMixedWorldAcceptanceCertificate
#print axioms generatedUniversalMixedWorldAcceptanceCertificate
#print axioms generatedMixedWorldProgramsEquivalent

end {spec.namespace}
"""


def write_relational_interpreter_mixed_kernel_binding(
    out: Path | str,
    plan: InterpreterMixedKernelBindingPlan,
) -> tuple[Path, ...]:
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    plan_path = root / "interpreter-mixed-kernel-binding-plan.json"
    plan_path.write_text(
        json.dumps(plan.to_json(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    stage_a = root / "StageA"
    source_path = stage_a / f"{plan.spec.output_module}.lean"
    if not plan.complete:
        if source_path.exists():
            source_path.unlink()
        return (plan_path,)
    stage_a.mkdir(parents=True, exist_ok=True)
    source_path.write_text(
        relational_interpreter_mixed_kernel_binding_source(plan),
        encoding="utf-8",
    )
    return (source_path, plan_path)


def generate_interpreter_mixed_kernel_binding(
    manifest: Path | str,
    out: Path | str,
) -> InterpreterMixedKernelBindingPlan:
    spec = load_interpreter_mixed_kernel_binding_spec(manifest)
    plan = plan_interpreter_mixed_kernel_binding(spec)
    write_relational_interpreter_mixed_kernel_binding(out, plan)
    return plan


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Generate a fail-closed mixed decoded-original/native-kernel binding"
    )
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--out-dir", type=Path, required=True)
    arguments = parser.parse_args(argv)
    plan = generate_interpreter_mixed_kernel_binding(
        arguments.manifest, arguments.out_dir
    )
    print(json.dumps(plan.to_json(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "INTERPRETER_MIXED_KERNEL_BINDING_FORMAT",
    "INTERPRETER_MIXED_KERNEL_BINDING_MODULE",
    "DiagnosticArtifact",
    "InterpreterMixedKernelBindingGenerationError",
    "InterpreterMixedKernelBindingPlan",
    "InterpreterMixedKernelBindingSpec",
    "REQUIRED_INHABITANTS",
    "generate_interpreter_mixed_kernel_binding",
    "load_interpreter_mixed_kernel_binding_spec",
    "plan_interpreter_mixed_kernel_binding",
    "relational_interpreter_mixed_kernel_binding_source",
    "relational_interpreter_mixed_kernel_requirements_source",
    "write_relational_interpreter_mixed_kernel_binding",
]
