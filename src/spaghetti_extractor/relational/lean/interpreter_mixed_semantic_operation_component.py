"""Generate the exact semantic-operation component bridge.

The emitted Lean module wires proof-producing terms into
``CheckedMixedSemanticOperationEvidence`` and retains the corresponding
``MixedSemanticKernelOperationComponentCertificate``. Python never supplies a
request, path, endpoint, event list, or invariant-preservation assertion.
The checked evidence must include the exact computed original replay, its
one-step or direct-call/return shape, and its semantic-result endpoint proof.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from ...errors import StageAInputError


INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_FORMAT = (
    "stage-a-relational-interpreter-mixed-semantic-operation-component-plan-v1"
)
INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE = (
    "GeneratedRelationalInterpreterMixedSemanticOperationComponent"
)
INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_PLAN_FILENAME = (
    "interpreter-mixed-semantic-operation-component.json"
)

_LEAN_IDENTIFIER = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LEAN_LOCAL_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_STAGE_A_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_NAME_PARTS = frozenset(
    {
        "admit",
        "axiom",
        "by",
        "def",
        "else",
        "end",
        "import",
        "in",
        "inductive",
        "instance",
        "native_decide",
        "opaque",
        "partial",
        "sorry",
        "structure",
        "theorem",
        "then",
        "unsafe",
        "where",
        "with",
    }
)


class InterpreterMixedSemanticOperationComponentGenerationError(StageAInputError):
    """A requested module, namespace, or Lean term is malformed."""


@dataclass(frozen=True)
class MixedSemanticOperationComponentTerms:
    """Canonical Lean terms consumed by the generated bridge."""

    original_context: str
    original_authority: str
    launch: str
    original_root: str
    reachability: str
    original_program: str
    candidate: str
    candidate_authority: str
    relation_contract: str
    invariant: str
    compiled_program: str
    kernel_abi: str
    kernel_dispatches: str
    classifier: str
    source_binding_factory: str
    semantic_evidence_factory: str
    external_operation_evidence_factory: str


@dataclass(frozen=True)
class InterpreterMixedSemanticOperationComponentSpec:
    """Names needed to emit the retaining component and acceptance factories."""

    binding_module: str
    namespace: str
    terms: MixedSemanticOperationComponentTerms
    parameter_name: str | None = None
    parameter_type: str | None = None
    output_module: str = INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_MODULE

    def validate(self) -> None:
        if _STAGE_A_MODULE.fullmatch(self.binding_module) is None:
            raise InterpreterMixedSemanticOperationComponentGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if not _valid_identifier(self.namespace):
            raise InterpreterMixedSemanticOperationComponentGenerationError(
                "namespace must be a canonical Lean namespace"
            )
        if not _valid_local_name(self.output_module):
            raise InterpreterMixedSemanticOperationComponentGenerationError(
                "output_module must be a canonical Lean module name"
            )
        if (self.parameter_name is None) != (self.parameter_type is None):
            raise InterpreterMixedSemanticOperationComponentGenerationError(
                "parameter_name and parameter_type must be supplied together"
            )
        if self.parameter_name is not None:
            if not _valid_local_name(self.parameter_name):
                raise InterpreterMixedSemanticOperationComponentGenerationError(
                    "parameter_name must be a canonical Lean local name"
                )
            if not _valid_identifier(self.parameter_type or ""):
                raise InterpreterMixedSemanticOperationComponentGenerationError(
                    "parameter_type must be a canonical Lean identifier"
                )
        for field in fields(self.terms):
            value = getattr(self.terms, field.name)
            if not _valid_identifier(value):
                raise InterpreterMixedSemanticOperationComponentGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


@dataclass(frozen=True)
class InterpreterMixedSemanticOperationComponentPlan:
    """Non-authoritative description of the emitted Lean wiring."""

    spec: InterpreterMixedSemanticOperationComponentSpec

    def payload(self) -> dict[str, Any]:
        self.spec.validate()
        parameter: dict[str, str] | None = None
        if self.spec.parameter_name is not None:
            parameter = {
                "name": self.spec.parameter_name,
                "type": self.spec.parameter_type or "",
            }
        return {
            "format": INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_FORMAT,
            "acceptance_authority": False,
            "scope": "exact-original-semantic-checked-kernel-operation-bridge",
            "lean": {
                "binding_module": self.spec.binding_module,
                "module": self.spec.output_module,
                "namespace": self.spec.namespace,
                "parameter": parameter,
                "retaining_definitions": [
                    "generatedMixedSemanticOperationComponent",
                    "generatedMixedExternalOperationComponent",
                ],
                "acceptance_projections": [
                    "generatedSemanticChunkFactory",
                    "generatedExternalOperationChunkFactory",
                ],
            },
            "checked_inputs": {
                field.name: getattr(self.spec.terms, field.name)
                for field in fields(self.spec.terms)
            },
            "residual_evidence": [
                "exact source record to normalized transfer binding",
                "classifier-indexed canonical abstract request and transition",
                "ABI request relation derived at the exact before state",
                (
                    "computed original replay with one-step or exact "
                    "direct-call-return shape"
                ),
                "checked semantic result at the computed original endpoint",
                "selected dispatch to computed candidate replay",
                "related observations and invariant at computed endpoints",
            ],
        }


def build_mixed_semantic_operation_component_plan(
    spec: InterpreterMixedSemanticOperationComponentSpec,
) -> InterpreterMixedSemanticOperationComponentPlan:
    spec.validate()
    return InterpreterMixedSemanticOperationComponentPlan(spec)


def relational_interpreter_mixed_semantic_operation_component_source(
    plan: InterpreterMixedSemanticOperationComponentPlan,
) -> str:
    spec = plan.spec
    spec.validate()
    terms = spec.terms
    parameter = _parameter_binder(spec)
    argument = _parameter_argument(spec)
    type_arguments = _type_arguments(terms)
    source_arguments = _source_arguments(terms)
    classifier = terms.classifier
    invariant = terms.invariant

    return f"""import StageA.RelationalInterpreterMixedSemanticOperationComponent
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational
open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterMixedKernelComposition
open StageA.Relational.InterpreterMixedSemanticOperationComponent

abbrev GeneratedExactSemanticSource{parameter} :=
  ExactOriginalSemanticSource {source_arguments}

abbrev GeneratedExactSemanticTransferBinding{parameter}
    (source : GeneratedExactSemanticSource{argument}) :=
  ExactOriginalSemanticTransferBinding {source_arguments} source

def GeneratedSemanticOperationEvidenceFactory{parameter} : Type :=
  forall originalBefore candidateBefore
      (source : GeneratedExactSemanticSource{argument})
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated :
        {invariant}.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtTargetId source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entryRva candidateBefore)
      (entryExact :
        {terms.compiled_program}.functionEntry? operation.role = some entryRva)
      (classified :
        {classifier}.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .semanticTransfer source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    CheckedMixedSemanticOperationEvidence {terms.original_program}
      {terms.candidate} {terms.candidate_authority}
      {terms.relation_contract} {invariant} {terms.compiled_program}
      {terms.kernel_abi} {terms.kernel_dispatches}
      source.source.target.rva source.record operation entryRva originalBefore
      candidateBefore
      ({classifier}.classifier.classify originalBefore candidateBefore
          beforeRelated =
        .semanticTransfer source operation entryRva originalAtSource
          candidateAtEntry entryExact)
      beforeRelated classified

def GeneratedExternalOperationEvidenceFactory{parameter} : Type :=
  forall originalBefore candidateBefore
      (source : GeneratedExactSemanticSource{argument})
      (operation : KernelOperation) (entryRva : Nat)
      (beforeRelated :
        {invariant}.holds originalBefore candidateBefore)
      (originalAtSource :
        originalExecutionAtBoundarySource source.targetId originalBefore)
      (candidateAtEntry :
        nativeExecutionAtRva entryRva candidateBefore)
      (entryExact :
        {terms.compiled_program}.functionEntry? operation.role = some entryRva)
      (classified :
        {classifier}.classifier.classify originalBefore candidateBefore
            beforeRelated =
          .externalOperation source operation entryRva originalAtSource
            candidateAtEntry entryExact),
    CheckedMixedSemanticOperationEvidence {terms.original_program}
      {terms.candidate} {terms.candidate_authority}
      {terms.relation_contract} {invariant} {terms.compiled_program}
      {terms.kernel_abi} {terms.kernel_dispatches}
      source.source.target.rva source.record operation entryRva originalBefore
      candidateBefore
      ({classifier}.classifier.classify originalBefore candidateBefore
          beforeRelated =
        .externalOperation source operation entryRva originalAtSource
          candidateAtEntry entryExact)
      beforeRelated classified

noncomputable def generatedMixedSemanticOperationComponent{parameter}
    (originalBefore candidateBefore)
    (source : GeneratedExactSemanticSource{argument})
    (operation : KernelOperation) (entryRva : Nat)
    (beforeRelated : {invariant}.holds originalBefore candidateBefore)
    (originalAtSource :
      originalExecutionAtTargetId source.targetId originalBefore)
    (candidateAtEntry :
      nativeExecutionAtRva entryRva candidateBefore)
    (entryExact :
      {terms.compiled_program}.functionEntry? operation.role = some entryRva)
    (classified :
      {classifier}.classifier.classify originalBefore candidateBefore
          beforeRelated =
        .semanticTransfer source operation entryRva originalAtSource
          candidateAtEntry entryExact)
    (operationRefines :
      KernelOperationRefinesUsing {terms.compiled_program} {terms.kernel_abi}
        {terms.kernel_dispatches} operation) :
    MixedSemanticKernelOperationComponentCertificate {type_arguments}
      source ({terms.source_binding_factory} source) operation entryRva
      originalBefore candidateBefore :=
  ({terms.semantic_evidence_factory} originalBefore candidateBefore source
    operation entryRva beforeRelated originalAtSource candidateAtEntry entryExact
    classified).toComponentCertificate
      ({terms.source_binding_factory} source) entryExact operationRefines

noncomputable def generatedMixedExternalOperationComponent{parameter}
    (originalBefore candidateBefore)
    (source : GeneratedExactSemanticSource{argument})
    (operation : KernelOperation) (entryRva : Nat)
    (beforeRelated : {invariant}.holds originalBefore candidateBefore)
    (originalAtSource :
      originalExecutionAtBoundarySource source.targetId originalBefore)
    (candidateAtEntry :
      nativeExecutionAtRva entryRva candidateBefore)
    (entryExact :
      {terms.compiled_program}.functionEntry? operation.role = some entryRva)
    (classified :
      {classifier}.classifier.classify originalBefore candidateBefore
          beforeRelated =
        .externalOperation source operation entryRva originalAtSource
          candidateAtEntry entryExact)
    (operationRefines :
      KernelOperationRefinesUsing {terms.compiled_program} {terms.kernel_abi}
        {terms.kernel_dispatches} operation) :
    MixedSemanticKernelOperationComponentCertificate {type_arguments}
      source ({terms.source_binding_factory} source) operation entryRva
      originalBefore candidateBefore :=
  ({terms.external_operation_evidence_factory} originalBefore candidateBefore
    source operation entryRva beforeRelated originalAtSource candidateAtEntry
    entryExact classified).toComponentCertificate
      ({terms.source_binding_factory} source) entryExact operationRefines

noncomputable def generatedSemanticChunkFactory{parameter} :=
  fun originalBefore candidateBefore source operation entryRva beforeRelated
      originalAtSource candidateAtEntry entryExact classified operationRefines =>
    MixedSemanticKernelOperationComponentCertificate.toMixedKernelOperationComponentCertificate
      (generatedMixedSemanticOperationComponent{argument} originalBefore
        candidateBefore source operation entryRva beforeRelated originalAtSource
        candidateAtEntry entryExact classified operationRefines)

noncomputable def generatedExternalOperationChunkFactory{parameter} :=
  fun originalBefore candidateBefore source operation entryRva beforeRelated
      originalAtSource candidateAtEntry entryExact classified operationRefines =>
    MixedSemanticKernelOperationComponentCertificate.toMixedKernelOperationComponentCertificate
      (generatedMixedExternalOperationComponent{argument} originalBefore
        candidateBefore source operation entryRva beforeRelated originalAtSource
        candidateAtEntry entryExact classified operationRefines)

#print axioms generatedMixedSemanticOperationComponent
#print axioms generatedMixedExternalOperationComponent
#print axioms generatedSemanticChunkFactory
#print axioms generatedExternalOperationChunkFactory

end {spec.namespace}
"""


def write_mixed_semantic_operation_component_bundle(
    out: Path | str,
    plan: InterpreterMixedSemanticOperationComponentPlan,
) -> tuple[Path, Path]:
    root = Path(out)
    root.mkdir(parents=True, exist_ok=True)
    plan_path = (
        root / INTERPRETER_MIXED_SEMANTIC_OPERATION_COMPONENT_PLAN_FILENAME
    )
    lean_path = root / f"{plan.spec.output_module}.lean"
    plan_path.write_text(
        json.dumps(plan.payload(), indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    lean_path.write_text(
        relational_interpreter_mixed_semantic_operation_component_source(plan),
        encoding="utf-8",
    )
    return plan_path, lean_path


def _parameter_binder(
    spec: InterpreterMixedSemanticOperationComponentSpec,
) -> str:
    if spec.parameter_name is None:
        return ""
    return f" ({spec.parameter_name} : {spec.parameter_type})"


def _parameter_argument(
    spec: InterpreterMixedSemanticOperationComponentSpec,
) -> str:
    if spec.parameter_name is None:
        return ""
    return f" {spec.parameter_name}"


def _source_arguments(terms: MixedSemanticOperationComponentTerms) -> str:
    return (
        f"{terms.original_context} {terms.original_authority} {terms.launch} "
        f"{terms.original_root} {terms.reachability} {terms.candidate} "
        f"{terms.candidate_authority}"
    )


def _type_arguments(terms: MixedSemanticOperationComponentTerms) -> str:
    return (
        f"{terms.original_context} {terms.original_authority} {terms.launch} "
        f"{terms.original_root} {terms.reachability} {terms.original_program} "
        f"{terms.candidate} {terms.candidate_authority} "
        f"{terms.relation_contract} {terms.invariant} {terms.compiled_program} "
        f"{terms.kernel_abi} {terms.kernel_dispatches}"
    )


def _valid_identifier(value: str) -> bool:
    if _LEAN_IDENTIFIER.fullmatch(value) is None:
        return False
    return all(part not in _FORBIDDEN_NAME_PARTS for part in value.split("."))


def _valid_local_name(value: str) -> bool:
    return (
        _LEAN_LOCAL_NAME.fullmatch(value) is not None
        and value not in _FORBIDDEN_NAME_PARTS
    )
