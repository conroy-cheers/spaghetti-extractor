"""Generate checked exact-original semantic source coverage.

This module only binds already generated Lean values to
``ExactOriginalSemanticSourceCoverage``.  Python does not decide whether the
coverage holds: the emitted ``checked`` field is reduced by Lean with
``by decide +kernel``.  The companion JSON artifact is a non-acceptance plan
and cannot authorize whole-program equivalence.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, fields
from pathlib import Path
from typing import Any

from ...errors import StageAInputError
from ...util import write_json


INTERPRETER_MIXED_SOURCE_COVERAGE_FORMAT = (
    "stage-a-relational-interpreter-mixed-source-coverage-plan-v1"
)
INTERPRETER_MIXED_SOURCE_COVERAGE_MODULE = (
    "GeneratedRelationalInterpreterMixedSourceCoverage"
)
INTERPRETER_MIXED_SOURCE_COVERAGE_LEAN_FILENAME = (
    f"{INTERPRETER_MIXED_SOURCE_COVERAGE_MODULE}.lean"
)
INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME = (
    "interpreter-mixed-source-coverage.json"
)
INTERPRETER_MIXED_SOURCE_COVERAGE_DEFINITION = (
    "generatedExactOriginalSemanticSourceCoverage"
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
        "let",
        "match",
        "namespace",
        "native_decide",
        "opaque",
        "partial",
        "protected",
        "sorry",
        "structure",
        "theorem",
        "then",
        "unsafe",
        "where",
        "with",
    }
)


class InterpreterMixedSourceCoverageGenerationError(StageAInputError):
    """A requested module, namespace, parameter, or Lean term is malformed."""


@dataclass(frozen=True)
class InterpreterMixedSourceCoverageSpec:
    """Canonical Lean names needed to construct source coverage."""

    binding_module: str
    namespace: str
    parameter_name: str
    parameter_type: str
    context: str
    authority: str
    launch: str
    root: str
    reachability: str
    candidate: str
    candidate_authority: str
    candidate_source_rvas: str
    candidate_source_rvas_exact: str
    coverage_name: str = INTERPRETER_MIXED_SOURCE_COVERAGE_DEFINITION
    output_module: str = INTERPRETER_MIXED_SOURCE_COVERAGE_MODULE

    def validate(self) -> None:
        if not _valid_stage_a_module(self.binding_module):
            raise InterpreterMixedSourceCoverageGenerationError(
                "binding_module must be a canonical StageA module"
            )
        if not _valid_identifier(self.namespace):
            raise InterpreterMixedSourceCoverageGenerationError(
                "namespace must be a canonical Lean namespace"
            )
        if not _valid_local_name(self.parameter_name):
            raise InterpreterMixedSourceCoverageGenerationError(
                "parameter_name must be a canonical Lean local name"
            )
        if not _valid_identifier(self.parameter_type):
            raise InterpreterMixedSourceCoverageGenerationError(
                "parameter_type must be a canonical Lean identifier"
            )
        if not _valid_local_name(self.coverage_name):
            raise InterpreterMixedSourceCoverageGenerationError(
                "coverage_name must be a canonical Lean local name"
            )
        if not _valid_local_name(self.output_module):
            raise InterpreterMixedSourceCoverageGenerationError(
                "output_module must be a canonical Lean module name"
            )

        metadata_names = {
            "binding_module",
            "namespace",
            "parameter_name",
            "parameter_type",
            "coverage_name",
            "output_module",
        }
        for field in fields(self):
            if field.name in metadata_names:
                continue
            if not _valid_identifier(getattr(self, field.name)):
                raise InterpreterMixedSourceCoverageGenerationError(
                    f"{field.name} must be a canonical Lean identifier"
                )


@dataclass(frozen=True)
class InterpreterMixedSourceCoveragePlan:
    """Non-authoritative description of one generated Lean coverage binding."""

    spec: InterpreterMixedSourceCoverageSpec

    @property
    def definition(self) -> str:
        return f"{self.spec.namespace}.{self.spec.coverage_name}"

    def payload(self) -> dict[str, Any]:
        self.spec.validate()
        return {
            "format": INTERPRETER_MIXED_SOURCE_COVERAGE_FORMAT,
            "acceptance_authority": False,
            "scope": "exact-original-semantic-source-coverage",
            "lean": {
                "binding_module": self.spec.binding_module,
                "module": self.spec.output_module,
                "namespace": self.spec.namespace,
                "parameter": {
                    "name": self.spec.parameter_name,
                    "type": self.spec.parameter_type,
                },
                "definition": self.definition,
            },
            "terms": {
                "context": self.spec.context,
                "authority": self.spec.authority,
                "launch": self.spec.launch,
                "root": self.spec.root,
                "reachability": self.spec.reachability,
                "candidate": self.spec.candidate,
                "candidate_authority": self.spec.candidate_authority,
                "candidate_source_rvas": self.spec.candidate_source_rvas,
                "candidate_source_rvas_exact": (
                    self.spec.candidate_source_rvas_exact
                ),
            },
            "checked_authority": {
                "structure": "ExactOriginalSemanticSourceCoverage",
                "coverage_predicate": (
                    "exactOriginalSemanticSourceCoverageChecked"
                ),
                "candidate_source_rvas_equality": (
                    self.spec.candidate_source_rvas_exact
                ),
                "checked_field": "by decide +kernel",
            },
            "remaining_proof_premises": [
                "constructive_source_classification",
                "source_indexed_local_semantics",
                "mixed_component_composition",
                "whole_program_acceptance",
            ],
            "result": {"definition": self.definition},
            "failure_mode": "incomplete",
        }


def _valid_identifier(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LEAN_IDENTIFIER.fullmatch(value) is not None
        and all(part not in _FORBIDDEN_NAME_PARTS for part in value.split("."))
    )


def _valid_local_name(value: object) -> bool:
    return (
        isinstance(value, str)
        and _LEAN_LOCAL_NAME.fullmatch(value) is not None
        and value not in _FORBIDDEN_NAME_PARTS
    )


def _valid_stage_a_module(value: object) -> bool:
    return (
        isinstance(value, str)
        and _STAGE_A_MODULE.fullmatch(value) is not None
        and all(part not in _FORBIDDEN_NAME_PARTS for part in value.split("."))
    )


def build_interpreter_mixed_source_coverage_plan(
    spec: InterpreterMixedSourceCoverageSpec,
) -> InterpreterMixedSourceCoveragePlan:
    """Validate the requested Lean binding and build its non-acceptance plan."""

    spec.validate()
    return InterpreterMixedSourceCoveragePlan(spec)


def relational_interpreter_mixed_source_coverage_source(
    plan: InterpreterMixedSourceCoveragePlan,
) -> str:
    """Emit the Lean-checked source coverage definition."""

    plan.spec.validate()
    spec = plan.spec
    return f"""import StageA.RelationalInterpreterMixedConstructiveSourceClassifier
import {spec.binding_module}

namespace {spec.namespace}

open StageA.Relational.InterpreterMixedConstructiveSourceClassifier

variable ({spec.parameter_name} : {spec.parameter_type})

def {spec.coverage_name} :
    ExactOriginalSemanticSourceCoverage {spec.context} {spec.authority}
      {spec.launch} {spec.root} {spec.reachability} {spec.candidate}
      {spec.candidate_authority} := {{
  candidateSourceRvas := {spec.candidate_source_rvas}
  candidateSourceRvasExact := {spec.candidate_source_rvas_exact}
  checked := by decide +kernel
}}

#print axioms {spec.coverage_name}

end {spec.namespace}
"""


def write_interpreter_mixed_source_coverage_bundle(
    *,
    out: Path | str,
    spec: InterpreterMixedSourceCoverageSpec,
) -> InterpreterMixedSourceCoveragePlan:
    """Write a deterministic non-acceptance plan and generated Lean source."""

    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_interpreter_mixed_source_coverage_plan(spec)
    write_json(
        output / INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME,
        plan.payload(),
    )
    (output / f"{spec.output_module}.lean").write_text(
        relational_interpreter_mixed_source_coverage_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_MIXED_SOURCE_COVERAGE_DEFINITION",
    "INTERPRETER_MIXED_SOURCE_COVERAGE_FORMAT",
    "INTERPRETER_MIXED_SOURCE_COVERAGE_LEAN_FILENAME",
    "INTERPRETER_MIXED_SOURCE_COVERAGE_MODULE",
    "INTERPRETER_MIXED_SOURCE_COVERAGE_PLAN_FILENAME",
    "InterpreterMixedSourceCoverageGenerationError",
    "InterpreterMixedSourceCoveragePlan",
    "InterpreterMixedSourceCoverageSpec",
    "build_interpreter_mixed_source_coverage_plan",
    "relational_interpreter_mixed_source_coverage_source",
    "write_interpreter_mixed_source_coverage_bundle",
]
