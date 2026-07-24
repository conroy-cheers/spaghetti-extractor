"""Emit the generic checked abstract-operation transition layer.

The Lean layer reconstructs ``AbstractKernelTransition`` from the authoritative
operation-specific semantic derivations.  It never accepts a submitted
transition, response relation, endpoint, status, or report as authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_operation_result_encoding import (
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES,
    INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM,
)


INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FORMAT = (
    "stage-a-relational-interpreter-kernel-abstract-operation-transition-v1"
)
INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_PLAN_FILENAME = (
    "interpreter-kernel-abstract-operation-transition.json"
)
INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelAbstractOperationTransition.lean"
)
INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelAbstractOperationTransition."
    "generatedCheckedAbstractOperationTransition"
)
INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FRONTIER = (
    "checked_abstract_operation_transition_derivation"
)
INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_CLOSED_PREMISES = (
    "exact_abstract_operation_transition",
)
INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_REMAINING_PREMISES = tuple(
    premise
    for premise in INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES
    if premise != "exact_abstract_operation_transition"
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_SUBMITTED_KEYS = frozenset(
    {
        "abstract_kernel_transition",
        "endpoint",
        "final_machine_state",
        "operation_status",
        "report",
        "response",
        "response_related",
        "return_endpoint",
        "status",
        "transition",
    }
)


class RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
    StageAInputError
):
    """The preceding result-encoding plan is stale or unsound."""


@dataclass(frozen=True)
class InterpreterKernelAbstractOperationTransitionPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    operation_result_plan_path: Path
    operation_result_plan_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FORMAT,
            "acceptance_authority": False,
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "candidate": {
                    "path": self.candidate_path.name,
                    "sha256": self.candidate_sha256,
                },
                "operation_result_encoding_plan": {
                    "path": self.operation_result_plan_path.name,
                    "sha256": self.operation_result_plan_sha256,
                },
            },
            "frontier": INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FRONTIER,
            "closed_premise_families": list(
                INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_REMAINING_PREMISES
            ),
            "checked_authority": {
                "derivation": "CheckedAbstractOperationDerivation",
                "transition": (
                    "CheckedAbstractOperationDerivation.toTransition"
                ),
                "operation_result_closure": (
                    "ExactAbstractOperationResultClosure"
                ),
                "cdecl_adapter": (
                    "ExactAbstractOperationResultClosure."
                    "toEnvironmentClosedCDeclEpilogue"
                ),
                "typed_residuals": {
                    "program_lookup": [],
                    "interpreter_step": [],
                    "run_function": ["AbstractRunFunction"],
                    "invoke_external": ["event_kind_external"],
                    "invoke_internal": [
                        "event_kind_internal",
                        "AbstractRunFunction",
                    ],
                    "invoke_indirect": [
                        "event_kind_indirect",
                        "exact_resolver_target",
                        "AbstractRunFunction",
                    ],
                },
            },
            "forbidden_submitted_evidence": sorted(_FORBIDDEN_SUBMITTED_KEYS),
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            f"cannot read {context}: {exc}"
        ) from exc


def _contains_forbidden_submitted_evidence(value: object) -> bool:
    if isinstance(value, Mapping):
        if any(key in _FORBIDDEN_SUBMITTED_KEYS for key in value):
            return True
        return any(
            _contains_forbidden_submitted_evidence(item)
            for item in value.values()
        )
    if isinstance(value, list):
        return any(_contains_forbidden_submitted_evidence(item) for item in value)
    return False


def _validate_operation_result_plan(
    payload: Mapping[str, Any],
    *,
    candidate_sha256: str,
    candidate_size: int,
) -> None:
    candidate = _object(payload.get("candidate"), "operation-result candidate")
    result = _object(payload.get("result"), "operation-result result")
    if (
        payload.get("format") != INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("frontier")
        != INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER
        or payload.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES)
        or result
        != {"theorem": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM}
    ):
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            "operation-result encoding plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            "operation-result encoding candidate is stale"
        )
    if _contains_forbidden_submitted_evidence(payload):
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            "operation-result encoding plan contains submitted transition, "
            "response, endpoint, response relation, report, or status authority"
        )


def build_relational_interpreter_kernel_abstract_operation_transition_plan(
    *,
    candidate_pe: Path | str,
    operation_result_encoding_plan: Path | str,
) -> InterpreterKernelAbstractOperationTransitionPlan:
    candidate_path = Path(candidate_pe)
    result_path = Path(operation_result_encoding_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(result_path, "operation-result encoding plan")
    _validate_operation_result_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelAbstractOperationTransitionPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        operation_result_plan_path=result_path,
        operation_result_plan_sha256=sha256_file(result_path),
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelAbstractOperationTransitionGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_abstract_operation_transition_source(
    plan: InterpreterKernelAbstractOperationTransitionPlan,
    *,
    generated_operation_result_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelOperationResultEncoding"
    ),
) -> str:
    _validate_module(
        generated_operation_result_module,
        "generated operation-result encoding module",
    )
    return f"""import StageA.RelationalInterpreterKernelAbstractOperationTransition
import {generated_operation_result_module}

namespace StageA.GeneratedRelational.InterpreterKernelAbstractOperationTransition

open StageA.Relational.InterpreterKernel
open StageA.Relational.InterpreterKernelAbstractOperationTransition

theorem generatedCheckedAbstractOperationTransition
    (derivation : CheckedAbstractOperationDerivation request response) :
    AbstractKernelTransition request response :=
  derivation.toTransition

#print axioms generatedCheckedAbstractOperationTransition

end StageA.GeneratedRelational.InterpreterKernelAbstractOperationTransition
"""


def write_relational_interpreter_kernel_abstract_operation_transition_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelAbstractOperationTransitionPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = (
        build_relational_interpreter_kernel_abstract_operation_transition_plan(
            **kwargs
        )
    )
    write_json(
        output
        / INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output
        / INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_abstract_operation_transition_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FORMAT",
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_FRONTIER",
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_ABSTRACT_OPERATION_TRANSITION_THEOREM",
    "InterpreterKernelAbstractOperationTransitionPlan",
    "RelationalInterpreterKernelAbstractOperationTransitionGenerationError",
    "build_relational_interpreter_kernel_abstract_operation_transition_plan",
    "relational_interpreter_kernel_abstract_operation_transition_source",
    "write_relational_interpreter_kernel_abstract_operation_transition_bundle",
]
