"""Emit generic exact-endpoint operation-result encoding bindings.

The Lean layer closes ``programLookup`` directly from its exact native return
certificate.  InterpreterStep, RunFunction, and InvokeCall retain only the
register/workspace facts that their exact executor endpoints do not currently
establish.  This planner carries those typed residuals without accepting a
submitted endpoint, ABI response relation, report, or status.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_cdecl_epilogue_external_payload import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM,
)


INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT = (
    "stage-a-relational-interpreter-kernel-operation-result-encoding-v1"
)
INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_PLAN_FILENAME = (
    "interpreter-kernel-operation-result-encoding.json"
)
INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelOperationResultEncoding.lean"
)
INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelOperationResultEncoding."
    "generatedInterpreterStepOperationResultEvidence"
)
INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER = (
    "exact_executor_endpoint_operation_result_encoding"
)
INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_CLOSED_PREMISES = (
    "program_lookup_exact_operation_result_encoding",
    "endpoint_indexed_operation_result_evidence_construction",
)
INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES = (
    "exact_abstract_operation_transition",
    "interpreter_step_exact_result_words_and_engine_state",
    "run_function_exact_status_and_output_engine_state",
    "invoke_call_exact_status_and_output_engine_state",
    "checked_one_to_one_external_response_trace",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_SUBMITTED_KEYS = frozenset(
    {
        "endpoint",
        "final_machine_state",
        "operation_status",
        "report",
        "response_related",
        "return_endpoint",
        "status",
    }
)


class RelationalInterpreterKernelOperationResultEncodingGenerationError(
    StageAInputError
):
    """The external-payload plan is stale or contains unsupported authority."""


@dataclass(frozen=True)
class InterpreterKernelOperationResultEncodingPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    external_payload_plan_path: Path
    external_payload_plan_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT,
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
                "external_payload_plan": {
                    "path": self.external_payload_plan_path.name,
                    "sha256": self.external_payload_plan_sha256,
                },
            },
            "frontier": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER,
            "closed_premise_families": list(
                INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES
            ),
            "checked_authority": {
                "program_lookup": (
                    "ProgramLookupNativeReturnState."
                    "toCheckedOperationResultEvidence"
                ),
                "interpreter_step_residual": (
                    "InterpreterStepResultEncodingResidual"
                ),
                "call_result_residual": "CallResultEncodingResidual",
                "exact_endpoint_adapters": [
                    "InterpreterStepNativeEpiloguePhase",
                    "RunFunctionNativeEpiloguePhase",
                    "InvokeCallNativeArmExecution",
                    "InvokeCallNativeExternalHelperArmExecution",
                    "InvokeCallNativeIndirectArmExecution",
                ],
            },
            "forbidden_submitted_evidence": sorted(_FORBIDDEN_SUBMITTED_KEYS),
            "result": {
                "theorem": INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
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


def _validate_external_payload_plan(
    payload: Mapping[str, Any],
    *,
    candidate_sha256: str,
    candidate_size: int,
) -> None:
    candidate = _object(payload.get("candidate"), "external-payload candidate")
    result = _object(payload.get("result"), "external-payload result")
    if (
        payload.get("format")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("frontier")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER
        or payload.get("remaining_proof_premises")
        != list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
        )
        or result
        != {
            "theorem": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM
            )
        }
    ):
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
            "external-payload plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
            "external-payload candidate is stale"
        )
    if _contains_forbidden_submitted_evidence(payload):
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
            "external-payload plan contains submitted endpoint, response "
            "relation, report, or status authority"
        )


def build_relational_interpreter_kernel_operation_result_encoding_plan(
    *,
    candidate_pe: Path | str,
    external_payload_plan: Path | str,
) -> InterpreterKernelOperationResultEncodingPlan:
    candidate_path = Path(candidate_pe)
    external_path = Path(external_payload_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(external_path, "cdecl external-payload plan")
    _validate_external_payload_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelOperationResultEncodingPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        external_payload_plan_path=external_path,
        external_payload_plan_sha256=sha256_file(external_path),
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelOperationResultEncodingGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_operation_result_encoding_source(
    plan: InterpreterKernelOperationResultEncodingPlan,
    *,
    generated_external_payload_module: str = (
        "StageA.GeneratedRelational"
        "InterpreterKernelCdeclEpilogueExternalPayload"
    ),
) -> str:
    _validate_module(
        generated_external_payload_module,
        "generated cdecl external-payload module",
    )
    return f"""import StageA.RelationalInterpreterKernelOperationResultEncoding
import {generated_external_payload_module}

namespace StageA.GeneratedRelational.InterpreterKernelOperationResultEncoding

open StageA.Formal StageA.Relational
open StageA.Relational.Interpreter
open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterKernelOperationResultEncoding
open StageA.GeneratedRelational.InterpreterKernelABI

abbrev GeneratedInterpreterStepResultEncodingResidual :=
  InterpreterStepResultEncodingResidual generatedConcreteInterpreterKernelABI

abbrev GeneratedCallResultEncodingResidual :=
  CallResultEncodingResidual generatedConcreteInterpreterKernelABI

theorem generatedInterpreterStepOperationResultEvidence
    (residual :
      GeneratedInterpreterStepResultEncodingResidual sourceRva result state)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (logical : InterpreterMachine) :
    CheckedOperationResultEvidence generatedConcreteInterpreterKernelABI
      (.interpreterStep requestRecords environment sourceRva logical)
      (.interpreterStep result) state :=
  residual.toCheckedOperationResultEvidence requestRecords environment logical

theorem generatedRunFunctionOperationResultEvidence
    (residual :
      GeneratedCallResultEncodingResidual sourceRva result state)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine) :
    CheckedOperationResultEvidence generatedConcreteInterpreterKernelABI
      (.runFunction requestRecords environment resolveCodeTarget sourceRva logical)
      (.call result) state :=
  residual.toRunFunctionEvidence requestRecords environment resolveCodeTarget
    logical

theorem generatedInvokeCallOperationResultEvidence
    (residual :
      GeneratedCallResultEncodingResidual event.targetRva.toNat result state)
    (requestRecords : List ProgramRecord)
    (environment : StageA.Relational.Interpreter.Environment)
    (resolveCodeTarget : Word -> Option Nat) (logical : InterpreterMachine) :
    CheckedOperationResultEvidence generatedConcreteInterpreterKernelABI
      (.invokeCall requestRecords environment resolveCodeTarget event logical)
      (.call result) state :=
  residual.toInvokeCallEvidence requestRecords environment resolveCodeTarget
    logical

#print axioms generatedInterpreterStepOperationResultEvidence
#print axioms generatedRunFunctionOperationResultEvidence
#print axioms generatedInvokeCallOperationResultEvidence

end StageA.GeneratedRelational.InterpreterKernelOperationResultEncoding
"""


def write_relational_interpreter_kernel_operation_result_encoding_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelOperationResultEncodingPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_operation_result_encoding_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_operation_result_encoding_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FORMAT",
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_FRONTIER",
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_LEAN_FILENAME",
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_PLAN_FILENAME",
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_OPERATION_RESULT_ENCODING_THEOREM",
    "InterpreterKernelOperationResultEncodingPlan",
    "RelationalInterpreterKernelOperationResultEncodingGenerationError",
    "build_relational_interpreter_kernel_operation_result_encoding_plan",
    "relational_interpreter_kernel_operation_result_encoding_source",
    "write_relational_interpreter_kernel_operation_result_encoding_bundle",
]
