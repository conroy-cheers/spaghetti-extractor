"""Emit checked operation-result and external-trace payload bindings.

This layer consumes the static-preservation plan and exposes the generic Lean
certificate that constructs ``ResponsePayloadHolds`` from case-specific exact
operation-result evidence and checked one-to-one external responses.  It does
not accept an endpoint, response relation, payload proposition, or report
status as evidence.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_cdecl_epilogue_static_preservation import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM,
)


INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT = (
    "stage-a-relational-interpreter-kernel-cdecl-epilogue-external-payload-v1"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME = (
    "interpreter-kernel-cdecl-epilogue-external-payload.json"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelCdeclEpilogueExternalPayload.lean"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueExternalPayload."
    "generatedKernelCDeclExternalPayloadBindings"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER = (
    "cdecl_epilogue_checked_operation_result_and_external_trace"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES = (
    "environmental_typed_response_payload",
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES = (
    "exact_abstract_operation_transition",
    "exact_operation_result_encoding",
    "checked_one_to_one_external_response_trace",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "endpoint",
        "environmental_payload",
        "final_machine_state",
        "operation_status",
        "response_payload",
        "response_payload_holds",
        "response_related",
        "return_endpoint",
        "status",
    }
)


class RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
    StageAInputError
):
    """The upstream static-preservation plan is stale or unsafe."""


@dataclass(frozen=True)
class InterpreterKernelCDeclEpilogueExternalPayloadPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    static_preservation_plan_path: Path
    static_preservation_plan_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT,
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
                "static_preservation_plan": {
                    "path": self.static_preservation_plan_path.name,
                    "sha256": self.static_preservation_plan_sha256,
                },
            },
            "frontier": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER,
            "closed_premise_families": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES
            ),
            "checked_authority": {
                "operation_result": "CheckedOperationResultEvidence",
                "external_response": "CheckedOneToOneKernelExternalResponse",
                "external_trace": "CheckedResponseExternalTrace",
                "constructor": ("EnvironmentClosedCDeclEpilogueCertificate.toChecked"),
            },
            "forbidden_submitted_evidence": sorted(_FORBIDDEN_EVIDENCE_KEYS),
            "result": {
                "theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            f"cannot read {context}: {exc}"
        ) from exc


def _contains_forbidden_evidence(value: object) -> bool:
    if isinstance(value, Mapping):
        if any(key in _FORBIDDEN_EVIDENCE_KEYS for key in value):
            return True
        return any(_contains_forbidden_evidence(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_evidence(item) for item in value)
    return False


def _validate_upstream_plan(
    payload: Mapping[str, Any],
    *,
    candidate_sha256: str,
    candidate_size: int,
) -> None:
    candidate = _object(payload.get("candidate"), "static preservation candidate")
    result = _object(payload.get("result"), "static preservation result")
    if (
        payload.get("format")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("frontier")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER
        or payload.get("remaining_proof_premises")
        != list(
            INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES
        )
        or result
        != {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM}
    ):
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            "cdecl static-preservation plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            "cdecl static-preservation candidate is stale"
        )
    if _contains_forbidden_evidence(payload):
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            "cdecl static-preservation plan contains submitted endpoint, "
            "payload, response relation, or status evidence"
        )


def build_relational_interpreter_kernel_cdecl_epilogue_external_payload_plan(
    *,
    candidate_pe: Path | str,
    static_preservation_plan: Path | str,
) -> InterpreterKernelCDeclEpilogueExternalPayloadPlan:
    candidate_path = Path(candidate_pe)
    static_path = Path(static_preservation_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(static_path, "cdecl static-preservation plan")
    _validate_upstream_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelCDeclEpilogueExternalPayloadPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        static_preservation_plan_path=static_path,
        static_preservation_plan_sha256=sha256_file(static_path),
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_cdecl_epilogue_external_payload_source(
    plan: InterpreterKernelCDeclEpilogueExternalPayloadPlan,
    *,
    generated_static_preservation_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation"
    ),
) -> str:
    _validate_module(
        generated_static_preservation_module,
        "generated cdecl static-preservation module",
    )
    return f"""import StageA.RelationalInterpreterKernelCdeclEpilogueExternalPayload
import {generated_static_preservation_module}

namespace StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueExternalPayload

open StageA.Relational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue

abbrev GeneratedInterpreterStepCDeclExternalPayloadCertificate
    (environment : NativeWorldEnvironment) :=
  EnvironmentClosedCDeclEpilogueCertificate
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedInterpreterStepCDeclEpilogueStatic environment)

abbrev GeneratedRunFunctionCDeclExternalPayloadCertificate
    (environment : NativeWorldEnvironment) :=
  EnvironmentClosedCDeclEpilogueCertificate
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionCDeclEpilogueStatic environment)

abbrev GeneratedCDeclOperationResultEvidence :=
  CheckedOperationResultEvidence generatedConcreteInterpreterKernelABI

abbrev GeneratedCDeclExternalTraceEvidence :=
  CheckedResponseExternalTrace

theorem generatedKernelCDeclExternalPayloadBindings
    (environment : NativeWorldEnvironment) :=
  generatedKernelCDeclEpiloguesChecked environment

#print axioms generatedKernelCDeclExternalPayloadBindings

end StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueExternalPayload
"""


def write_relational_interpreter_kernel_cdecl_epilogue_external_payload_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelCDeclEpilogueExternalPayloadPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_cdecl_epilogue_external_payload_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_cdecl_epilogue_external_payload_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_PLAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM",
    "InterpreterKernelCDeclEpilogueExternalPayloadPlan",
    "RelationalInterpreterKernelCDeclEpilogueExternalPayloadGenerationError",
    "build_relational_interpreter_kernel_cdecl_epilogue_external_payload_plan",
    "relational_interpreter_kernel_cdecl_epilogue_external_payload_source",
    "write_relational_interpreter_kernel_cdecl_epilogue_external_payload_bundle",
]
