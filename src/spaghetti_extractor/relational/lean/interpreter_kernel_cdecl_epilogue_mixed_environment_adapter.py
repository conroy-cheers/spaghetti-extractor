"""Emit the mixed-environment to cdecl response adapter interface.

The generated interface records the exact dependent residual between the
whole-program mixed environment and the cdecl response payload proof.  It does
not submit a response, endpoint, verdict, or proof status.
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


INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FORMAT = (
    "stage-a-relational-interpreter-kernel-cdecl-epilogue-"
    "mixed-environment-adapter-v1"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_PLAN_FILENAME = (
    "interpreter-kernel-cdecl-epilogue-mixed-environment-adapter.json"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelCdeclEpilogueMixedEnvironmentAdapter.lean"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_THEOREM = (
    "StageA.GeneratedRelational."
    "InterpreterKernelCdeclEpilogueMixedEnvironmentAdapter."
    "generatedMixedEnvironmentCDeclAdapterBindings"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FRONTIER = (
    "cdecl_epilogue_mixed_environment_response_adapter"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_CLOSED_PREMISES = (
    "native_return_from_exact_mixed_environment",
    "mixed_returned_world_and_state_relation",
    "singleton_checked_external_response_trace",
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_REMAINING_PREMISES = (
    "checked_static_machine_call_contract",
    "mixed_to_static_boundary_alignment",
    "protocol_and_world_result_environment_alignment",
    "semantic_call_identity",
    "operation_external_trace_position",
)

_RESIDUAL_FIELDS = (
    "checkedMachineCall",
    "originalReturned",
    "siteIdExact",
    "importExact",
    "worldExact",
    "boundaryState",
    "boundaryArguments",
    "originalResultExact",
    "candidateResultExact",
    "semanticKind",
    "semanticImport",
    "semanticArguments",
)
_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_KEYS = frozenset(
    {
        "accept",
        "accepted",
        "endpoint",
        "response_payload_holds",
        "response_related",
        "status",
        "verdict",
    }
)


class RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
    StageAInputError
):
    """The cdecl payload input is stale or contains forbidden authority."""


@dataclass(frozen=True)
class InterpreterKernelCDeclEpilogueMixedEnvironmentAdapterPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    external_payload_plan_path: Path
    external_payload_plan_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FORMAT
            ),
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
            "frontier": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FRONTIER
            ),
            "closed_premise_families": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_REMAINING_PREMISES
            ),
            "dependent_residual": {
                "lean_type": "MixedCDeclExternalReturnResidual",
                "fields": list(_RESIDUAL_FIELDS),
                "operation_trace_position_is_separate": True,
            },
            "checked_construction": {
                "mixed_environment": "ExactOneToOneMixedExternalEnvironmentsRefine",
                "native_dispatch": "ExactNativeExternalDispatch",
                "response": "CheckedMixedCDeclKernelExternalResponse",
                "singleton_trace": (
                    "CheckedMixedCDeclKernelExternalResponse.oneToOneTrace"
                ),
            },
            "lean_interface": {
                "theorem": (
                    INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            f"cannot read {context}: {exc}"
        ) from exc


def _contains_forbidden_authority(value: object) -> bool:
    if isinstance(value, Mapping):
        if any(key in _FORBIDDEN_KEYS for key in value):
            return True
        return any(_contains_forbidden_authority(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_forbidden_authority(item) for item in value)
    return False


def _validate_external_payload_plan(
    payload: Mapping[str, Any],
    *,
    candidate_sha256: str,
    candidate_size: int,
) -> None:
    candidate = _object(payload.get("candidate"), "external payload candidate")
    result = _object(payload.get("result"), "external payload result")
    if (
        payload.get("format")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("frontier")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_FRONTIER
        or payload.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_REMAINING_PREMISES)
        or result
        != {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_EXTERNAL_PAYLOAD_THEOREM}
    ):
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            "cdecl external-payload plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            "cdecl external-payload candidate is stale"
        )
    if _contains_forbidden_authority(payload):
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            "cdecl external-payload plan contains status, verdict, endpoint, "
            "or submitted response authority"
        )


def build_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_plan(
    *,
    candidate_pe: Path | str,
    external_payload_plan: Path | str,
) -> InterpreterKernelCDeclEpilogueMixedEnvironmentAdapterPlan:
    candidate_path = Path(candidate_pe)
    external_payload_path = Path(external_payload_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(external_payload_path, "cdecl external-payload plan")
    _validate_external_payload_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelCDeclEpilogueMixedEnvironmentAdapterPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        external_payload_plan_path=external_payload_path,
        external_payload_plan_sha256=sha256_file(external_payload_path),
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source(
    plan: InterpreterKernelCDeclEpilogueMixedEnvironmentAdapterPlan,
    *,
    generated_external_payload_module: str = (
        "StageA.GeneratedRelational."
        "InterpreterKernelCdeclEpilogueExternalPayload"
    ),
) -> str:
    _validate_module(
        generated_external_payload_module,
        "generated cdecl external-payload module",
    )
    return f"""import StageA.RelationalInterpreterKernelCdeclEpilogueMixedEnvironmentAdapter
import {generated_external_payload_module}

namespace StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueMixedEnvironmentAdapter

open StageA.Relational.InterpreterKernelCdeclEpilogueMixedEnvironmentAdapter
open StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueExternalPayload
open StageA.Relational.InterpreterNativeWorld

abbrev GeneratedMixedCDeclExternalReturnResidual :=
  MixedCDeclExternalReturnResidual

abbrev GeneratedCheckedMixedCDeclKernelExternalResponse :=
  CheckedMixedCDeclKernelExternalResponse

theorem generatedMixedEnvironmentCDeclAdapterBindings
    (environment : NativeWorldEnvironment) :=
  generatedKernelCDeclExternalPayloadBindings environment

#print axioms generatedMixedEnvironmentCDeclAdapterBindings

end StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueMixedEnvironmentAdapter
"""


def write_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelCDeclEpilogueMixedEnvironmentAdapterPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = (
        build_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_plan(
            **kwargs
        )
    )
    write_json(
        output
        / INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output
        / INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source(
            plan
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FORMAT",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_FRONTIER",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_PLAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_MIXED_ENVIRONMENT_ADAPTER_THEOREM",
    "InterpreterKernelCDeclEpilogueMixedEnvironmentAdapterPlan",
    "RelationalInterpreterKernelCDeclEpilogueMixedEnvironmentAdapterGenerationError",
    "build_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_plan",
    "relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_source",
    "write_relational_interpreter_kernel_cdecl_epilogue_mixed_environment_adapter_bundle",
]
