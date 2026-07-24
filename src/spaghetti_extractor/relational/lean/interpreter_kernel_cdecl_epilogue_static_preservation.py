"""Emit checked static-memory preservation bindings for cdecl epilogues.

The upstream symbolic closure binds exact native execution to a finite write
footprint.  This layer records that Lean derives loaded candidate-image and
original program-table preservation from the checked ABI workspace
disjointness.  The environment-indexed typed response payload remains the only
dynamic premise.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_cdecl_epilogue_symbolic_closure import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM,
)


INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT = (
    "stage-a-relational-interpreter-kernel-cdecl-epilogue-static-preservation-v1"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME = (
    "interpreter-kernel-cdecl-epilogue-static-preservation.json"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelCdeclEpilogueStaticPreservation.lean"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM = (
    "StageA.GeneratedRelational."
    "InterpreterKernelCdeclEpilogueStaticPreservation."
    "generatedKernelCDeclStaticPreservationBindings"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER = (
    "cdecl_epilogue_static_memory_preservation"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES = (
    "loaded_image_and_original_program_table_preservation",
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES = (
    "environmental_typed_response_payload",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "candidate_image_preserved",
        "endpoint",
        "final_machine_state",
        "loaded_image_preservation",
        "operation_status",
        "original_program_table_preserved",
        "program_table_preservation",
        "return_endpoint",
        "status",
    }
)


class RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
    StageAInputError
):
    """The upstream symbolic closure is stale, unsafe, or incompatible."""


@dataclass(frozen=True)
class InterpreterKernelCDeclEpilogueStaticPreservationPlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    symbolic_closure_plan_path: Path
    symbolic_closure_plan_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": (INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT),
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
                "symbolic_closure_plan": {
                    "path": self.symbolic_closure_plan_path.name,
                    "sha256": self.symbolic_closure_plan_sha256,
                },
            },
            "frontier": (
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER
            ),
            "closed_premise_families": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES
            ),
            "checked_authority": {
                "exact_write_frame": (
                    "ExactDecodedCDeclSymbolicExecution.exactWriteFootprint"
                ),
                "workspace_disjointness": (
                    "ConcreteKernelABI.cdeclStaticPreservationFacts"
                ),
                "constructor": (
                    "StaticallyPreservedCDeclEpilogueCertificate.toChecked"
                ),
            },
            "forbidden_submitted_evidence": sorted(_FORBIDDEN_EVIDENCE_KEYS),
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
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
    candidate = _object(payload.get("candidate"), "symbolic closure candidate")
    result = _object(payload.get("result"), "symbolic closure result")
    if (
        payload.get("format")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("frontier")
        != INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER
        or payload.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES)
        or result
        != {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM}
    ):
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
            "symbolic cdecl closure plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
            "symbolic cdecl closure candidate is stale"
        )
    if _contains_forbidden_evidence(payload):
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
            "symbolic cdecl closure contains submitted preservation, endpoint, "
            "or status evidence"
        )


def build_relational_interpreter_kernel_cdecl_epilogue_static_preservation_plan(
    *,
    candidate_pe: Path | str,
    symbolic_closure_plan: Path | str,
) -> InterpreterKernelCDeclEpilogueStaticPreservationPlan:
    candidate_path = Path(candidate_pe)
    symbolic_path = Path(symbolic_closure_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(symbolic_path, "symbolic cdecl closure plan")
    _validate_upstream_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelCDeclEpilogueStaticPreservationPlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        symbolic_closure_plan_path=symbolic_path,
        symbolic_closure_plan_sha256=sha256_file(symbolic_path),
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_cdecl_epilogue_static_preservation_source(
    plan: InterpreterKernelCDeclEpilogueStaticPreservationPlan,
    *,
    generated_symbolic_closure_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure"
    ),
) -> str:
    _validate_module(
        generated_symbolic_closure_module,
        "generated symbolic cdecl closure module",
    )
    return f"""import StageA.RelationalInterpreterKernelCdeclEpilogueStaticPreservation
import {generated_symbolic_closure_module}

namespace StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueStaticPreservation

open StageA.Relational.InterpreterKernelABI
open StageA.Relational.InterpreterKernelCdeclEpilogueStaticPreservation
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue

abbrev GeneratedInterpreterStepCDeclStaticPreservationCertificate
    (environment : NativeWorldEnvironment) :=
  StaticallyPreservedCDeclEpilogueCertificate
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedInterpreterStepCDeclEpilogueStatic environment)

abbrev GeneratedRunFunctionCDeclStaticPreservationCertificate
    (environment : NativeWorldEnvironment) :=
  StaticallyPreservedCDeclEpilogueCertificate
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionCDeclEpilogueStatic environment)

abbrev GeneratedCDeclEnvironmentalPayload :=
  ResponsePayloadHolds generatedConcreteInterpreterKernelABI

theorem generatedKernelCDeclStaticPreservationBindings
    (environment : NativeWorldEnvironment) :=
  generatedKernelCDeclEpiloguesChecked environment

#print axioms generatedKernelCDeclStaticPreservationBindings

end StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueStaticPreservation
"""


def write_relational_interpreter_kernel_cdecl_epilogue_static_preservation_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelCDeclEpilogueStaticPreservationPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_cdecl_epilogue_static_preservation_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_cdecl_epilogue_static_preservation_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FORMAT",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_FRONTIER",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_PLAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_STATIC_PRESERVATION_THEOREM",
    "InterpreterKernelCDeclEpilogueStaticPreservationPlan",
    "RelationalInterpreterKernelCDeclEpilogueStaticPreservationGenerationError",
    "build_relational_interpreter_kernel_cdecl_epilogue_static_preservation_plan",
    "relational_interpreter_kernel_cdecl_epilogue_static_preservation_source",
    "write_relational_interpreter_kernel_cdecl_epilogue_static_preservation_bundle",
]
