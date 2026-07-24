"""Emit the symbolic closure binding for checked cdecl epilogues.

The input cdecl plan already binds exact candidate functions and checked plain
returns.  This layer adds no dynamic evidence.  Generated Lean exposes the
generic symbolic certificate that derives the stack return word, preserved
registers/ESP, and finite write footprint from exact execution and ABI frame
facts.  Only loaded-image/table preservation and the environment-indexed typed
response payload remain in the residual premise record.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_cdecl_epilogue import (
    INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES,
    INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM,
)


INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT = (
    "stage-a-relational-interpreter-kernel-cdecl-epilogue-symbolic-closure-v1"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME = (
    "interpreter-kernel-cdecl-epilogue-symbolic-closure.json"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelCdeclEpilogueSymbolicClosure.lean"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueSymbolicClosure."
    "generatedKernelCDeclSymbolicClosureBindings"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER = (
    "cdecl_epilogue_exact_symbolic_execution_and_abi_frame"
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES = (
    "loaded_image_and_original_program_table_preservation",
    "environmental_typed_response_payload",
)
INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES = (
    "checked_stack_return_word",
    "preserved_cdecl_registers_and_stack_pop",
    "checked_write_footprint_disjointness",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "endpoint",
        "final_machine_state",
        "operation_status",
        "preserved_registers",
        "return_endpoint",
        "stack_pop",
        "stack_return_word",
        "status",
        "write_footprint",
    }
)


class RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
    StageAInputError
):
    """The upstream checked cdecl plan is stale, unsafe, or incompatible."""


@dataclass(frozen=True)
class InterpreterKernelCDeclEpilogueSymbolicClosurePlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    cdecl_epilogue_plan_path: Path
    cdecl_epilogue_plan_sha256: str

    def payload(self) -> dict[str, Any]:
        return {
            "format": (INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT),
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
                "cdecl_epilogue_plan": {
                    "path": self.cdecl_epilogue_plan_path.name,
                    "sha256": self.cdecl_epilogue_plan_sha256,
                },
            },
            "frontier": (INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER),
            "closed_premise_families": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES
            ),
            "checked_authority": {
                "exact_execution": ("ExactDecodedCDeclSymbolicExecution"),
                "abi_frame": "CDeclSymbolicABIFrameFacts",
                "constructor": ("SymbolicallyClosedCDeclEpilogueCertificate.toChecked"),
            },
            "forbidden_submitted_evidence": sorted(_FORBIDDEN_EVIDENCE_KEYS),
            "result": {
                "theorem": (INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM)
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
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
    candidate = _object(payload.get("candidate"), "cdecl epilogue candidate")
    result = _object(payload.get("result"), "cdecl epilogue result")
    if (
        payload.get("format") != INTERPRETER_KERNEL_CDECL_EPILOGUE_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("frontier") != INTERPRETER_KERNEL_CDECL_EPILOGUE_FRONTIER
        or payload.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES)
        or result != {"theorem": INTERPRETER_KERNEL_CDECL_EPILOGUE_THEOREM}
    ):
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            "cdecl epilogue plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            "cdecl epilogue plan candidate is stale"
        )
    frontiers = payload.get("proof_frontiers")
    if (
        not isinstance(frontiers, list)
        or [row.get("operation") for row in frontiers if isinstance(row, Mapping)]
        != ["interpreterStep", "runFunction"]
        or any(
            not isinstance(row, Mapping)
            or row.get("premises")
            != list(INTERPRETER_KERNEL_CDECL_EPILOGUE_REMAINING_PREMISES)
            for row in frontiers
        )
    ):
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            "cdecl epilogue proof frontiers are stale or ambiguous"
        )
    if _contains_forbidden_evidence(payload):
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            "cdecl epilogue plan contains submitted endpoint, status, or "
            "derived cdecl evidence"
        )


def build_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_plan(
    *,
    candidate_pe: Path | str,
    cdecl_epilogue_plan: Path | str,
) -> InterpreterKernelCDeclEpilogueSymbolicClosurePlan:
    candidate_path = Path(candidate_pe)
    cdecl_path = Path(cdecl_epilogue_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(cdecl_path, "cdecl epilogue plan")
    _validate_upstream_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelCDeclEpilogueSymbolicClosurePlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        cdecl_epilogue_plan_path=cdecl_path,
        cdecl_epilogue_plan_sha256=sha256_file(cdecl_path),
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source(
    plan: InterpreterKernelCDeclEpilogueSymbolicClosurePlan,
    *,
    generated_cdecl_module: str = (
        "StageA.GeneratedRelationalInterpreterKernelCdeclEpilogue"
    ),
) -> str:
    _validate_module(generated_cdecl_module, "generated cdecl epilogue module")
    return f"""import StageA.RelationalInterpreterKernelCdeclEpilogueSymbolicClosure
import {generated_cdecl_module}

namespace StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueSymbolicClosure

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelCdeclEpilogue
open StageA.Relational.InterpreterKernelCdeclEpilogueSymbolicClosure
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernel
open StageA.GeneratedRelational.InterpreterKernelCdeclEpilogue

abbrev GeneratedInterpreterStepCDeclSymbolicClosureCertificate
    (environment : NativeWorldEnvironment) :=
  SymbolicallyClosedCDeclEpilogueCertificate
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedInterpreterStepCDeclEpilogueStatic environment)

abbrev GeneratedRunFunctionCDeclSymbolicClosureCertificate
    (environment : NativeWorldEnvironment) :=
  SymbolicallyClosedCDeclEpilogueCertificate
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment)
    (generatedRunFunctionCDeclEpilogueStatic environment)

abbrev GeneratedCDeclSymbolicClosureRemaining :=
  CDeclSymbolicClosureRemaining generatedConcreteInterpreterKernelABI

theorem generatedKernelCDeclSymbolicClosureBindings
    (environment : NativeWorldEnvironment) :=
  generatedKernelCDeclEpiloguesChecked environment

#print axioms generatedKernelCDeclSymbolicClosureBindings

end StageA.GeneratedRelational.InterpreterKernelCdeclEpilogueSymbolicClosure
"""


def write_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelCDeclEpilogueSymbolicClosurePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_plan(
        **kwargs
    )
    write_json(
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FORMAT",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_FRONTIER",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_PLAN_FILENAME",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_CDECL_EPILOGUE_SYMBOLIC_CLOSURE_THEOREM",
    "InterpreterKernelCDeclEpilogueSymbolicClosurePlan",
    "RelationalInterpreterKernelCDeclEpilogueSymbolicClosureGenerationError",
    "build_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_plan",
    "relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_source",
    "write_relational_interpreter_kernel_cdecl_epilogue_symbolic_closure_bundle",
]
