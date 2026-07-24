"""Emit the exact-computation closure for the Step ProgramLookup call.

The upstream plan fixes the candidate bytes and direct call site. This layer
does not accept runtime paths, endpoints, or nested request assertions. It
exposes the Lean interface that derives those objects from exact native-world
fuel computations and concrete ABI frame facts.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_kernel_step_program_lookup_call import (
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES,
    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM,
)


INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT = (
    "stage-a-relational-interpreter-kernel-step-program-lookup-call-closure-v1"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME = (
    "interpreter-kernel-step-program-lookup-call-closure.json"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterKernelStepProgramLookupCallClosure.lean"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM = (
    "StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCallClosure."
    "generatedInterpreterStepProgramLookupCallClosureBindings"
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES = (
    "submitted_step_caller_path",
    "bare_program_lookup_request_relation",
    "submitted_program_lookup_return_path",
)
INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES = (
    "exact_step_prefix_and_helper_runtime_endpoints",
    "nested_program_lookup_cdecl_image_and_table_facts",
    "exact_program_lookup_return_replay_fuel_and_endpoint",
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_FORBIDDEN_EVIDENCE_KEYS = frozenset(
    {
        "call_frame",
        "caller_path",
        "final_machine_state",
        "lookup_before",
        "nested_request",
        "prefix_path",
        "return_endpoint",
        "return_path",
        "runtime_endpoint",
        "runtime_fuel",
    }
)


class RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
    StageAInputError
):
    """The upstream call plan is stale, unsafe, or incompatible."""


@dataclass(frozen=True)
class InterpreterKernelStepProgramLookupCallClosurePlan:
    candidate_path: Path
    candidate_sha256: str
    candidate_size: int
    call_plan_path: Path
    call_plan_sha256: str
    call_site_rva: int
    call_block_rva: int
    target_rva: int
    continuation_rva: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": (
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT
            ),
            "acceptance_authority": False,
            "operation": "interpreterStep.programLookupCall",
            "candidate": {
                "sha256": self.candidate_sha256,
                "size": self.candidate_size,
            },
            "inputs": {
                "candidate": {
                    "path": self.candidate_path.name,
                    "sha256": self.candidate_sha256,
                },
                "program_lookup_call_plan": {
                    "path": self.call_plan_path.name,
                    "sha256": self.call_plan_sha256,
                },
            },
            "checked_static_authority": {
                "call_site_rva": self.call_site_rva,
                "call_block_rva": self.call_block_rva,
                "target_rva": self.target_rva,
                "continuation_rva": self.continuation_rva,
            },
            "closed_premise_families": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES
            ),
            "remaining_proof_premises": list(
                INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES
            ),
            "checked_authority": {
                "caller_path": "ExactComputedInterpreterStepPath",
                "nested_request": "ConcreteProgramLookupNestedRequestFacts",
                "return_replay": (
                    "ExactComputedInterpreterStepProgramLookupReturn"
                ),
                "constructor": (
                    "SymbolicallyClosedInterpreterStepProgramLookupCallerFrame."
                    "toCallerFrame"
                ),
            },
            "forbidden_submitted_evidence": sorted(
                _FORBIDDEN_EVIDENCE_KEYS
            ),
            "result": {
                "theorem": (
                    INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            f"{context} must be an object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            f"{context} must be a natural number"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, json.JSONDecodeError) as exc:
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
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
) -> tuple[int, int, int, int]:
    candidate = _object(payload.get("candidate"), "call-plan candidate")
    result = _object(payload.get("result"), "call-plan result")
    if (
        payload.get("format")
        != INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_FORMAT
        or payload.get("acceptance_authority") is not False
        or payload.get("operation") != "interpreterStep.programLookupCall"
        or payload.get("remaining_proof_premises")
        != list(INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES)
        or result
        != {
            "status": "typed-interface-ready",
            "theorem": INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_THEOREM,
        }
    ):
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            "ProgramLookup call plan is stale or incompatible"
        )
    if (
        candidate.get("sha256") != candidate_sha256
        or candidate.get("size") != candidate_size
    ):
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            "ProgramLookup call plan candidate is stale"
        )
    if _contains_forbidden_evidence(
        {key: value for key, value in payload.items() if key != "result"}
    ):
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            "ProgramLookup call plan contains submitted runtime evidence"
        )
    authority = _object(
        payload.get("checked_static_authority"),
        "call-plan static authority",
    )
    call_site = _nat(authority.get("call_site_rva"), "call-site RVA")
    call_block = _nat(authority.get("call_block_rva"), "call-block RVA")
    target = _nat(authority.get("target_rva"), "call target RVA")
    continuation = _nat(
        authority.get("continuation_rva"),
        "call continuation RVA",
    )
    frontiers = payload.get("proof_frontiers")
    if (
        not isinstance(frontiers, list)
        or len(frontiers) != 3
        or [
            row.get("premise") if isinstance(row, Mapping) else None
            for row in frontiers
        ]
        != list(INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_REMAINING_PREMISES)
    ):
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            "ProgramLookup call proof frontiers are stale or ambiguous"
        )
    return call_site, call_block, target, continuation


def build_relational_interpreter_kernel_step_program_lookup_call_closure_plan(
    *,
    candidate_pe: Path | str,
    program_lookup_call_plan: Path | str,
) -> InterpreterKernelStepProgramLookupCallClosurePlan:
    candidate_path = Path(candidate_pe)
    call_plan_path = Path(program_lookup_call_plan)
    if not candidate_path.is_file():
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            "candidate PE does not exist"
        )
    candidate_sha256 = sha256_file(candidate_path)
    candidate_size = candidate_path.stat().st_size
    payload = _load(call_plan_path, "ProgramLookup call plan")
    call_site, call_block, target, continuation = _validate_upstream_plan(
        payload,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
    )
    return InterpreterKernelStepProgramLookupCallClosurePlan(
        candidate_path=candidate_path,
        candidate_sha256=candidate_sha256,
        candidate_size=candidate_size,
        call_plan_path=call_plan_path,
        call_plan_sha256=sha256_file(call_plan_path),
        call_site_rva=call_site,
        call_block_rva=call_block,
        target_rva=target,
        continuation_rva=continuation,
    )


def _validate_module(module: str, context: str) -> None:
    if _LEAN_MODULE.fullmatch(module) is None:
        raise RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError(
            f"{context} must be a qualified StageA Lean module"
        )


def relational_interpreter_kernel_step_program_lookup_call_closure_source(
    plan: InterpreterKernelStepProgramLookupCallClosurePlan,
    *,
    generated_call_module: str = (
        "StageA.GeneratedRelational"
        "InterpreterKernelStepProgramLookupCall"
    ),
) -> str:
    _validate_module(generated_call_module, "generated ProgramLookup call module")
    return f"""import StageA.RelationalInterpreterKernelStepProgramLookupCallClosure
import {generated_call_module}

namespace StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCallClosure

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelStepProgramLookupCallClosure
open StageA.Relational.InterpreterNativeWorld
open StageA.GeneratedRelational.InterpreterKernelABI
open StageA.GeneratedRelational.InterpreterKernelStepOperation
open StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCall

abbrev GeneratedInterpreterStepProgramLookupClosedCallerFrame
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  SymbolicallyClosedInterpreterStepProgramLookupCallerFrame
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)

abbrev GeneratedInterpreterStepProgramLookupClosedComposition
    (environment : NativeWorldEnvironment) (world : RelationalWorld) :=
  SymbolicallyClosedInterpreterStepProgramLookupCallComposition
    generatedCompiledKernelProgram semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI
    (generatedInterpreterStepNativeProgram environment) world
    (generatedInterpreterStepOperationStatic environment)
    (generatedInterpreterStepProgramLookupCallSite environment)

abbrev GeneratedInterpreterStepProgramLookupNestedRequestFacts :=
  ConcreteProgramLookupNestedRequestFacts semanticInterpreterProgramRecords
    generatedConcreteInterpreterKernelABI

theorem generatedInterpreterStepProgramLookupCallClosureBindings
    (environment : NativeWorldEnvironment) :
    generatedInterpreterStepProgramLookupCallSiteParameters.checked
      generatedCompiledKernelProgram
      (generatedInterpreterStepNativeProgram environment).pe
      (generatedInterpreterStepOperationStatic environment).function
      (generatedInterpreterStepOperationStatic environment).reflected.template =
        true :=
  generatedInterpreterStepProgramLookupCallSiteChecked environment

#print axioms generatedInterpreterStepProgramLookupCallClosureBindings

end StageA.GeneratedRelational.InterpreterKernelStepProgramLookupCallClosure
"""


def write_relational_interpreter_kernel_step_program_lookup_call_closure_bundle(
    *,
    out: Path | str,
    **kwargs: Any,
) -> InterpreterKernelStepProgramLookupCallClosurePlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = (
        build_relational_interpreter_kernel_step_program_lookup_call_closure_plan(
            **kwargs
        )
    )
    write_json(
        output
        / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output
        / INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME
    ).write_text(
        relational_interpreter_kernel_step_program_lookup_call_closure_source(
            plan
        ),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_CLOSED_PREMISES",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_FORMAT",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_LEAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_PLAN_FILENAME",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_REMAINING_PREMISES",
    "INTERPRETER_KERNEL_STEP_PROGRAM_LOOKUP_CALL_CLOSURE_THEOREM",
    "InterpreterKernelStepProgramLookupCallClosurePlan",
    "RelationalInterpreterKernelStepProgramLookupCallClosureGenerationError",
    "build_relational_interpreter_kernel_step_program_lookup_call_closure_plan",
    "relational_interpreter_kernel_step_program_lookup_call_closure_source",
    "write_relational_interpreter_kernel_step_program_lookup_call_closure_bundle",
]
