"""Materialize one checked operation block from an untrusted side extraction.

The side extractor provides compact Lean terms quickly, but those terms carry
no proof authority.  This module emits one exact-decoder equality per
instruction.  Downstream route certificates may then use the materialized
terms without reducing PE parsing and instruction decoding again.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from .interpreter_kernel_step_world_program_lookup import (
    InterpreterKernelStepWorldProgramLookupPlan,
    build_relational_interpreter_kernel_step_world_program_lookup_plan,
)
from .interpreter_kernel_step_program_lookup_projection import (
    write_interpreter_step_program_lookup_projection,
)


INTERPRETER_STEP_PROGRAM_LOOKUP_CALL_BEHAVIORS_LEAN_MODULE = (
    "GeneratedRelationalInterpreterStepProgramLookupCallBehaviors"
)
_EXTRACTION_FORMAT = "stage-a-relational-side-extraction-v1"
_EXTRACTION_STATUS = "untrusted_proposal_requires_lean_decode_replay"


class OperationBlockBehaviorMaterializationError(StageAInputError):
    """A side extraction does not match the selected checked operation block."""


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise OperationBlockBehaviorMaterializationError(
            f"{context} must be an object"
        )
    return value


def _load(path: Path, context: str) -> Mapping[str, Any]:
    try:
        return _object(json.loads(path.read_text(encoding="utf-8")), context)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise OperationBlockBehaviorMaterializationError(
            f"cannot read {context} {path}: {exc}"
        ) from exc


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _behavior_terms(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    extraction_path: Path,
) -> tuple[str, ...]:
    payload = _load(extraction_path, "operation-block behavior extraction")
    expected = plan.behavior_request_payload()
    if (
        payload.get("format") != _EXTRACTION_FORMAT
        or payload.get("status") != _EXTRACTION_STATUS
        or payload.get("profile") != expected["profile"]
        or payload.get("model") != expected["model"]
        or payload.get("side") != "candidate"
        or payload.get("binary_sha256") != plan.candidate_sha256
    ):
        raise OperationBlockBehaviorMaterializationError(
            "operation-block behavior extraction identity mismatch"
        )
    observed_regions = payload.get("regions")
    expected_regions = expected["regions"]
    if not isinstance(observed_regions, list) or len(observed_regions) != len(
        expected_regions
    ):
        raise OperationBlockBehaviorMaterializationError(
            "operation-block behavior extraction region count mismatch"
        )
    terms: list[str] = []
    for index, (observed_value, requested_value) in enumerate(
        zip(observed_regions, expected_regions, strict=True)
    ):
        observed = _object(
            observed_value, f"operation-block extraction region {index}"
        )
        for field in ("index", "id", "numeric_id", "span"):
            if observed.get(field) != requested_value[field]:
                raise OperationBlockBehaviorMaterializationError(
                    "operation-block behavior extraction "
                    f"region {index} {field} mismatch"
                )
        term = observed.get("behavior_term")
        digest = observed.get("behavior_sha256")
        if (
            not isinstance(term, str)
            or not term
            or digest != _sha256_text(term)
        ):
            raise OperationBlockBehaviorMaterializationError(
                f"operation-block extraction region {index} term mismatch"
            )
        terms.append(term)
    return tuple(terms)


def operation_block_behavior_materialization_source(
    plan: InterpreterKernelStepWorldProgramLookupPlan,
    terms: tuple[str, ...],
) -> str:
    """Emit exact-decoder bindings for the selected direct-call block."""

    instructions = plan.call_block_instruction_spans
    if len(terms) != len(instructions):
        raise OperationBlockBehaviorMaterializationError(
            "operation-block materialization term count mismatch"
        )
    block_prefix = (
        "generatedNativeOperationFunctionReplay"
        f"{plan.step_function_ordinal:04d}"
        f"Block{plan.call_block_ordinal:04d}"
    )
    definitions: list[str] = []
    audits: list[str] = []
    last_index = len(instructions) - 1
    for index, (term, (ordinal, _rva, _size)) in enumerate(
        zip(terms, instructions, strict=True)
    ):
        base = (
            "generatedInterpreterStepProgramLookupCall"
            f"Instruction{ordinal:04d}MaterializedBehavior"
        )
        decoded = f"{block_prefix}Instruction{ordinal:04d}Behavior"
        edge = f"{block_prefix}Instruction{ordinal:04d}Edge"
        decoded_exact = f"{decoded}Exact"
        materialized = (
            term
            if index == last_index
            else f"{{ ({term} : SymbolicBehavior) with outcome := none }}"
        )
        definitions.append(
            f"""def {base} : SymbolicBehavior :=
  {materialized}

theorem {base}Exact :
    {decoded} = {base} := by
  decide +kernel

theorem {base}EdgeBehaviorExact
    (environment : NativeWorldEnvironment) :
    ({edge} environment).replay.behavior = {base} := by
  exact ({decoded_exact} environment).trans {base}Exact"""
        )
        audits.extend(
            (
                f"#print axioms {base}Exact",
                f"#print axioms {base}EdgeBehaviorExact",
            )
        )
    return f"""import StageA.RelationalInterpreterKernelOperationProjection
import StageA.GeneratedRelationalInterpreterKernelOperationBlockFunction{plan.step_function_ordinal:04d}Block{plan.call_block_ordinal:04d}

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterKernelOperationProjection
open StageA.Relational.InterpreterKernelOperationTraceChecker
open StageA.Relational.InterpreterNativeWorld

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{chr(10).join(definitions)}

{chr(10).join(audits)}

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def write_operation_block_behavior_materialization_bundle(
    *,
    extraction: Path | str,
    out: Path | str,
    **plan_arguments: Any,
) -> None:
    plan = build_relational_interpreter_kernel_step_world_program_lookup_plan(
        **plan_arguments
    )
    terms = _behavior_terms(plan, Path(extraction))
    output = Path(out) / "StageA"
    output.mkdir(parents=True, exist_ok=True)
    (
        output
        / f"{INTERPRETER_STEP_PROGRAM_LOOKUP_CALL_BEHAVIORS_LEAN_MODULE}.lean"
    ).write_text(
        operation_block_behavior_materialization_source(plan, terms),
        encoding="ascii",
    )
    write_interpreter_step_program_lookup_projection(plan=plan, out=out)


__all__ = [
    "INTERPRETER_STEP_PROGRAM_LOOKUP_CALL_BEHAVIORS_LEAN_MODULE",
    "OperationBlockBehaviorMaterializationError",
    "operation_block_behavior_materialization_source",
    "write_operation_block_behavior_materialization_bundle",
]
