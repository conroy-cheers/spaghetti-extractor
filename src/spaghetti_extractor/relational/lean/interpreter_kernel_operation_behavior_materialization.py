"""Materialize compact symbolic behaviors checked against exact PE decoding.

Raw side extraction is deliberately untrusted.  This emitter binds every
submitted behavior literal to the corresponding canonical Lean decoder result.
Downstream route proofs can then rewrite to the compact literal without
re-evaluating PE parsing and instruction semantics.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from .interpreter_kernel_run_entry_route import (
    RunEntryRoute,
    build_run_entry_route,
    run_entry_behavior_request_payload,
)


INTERPRETER_KERNEL_RUN_ENTRY_BEHAVIORS_LEAN_MODULE = (
    "GeneratedRelationalInterpreterKernelRunEntryBehaviors"
)
_EXTRACTION_FORMAT = "stage-a-relational-side-extraction-v1"
_EXTRACTION_STATUS = "untrusted_proposal_requires_lean_decode_replay"


class InterpreterKernelOperationBehaviorMaterializationError(ValueError):
    """Behavior extraction does not match the exact selected instructions."""


def _load_object(path: Path, context: str) -> dict[str, Any]:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InterpreterKernelOperationBehaviorMaterializationError(
            f"cannot read {context} {path}: {exc}"
        ) from exc
    if not isinstance(payload, dict):
        raise InterpreterKernelOperationBehaviorMaterializationError(
            f"{context} must be an object"
        )
    return payload


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _behavior_terms(
    route: RunEntryRoute,
    extraction_path: Path,
) -> tuple[str, ...]:
    payload = _load_object(extraction_path, "Run-entry behavior extraction")
    expected = run_entry_behavior_request_payload(route)
    if (
        payload.get("format") != _EXTRACTION_FORMAT
        or payload.get("status") != _EXTRACTION_STATUS
        or payload.get("profile") != expected["profile"]
        or payload.get("model") != expected["model"]
        or payload.get("side") != "candidate"
        or payload.get("binary_sha256") != route.candidate_sha256
    ):
        raise InterpreterKernelOperationBehaviorMaterializationError(
            "Run-entry behavior extraction identity mismatch"
        )
    regions = payload.get("regions")
    if not isinstance(regions, list) or len(regions) != len(expected["regions"]):
        raise InterpreterKernelOperationBehaviorMaterializationError(
            "Run-entry behavior extraction region count mismatch"
        )
    terms: list[str] = []
    for index, (observed, requested) in enumerate(
        zip(regions, expected["regions"], strict=True)
    ):
        if not isinstance(observed, dict):
            raise InterpreterKernelOperationBehaviorMaterializationError(
                f"Run-entry behavior extraction region {index} is malformed"
            )
        for field in ("index", "id", "numeric_id", "span"):
            if observed.get(field) != requested[field]:
                raise InterpreterKernelOperationBehaviorMaterializationError(
                    f"Run-entry behavior extraction region {index} "
                    f"{field} mismatch"
                )
        term = observed.get("behavior_term")
        digest = observed.get("behavior_sha256")
        if (
            not isinstance(term, str)
            or not term
            or digest != _sha256_text(term)
        ):
            raise InterpreterKernelOperationBehaviorMaterializationError(
                f"Run-entry behavior extraction region {index} term mismatch"
            )
        terms.append(term)
    return tuple(terms)


def run_entry_behavior_materialization_source(
    route: RunEntryRoute,
    terms: tuple[str, ...],
) -> str:
    """Emit exact-decoder bindings for all selected Run-entry instructions."""

    instructions = [
        (block_index, block, instruction)
        for block_index, block in enumerate(route.path)
        for instruction in block.instructions
    ]
    if len(terms) != len(instructions):
        raise InterpreterKernelOperationBehaviorMaterializationError(
            "Run-entry materialization term count mismatch"
        )
    block_imports = "\n".join(
        "import StageA."
        "GeneratedRelationalInterpreterKernelOperationBlockFunction"
        f"{route.function_ordinal:04d}Block{ordinal:04d}"
        for ordinal in dict.fromkeys(block.ordinal for block in route.path)
    )
    definitions: list[str] = []
    audits: list[str] = []
    for term, (block_index, block, instruction) in zip(
        terms, instructions, strict=True
    ):
        base = (
            f"generatedRunEntryBlock{block_index}"
            f"Instruction{instruction.ordinal:04d}MaterializedBehavior"
        )
        decoded = (
            "generatedNativeOperationFunctionReplay"
            f"{route.function_ordinal:04d}Block{block.ordinal:04d}"
            f"Instruction{instruction.ordinal:04d}Behavior"
        )
        edge = (
            "generatedNativeOperationFunctionReplay"
            f"{route.function_ordinal:04d}Block{block.ordinal:04d}"
            f"Instruction{instruction.ordinal:04d}Edge"
        )
        decoded_exact = f"{decoded}Exact"
        # A one-instruction side extraction reports its region boundary as a
        # direct fallthrough outcome. Operation replay instead represents
        # nonterminal control through the containing checked block. Remove
        # only that synthetic boundary; the kernel equality below checks every
        # remaining field and rejects any other semantic discrepancy.
        materialized = (
            term
            if instruction.ordinal == block.instruction_count - 1
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
        audits.append(
            "#print axioms "
            "StageA.GeneratedRelational."
            "InterpreterKernelOperationInstantiation."
            f"{base}Exact"
        )
        audits.append(
            "#print axioms "
            "StageA.GeneratedRelational."
            "InterpreterKernelOperationInstantiation."
            f"{base}EdgeBehaviorExact"
        )
    return f"""{block_imports}

namespace StageA.GeneratedRelational.InterpreterKernelOperationInstantiation

open StageA.Formal StageA.Relational
open StageA.Relational.InterpreterNativeWorld

set_option maxRecDepth 1000000
set_option maxHeartbeats 0

{chr(10).join(definitions)}

{chr(10).join(audits)}

end StageA.GeneratedRelational.InterpreterKernelOperationInstantiation
"""


def write_run_entry_behavior_materialization_bundle(
    *,
    operation_manifest: Path | str,
    extraction: Path | str,
    out: Path | str,
) -> None:
    route = build_run_entry_route(operation_manifest)
    terms = _behavior_terms(route, Path(extraction))
    output = Path(out) / "StageA"
    output.mkdir(parents=True, exist_ok=True)
    (
        output
        / f"{INTERPRETER_KERNEL_RUN_ENTRY_BEHAVIORS_LEAN_MODULE}.lean"
    ).write_text(
        run_entry_behavior_materialization_source(route, terms),
        encoding="utf-8",
    )


__all__ = [
    "INTERPRETER_KERNEL_RUN_ENTRY_BEHAVIORS_LEAN_MODULE",
    "InterpreterKernelOperationBehaviorMaterializationError",
    "run_entry_behavior_materialization_source",
    "write_run_entry_behavior_materialization_bundle",
]
