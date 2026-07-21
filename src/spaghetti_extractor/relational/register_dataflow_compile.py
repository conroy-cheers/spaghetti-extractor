"""Compile a solved-independent register problem after proposal discovery."""

from __future__ import annotations

import json
from typing import Any

from ..stage_binary import StageABinary
from ..util import sha256_bytes
from .analyses.registers import _synthesize_register_relations
from .register_dataflow_problem import register_dataflow_problem_payload


def compile_register_dataflow_problem(
    contract: dict[str, Any],
    behaviors: list[dict[str, Any]],
    *,
    original_image_base: int,
    candidate_image_base: int,
    indirect_call_candidates: list[dict[str, Any]] | None = None,
    import_call_candidates: list[dict[str, Any]] | None = None,
    callsite_summary_predecessors: list[dict[str, Any]] | None = None,
    original_bin: StageABinary,
    candidate_bin: StageABinary,
    transfer_program_cache: dict[
        str, tuple[dict[str, Any], list[dict[str, Any]]]
    ] | None = None,
) -> dict[str, Any]:
    """Compile one immutable register proposal round without solving it."""
    compiled: dict[str, Any] = {}
    _synthesize_register_relations(
        contract,
        behaviors,
        original_image_base=original_image_base,
        candidate_image_base=candidate_image_base,
        indirect_call_candidates=indirect_call_candidates,
        import_call_candidates=import_call_candidates,
        callsite_summary_predecessors=callsite_summary_predecessors,
        original_bin=original_bin,
        candidate_bin=candidate_bin,
        _transfer_program_cache=transfer_program_cache,
        _compiled_problem_out=compiled,
    )

    def digest(value: object) -> str:
        return sha256_bytes(json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8"))

    return register_dataflow_problem_payload(
        original_sha256=original_bin.sha256,
        candidate_sha256=candidate_bin.sha256,
        contract_sha256=digest(contract),
        behaviors_sha256=digest(behaviors),
        indirect_call_candidates=indirect_call_candidates or [],
        import_call_candidates=import_call_candidates or [],
        callsite_summary_predecessors=callsite_summary_predecessors or [],
        graph=compiled["graph"],
        transfer_programs=compiled["transfer_programs"],
    )


__all__ = ["compile_register_dataflow_problem"]
