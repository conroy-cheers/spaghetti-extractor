"""Emit exact static reachability without hiding runtime control frontiers."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from ...util import sha256_file, write_json
from .interpreter_mixed_original import INTERPRETER_MIXED_ORIGINAL_FORMAT


INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_FORMAT = (
    "stage-a-interpreter-mixed-original-static-reachability-v1"
)
INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_PLAN_FILENAME = (
    "interpreter-mixed-original-static-reachability.json"
)
INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME = (
    "GeneratedRelationalInterpreterMixedOriginalStaticReachability.lean"
)
INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM = (
    "StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability."
    "generatedExactOriginalDecodedStaticReachability"
)

_LEAN_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)


class InterpreterMixedOriginalStaticReachabilityGenerationError(StageAInputError):
    """The exact original inventory cannot authorize static reachability."""


@dataclass(frozen=True)
class InterpreterMixedOriginalStaticReachabilityPlan:
    mixed_original_plan_path: Path
    mixed_original_plan_sha256: str
    state_machine_sha256: str
    reachable_target_count: int
    runtime_frontier_count: int

    def payload(self) -> dict[str, Any]:
        return {
            "format": INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_FORMAT,
            "acceptance_authority": False,
            "scope": "decoded-direct-successors-only",
            "inputs": {
                "mixed_original_plan": {
                    "path": self.mixed_original_plan_path.name,
                    "sha256": self.mixed_original_plan_sha256,
                },
                "state_machine_sha256": self.state_machine_sha256,
            },
            "counts": {
                "reachable_targets": self.reachable_target_count,
                "runtime_indirect_frontiers": self.runtime_frontier_count,
            },
            "runtime_indirect_control": {
                "status": (
                    "satisfied"
                    if self.runtime_frontier_count == 0
                    else "incomplete"
                ),
                "closed_by_this_artifact": False,
                "required_at": "mixed-component-composition",
            },
            "result": {
                "theorem": (
                    INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM
                )
            },
            "failure_mode": "incomplete",
        }


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            f"{context} must be an object"
        )
    return value


def _nat(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            f"{context} must be a natural number"
        )
    return value


def build_interpreter_mixed_original_static_reachability_plan(
    *, mixed_original_plan: Path | str
) -> InterpreterMixedOriginalStaticReachabilityPlan:
    path = Path(mixed_original_plan)
    try:
        payload = _object(
            json.loads(path.read_text(encoding="utf-8")),
            "mixed-original plan",
        )
    except (OSError, json.JSONDecodeError) as exc:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            f"cannot read mixed-original plan: {exc}"
        ) from exc

    counts = _object(payload.get("counts"), "mixed-original counts")
    reachable = payload.get("reachable_target_ids")
    blockers = payload.get("blockers")
    digest = payload.get("state_machine_sha256")
    if payload.get("format") != INTERPRETER_MIXED_ORIGINAL_FORMAT:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original plan has an unsupported format"
        )
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original state-machine digest is invalid"
        )
    if not isinstance(reachable, list) or not reachable:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original reachable inventory must be nonempty"
        )
    target_ids = tuple(
        _nat(value, f"reachable_target_ids[{index}]")
        for index, value in enumerate(reachable)
    )
    if tuple(sorted(set(target_ids))) != target_ids:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original reachable inventory must be sorted and unique"
        )
    if not isinstance(blockers, list):
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original runtime blocker inventory must be a list"
        )
    if _nat(
        counts.get("reachable_missing_successors"),
        "reachable missing-successor count",
    ) != 0:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "static rooted inventory has missing decoded successors"
        )
    if _nat(counts.get("reachable_targets"), "reachable-target count") != len(
        target_ids
    ):
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original reachable-target count is stale"
        )
    if _nat(counts.get("blockers"), "runtime blocker count") != len(blockers):
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "mixed-original runtime blocker count is stale"
        )
    return InterpreterMixedOriginalStaticReachabilityPlan(
        mixed_original_plan_path=path,
        mixed_original_plan_sha256=sha256_file(path),
        state_machine_sha256=digest,
        reachable_target_count=len(target_ids),
        runtime_frontier_count=len(blockers),
    )


def interpreter_mixed_original_static_reachability_source(
    plan: InterpreterMixedOriginalStaticReachabilityPlan,
    *,
    generated_module: str = (
        "StageA.GeneratedRelationalInterpreterMixedOriginal"
    ),
) -> str:
    if _LEAN_MODULE.fullmatch(generated_module) is None:
        raise InterpreterMixedOriginalStaticReachabilityGenerationError(
            "generated mixed-original module must be a qualified StageA module"
        )
    return f"""import StageA.RelationalInterpreterMixedOriginalReachabilityCertificates
import {generated_module}

namespace StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability

open StageA.Relational.InterpreterMixedOriginal
open StageA.GeneratedRelational.InterpreterMixedOriginal

/- Static decoded closure only.  The {plan.runtime_frontier_count} runtime
indirect-control frontiers remain obligations of mixed component composition. -/
def generatedExactOriginalDecodedStaticReachability :
    ExactOriginalDecodedReachability generatedOriginalStaticContext
      generatedExactOriginalDecodedAuthority generatedOriginalLaunch
      generatedDirectExactOriginalDecodedLaunchRoot :=
  exactOriginalDecodedReachabilityOfCheckedStaticInventory
    generatedOriginalStaticContext generatedExactOriginalDecodedAuthority
    generatedOriginalLaunch generatedDirectExactOriginalDecodedLaunchRoot
    generatedReachableTargetIds
    (by decide +kernel)
    (by decide +kernel)
    (by decide +kernel)
    generatedOriginalReachabilityInventoryChecked

#print axioms generatedExactOriginalDecodedStaticReachability

end StageA.GeneratedRelational.InterpreterMixedOriginalStaticReachability
"""


def write_interpreter_mixed_original_static_reachability_bundle(
    *, out: Path | str, **kwargs: Any
) -> InterpreterMixedOriginalStaticReachabilityPlan:
    output = Path(out)
    output.mkdir(parents=True, exist_ok=True)
    plan = build_interpreter_mixed_original_static_reachability_plan(**kwargs)
    write_json(
        output / INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_PLAN_FILENAME,
        plan.payload(),
    )
    (
        output / INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME
    ).write_text(
        interpreter_mixed_original_static_reachability_source(plan),
        encoding="ascii",
    )
    return plan


__all__ = [
    "INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_FORMAT",
    "INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_LEAN_FILENAME",
    "INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_PLAN_FILENAME",
    "INTERPRETER_MIXED_ORIGINAL_STATIC_REACHABILITY_THEOREM",
    "InterpreterMixedOriginalStaticReachabilityGenerationError",
    "InterpreterMixedOriginalStaticReachabilityPlan",
    "build_interpreter_mixed_original_static_reachability_plan",
    "interpreter_mixed_original_static_reachability_source",
    "write_interpreter_mixed_original_static_reachability_bundle",
]
