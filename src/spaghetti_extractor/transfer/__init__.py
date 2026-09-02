"""Canonical executable-transfer planning, codecs, and diagnostics.

Importing a transfer submodule is on the production semantic-link path.  Keep
the package initializer lazy so the host-only evaluator does not leak into
operator or authority closures merely because Python initializes the package.
"""

from importlib import import_module
from typing import Any


_EVALUATOR_EXPORTS = {
    "EvaluatorMemoryV1", "EvaluatorStateV1", "compare_observations",
    "evaluate_transfer_plan_case", "generated_differential_cases",
    "inspect_transfer_plan", "minimize_mismatch_case",
}
_PLAN_EXPORTS = {
    "load_executable_transfer_plan", "parse_executable_transfer_plan",
    "write_executable_transfer_plan",
}


def __getattr__(name: str) -> Any:
    if name in _EVALUATOR_EXPORTS:
        return getattr(import_module(".evaluator", __name__), name)
    if name in _PLAN_EXPORTS:
        return getattr(import_module(".plan", __name__), name)
    raise AttributeError(name)

__all__ = [
    "EvaluatorMemoryV1", "EvaluatorStateV1", "compare_observations",
    "evaluate_transfer_plan_case", "generated_differential_cases",
    "inspect_transfer_plan", "minimize_mismatch_case",
    "load_executable_transfer_plan", "parse_executable_transfer_plan",
    "write_executable_transfer_plan",
]
