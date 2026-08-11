"""Stable execution-mode identifiers for generated Stage B candidates."""

from __future__ import annotations

from .errors import StageAInputError


STATIC_CLOSED_CANDIDATE_MODE = "static-closed"
STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE = "structural-diagnostic"
CANDIDATE_MODES = frozenset({
    STATIC_CLOSED_CANDIDATE_MODE,
    STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE,
})


def require_candidate_mode(value: object) -> str:
    if value not in CANDIDATE_MODES:
        raise StageAInputError(
            "candidate mode must be static-closed or structural-diagnostic"
        )
    return str(value)


__all__ = [
    "CANDIDATE_MODES",
    "STATIC_CLOSED_CANDIDATE_MODE",
    "STRUCTURAL_DIAGNOSTIC_CANDIDATE_MODE",
    "require_candidate_mode",
]
