"""Shared fail-closed errors for machine-derived semantic path checking."""


class SemanticPathError(ValueError):
    """A machine-derived semantic path cannot be represented soundly."""


class SemanticPathViolation(SemanticPathError):
    """A submitted logical binding contradicts exact machine semantics."""


__all__ = ["SemanticPathError", "SemanticPathViolation"]
