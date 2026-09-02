"""Shared failures for canonical component artifacts."""


class ComponentArtifactError(ValueError):
    """A component artifact is malformed, stale, or ambiguous."""


__all__ = ["ComponentArtifactError"]
