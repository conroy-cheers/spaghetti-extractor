"""Shared fail-closed error type for native ingress artifacts."""

from ..errors import ToolkitInputError


class NativeIngressError(ToolkitInputError):
    """Native ingress authority is malformed, stale, ambiguous, or incomplete."""


__all__ = ["NativeIngressError"]
