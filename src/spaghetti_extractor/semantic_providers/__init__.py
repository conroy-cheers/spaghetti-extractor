"""Qualified implementation providers for linked semantic definitions.

Keep the package import cheap: qualification and selection are separate cache
and review boundaries, so their convenience exports resolve only on demand.
"""

from importlib import import_module
from typing import Any


_QUALIFICATION_V2_EXPORTS = {
    "SemanticProviderQualificationV2Error",
    "SemanticProviderQualificationV2",
    "build_semantic_provider_qualification_v2",
    "write_semantic_provider_qualification_v2",
}
_SELECTION_V2_EXPORTS = {
    "ImplementationSelectionV2Error",
    "ImplementationSelectionV2",
    "build_implementation_selection_v2",
    "write_implementation_selection_v2",
}


def __getattr__(name: str) -> Any:
    if name in _QUALIFICATION_V2_EXPORTS:
        return getattr(import_module(".qualification_v2", __name__), name)
    if name in _SELECTION_V2_EXPORTS:
        return getattr(import_module(".selection_v2", __name__), name)
    raise AttributeError(name)

__all__ = [
    "ImplementationSelectionV2Error",
    "ImplementationSelectionV2",
    "SemanticProviderQualificationV2Error",
    "SemanticProviderQualificationV2",
    "build_implementation_selection_v2",
    "build_semantic_provider_qualification_v2",
    "write_implementation_selection_v2",
    "write_semantic_provider_qualification_v2",
]
