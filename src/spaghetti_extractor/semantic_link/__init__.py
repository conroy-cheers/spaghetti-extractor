"""Checked linking of relocatable semantic objects.

The domain-owned format declaration must remain importable without loading the
semantic compiler and its decoder dependencies.  Public compiler conveniences
therefore resolve lazily for callers that explicitly request them.
"""

from importlib import import_module
from typing import Any

from .formats import (
    LINKED_SEMANTIC_MODULE_V2_FORMAT,
)


_MODULE_V2_EXPORTS = {
    "LinkedSemanticModuleV2",
    "build_linked_semantic_module_v2",
    "linked_execution_view_v2",
    "write_linked_semantic_module_from_inputs_v2",
}


def __getattr__(name: str) -> Any:
    if name == "LinkedSemanticModuleError":
        return getattr(import_module(".errors", __name__), name)
    if name in _MODULE_V2_EXPORTS:
        return getattr(import_module(".module_v2", __name__), name)
    raise AttributeError(name)

__all__ = [
    "LINKED_SEMANTIC_MODULE_V2_FORMAT",
    "LinkedSemanticModuleError",
    "LinkedSemanticModuleV2",
    "build_linked_semantic_module_v2",
    "linked_execution_view_v2",
    "write_linked_semantic_module_from_inputs_v2",
]
