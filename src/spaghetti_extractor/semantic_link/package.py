"""Filesystem publication for a checked linked-semantic-module package."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path

from ..semantic_objects.semantic_object import SemanticObjectV1
from .errors import LinkedSemanticModuleError


def publish_semantic_package_v1(
    *, semantic: SemanticObjectV1, semantic_object: Path, out: Path,
) -> None:
    """Publish checked semantic-object members without copying or rewriting."""

    if semantic.package_root is None:
        raise LinkedSemanticModuleError(
            "semantic link requires a packaged semantic object"
        )
    rows = [(Path(semantic_object), Path("semantic-object.json"))]
    for raw in semantic.payload["members"].values():
        if not isinstance(raw, Mapping):
            raise LinkedSemanticModuleError(
                "semantic-object package member must be an object"
            )
        relative = Path(str(raw["path"]))
        if relative.is_absolute() or ".." in relative.parts:
            raise LinkedSemanticModuleError(
                "semantic-object package member path escapes its package"
            )
        rows.append((semantic.package_root / relative, relative))
    for source, relative in rows:
        if not source.exists():
            raise LinkedSemanticModuleError(
                f"semantic-object package member {relative} is absent"
            )
        destination = Path(out) / relative
        if destination.exists() or destination.is_symlink():
            if destination.resolve() == source.resolve():
                continue
            raise LinkedSemanticModuleError(
                f"linked semantic package member {relative} collides"
            )
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.symlink_to(
            source.resolve(), target_is_directory=source.is_dir()
        )


__all__ = ["publish_semantic_package_v1"]
