"""Lightweight V3 behavior-pack declaration loading for proposal phases."""

from __future__ import annotations

from pathlib import Path

from .behavior_pack_v3 import (
    ReusableLibraryBehaviorPackV3,
    ReusableLibraryBehaviorPackV3Error,
    load_reusable_library_behavior_pack_v3,
)


LibraryBehaviorManifestError = ReusableLibraryBehaviorPackV3Error
LibraryBehaviorPackDeclarationV3 = ReusableLibraryBehaviorPackV3


def read_library_behavior_pack_declaration(
    value: Path | str,
) -> LibraryBehaviorPackDeclarationV3:
    """Read the sole active reusable-library behavior-pack contract."""

    return load_reusable_library_behavior_pack_v3(value)


__all__ = [
    "LibraryBehaviorManifestError",
    "LibraryBehaviorPackDeclarationV3",
    "read_library_behavior_pack_declaration",
]
