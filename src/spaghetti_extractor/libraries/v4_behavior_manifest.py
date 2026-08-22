"""Lightweight behavior-pack manifest parsing for proposal and status phases."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import (
    REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT,
    REUSABLE_LIBRARY_BEHAVIOR_PACK_V2_FORMAT,
)
from ..util import sha256_file
from .v4_adoption_records import (
    REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1,
    ReusableLibraryImplementationV1,
)
from .v4_record_support import canonical_sha256


_ARTIFACT_PATHS = {
    "implementation": "implementation.json",
    "source_manifest": "source-package/source-package.json",
    "interface": "portable-interface.json",
    "source_profile": "source-profile.json",
    "compile_receipt": "compile-receipt.json",
    "qualification_receipt": "qualification-receipt.json",
}
_ARTIFACT_PATHS_V2 = {
    **_ARTIFACT_PATHS,
    "behavior_contract": "behavior-contract.json",
}
_FIELDS = {
    "format",
    "id",
    "implementation_id",
    "implementation_sha256",
    "source_id",
    "source_package_sha256",
    "interface_contract_id",
    "interface_sha256",
    "effect_contract_ids",
    "compile_profile_id",
    "source_profile_receipt_sha256",
    "compile_receipt_sha256",
    "qualification_checker_id",
    "qualification_receipt_sha256",
    "artifacts",
    "pack_sha256",
}
_FIELDS_V2 = {
    "format",
    "id",
    "implementation_id",
    "implementation_sha256",
    "source_id",
    "source_package_sha256",
    "interface_contract_id",
    "interface_sha256",
    "behavior_contract_id",
    "behavior_contract_sha256",
    "state_field_ids",
    "operation_ids",
    "memory_effect_ids",
    "resource_effect_ids",
    "callback_effect_ids",
    "externally_visible_effect_ids",
    "service_ids",
    "compile_profile_id",
    "source_profile_receipt_sha256",
    "compile_receipt_sha256",
    "qualification_checker_id",
    "qualification_receipt_sha256",
    "artifacts",
    "pack_sha256",
}


class LibraryBehaviorManifestError(ValueError):
    """A behavior-pack inventory is malformed or stale."""


@dataclass(frozen=True)
class LibraryBehaviorPackDeclarationV1:
    root: Path
    manifest: Mapping[str, Any]
    implementation: ReusableLibraryImplementationV1

    @property
    def pack_sha256(self) -> str:
        return str(self.manifest["pack_sha256"])


def read_library_behavior_pack_declaration_v1(
    value: Path | str,
) -> LibraryBehaviorPackDeclarationV1:
    result = read_library_behavior_pack_declaration(value)
    if result.manifest.get("format") != REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT:
        raise LibraryBehaviorManifestError("behavior pack is not V1")
    return result


def read_library_behavior_pack_declaration(
    value: Path | str,
) -> LibraryBehaviorPackDeclarationV1:
    root = Path(value)
    if root.is_file():
        root = root.parent
    try:
        raw = json.loads((root / "behavior-pack.json").read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise LibraryBehaviorManifestError(
            f"cannot read behavior-pack manifest: {error}"
        ) from error
    if not isinstance(raw, Mapping):
        raise LibraryBehaviorManifestError(
            "behavior-pack manifest is not an object"
        )
    format_name = raw.get("format")
    if format_name == REUSABLE_LIBRARY_BEHAVIOR_PACK_V1_FORMAT:
        fields = _FIELDS
        artifact_paths = _ARTIFACT_PATHS
    elif format_name == REUSABLE_LIBRARY_BEHAVIOR_PACK_V2_FORMAT:
        fields = _FIELDS_V2
        artifact_paths = _ARTIFACT_PATHS_V2
    else:
        raise LibraryBehaviorManifestError("unsupported behavior-pack format")
    if set(raw) != fields:
        raise LibraryBehaviorManifestError(
            "behavior-pack manifest fields are not canonical"
        )
    manifest = dict(raw)
    core = dict(manifest)
    if core.pop("pack_sha256", None) != canonical_sha256(core):
        raise LibraryBehaviorManifestError("behavior-pack manifest hash is stale")
    artifacts = manifest.get("artifacts")
    if not isinstance(artifacts, Mapping) or set(artifacts) != set(artifact_paths):
        raise LibraryBehaviorManifestError(
            "behavior-pack artifact inventory is not canonical"
        )
    for artifact_id, relative in artifact_paths.items():
        row = artifacts[artifact_id]
        if not isinstance(row, Mapping) or set(row) != {"path", "sha256"}:
            raise LibraryBehaviorManifestError(
                f"behavior-pack artifact {artifact_id!r} is malformed"
            )
        if row.get("path") != relative:
            raise LibraryBehaviorManifestError(
                f"behavior-pack artifact {artifact_id!r} has a stale path"
            )
        path = root / relative
        if not path.is_file() or row.get("sha256") != sha256_file(path):
            raise LibraryBehaviorManifestError(
                f"behavior-pack artifact {artifact_id!r} has a stale hash"
            )
    implementation = REUSABLE_LIBRARY_IMPLEMENTATION_CODEC_V1.read(
        root / artifact_paths["implementation"]
    )
    if (
        implementation.implementation_id != manifest.get("implementation_id")
        or implementation.implementation_sha256
        != manifest.get("implementation_sha256")
    ):
        raise LibraryBehaviorManifestError(
            "behavior-pack implementation binding is stale"
        )
    return LibraryBehaviorPackDeclarationV1(root, manifest, implementation)


__all__ = [
    "LibraryBehaviorManifestError",
    "LibraryBehaviorPackDeclarationV1",
    "read_library_behavior_pack_declaration",
    "read_library_behavior_pack_declaration_v1",
]
