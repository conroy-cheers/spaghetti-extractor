"""Exact target-bundle file ownership checks."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path, PurePosixPath
from typing import Any, Iterable, Mapping

from ..util import write_json
from .metadata import TargetMetadata, TargetMetadataError


TARGET_BUNDLE_LINT_FORMAT = "spaghetti-extractor-target-bundle-lint-v1"
TARGET_ASSET_ROLES = frozenset(
    {
        "metadata",
        "module",
        "component_intent",
        "component_review",
        "component_source",
        "candidate_test",
        "runtime",
        "documentation",
        "license",
    }
)
_MANUAL_ROLES = frozenset({"runtime", "documentation", "license"})
_FORBIDDEN_PARTS = frozenset(
    {".cache", ".direnv", "build", "generated", "result", "results"}
)


class TargetBundleLintError(ValueError):
    """A target ownership declaration is malformed."""


@dataclass(frozen=True, order=True)
class TargetAsset:
    path: PurePosixPath
    role: str
    owner: str

    @classmethod
    def parse(cls, value: Mapping[str, Any], *, index: int) -> "TargetAsset":
        if set(value) != {"path", "role", "owner"}:
            raise TargetBundleLintError(
                f"target asset {index} must contain path, role, and owner"
            )
        raw_path = value.get("path")
        role = value.get("role")
        owner = value.get("owner")
        if not all(isinstance(item, str) and item for item in (raw_path, role, owner)):
            raise TargetBundleLintError(f"target asset {index} has empty fields")
        path = PurePosixPath(str(raw_path))
        if path.is_absolute() or not path.parts or any(
            part in {"", ".", ".."} for part in path.parts
        ):
            raise TargetBundleLintError(
                f"target asset {index} path is not a strict relative path"
            )
        if role not in TARGET_ASSET_ROLES:
            raise TargetBundleLintError(
                f"target asset {index} has unsupported role {role!r}"
            )
        if role in _MANUAL_ROLES and path.parts[0] in _FORBIDDEN_PARTS:
            raise TargetBundleLintError(
                f"target asset {index} declares generated workspace content"
            )
        return cls(path=path, role=str(role), owner=str(owner))

    def as_json(self) -> dict[str, str]:
        return {"path": self.path.as_posix(), "role": self.role, "owner": self.owner}


def lint_target_bundle(
    *,
    target_root: Path,
    target_id: str,
    declared_assets: Iterable[Mapping[str, Any]],
    out: Path,
) -> dict[str, Any]:
    root = Path(target_root)
    if not target_id:
        raise TargetBundleLintError("target id must be nonempty")
    if not root.is_dir():
        raise TargetBundleLintError("target root is not a directory")
    try:
        metadata = TargetMetadata.load(root / "target.json")
    except TargetMetadataError as exc:
        raise TargetBundleLintError(str(exc)) from exc
    if metadata.identity != target_id:
        raise TargetBundleLintError("target metadata ID does not match the bundle")
    assets = tuple(
        TargetAsset.parse(value, index=index)
        for index, value in enumerate(declared_assets)
    )
    paths = [asset.path.as_posix() for asset in assets]
    duplicates = sorted({path for path in paths if paths.count(path) > 1})
    declared = set(paths)
    actual: set[str] = set()
    symlinks: list[str] = []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root).as_posix()
        if path.is_symlink():
            symlinks.append(relative)
        elif path.is_file():
            actual.add(relative)
    missing = sorted(declared - actual)
    undeclared = sorted(actual - declared)
    issues = [
        *(
            {"code": "duplicate_asset_declaration", "path": path}
            for path in duplicates
        ),
        *({"code": "missing_declared_asset", "path": path} for path in missing),
        *({"code": "undeclared_target_asset", "path": path} for path in undeclared),
        *({"code": "target_asset_symlink", "path": path} for path in symlinks),
    ]
    core: dict[str, Any] = {
        "format": TARGET_BUNDLE_LINT_FORMAT,
        "target_id": target_id,
        "status": "checked" if not issues else "violated",
        "assets": [asset.as_json() for asset in sorted(assets)],
        "counts": {
            "declared": len(declared),
            "actual": len(actual),
            "issues": len(issues),
        },
        "issues": issues,
        "policy": {
            "exact_file_ownership": True,
            "symlinks_allowed": False,
            "generated_target_assets_allowed": False,
        },
    }
    digest = hashlib.sha256(
        json.dumps(core, sort_keys=True, separators=(",", ":")).encode("ascii")
    ).hexdigest()
    result = {**core, "lint_sha256": digest}
    write_json(Path(out), result)
    return result


__all__ = [
    "TARGET_ASSET_ROLES",
    "TARGET_BUNDLE_LINT_FORMAT",
    "TargetAsset",
    "TargetBundleLintError",
    "lint_target_bundle",
]
