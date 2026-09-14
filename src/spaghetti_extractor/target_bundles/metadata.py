"""Strict metadata model for reusable validation target bundles."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Mapping


TARGET_BUNDLE_METADATA_FORMAT = "spaghetti-extractor-target-bundle-v3"
_IDENTIFIER = re.compile(r"[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


class TargetMetadataError(ValueError):
    """Target metadata is malformed, ambiguous, or unsupported."""


@dataclass(frozen=True)
class TargetInputMetadata:
    kind: str
    expected_sha256: str


@dataclass(frozen=True)
class TargetWorkflowMetadata:
    default_configuration: str | None


@dataclass(frozen=True)
class TargetMetadata:
    identity: str
    display_name: str
    input: TargetInputMetadata
    paths: tuple[tuple[str, PurePosixPath], ...]
    workflow: TargetWorkflowMetadata

    @classmethod
    def parse(cls, value: object) -> "TargetMetadata":
        root = _object(value, "target metadata")
        _exact_keys(
            root,
            {"format", "id", "display_name", "input", "paths", "workflow"},
            "target metadata",
        )
        if root.get("format") != TARGET_BUNDLE_METADATA_FORMAT:
            raise TargetMetadataError("unsupported target metadata format")
        identity = _identifier(root.get("id"), "target id")
        display_name = _text(root.get("display_name"), "target display name")

        input_row = _object(root.get("input"), "target input")
        _exact_keys(input_row, {"kind", "expected_sha256"}, "target input")
        kind = _text(input_row.get("kind"), "target input kind")
        if kind != "pe32":
            raise TargetMetadataError(f"unsupported target input kind: {kind}")
        digest = _text(input_row.get("expected_sha256"), "target input SHA-256")
        if _SHA256.fullmatch(digest) is None:
            raise TargetMetadataError("target input SHA-256 is not canonical")

        path_row = _object(root.get("paths"), "target paths")
        _required_optional_keys(
            path_row,
            {"nix", "components"},
            {"component_sources", "libraries"},
            "target paths",
        )
        component_path = path_row.get("components")
        path_items = [
            ("nix", _relative_path(path_row["nix"], "target path nix"))
        ]
        if component_path is not None:
            path_items.append(
                (
                    "components",
                    _relative_path(component_path, "target path components"),
                )
            )
        component_source_path = path_row.get("component_sources")
        if component_source_path is not None:
            if component_path is None:
                raise TargetMetadataError(
                    "component source path requires a component intent path"
                )
            path_items.append(
                (
                    "component_sources",
                    _relative_path(
                        component_source_path, "target path component sources"
                    ),
                )
            )
        library_path = path_row.get("libraries")
        if library_path is not None:
            path_items.append(
                (
                    "libraries",
                    _relative_path(library_path, "target path libraries"),
                )
            )
        paths = tuple(path_items)

        workflow_row = _object(root.get("workflow"), "target workflow")
        _exact_keys(
            workflow_row,
            {"default_configuration"},
            "target workflow",
        )
        default_value = workflow_row.get("default_configuration")
        default_configuration = (
            None
            if default_value is None
            else _identifier(default_value, "default component configuration")
        )
        if (component_path is None) != (default_configuration is None):
            raise TargetMetadataError(
                "component path and default configuration must both be set or both be null"
            )
        return cls(
            identity=identity,
            display_name=display_name,
            input=TargetInputMetadata(kind=kind, expected_sha256=digest),
            paths=paths,
            workflow=TargetWorkflowMetadata(
                default_configuration=default_configuration
            ),
        )

    @classmethod
    def load(cls, path: Path | str) -> "TargetMetadata":
        try:
            payload = json.loads(Path(path).read_text(encoding="utf-8"))
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise TargetMetadataError(f"cannot read target metadata: {exc}") from exc
        return cls.parse(payload)


def _object(value: object, description: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping) or any(
        not isinstance(key, str) for key in value
    ):
        raise TargetMetadataError(f"{description} must be an object")
    return value


def _exact_keys(
    value: Mapping[str, object], expected: set[str], description: str
) -> None:
    if set(value) != expected:
        missing = sorted(expected - set(value))
        extra = sorted(set(value) - expected)
        raise TargetMetadataError(
            f"{description} has invalid fields: missing={missing}, extra={extra}"
        )


def _required_optional_keys(
    value: Mapping[str, object],
    required: set[str],
    optional: set[str],
    description: str,
) -> None:
    missing = sorted(required - set(value))
    extra = sorted(set(value) - required - optional)
    if missing or extra:
        raise TargetMetadataError(
            f"{description} has invalid fields: missing={missing}, extra={extra}"
        )


def _text(value: object, description: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise TargetMetadataError(f"{description} must be a nonempty canonical string")
    return value


def _identifier(value: object, description: str) -> str:
    text = _text(value, description)
    if _IDENTIFIER.fullmatch(text) is None:
        raise TargetMetadataError(f"{description} is not a canonical identifier")
    return text


def _relative_path(value: object, description: str) -> PurePosixPath:
    path = PurePosixPath(_text(value, description))
    if path.is_absolute() or not path.parts or any(
        part in {"", ".", ".."} for part in path.parts
    ):
        raise TargetMetadataError(f"{description} is not a strict relative path")
    return path


__all__ = [
    "TARGET_BUNDLE_METADATA_FORMAT",
    "TargetInputMetadata",
    "TargetMetadata",
    "TargetMetadataError",
    "TargetWorkflowMetadata",
]
