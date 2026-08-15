"""Data model and constants for interpreter-native builds."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from . import native_build


INTERPRETER_NATIVE_BUILD_MANIFEST_FILENAME = "interpreter-native-build-manifest.json"
INTERPRETER_NATIVE_OBJECT_GRAPH_FORMAT = "spaghetti-extractor-interpreter-native-object-graph-v2"
INTERPRETER_NATIVE_OBJECT_FORMAT = "spaghetti-extractor-interpreter-native-object-v2"
INTERPRETER_NATIVE_OBJECT_PACKAGE_FORMAT = "spaghetti-extractor-interpreter-native-object-package-v2"
INTERPRETER_NATIVE_SOURCE_BUNDLE_FORMAT = (
    "spaghetti-extractor-interpreter-native-source-bundle-v1"
)
INTERPRETER_NATIVE_BUNDLE_INDEX_FORMAT = (
    "spaghetti-extractor-interpreter-native-bundle-index-v1"
)

_INTERPRETER_MANIFEST_FILENAME = "state-machine-interpreter-package.json"
_ENGINE_MANIFEST_FILENAME = "native-engine-package.json"
_PAYLOAD_FILENAME = native_build.PAYLOAD_FILENAME
_PAYLOAD_MAP_FILENAME = native_build.PAYLOAD_MAP_FILENAME
_ENGINE_LAYOUT_FILENAME = native_build.ENGINE_LAYOUT_FILENAME
_RELOCATION_INVENTORY_FILENAME = native_build.PAYLOAD_RELOCATION_INVENTORY_FILENAME
_GENERATED_ANCHOR_FILENAME = "executable-anchor-manifest.json"
_C_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*\Z")
_INCLUDE_DIRECTIVE = re.compile(r'^\s*#\s*include\s+(.+?)\s*(?://.*)?$')
_QUOTED_INCLUDE = re.compile(r'^"([^"\r\n]+)"(?:\s*/\*.*\*/\s*)?$')
_SYSTEM_INCLUDE = re.compile(r"^<[^>\r\n]+>(?:\s*/\*.*\*/\s*)?$")
_PAYLOAD_SYMBOL = re.compile(
    r"(?m)^\s*(0x[0-9a-fA-F]+)\s+(_?spx_payload_(?:entry|callback_[0-9a-fA-F]{8}))\b"
)


class CandidateNativeBuildError(ValueError):
    """An interpreter-native candidate input or output failed validation."""


@dataclass(frozen=True)
class _Artifact:
    owner: str
    role: str
    relative_path: str
    sha256: str
    path: Path

    def payload(self) -> dict[str, Any]:
        return {
            "owner": self.owner,
            "role": self.role,
            "path": self.relative_path,
            "sha256": self.sha256,
        }


@dataclass(frozen=True)
class _Package:
    owner: str
    root: Path
    manifest_path: Path
    manifest_sha256: str
    payload: Mapping[str, Any]
    artifacts: tuple[_Artifact, ...]

    def binding(self) -> dict[str, Any]:
        return {
            "manifest": self.manifest_path.name,
            "manifest_sha256": self.manifest_sha256,
            "artifacts": [item.payload() for item in self.artifacts],
        }
