"""Regional replacement formats, models, and JSON primitives."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Mapping

from ..artifacts.formats import REGION_REPLACEMENT_BUNDLE_FORMAT
from ..pe32.stage_binary import StageAInputError

REGION_REPLACEMENT_FORMAT = "stage-b-region-replacement-v1"
_REGION_REPLACEMENT_FORMATS = frozenset(
    {REGION_REPLACEMENT_FORMAT, REGION_REPLACEMENT_BUNDLE_FORMAT}
)
REGION_OBSERVATIONS_FORMAT = "stage-b-region-observations-v1"
REGION_REPLACEMENT_VALIDATION_FORMAT = (
    "stage-b-region-replacement-validation-v1"
)
REGION_OVERRIDE_TABLE_FORMAT = "stage-b-region-override-table-v1"

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_ID_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9_.:/-]{0,254}[A-Za-z0-9])?")
_C_ID_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_HEX_RE = re.compile(r"(?:[0-9a-f]{2})*")
_UINT32_MAX = (1 << 32) - 1
_REGISTERS = frozenset(
    {
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp", "eip",
        "cf", "pf", "af", "zf", "sf", "tf", "if", "df", "of",
        "st0", "st1", "st2", "st3", "st4", "st5", "st6", "st7",
    }
)
_EVIDENCE_CLASSES = frozenset(
    {
        "formal", "exhaustive", "solver", "differential", "fuzzed",
        "integration", "assumed", "unsupported",
    }
)
_STATUSES = frozenset({"qualified", "incomplete", "violated"})
_CALLING_CONVENTIONS = frozenset(
    {"machine_state", "cdecl", "stdcall", "fastcall", "thiscall", "custom"}
)
_LIVE_KINDS = frozenset(
    {"register", "flag", "x87", "memory", "resource", "external_world"}
)
_MEMORY_ACCESS = frozenset({"read", "write", "read_write"})
_CONTROL_KINDS = frozenset(
    {
        "fallthrough", "jump", "branch", "return", "indirect_jump",
        "external_jump", "terminate",
    }
)
_TYPE_BASES = frozenset({"checked", "inferred", "manual"})


@dataclass(frozen=True)
class RegionReplacementManifest:
    """A validated, canonical regional replacement contract."""

    payload: Mapping[str, Any]

    @property
    def id(self) -> str:
        return str(self.payload["id"])

    @property
    def manifest_sha256(self) -> str:
        return str(self.payload["manifest_sha256"])

    @property
    def cluster(self) -> Mapping[str, Any]:
        return _object(self.payload["cluster"], "replacement cluster")

    @property
    def source(self) -> Mapping[str, Any]:
        return _object(self.payload["source"], "replacement source")

    @property
    def support_sources(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            _object(item, "replacement support source")
            for item in self.payload.get("support_sources", [])
        )

    @property
    def bindings(self) -> Mapping[str, Any]:
        return _object(self.payload["bindings"], "replacement bindings")

    @property
    def evidence(self) -> tuple[Mapping[str, Any], ...]:
        return tuple(
            _object(item, "replacement evidence")
            for item in _array(self.payload["evidence"], "replacement evidence")
        )

    def to_payload(self) -> dict[str, Any]:
        return _json_copy(self.payload)


@dataclass(frozen=True)
class RegionOverrideTableArtifacts:
    header: Path
    source: Path
    manifest: Path
    count: int


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")
    return sha256(encoded).hexdigest()


def _json_copy(value: Any) -> Any:
    return json.loads(json.dumps(value, sort_keys=True, ensure_ascii=True))


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _array(value: Any, context: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    return value
