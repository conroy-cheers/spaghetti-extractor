"""Linked-library model."""

from __future__ import annotations

import copy
import json
import struct
from collections import Counter, defaultdict
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import Any, Iterable, Mapping, Sequence

from ..artifacts.formats import (
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
    LIBRARY_CATALOG_LOCK_FORMAT,
    LIBRARY_HYPOTHESIS_SET_FORMAT,
    LIBRARY_INTERFACE_CATALOG_FORMAT,
    LIBRARY_MATCH_EVIDENCE_FORMAT,
    LIBRARY_REPLACEMENT_PLAN_FORMAT,
    DYNAMIC_LIBRARY_REQUIREMENTS_FORMAT,
    LINKED_INTERFACE_ASSIGNMENTS_FORMAT,
    LINKED_INTERFACE_QUALIFICATION_FORMAT,
    LINKED_ISLAND_MANIFEST_FORMAT,
    LINKED_ISLAND_MANIFEST_V2_FORMAT,
    LINKED_ISLAND_REVIEW_FORMAT,
    MACHINE_IR_FORMAT,
)
from ..errors import ToolkitInputError
from ..pe32.image import parse_pe_image
from .contracts import (
    validate_linked_island_manifest as _validate_linked_island_contract,
)
from ..util import sha256_file, write_json



_AR_MAGIC = b"!<arch>\n"
_THIN_AR_MAGIC = b"!<thin>\n"
_PE_MACHINE_I386 = 0x014C
_PE_MACHINE_AMD64 = 0x8664
_COFF_RELOCATION_WIDTHS_I386 = {
    0x0001: 2,
    0x0002: 2,
    0x0006: 4,
    0x0007: 4,
    0x000A: 2,
    0x000B: 4,
    0x000C: 1,
    0x0014: 4,
}
_COFF_RELOCATION_WIDTHS_AMD64 = {
    0x0001: 8,
    0x0002: 4,
    0x0003: 4,
    0x0004: 4,
    0x0005: 4,
    0x0006: 4,
    0x0007: 4,
    0x0008: 4,
    0x0009: 4,
    0x000A: 4,
    0x000B: 4,
}
_ISLAND_KINDS = {
    "application",
    "linked_dependency",
    "compiler_linker_support",
    "import_thunk",
    "unknown",
}
_MATCH_AUTHORITIES = {
    "exact_artifact",
    "exact_normalized_object",
    "operator_reviewed_exact_complement",
    "operator_reviewed_exact_range",
    "proposal_only",
    "none",
}
_REVIEWED_COMPLEMENT_AUTHORITY = "operator_reviewed_exact_complement"
_REVIEWED_COMPLEMENT_SCOPE = "otherwise_unclaimed_exact_machine_units"
_REPLACEMENT_KINDS = {
    "replace_by_canonical_interface",
    "replace_with_pinned_source_dependency",
    "relink_pinned_object",
    "lift_locally",
    "portable_machine_ir_fallback",
}
_ARTIFACT_INPUT_FORMATS = {
    LIBRARY_ARTIFACT_INPUTS_FORMAT,
    LIBRARY_ARTIFACT_INPUTS_V2_FORMAT,
}
_ARTIFACT_INDEX_FORMATS = {
    LIBRARY_ARTIFACT_INDEX_FORMAT,
    LIBRARY_ARTIFACT_INDEX_V2_FORMAT,
}
_IDENTITY_STATUSES = {
    "exact_artifact",
    "exact_release",
    "library_family_abi",
    "ambiguous_family",
    "unidentified",
}
_DEFAULT_HYPOTHESIS_CAP = 256


class LinkedLibraryError(ValueError):
    """A linked-library artifact is malformed, stale, or contradictory."""


@dataclass(frozen=True)
class _Unit:
    identity: str
    start: int
    end: int
    payload: Mapping[str, Any]


@dataclass(frozen=True)
class _MachinePackage:
    root: Path
    manifest_path: Path
    ir_path: Path
    manifest: Mapping[str, Any]
    units: tuple[_Unit, ...]
    by_id: Mapping[str, _Unit]
    ir_sha256: str
    manifest_sha256: str
