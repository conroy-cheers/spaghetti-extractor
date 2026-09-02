"""Closed, target-independent IA-32 semantic-form inventory.

The current inventory is a migration seed frozen from the four-target parity
prototype, not a projection of any target at build time and not qualification
evidence.  Each entry names one Lean-owned semantic form and one canonical
representative encoding.  Lean replay, finite-inventory review, and
qualification are separate steps; this codec grants none of them authority.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..extraction.schema import STATIC_ANALYSIS_MODEL_ID
from ..isa.catalog import ISA_PROFILE_ID
from ..isa.semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from ..util import write_json
from .formats import QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_FORMAT


MAX_QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_BYTES = 4 * 1024 * 1024
PYTHON_RESOURCES = (
    "src/spaghetti_extractor/qualified_platform/pe32_i686_isa_forms.json",
)
_FIELDS = {
    "format",
    "profile",
    "model",
    "classifier_sha256",
    "role",
    "forms",
    "counts",
    "inventory_sha256",
}
_FORM_FIELDS = {
    "form_id",
    "semantic_form",
    "representative_instruction_hex",
}


class QualifiedPlatformISAFormInventoryError(ToolkitInputError):
    """The intrinsic platform form inventory is malformed or stale."""


def _fail(message: str) -> None:
    raise QualifiedPlatformISAFormInventoryError(message)


def _object(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{context} must be an object")
    return value


def _string(value: object, context: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(
            ord(character) < 0x20 and character not in "\n\t"
            for character in value
        )
    ):
        _fail(f"{context} must be a nonempty canonical string")
    return value


def _instruction_hex(value: object, context: str) -> str:
    encoded = _string(value, context)
    if (
        len(encoded) % 2
        or not 1 <= len(encoded) // 2 <= 15
        or any(character not in "0123456789abcdef" for character in encoded)
    ):
        _fail(f"{context} must be one canonical IA-32 instruction")
    return encoded


def build_qualified_platform_isa_form_inventory_v1(
    forms: Sequence[Mapping[str, object]],
) -> dict[str, Any]:
    """Build a canonical inventory from reviewed form declarations."""

    classifier_sha256 = lean_semantic_form_classifier_sha256()
    rows: list[dict[str, str]] = []
    for index, raw in enumerate(forms):
        row = _object(raw, f"form {index}")
        if set(row) != _FORM_FIELDS:
            _fail(f"form {index} field inventory is invalid")
        semantic_form = _string(row.get("semantic_form"), f"form {index} semantics")
        form_id = _string(row.get("form_id"), f"form {index} ID")
        if form_id != lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        ):
            _fail(f"form {index} identity is stale")
        rows.append({
            "form_id": form_id,
            "semantic_form": semantic_form,
            "representative_instruction_hex": _instruction_hex(
                row.get("representative_instruction_hex"),
                f"form {index} representative",
            ),
        })
    if not rows:
        _fail("platform form inventory must not be empty")
    form_ids = [row["form_id"] for row in rows]
    if form_ids != sorted(set(form_ids)):
        _fail("platform forms must have unique canonical IDs in order")
    representatives = [row["representative_instruction_hex"] for row in rows]
    if len(representatives) != len(set(representatives)):
        _fail("platform forms must have distinct representative encodings")
    payload: dict[str, Any] = {
        "format": QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_FORMAT,
        "profile": ISA_PROFILE_ID,
        "model": STATIC_ANALYSIS_MODEL_ID,
        "classifier_sha256": classifier_sha256,
        "role": "target_independent_migration_seed",
        "forms": rows,
        "counts": {"forms": len(rows), "representatives": len(rows)},
    }
    payload["inventory_sha256"] = canonical_sha256_v3(payload)
    return payload


def parse_qualified_platform_isa_form_inventory_v1(
    value: object,
) -> dict[str, Any]:
    payload = dict(_object(value, "qualified-platform ISA form inventory"))
    if set(payload) != _FIELDS:
        _fail("qualified-platform ISA form inventory fields are invalid")
    if payload.get("format") != QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_FORMAT:
        _fail("qualified-platform ISA form inventory format is unsupported")
    raw_forms = payload.get("forms")
    if not isinstance(raw_forms, list):
        _fail("qualified-platform ISA form inventory forms must be an array")
    rebuilt = build_qualified_platform_isa_form_inventory_v1(raw_forms)
    if payload != rebuilt:
        _fail("qualified-platform ISA form inventory does not replay")
    return rebuilt


def load_qualified_platform_isa_form_inventory_v1(path: Path) -> dict[str, Any]:
    source = Path(path)
    try:
        if source.stat().st_size > MAX_QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_BYTES:
            _fail("qualified-platform ISA form inventory exceeds the byte bound")
        payload = json.loads(source.read_bytes())
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(f"cannot read qualified-platform ISA form inventory: {exc}")
    return parse_qualified_platform_isa_form_inventory_v1(payload)


def default_qualified_platform_isa_form_inventory_path() -> Path:
    return Path(__file__).with_name("pe32_i686_isa_forms.json")


def write_qualified_platform_isa_form_inventory_v1(
    *, forms: Sequence[Mapping[str, object]], out: Path,
) -> dict[str, Any]:
    payload = build_qualified_platform_isa_form_inventory_v1(forms)
    write_json(Path(out), payload)
    return payload


__all__ = [
    "MAX_QUALIFIED_PLATFORM_ISA_FORM_INVENTORY_BYTES",
    "QualifiedPlatformISAFormInventoryError",
    "build_qualified_platform_isa_form_inventory_v1",
    "default_qualified_platform_isa_form_inventory_path",
    "load_qualified_platform_isa_form_inventory_v1",
    "parse_qualified_platform_isa_form_inventory_v1",
    "write_qualified_platform_isa_form_inventory_v1",
]
