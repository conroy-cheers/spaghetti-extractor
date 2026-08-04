"""Canonical identities for Lean-owned IA-32 semantic forms.

These identities connect exact-PE extraction to the untrusted ISA
qualification pipeline. They are cache and cross-artifact identities only;
they do not establish decoding or semantic correctness.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from .analysis.schema import STATIC_ANALYSIS_MODEL_ID
from .stage_binary import StageAInputError
from .util import sha256_bytes


LEAN_ISA_REQUIREMENT_FORM_FORMAT = "stage-a-lean-x86-semantic-form-v1"
_CLASSIFIER_SOURCES = ("X87.lean", "Formal.lean", "ISAQualification.lean")
_SHA256_RE = re.compile(r"[0-9a-f]{64}")


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def lean_semantic_form_classifier_sha256(
    source_root: Path | None = None,
) -> str:
    """Return the shared identity of the Lean semantic-form classifier."""

    root = (
        Path(__file__).parent / "lean" / "StageA"
        if source_root is None
        else Path(source_root)
    )
    hashes = {
        name: hashlib.sha256((root / name).read_bytes()).hexdigest()
        for name in _CLASSIFIER_SOURCES
    }
    return _canonical_sha256(hashes)


def lean_semantic_form_core(
    semantic_form: str,
    *,
    classifier_sha256: str,
    model: str = STATIC_ANALYSIS_MODEL_ID,
) -> dict[str, str]:
    """Build the sole canonical payload from which a form ID is derived."""

    if (
        not isinstance(classifier_sha256, str)
        or _SHA256_RE.fullmatch(classifier_sha256) is None
    ):
        raise StageAInputError(
            "Lean semantic-form classifier SHA-256 must be 64 lowercase hex characters"
        )
    if (
        not isinstance(semantic_form, str)
        or not semantic_form
        or semantic_form.strip() != semantic_form
    ):
        raise StageAInputError(
            "Lean semantic form must be a nonempty canonical string"
        )
    if not isinstance(model, str) or not model:
        raise StageAInputError("Lean semantic-form model must be nonempty")
    return {
        "format": LEAN_ISA_REQUIREMENT_FORM_FORMAT,
        "model": model,
        "classifier_sha256": classifier_sha256,
        "semantic_form": semantic_form,
    }


def lean_semantic_form_id(
    semantic_form: str,
    *,
    classifier_sha256: str,
    model: str = STATIC_ANALYSIS_MODEL_ID,
) -> str:
    """Return the canonical stable ID for one Lean semantic form."""

    core = lean_semantic_form_core(
        semantic_form,
        classifier_sha256=classifier_sha256,
        model=model,
    )
    return "lean-x86-form-" + _canonical_sha256(core)[:20]


__all__ = [
    "LEAN_ISA_REQUIREMENT_FORM_FORMAT",
    "lean_semantic_form_classifier_sha256",
    "lean_semantic_form_core",
    "lean_semantic_form_id",
]
