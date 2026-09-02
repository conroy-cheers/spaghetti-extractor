"""Reviewed finite support boundary over the Lean IA-32 form classifier.

This review does not claim that the allowlist is the image of every possible
decoder input.  It makes the stronger fail-closed scheduling statement needed
by the platform: exactly the listed forms are supported, every classifier
constructor is accounted for, and every other classifier output is rejected.
"""

from __future__ import annotations

from pathlib import Path
import re
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..errors import ToolkitInputError
from ..isa.semantic_forms import lean_semantic_form_classifier_sha256
from ..util import sha256_file


PYTHON_RESOURCES = (
    "src/spaghetti_extractor/lean/SpaghettiExtractor/ISA/ISAQualification.lean",
)
_FORM_PREFIX = "SpaghettiExtractor.ISA.Formal.InstructionSemanticForm."
_FORM_RE = re.compile(
    r"SpaghettiExtractor\.ISA\.Formal\.InstructionSemanticForm\."
    r"([A-Za-z][A-Za-z0-9_]*)"
)
_CONSTRUCTOR_RE = re.compile(r"^  \| ([A-Za-z][A-Za-z0-9_]*)", re.MULTILINE)


class QualifiedPlatformISASurfaceReviewError(ToolkitInputError):
    """The finite supported classifier surface is stale or malformed."""


def _fail(message: str) -> None:
    raise QualifiedPlatformISASurfaceReviewError(message)


def _default_classifier_source() -> Path:
    prefix = "src/spaghetti_extractor/"
    relative = PYTHON_RESOURCES[0]
    if not relative.startswith(prefix):
        _fail("classifier resource is outside the Python package")
    package_root = Path(__file__).resolve().parents[1]
    return package_root / relative.removeprefix(prefix)


def _classifier_constructors(source: Path) -> tuple[str, ...]:
    try:
        text = Path(source).read_text(encoding="utf-8")
        block = text.split("inductive InstructionSemanticForm where", 1)[1]
        block = block.split("deriving Repr, DecidableEq", 1)[0]
    except (OSError, UnicodeError, IndexError) as exc:
        _fail(f"cannot read the closed Lean classifier surface: {exc}")
    constructors = tuple(_CONSTRUCTOR_RE.findall(block))
    if not constructors or len(constructors) != len(set(constructors)):
        _fail("Lean instruction semantic-form constructors are missing or duplicated")
    return constructors


def isa_surface_review_payload_v1(
    inventory: Mapping[str, Any],
    *,
    classifier_source: Path | None = None,
) -> dict[str, Any]:
    """Account for the full classifier and freeze one finite exact allowlist."""

    source = (
        _default_classifier_source()
        if classifier_source is None
        else Path(classifier_source)
    )
    classifier_sha256 = lean_semantic_form_classifier_sha256()
    if inventory.get("classifier_sha256") != classifier_sha256:
        _fail("ISA surface review binds a stale classifier")
    inventory_sha256 = inventory.get("inventory_sha256")
    forms = inventory.get("forms")
    if not isinstance(inventory_sha256, str) or not isinstance(forms, list):
        _fail("ISA surface review inventory binding is malformed")
    constructors = _classifier_constructors(source)
    counts = {constructor: 0 for constructor in constructors}
    for index, row in enumerate(forms):
        if not isinstance(row, Mapping):
            _fail(f"ISA surface form {index} is malformed")
        semantic_form = row.get("semantic_form")
        if not isinstance(semantic_form, str):
            _fail(f"ISA surface form {index} has no semantic text")
        match = _FORM_RE.search(semantic_form)
        if match is None or not semantic_form.startswith(_FORM_PREFIX):
            _fail(f"ISA surface form {index} has no canonical constructor")
        constructor = match.group(1)
        if constructor not in counts:
            _fail(
                f"ISA surface form {index} names unknown constructor "
                f"{constructor!r}"
            )
        counts[constructor] += 1
    constructor_rows = [
        {
            "constructor": constructor,
            "listed_form_count": counts[constructor],
            "selection": (
                "exact_form_allowlist" if counts[constructor] else "unsupported"
            ),
        }
        for constructor in sorted(constructors)
    ]
    core: dict[str, Any] = {
        "kind": "qualified-platform-isa-surface-review-v1",
        "status": "complete",
        "role": "reviewed_finite_supported_allowlist",
        "classifier_sha256": classifier_sha256,
        "classifier_surface_source_sha256": sha256_file(source),
        "inventory_sha256": inventory_sha256,
        "selection_policy": {
            "listed_form": "select_exact_qualified_platform_form",
            "unlisted_form": "reject_as_unsupported",
            "constructor_membership": "does_not_imply_form_support",
            "target_occurrence_claims": False,
        },
        "constructors": constructor_rows,
        "counts": {
            "constructors": len(constructors),
            "constructors_with_listed_forms": sum(value > 0 for value in counts.values()),
            "unsupported_constructors": sum(value == 0 for value in counts.values()),
            "listed_forms": len(forms),
        },
    }
    core["review_sha256"] = canonical_sha256_v3(core)
    return core


__all__ = [
    "QualifiedPlatformISASurfaceReviewError",
    "isa_surface_review_payload_v1",
]
