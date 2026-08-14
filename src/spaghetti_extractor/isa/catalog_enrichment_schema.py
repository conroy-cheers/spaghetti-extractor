"""Validation for side-ISA executable catalog proposals."""

from __future__ import annotations

import re
from typing import Any

from .catalog import ISA_PROFILE_ID
from .catalog_enrichment import (
    _PROPOSAL_ENCODING_FORMAT,
    _encoding_id,
    _exact_fields,
    _objects,
    _sha256,
    _string,
    _strings,
    _uint,
)
from .semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from .side_adapter import SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
from ..extraction.schema import STATIC_ANALYSIS_MODEL_ID
from ..pe32.stage_binary import StageAInputError

def _parse_proposal(value: Any) -> dict[str, Any]:
    payload = _exact_fields(
        value,
        {
            "format",
            "status",
            "profile",
            "model",
            "classifier_sha256",
            "requirements_sha256",
            "source",
            "forms",
            "encodings",
            "missing_enrichment",
            "counts",
            "trust",
        },
        "side-ISA catalog proposal",
    )
    if payload.get("format") != SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT:
        raise StageAInputError("unsupported side-ISA catalog proposal format")
    if payload.get("status") != "incomplete_missing_effect_enrichment":
        raise StageAInputError("side-ISA catalog proposal status is invalid")
    if payload.get("profile") != ISA_PROFILE_ID:
        raise StageAInputError("side-ISA catalog proposal profile is invalid")
    if payload.get("model") != STATIC_ANALYSIS_MODEL_ID:
        raise StageAInputError("side-ISA catalog proposal model is invalid")
    classifier_sha256 = _sha256(
        payload.get("classifier_sha256"),
        "side-ISA catalog proposal classifier_sha256",
    )
    if classifier_sha256 != lean_semantic_form_classifier_sha256():
        raise StageAInputError(
            "side-ISA catalog proposal uses a stale Lean semantic classifier"
        )
    _sha256(
        payload.get("requirements_sha256"),
        "side-ISA catalog proposal requirements_sha256",
    )

    source = _exact_fields(
        payload.get("source"),
        {"adapter", "side_isa_artifacts"},
        "side-ISA catalog proposal source",
    )
    _string(source.get("adapter"), "side-ISA catalog proposal source.adapter")
    side_sources = _objects(
        source.get("side_isa_artifacts"),
        "side-ISA catalog proposal source.side_isa_artifacts",
    )
    if not 1 <= len(side_sources) <= 2:
        raise StageAInputError(
            "side-ISA catalog proposal must name one or two side artifacts"
        )
    seen_sides: list[str] = []
    for index, row in enumerate(side_sources):
        context = f"side-ISA catalog proposal side source {index}"
        row = _exact_fields(
            row,
            {"side", "binary_sha256", "artifact_sha256"},
            context,
        )
        side = _string(row.get("side"), f"{context}.side")
        if side not in {"original", "candidate"}:
            raise StageAInputError(f"{context}.side is invalid")
        seen_sides.append(side)
        _sha256(row.get("binary_sha256"), f"{context}.binary_sha256")
        _sha256(row.get("artifact_sha256"), f"{context}.artifact_sha256")
    if seen_sides != [side for side in ("original", "candidate") if side in seen_sides]:
        raise StageAInputError(
            "side-ISA catalog proposal side sources are not canonically ordered"
        )
    if len(seen_sides) != len(set(seen_sides)):
        raise StageAInputError("side-ISA catalog proposal repeats a side source")

    raw_forms = _objects(payload.get("forms"), "side-ISA catalog proposal forms")
    forms: list[dict[str, Any]] = []
    forms_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_forms):
        context = f"side-ISA catalog proposal forms[{index}]"
        row = _exact_fields(
            raw,
            {
                "form_id",
                "semantic_form",
                "representative_encoding_id",
                "encoding_ids",
            },
            context,
        )
        semantic_form = _string(row.get("semantic_form"), f"{context}.semantic_form")
        form_id = _string(row.get("form_id"), f"{context}.form_id")
        expected_form_id = lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        )
        if form_id != expected_form_id:
            raise StageAInputError(f"{context}.form_id is not canonical")
        parsed = {
            "form_id": form_id,
            "semantic_form": semantic_form,
            "representative_encoding_id": _string(
                row.get("representative_encoding_id"),
                f"{context}.representative_encoding_id",
            ),
            "encoding_ids": _strings(
                row.get("encoding_ids"), f"{context}.encoding_ids"
            ),
        }
        if form_id in forms_by_id:
            raise StageAInputError("side-ISA catalog proposal repeats a form ID")
        forms.append(parsed)
        forms_by_id[form_id] = parsed
    if [row["form_id"] for row in forms] != sorted(forms_by_id):
        raise StageAInputError(
            "side-ISA catalog proposal forms are not canonically ordered"
        )
    if not forms:
        raise StageAInputError("side-ISA catalog proposal has no forms")

    raw_encodings = _objects(
        payload.get("encodings"), "side-ISA catalog proposal encodings"
    )
    encodings: list[dict[str, Any]] = []
    encodings_by_id: dict[str, dict[str, Any]] = {}
    for index, raw in enumerate(raw_encodings):
        context = f"side-ISA catalog proposal encodings[{index}]"
        row = _exact_fields(
            raw,
            {
                "format",
                "encoding_id",
                "form_id",
                "semantic_form",
                "instruction_bytes",
                "instruction_hex",
                "source_occurrence_ids",
                "representative",
                "enrichment",
            },
            context,
        )
        if row.get("format") != _PROPOSAL_ENCODING_FORMAT:
            raise StageAInputError(f"{context}.format is invalid")
        form_id = _string(row.get("form_id"), f"{context}.form_id")
        form = forms_by_id.get(form_id)
        if form is None:
            raise StageAInputError(f"{context} names an unknown form")
        semantic_form = _string(row.get("semantic_form"), f"{context}.semantic_form")
        if semantic_form != form["semantic_form"]:
            raise StageAInputError(f"{context} semantic form disagrees with its form")
        instruction_hex = _string(
            row.get("instruction_hex"), f"{context}.instruction_hex"
        )
        if (
            len(instruction_hex) % 2
            or not 1 <= len(instruction_hex) // 2 <= 15
            or re.fullmatch(r"[0-9a-f]+", instruction_hex) is None
        ):
            raise StageAInputError(f"{context}.instruction_hex is invalid")
        raw_bytes = row.get("instruction_bytes")
        if not isinstance(raw_bytes, list):
            raise StageAInputError(f"{context}.instruction_bytes must be a list")
        instruction_bytes = [
            _uint(byte, 8, f"{context}.instruction_bytes[{offset}]")
            for offset, byte in enumerate(raw_bytes)
        ]
        if bytes(instruction_bytes).hex() != instruction_hex:
            raise StageAInputError(
                f"{context} instruction bytes and hexadecimal encoding disagree"
            )
        encoding_id = _string(row.get("encoding_id"), f"{context}.encoding_id")
        if encoding_id != _encoding_id(form_id, instruction_hex):
            raise StageAInputError(f"{context}.encoding_id is not canonical")
        if encoding_id in encodings_by_id:
            raise StageAInputError("side-ISA catalog proposal repeats an encoding ID")
        source_occurrence_ids = _strings(
            row.get("source_occurrence_ids"),
            f"{context}.source_occurrence_ids",
        )
        representative = row.get("representative")
        if not isinstance(representative, bool):
            raise StageAInputError(f"{context}.representative must be a boolean")
        enrichment = _exact_fields(
            row.get("enrichment"),
            {"status", "missing_fields"},
            f"{context}.enrichment",
        )
        if enrichment.get("status") != "missing" or enrichment.get(
            "missing_fields"
        ) != ["defined_outputs", "effects", "required_features"]:
            raise StageAInputError(f"{context}.enrichment is not the v1 missing marker")
        parsed = {
            "format": _PROPOSAL_ENCODING_FORMAT,
            "encoding_id": encoding_id,
            "form_id": form_id,
            "semantic_form": semantic_form,
            "instruction_bytes": instruction_bytes,
            "instruction_hex": instruction_hex,
            "source_occurrence_ids": source_occurrence_ids,
            "representative": representative,
        }
        encodings.append(parsed)
        encodings_by_id[encoding_id] = parsed
    if [
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ] != sorted(
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ):
        raise StageAInputError(
            "side-ISA catalog proposal encodings are not canonically ordered"
        )
    if not encodings:
        raise StageAInputError("side-ISA catalog proposal has no encodings")

    for form in forms:
        actual_ids = sorted(
            row["encoding_id"]
            for row in encodings
            if row["form_id"] == form["form_id"]
        )
        if form["encoding_ids"] != actual_ids:
            raise StageAInputError(
                f"side-ISA catalog proposal form {form['form_id']} encoding inventory "
                "does not match the encoding rows"
            )
        representative_ids = [
            row["encoding_id"]
            for row in encodings
            if row["form_id"] == form["form_id"] and row["representative"]
        ]
        if representative_ids != [form["representative_encoding_id"]]:
            raise StageAInputError(
                f"side-ISA catalog proposal form {form['form_id']} has an invalid "
                "representative encoding"
            )

    missing = _exact_fields(
        payload.get("missing_enrichment"),
        {"status", "fields", "encoding_count", "corpus_generation_allowed"},
        "side-ISA catalog proposal missing_enrichment",
    )
    if (
        missing.get("status") != "required"
        or missing.get("fields")
        != ["defined_outputs", "effects", "required_features"]
        or missing.get("encoding_count") != len(encodings)
        or missing.get("corpus_generation_allowed") is not False
    ):
        raise StageAInputError(
            "side-ISA catalog proposal missing_enrichment summary is invalid"
        )

    counts = _exact_fields(
        payload.get("counts"),
        {"forms", "encodings", "occurrences", "representatives"},
        "side-ISA catalog proposal counts",
    )
    expected_counts = {
        "forms": len(forms),
        "encodings": len(encodings),
        "representatives": len(forms),
    }
    for field, expected in expected_counts.items():
        if counts.get(field) != expected:
            raise StageAInputError(
                f"side-ISA catalog proposal counts.{field} is inconsistent"
            )
    occurrence_count = _uint(
        counts.get("occurrences"),
        64,
        "side-ISA catalog proposal counts.occurrences",
    )
    if occurrence_count != len(
        {
            occurrence_id
            for row in encodings
            for occurrence_id in row["source_occurrence_ids"]
        }
    ):
        raise StageAInputError(
            "side-ISA catalog proposal occurrence count is inconsistent"
        )
    trust = _exact_fields(
        payload.get("trust"),
        {"role", "proof_authority", "closes_stage_a_proof"},
        "side-ISA catalog proposal trust",
    )
    if (
        trust.get("role") != "untrusted_executable_catalog_enrichment_proposal"
        or trust.get("proof_authority") is not False
        or trust.get("closes_stage_a_proof") is not False
    ):
        raise StageAInputError("side-ISA catalog proposal trust marker is invalid")

    return {
        **dict(payload),
        "forms": forms,
        "encodings": encodings,
        "classifier_sha256": classifier_sha256,
    }
