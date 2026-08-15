"""Fail-closed enrichment for exact side-ISA catalog proposals.

The side adapter deliberately emits exact Lean semantic forms and encodings
without qualification metadata.  This module replays each encoding through
the authoritative Lean decoder, exports concrete decoded operands, and derives
only the generic effects representable by the existing corpus schema.
Unsupported forms remain explicit unresolved rows.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from ..artifacts.formats import ISA_ENCODING_PROPOSAL_FORMAT as _PROPOSAL_ENCODING_FORMAT
from .catalog import (
    ISA_FORM_CATALOG_ENTRY_FORMAT,
    ISA_FORM_CATALOG_FORMAT,
    ISA_PROFILE_ID,
    ISAFormCatalog,
    _effect_payload,
    _parse_effect,
    parse_isa_form_catalog,
)
from .conformance import ISAConformanceError
from .semantic_forms import (
    lean_semantic_form_classifier_sha256,
    lean_semantic_form_id,
)
from .side_adapter import SIDE_ISA_EXECUTABLE_CATALOG_PROPOSAL_FORMAT
from ..build_support.lean_runner import run_lean_module_graph
from ..extraction.schema import STATIC_ANALYSIS_MODEL_ID
from ..pe32.stage_binary import StageAInputError
from ..util import sha256_bytes, sha256_file, write_json


SIDE_ISA_CATALOG_ENRICHMENT_FORMAT = (
    "stage-a-side-isa-executable-catalog-enrichment-v1"
)
SIDE_ISA_ENCODING_ENRICHMENT_FORMAT = (
    "stage-a-side-isa-executable-encoding-enrichment-v1"
)
SIDE_ISA_CATALOG_ENRICHMENT_RESULT_FORMAT = (
    "stage-a-side-isa-catalog-enrichment-result-v1"
)
_ENRICHER_VERSION = "lean-exact-encoding-catalog-enrichment-v1"
_GPRS = ("eax", "ebp", "ebx", "ecx", "edi", "edx", "esi", "esp")
_ARITHMETIC_FLAGS = 0x8D5
_LOGICAL_FLAGS = 0x8C5
_MULTIPLY_FLAGS = 0x801
_ZERO_FLAG = 0x40
_CARRY_FLAG = 0x1
_TEST_EIP = 0x00401000
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SEGMENT_PREFIXES = frozenset({0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65})
_REP_PREFIXES = frozenset({0xF2, 0xF3})
_OTHER_UNRESOLVED_PREFIXES = {
    0x67: "address_size_override_not_representable",
}
_PREFIXES = _SEGMENT_PREFIXES | _REP_PREFIXES | frozenset({0x66, 0x67, 0xF0})


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    )


def _exact_fields(
    value: Any,
    expected: set[str],
    context: str,
) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    missing = expected - set(value)
    unknown = set(value) - expected
    if missing or unknown:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {sorted(missing)!r}")
        if unknown:
            details.append(f"unknown fields {sorted(unknown)!r}")
        raise StageAInputError(f"{context} has " + " and ".join(details))
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise StageAInputError(
            f"{context} must be a nonempty string without surrounding whitespace"
        )
    return value


def _sha256(value: Any, context: str) -> str:
    digest = _string(value, context)
    if _SHA256_RE.fullmatch(digest) is None:
        raise StageAInputError(
            f"{context} must be 64 lowercase hexadecimal characters"
        )
    return digest


def _uint(value: Any, bits: int, context: str) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 0 <= value < 2**bits
    ):
        raise StageAInputError(f"{context} must be an unsigned {bits}-bit integer")
    return value


def _objects(value: Any, context: str) -> list[Mapping[str, Any]]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result: list[Mapping[str, Any]] = []
    for index, row in enumerate(value):
        if not isinstance(row, Mapping):
            raise StageAInputError(f"{context}[{index}] must be an object")
        result.append(row)
    return result


def _strings(
    value: Any,
    context: str,
    *,
    allow_empty: bool = False,
) -> list[str]:
    if not isinstance(value, list):
        raise StageAInputError(f"{context} must be a list")
    result = [_string(row, f"{context}[{index}]") for index, row in enumerate(value)]
    if not allow_empty and not result:
        raise StageAInputError(f"{context} must not be empty")
    if result != sorted(set(result)):
        raise StageAInputError(f"{context} must be unique and canonically ordered")
    return result


def _encoding_id(form_id: str, instruction_hex: str) -> str:
    return "lean-x86-encoding-" + _canonical_sha256(
        {"form_id": form_id, "bytes": instruction_hex}
    )[:24]



from .catalog_enrichment_schema import _parse_proposal
from .catalog_enrichment_lean import extract_lean_decoded_metadata
from .catalog_enrichment_derivation import _derive_enrichment, _x87_format_width

def _qualified_representatives(
    encodings: Sequence[Mapping[str, Any]],
) -> list[Mapping[str, Any]]:
    rows_by_form: dict[str, list[Mapping[str, Any]]] = {}
    for row in encodings:
        rows_by_form.setdefault(str(row["form_id"]), []).append(row)
    representatives: list[Mapping[str, Any]] = []
    for form_id in sorted(rows_by_form):
        rows = rows_by_form[form_id]
        if any(row["enrichment"]["status"] != "resolved" for row in rows):
            continue
        representative = [row for row in rows if row["representative"]]
        if len(representative) != 1:
            raise StageAInputError(
                f"side-ISA enrichment form {form_id} does not have one representative"
            )
        representatives.append(representative[0])
    return representatives


def enrich_side_isa_catalog(
    proposal: Any,
    decoded_metadata: Mapping[str, Mapping[str, Any]],
    *,
    lean_binding: Mapping[str, str],
) -> dict[str, Any]:
    """Build one deterministic enrichment artifact from validated Lean rows."""

    parsed = _parse_proposal(proposal)
    expected_ids = [row["encoding_id"] for row in parsed["encodings"]]
    if list(decoded_metadata) != expected_ids:
        raise StageAInputError(
            "decoded metadata must cover proposal encodings in canonical order"
        )
    binding = _exact_fields(
        lean_binding,
        {"classifier_sha256", "metadata_exporter_sha256", "lean_version"},
        "Lean metadata binding",
    )
    if binding.get("classifier_sha256") != parsed["classifier_sha256"]:
        raise StageAInputError(
            "Lean metadata binding classifier does not match proposal"
        )
    _sha256(
        binding.get("metadata_exporter_sha256"),
        "Lean metadata binding metadata_exporter_sha256",
    )
    _string(binding.get("lean_version"), "Lean metadata binding lean_version")

    enriched_rows: list[dict[str, Any]] = []
    reason_counts: Counter[str] = Counter()
    for encoding in parsed["encodings"]:
        enrichment = _derive_enrichment(
            encoding,
            decoded_metadata[encoding["encoding_id"]],
        )
        if enrichment["status"] == "unresolved":
            reason_counts[str(enrichment["reason"])] += 1
        enriched_rows.append(
            {
                "format": SIDE_ISA_ENCODING_ENRICHMENT_FORMAT,
                "encoding_id": encoding["encoding_id"],
                "form_id": encoding["form_id"],
                "semantic_form": encoding["semantic_form"],
                "instruction_bytes": list(encoding["instruction_bytes"]),
                "instruction_hex": encoding["instruction_hex"],
                "source_occurrence_ids": list(encoding["source_occurrence_ids"]),
                "representative": encoding["representative"],
                "enrichment": enrichment,
            }
        )
    resolved = sum(
        row["enrichment"]["status"] == "resolved" for row in enriched_rows
    )
    unresolved = len(enriched_rows) - resolved
    qualified_representatives = _qualified_representatives(enriched_rows)
    qualified_forms = len(qualified_representatives)
    proposal_sha256 = _canonical_sha256(proposal)
    result = {
        "format": SIDE_ISA_CATALOG_ENRICHMENT_FORMAT,
        "status": "complete" if unresolved == 0 else "incomplete_unresolved_encodings",
        "profile": parsed["profile"],
        "model": parsed["model"],
        "classifier_sha256": parsed["classifier_sha256"],
        "proposal_sha256": proposal_sha256,
        "source": {
            "enricher": _ENRICHER_VERSION,
            "lean_version": binding["lean_version"],
            "metadata_exporter_sha256": binding["metadata_exporter_sha256"],
        },
        "forms": [dict(row) for row in parsed["forms"]],
        "encodings": enriched_rows,
        "counts": {
            "forms": len(parsed["forms"]),
            "encodings": len(enriched_rows),
            "resolved": resolved,
            "unresolved": unresolved,
            "qualified_forms": qualified_forms,
            "unresolved_forms": len(parsed["forms"]) - qualified_forms,
            "corpus_entries": qualified_forms,
        },
        "unresolved_reasons": {
            reason: reason_counts[reason] for reason in sorted(reason_counts)
        },
        "trust": {
            "role": "untrusted_lean_derived_isa_catalog_enrichment",
            "proof_authority": False,
            "closes_stage_a_proof": False,
            "corpus_generation_rule": (
                "one_representative_per_fully_resolved_form"
            ),
        },
    }
    # Ensure every resolved row is consumable by the existing typed catalog.
    if qualified_forms:
        resolved_isa_catalog(result)
    return result


def validate_side_isa_catalog_proposal(value: Any) -> dict[str, Any]:
    """Replay the strict proposal schema without performing Lean work."""

    return _parse_proposal(value)


def enrich_side_isa_catalog_with_lean(
    proposal: Any,
    *,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    parsed = _parse_proposal(proposal)
    metadata, binding = extract_lean_decoded_metadata(
        sorted(parsed["encodings"], key=lambda row: row["encoding_id"]),
        timeout_seconds=timeout_seconds,
    )
    # The proposal is ordered by form/bytes; the Lean exporter requires stable
    # encoding-ID order so output is independent of proposal form grouping.
    metadata_by_proposal_order = {
        row["encoding_id"]: metadata[row["encoding_id"]]
        for row in parsed["encodings"]
    }
    return enrich_side_isa_catalog(
        proposal,
        metadata_by_proposal_order,
        lean_binding=binding,
    )


def _parse_enrichment(value: Any) -> Mapping[str, Any]:
    payload = _exact_fields(
        value,
        {
            "format",
            "status",
            "profile",
            "model",
            "classifier_sha256",
            "proposal_sha256",
            "source",
            "forms",
            "encodings",
            "counts",
            "unresolved_reasons",
            "trust",
        },
        "side-ISA catalog enrichment",
    )
    if payload.get("format") != SIDE_ISA_CATALOG_ENRICHMENT_FORMAT:
        raise StageAInputError("unsupported side-ISA catalog enrichment format")
    if payload.get("status") not in {
        "complete",
        "incomplete_unresolved_encodings",
    }:
        raise StageAInputError("side-ISA catalog enrichment status is invalid")
    if payload.get("profile") != ISA_PROFILE_ID:
        raise StageAInputError("side-ISA catalog enrichment profile is invalid")
    if payload.get("model") != STATIC_ANALYSIS_MODEL_ID:
        raise StageAInputError("side-ISA catalog enrichment model is invalid")
    classifier_sha256 = _sha256(
        payload.get("classifier_sha256"),
        "side-ISA catalog enrichment classifier_sha256",
    )
    if classifier_sha256 != lean_semantic_form_classifier_sha256():
        raise StageAInputError(
            "side-ISA catalog enrichment uses a stale Lean semantic classifier"
        )
    _sha256(
        payload.get("proposal_sha256"),
        "side-ISA catalog enrichment proposal_sha256",
    )
    source = _exact_fields(
        payload.get("source"),
        {"enricher", "lean_version", "metadata_exporter_sha256"},
        "side-ISA catalog enrichment source",
    )
    if source.get("enricher") != _ENRICHER_VERSION:
        raise StageAInputError("side-ISA catalog enrichment enricher is invalid")
    _string(source.get("lean_version"), "side-ISA catalog enrichment lean_version")
    _sha256(
        source.get("metadata_exporter_sha256"),
        "side-ISA catalog enrichment metadata_exporter_sha256",
    )
    forms = _objects(payload.get("forms"), "side-ISA catalog enrichment forms")
    form_ids: list[str] = []
    forms_by_id: dict[str, Mapping[str, Any]] = {}
    for index, row in enumerate(forms):
        row = _exact_fields(
            row,
            {
                "form_id",
                "semantic_form",
                "representative_encoding_id",
                "encoding_ids",
            },
            f"side-ISA catalog enrichment forms[{index}]",
        )
        context = f"side-ISA catalog enrichment forms[{index}]"
        form_id = _string(
            row.get("form_id"),
            f"{context}.form_id",
        )
        semantic_form = _string(
            row.get("semantic_form"),
            f"{context}.semantic_form",
        )
        if form_id != lean_semantic_form_id(
            semantic_form,
            classifier_sha256=classifier_sha256,
        ):
            raise StageAInputError(f"{context}.form_id is not canonical")
        _string(
            row.get("representative_encoding_id"),
            f"{context}.representative_encoding_id",
        )
        _strings(
            row.get("encoding_ids"),
            f"{context}.encoding_ids",
        )
        form_ids.append(form_id)
        forms_by_id[form_id] = row
    if form_ids != sorted(set(form_ids)):
        raise StageAInputError(
            "side-ISA catalog enrichment forms are not canonically ordered"
        )
    encodings = _objects(
        payload.get("encodings"), "side-ISA catalog enrichment encodings"
    )
    encoding_ids: list[str] = []
    resolved_entries: list[dict[str, Any]] = []
    actual_reasons: Counter[str] = Counter()
    for index, row in enumerate(encodings):
        context = f"side-ISA catalog enrichment encodings[{index}]"
        row = _exact_fields(
            row,
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
        if row.get("format") != SIDE_ISA_ENCODING_ENRICHMENT_FORMAT:
            raise StageAInputError(f"{context}.format is invalid")
        encoding_id = _string(row.get("encoding_id"), f"{context}.encoding_id")
        encoding_ids.append(encoding_id)
        form_id = _string(row.get("form_id"), f"{context}.form_id")
        semantic_form = _string(
            row.get("semantic_form"), f"{context}.semantic_form"
        )
        if form_id not in forms_by_id:
            raise StageAInputError(f"{context} names an unknown form")
        raw_bytes = row.get("instruction_bytes")
        if not isinstance(raw_bytes, list):
            raise StageAInputError(f"{context}.instruction_bytes must be a list")
        instruction_bytes = [
            _uint(byte, 8, f"{context}.instruction_bytes[{offset}]")
            for offset, byte in enumerate(raw_bytes)
        ]
        if not 1 <= len(instruction_bytes) <= 15:
            raise StageAInputError(
                f"{context}.instruction_bytes must contain 1 to 15 bytes"
            )
        instruction_hex = _string(
            row.get("instruction_hex"), f"{context}.instruction_hex"
        )
        if bytes(instruction_bytes).hex() != instruction_hex:
            raise StageAInputError(
                f"{context} instruction bytes and hexadecimal encoding disagree"
            )
        if encoding_id != _encoding_id(form_id, instruction_hex):
            raise StageAInputError(f"{context}.encoding_id is not canonical")
        _strings(row.get("source_occurrence_ids"), f"{context}.source_occurrence_ids")
        if not isinstance(row.get("representative"), bool):
            raise StageAInputError(f"{context}.representative must be a boolean")
        enrichment = row.get("enrichment")
        if not isinstance(enrichment, Mapping):
            raise StageAInputError(f"{context}.enrichment must be an object")
        status = enrichment.get("status")
        if status == "resolved":
            enrichment = _exact_fields(
                enrichment,
                {
                    "status",
                    "required_features",
                    "effects",
                    "defined_outputs",
                },
                f"{context}.enrichment",
            )
            resolved_entries.append(
                {
                    "format": ISA_FORM_CATALOG_ENTRY_FORMAT,
                    "form_id": encoding_id,
                    "encoding_id": encoding_id,
                    "instruction_bytes": instruction_bytes,
                    "required_features": enrichment["required_features"],
                    "effects": enrichment["effects"],
                    "defined_outputs": enrichment["defined_outputs"],
                }
            )
        elif status == "unresolved":
            enrichment = _exact_fields(
                enrichment,
                {"status", "reason"},
                f"{context}.enrichment",
            )
            reason = _string(
                enrichment.get("reason"), f"{context}.enrichment.reason"
            )
            actual_reasons[reason] += 1
        else:
            raise StageAInputError(f"{context}.enrichment.status is invalid")
        if semantic_form != forms_by_id[form_id]["semantic_form"]:
            raise StageAInputError(f"{context} semantic form disagrees with its form")
    if [
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ] != sorted(
        (row["form_id"], row["instruction_hex"]) for row in encodings
    ) or len(encoding_ids) != len(set(encoding_ids)):
        raise StageAInputError(
            "side-ISA catalog enrichment encodings are not canonically ordered"
        )
    for form_id, form in forms_by_id.items():
        actual_ids = sorted(
            row["encoding_id"] for row in encodings if row["form_id"] == form_id
        )
        if list(form["encoding_ids"]) != actual_ids:
            raise StageAInputError(
                f"side-ISA catalog enrichment form {form_id} encoding inventory "
                "does not match the encoding rows"
            )
        representatives = [
            row["encoding_id"]
            for row in encodings
            if row["form_id"] == form_id and row["representative"]
        ]
        if representatives != [form["representative_encoding_id"]]:
            raise StageAInputError(
                f"side-ISA catalog enrichment form {form_id} has an invalid "
                "representative encoding"
            )
    reasons = payload.get("unresolved_reasons")
    if not isinstance(reasons, Mapping) or dict(reasons) != {
        reason: actual_reasons[reason] for reason in sorted(actual_reasons)
    }:
        raise StageAInputError(
            "side-ISA catalog enrichment unresolved reason summary is inconsistent"
        )
    counts = _exact_fields(
        payload.get("counts"),
        {
            "forms",
            "encodings",
            "resolved",
            "unresolved",
            "qualified_forms",
            "unresolved_forms",
            "corpus_entries",
        },
        "side-ISA catalog enrichment counts",
    )
    qualified_representatives = _qualified_representatives(encodings)
    qualified_forms = len(qualified_representatives)
    expected_counts = {
        "forms": len(forms),
        "encodings": len(encodings),
        "resolved": len(resolved_entries),
        "unresolved": len(encodings) - len(resolved_entries),
        "qualified_forms": qualified_forms,
        "unresolved_forms": len(forms) - qualified_forms,
        "corpus_entries": qualified_forms,
    }
    if dict(counts) != expected_counts:
        raise StageAInputError(
            "side-ISA catalog enrichment counts are inconsistent"
        )
    expected_status = (
        "complete"
        if expected_counts["unresolved"] == 0
        else "incomplete_unresolved_encodings"
    )
    if payload.get("status") != expected_status:
        raise StageAInputError(
            "side-ISA catalog enrichment aggregate status is inconsistent"
        )
    trust = _exact_fields(
        payload.get("trust"),
        {
            "role",
            "proof_authority",
            "closes_stage_a_proof",
            "corpus_generation_rule",
        },
        "side-ISA catalog enrichment trust",
    )
    if (
        trust.get("role") != "untrusted_lean_derived_isa_catalog_enrichment"
        or trust.get("proof_authority") is not False
        or trust.get("closes_stage_a_proof") is not False
        or trust.get("corpus_generation_rule")
        != "one_representative_per_fully_resolved_form"
    ):
        raise StageAInputError("side-ISA catalog enrichment trust marker is invalid")
    return payload


def resolved_isa_catalog(value: Any) -> ISAFormCatalog:
    """Project one representative from each fully resolved semantic form."""

    payload = _parse_enrichment(value)
    entries: list[dict[str, Any]] = []
    for row in sorted(
        _qualified_representatives(payload["encodings"]),
        key=lambda item: item["encoding_id"],
    ):
        enrichment = row["enrichment"]
        entries.append(
            {
                "format": ISA_FORM_CATALOG_ENTRY_FORMAT,
                # Existing catalogs require unique form IDs. Encoding IDs are
                # already canonical exact-(Lean-form, bytes) identities.
                "form_id": row["encoding_id"],
                "encoding_id": row["encoding_id"],
                "instruction_bytes": list(row["instruction_bytes"]),
                "required_features": list(enrichment["required_features"]),
                "effects": [
                    _effect_payload(
                        _parse_effect(
                            effect,
                            f"resolved enrichment {row['encoding_id']} effect {index}",
                            legacy=False,
                            allow_legacy_v2=True,
                        ),
                        legacy=False,
                    )
                    for index, effect in enumerate(enrichment["effects"])
                ],
                "defined_outputs": dict(enrichment["defined_outputs"]),
            }
        )
    if not entries:
        raise StageAInputError(
            "side-ISA catalog enrichment has no qualified representative "
            "corpus entries"
        )
    catalog_payload = {
        "format": ISA_FORM_CATALOG_FORMAT,
        "profile": ISA_PROFILE_ID,
        "source": {
            "extractor": _ENRICHER_VERSION,
            "version": "1",
            "input_sha256": payload["proposal_sha256"],
        },
        "entries": entries,
    }
    try:
        return parse_isa_form_catalog(catalog_payload)
    except ISAConformanceError as exc:
        raise StageAInputError(
            f"resolved side-ISA enrichment is not corpus-compatible: {exc}"
        ) from exc


def write_enriched_side_isa_catalog(
    *,
    proposal: Path,
    out: Path,
    timeout_seconds: int = 300,
) -> dict[str, Any]:
    try:
        payload = json.loads(Path(proposal).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise StageAInputError(
            f"cannot read side-ISA catalog proposal {proposal}: {exc}"
        ) from exc
    enriched = enrich_side_isa_catalog_with_lean(
        payload,
        timeout_seconds=timeout_seconds,
    )
    write_json(Path(out), enriched)
    return {
        "format": SIDE_ISA_CATALOG_ENRICHMENT_RESULT_FORMAT,
        "status": "generated",
        "enrichment_status": enriched["status"],
        "out": str(out),
        "sha256": sha256_file(Path(out)),
        "counts": enriched["counts"],
        "unresolved_reasons": enriched["unresolved_reasons"],
        "proof_authority": False,
        "closes_stage_a_proof": False,
    }


__all__ = [
    "SIDE_ISA_CATALOG_ENRICHMENT_FORMAT",
    "SIDE_ISA_CATALOG_ENRICHMENT_RESULT_FORMAT",
    "SIDE_ISA_ENCODING_ENRICHMENT_FORMAT",
    "enrich_side_isa_catalog",
    "enrich_side_isa_catalog_with_lean",
    "extract_lean_decoded_metadata",
    "resolved_isa_catalog",
    "validate_side_isa_catalog_proposal",
    "write_enriched_side_isa_catalog",
]
