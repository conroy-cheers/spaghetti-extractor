from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ..stage_binary import StageAInputError
from ..util import sha256_bytes
from .schema import STAGE_A_RELATIONAL_MODEL_ID, STAGE_A_RELATIONAL_PROFILE_ID
from .side_extraction_artifact import (
    SideExtractionRequest,
    canonical_request_sha256,
    parse_request,
)


SIDE_ISA_FORMAT = "stage-a-relational-side-isa-v1"
SIDE_ISA_STATUS = "untrusted_proposal_requires_lean_decode_replay"
_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TOP_FIELDS = {
    "format",
    "profile",
    "model",
    "status",
    "side",
    "binary_sha256",
    "request_sha256",
    "classifier_sha256",
    "extractor_sha256",
    "source_sha256",
    "regions",
}
_REGION_FIELDS = {
    "index",
    "id",
    "numeric_id",
    "span",
    "occurrences",
    "occurrences_sha256",
}
_OCCURRENCE_FIELDS = {"rva", "size", "bytes", "form"}


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be 64 lowercase hex characters")
    return value


def _canonical_sha256(value: Any) -> str:
    return sha256_bytes(
        json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    )


def _validate_occurrences(
    occurrences: Any, *, start: int, size: int, context: str
) -> list[dict[str, Any]]:
    if not isinstance(occurrences, list) or not occurrences:
        raise StageAInputError(f"{context} occurrences must be a nonempty list")
    result: list[dict[str, Any]] = []
    cursor = start
    for index, value in enumerate(occurrences):
        row_context = f"{context} occurrence {index}"
        if not isinstance(value, Mapping) or set(value) != _OCCURRENCE_FIELDS:
            raise StageAInputError(f"{row_context} is malformed")
        rva = value.get("rva")
        instruction_size = value.get("size")
        encoded = value.get("bytes")
        form = value.get("form")
        if (
            isinstance(rva, bool)
            or not isinstance(rva, int)
            or rva != cursor
            or isinstance(instruction_size, bool)
            or not isinstance(instruction_size, int)
            or not 1 <= instruction_size <= 15
            or not isinstance(encoded, str)
            or len(encoded) != instruction_size * 2
            or re.fullmatch(r"[0-9a-f]+", encoded) is None
            or not isinstance(form, str)
            or not form
        ):
            raise StageAInputError(f"{row_context} is invalid")
        cursor += instruction_size
        result.append({
            "rva": rva,
            "size": instruction_size,
            "bytes": encoded,
            "form": form,
        })
    if cursor != start + size:
        raise StageAInputError(f"{context} occurrences do not cover the span")
    return result


def side_isa_payload(
    request: SideExtractionRequest,
    *,
    forms: Mapping[tuple[str, int], tuple[dict[str, Any], ...]],
    classifier_sha256: str,
    extractor_sha256: str,
    source_sha256: str,
) -> dict[str, Any]:
    request = parse_request(request.to_payload())
    hashes = {
        "classifier_sha256": _sha256(classifier_sha256, "ISA classifier SHA-256"),
        "extractor_sha256": _sha256(extractor_sha256, "ISA extractor SHA-256"),
        "source_sha256": _sha256(source_sha256, "ISA source SHA-256"),
    }
    expected = {(request.side, region.index) for region in request.regions}
    if set(forms) != expected:
        raise StageAInputError("side ISA forms do not match the request inventory")
    regions: list[dict[str, Any]] = []
    for region in request.regions:
        occurrences = _validate_occurrences(
            list(forms[(request.side, region.index)]),
            start=region.span.rva_start,
            size=region.span.size,
            context=f"side ISA region {region.index}",
        )
        regions.append({
            **region.to_payload(),
            "occurrences": occurrences,
            "occurrences_sha256": _canonical_sha256(occurrences),
        })
    payload = {
        "format": SIDE_ISA_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": SIDE_ISA_STATUS,
        "side": request.side,
        "binary_sha256": request.binary_sha256,
        "request_sha256": canonical_request_sha256(request),
        **hashes,
        "regions": regions,
    }
    parse_side_isa_unbound(
        payload,
        expected_side=request.side,
        expected_binary_sha256=request.binary_sha256,
        **hashes,
    )
    return payload


def parse_side_isa_unbound(
    payload: Any,
    *,
    expected_side: str,
    expected_binary_sha256: str,
    classifier_sha256: str,
    extractor_sha256: str,
    source_sha256: str,
) -> tuple[SideExtractionRequest, list[tuple[dict[str, Any], ...]]]:
    if not isinstance(payload, Mapping) or set(payload) != _TOP_FIELDS:
        raise StageAInputError("side ISA artifact fields are malformed")
    expected_top = {
        "format": SIDE_ISA_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": SIDE_ISA_STATUS,
        "side": expected_side,
        "binary_sha256": _sha256(
            expected_binary_sha256, "expected side ISA binary SHA-256"
        ),
        "classifier_sha256": _sha256(
            classifier_sha256, "expected ISA classifier SHA-256"
        ),
        "extractor_sha256": _sha256(
            extractor_sha256, "expected ISA extractor SHA-256"
        ),
        "source_sha256": _sha256(source_sha256, "expected ISA source SHA-256"),
    }
    for field, expected in expected_top.items():
        if payload.get(field) != expected:
            raise StageAInputError(f"side ISA artifact {field} mismatch")
    raw_regions = payload.get("regions")
    if not isinstance(raw_regions, list):
        raise StageAInputError("side ISA artifact regions must be a list")
    request = parse_request({
        "format": "stage-a-relational-side-extraction-request-v1",
        "profile": payload.get("profile"),
        "model": payload.get("model"),
        "side": payload.get("side"),
        "binary_sha256": payload.get("binary_sha256"),
        "regions": [
            {
                "index": row.get("index"),
                "id": row.get("id"),
                "numeric_id": row.get("numeric_id"),
                "span": row.get("span"),
            }
            if isinstance(row, Mapping)
            else row
            for row in raw_regions
        ],
    })
    if payload.get("request_sha256") != canonical_request_sha256(request):
        raise StageAInputError("side ISA artifact request_sha256 mismatch")
    result: list[tuple[dict[str, Any], ...]] = []
    for region, raw in zip(request.regions, raw_regions, strict=True):
        if not isinstance(raw, Mapping) or set(raw) != _REGION_FIELDS:
            raise StageAInputError(
                f"side ISA artifact region {region.index} is malformed"
            )
        occurrences = _validate_occurrences(
            raw.get("occurrences"),
            start=region.span.rva_start,
            size=region.span.size,
            context=f"side ISA artifact region {region.index}",
        )
        if raw.get("occurrences_sha256") != _canonical_sha256(occurrences):
            raise StageAInputError(
                f"side ISA artifact region {region.index} hash mismatch"
            )
        result.append(tuple(occurrences))
    return request, result


def select_side_isa_spans(
    payload: Any,
    *,
    expected_request: SideExtractionRequest,
    classifier_sha256: str,
    extractor_sha256: str,
    source_sha256: str,
) -> dict[tuple[str, int], tuple[dict[str, Any], ...]]:
    expected_request = parse_request(expected_request.to_payload())
    inventory, rows = parse_side_isa_unbound(
        payload,
        expected_side=expected_request.side,
        expected_binary_sha256=expected_request.binary_sha256,
        classifier_sha256=classifier_sha256,
        extractor_sha256=extractor_sha256,
        source_sha256=source_sha256,
    )
    by_span: dict[tuple[int, int], tuple[dict[str, Any], ...]] = {}
    for region, occurrences in zip(inventory.regions, rows, strict=True):
        key = (region.span.rva_start, region.span.size)
        if key in by_span:
            raise StageAInputError("side ISA artifact contains duplicate spans")
        by_span[key] = occurrences
    selected: dict[tuple[str, int], tuple[dict[str, Any], ...]] = {}
    for region in expected_request.regions:
        key = (region.span.rva_start, region.span.size)
        if key not in by_span:
            raise StageAInputError(
                f"side ISA artifact omits required span {key[0]:#x}+{key[1]}"
            )
        selected[(expected_request.side, region.index)] = by_span[key]
    return selected
