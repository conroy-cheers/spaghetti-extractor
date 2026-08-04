from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from ..stage_binary import StageAInputError
from ..util import sha256_bytes
from .schema import STATIC_ANALYSIS_MODEL_ID, STATIC_ANALYSIS_PROFILE_ID


SIDE_EXTRACTION_REQUEST_FORMAT = "stage-a-static-region-request-v1"
SIDE_EXTRACTION_RESULT_FORMAT = "stage-a-static-region-inventory-v1"
SIDE_EXTRACTION_RESULT_STATUS = (
    "untrusted_proposal_requires_lean_decode_replay"
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_SIDES = frozenset({"original", "candidate"})
_REQUEST_FIELDS = {
    "format",
    "profile",
    "model",
    "side",
    "binary_sha256",
    "regions",
}
_REQUEST_REGION_FIELDS = {"index", "id", "numeric_id", "span"}
_SPAN_FIELDS = {"rva_start", "size"}
_RESULT_FIELDS = {
    "format",
    "profile",
    "model",
    "status",
    "side",
    "binary_sha256",
    "request_sha256",
    "decoder_semantics_sha256",
    "regions",
}
_RESULT_REGION_FIELDS = _REQUEST_REGION_FIELDS | {
    "behavior_term",
    "behavior_sha256",
}


def _object(value: Any, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise StageAInputError(f"{context} must be an object")
    return value


def _exact_fields(
    payload: Mapping[str, Any], expected: set[str], context: str,
) -> None:
    missing = sorted(expected - set(payload))
    extra = sorted(set(payload) - expected)
    if missing or extra:
        details: list[str] = []
        if missing:
            details.append(f"missing fields {missing}")
        if extra:
            details.append(f"unexpected fields {extra}")
        raise StageAInputError(f"{context} has " + " and ".join(details))


def _sha256(value: Any, context: str) -> str:
    if not isinstance(value, str) or _SHA256_RE.fullmatch(value) is None:
        raise StageAInputError(f"{context} must be 64 lowercase hex characters")
    return value


def _integer(value: Any, context: str, *, minimum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StageAInputError(f"{context} must be an integer >= {minimum}")
    return value


def _string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    return value


def _canonical_sha256(value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return sha256_bytes(encoded)


@dataclass(frozen=True)
class SideExtractionSpan:
    rva_start: int
    size: int

    @classmethod
    def parse(cls, payload: Any, context: str) -> "SideExtractionSpan":
        row = _object(payload, context)
        _exact_fields(row, _SPAN_FIELDS, context)
        rva_start = _integer(row["rva_start"], f"{context}.rva_start", minimum=0)
        size = _integer(row["size"], f"{context}.size", minimum=1)
        if rva_start >= 2**32 or rva_start + size > 2**32:
            raise StageAInputError(f"{context} must fit in the PE32 RVA space")
        return cls(rva_start=rva_start, size=size)

    def to_payload(self) -> dict[str, int]:
        return {"rva_start": self.rva_start, "size": self.size}


@dataclass(frozen=True)
class SideExtractionRegion:
    index: int
    id: str
    numeric_id: int
    span: SideExtractionSpan

    @classmethod
    def parse(
        cls, payload: Any, *, expected_index: int,
    ) -> "SideExtractionRegion":
        context = f"side extraction request region {expected_index}"
        row = _object(payload, context)
        _exact_fields(row, _REQUEST_REGION_FIELDS, context)
        index = _integer(row["index"], f"{context}.index", minimum=0)
        if index != expected_index:
            raise StageAInputError(
                "side extraction request region indices are not canonical"
            )
        return cls(
            index=index,
            id=_string(row["id"], f"{context}.id"),
            numeric_id=_integer(
                row["numeric_id"], f"{context}.numeric_id", minimum=0
            ),
            span=SideExtractionSpan.parse(row["span"], f"{context}.span"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "id": self.id,
            "numeric_id": self.numeric_id,
            "span": self.span.to_payload(),
        }


@dataclass(frozen=True)
class SideExtractionRequest:
    side: str
    binary_sha256: str
    regions: tuple[SideExtractionRegion, ...]
    profile: str = STATIC_ANALYSIS_PROFILE_ID
    model: str = STATIC_ANALYSIS_MODEL_ID
    format: str = SIDE_EXTRACTION_REQUEST_FORMAT

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": self.format,
            "profile": self.profile,
            "model": self.model,
            "side": self.side,
            "binary_sha256": self.binary_sha256,
            "regions": [region.to_payload() for region in self.regions],
        }


def parse_request(payload: Any) -> SideExtractionRequest:
    request = _object(payload, "side extraction request")
    _exact_fields(request, _REQUEST_FIELDS, "side extraction request")
    if request["format"] != SIDE_EXTRACTION_REQUEST_FORMAT:
        raise StageAInputError("unsupported side extraction request format")
    if request["profile"] != STATIC_ANALYSIS_PROFILE_ID:
        raise StageAInputError("side extraction request profile mismatch")
    if request["model"] != STATIC_ANALYSIS_MODEL_ID:
        raise StageAInputError("side extraction request model mismatch")
    side = request["side"]
    if side not in _SIDES:
        raise StageAInputError("side extraction request side is invalid")
    binary_sha256 = _sha256(
        request["binary_sha256"], "side extraction request binary_sha256"
    )

    raw_regions = request["regions"]
    if not isinstance(raw_regions, list):
        raise StageAInputError("side extraction request regions must be a list")
    regions = tuple(
        SideExtractionRegion.parse(row, expected_index=index)
        for index, row in enumerate(raw_regions)
    )
    ids = [region.id for region in regions]
    numeric_ids = [region.numeric_id for region in regions]
    if len(ids) != len(set(ids)):
        raise StageAInputError("side extraction request region ids must be unique")
    if len(numeric_ids) != len(set(numeric_ids)):
        raise StageAInputError(
            "side extraction request region numeric ids must be unique"
        )
    return SideExtractionRequest(
        side=side,
        binary_sha256=binary_sha256,
        regions=regions,
    )


def request_payload(
    contract: Mapping[str, Any], side: str, binary_sha256: str,
) -> dict[str, Any]:
    relation_contract = _object(contract, "normalized relation contract")
    if side not in _SIDES:
        raise StageAInputError("side extraction request side is invalid")
    _sha256(binary_sha256, "side extraction request binary_sha256")

    raw_regions = relation_contract.get("regions")
    if not isinstance(raw_regions, list):
        raise StageAInputError("normalized relation contract regions must be a list")
    regions: list[dict[str, Any]] = []
    for index, raw_region in enumerate(raw_regions):
        context = f"normalized relation contract region {index}"
        region = _object(raw_region, context)
        if "id" not in region or "numeric_id" not in region or side not in region:
            raise StageAInputError(f"{context} is missing side extraction identity")
        span = _object(region[side], f"{context}.{side}")
        if "rva_start" not in span or "size" not in span:
            raise StageAInputError(f"{context}.{side} is missing its span")
        regions.append({
            "index": index,
            "id": region["id"],
            "numeric_id": region["numeric_id"],
            "span": {
                "rva_start": span["rva_start"],
                "size": span["size"],
            },
        })

    payload = {
        "format": SIDE_EXTRACTION_REQUEST_FORMAT,
        "profile": STATIC_ANALYSIS_PROFILE_ID,
        "model": STATIC_ANALYSIS_MODEL_ID,
        "side": side,
        "binary_sha256": binary_sha256,
        "regions": regions,
    }
    return parse_request(payload).to_payload()


def canonical_request_sha256(
    request: SideExtractionRequest | Mapping[str, Any],
) -> str:
    payload = request.to_payload() if isinstance(request, SideExtractionRequest) else request
    parsed = parse_request(payload)
    return _canonical_sha256(parsed.to_payload())


def request_sha256(
    request: SideExtractionRequest | Mapping[str, Any],
) -> str:
    return canonical_request_sha256(request)


def result_payload(
    request: SideExtractionRequest,
    decoder_semantics_sha256: str,
    behavior_terms: list[str],
) -> dict[str, Any]:
    if not isinstance(request, SideExtractionRequest):
        raise StageAInputError("side extraction result requires a parsed request")
    request = parse_request(request.to_payload())
    decoder_sha256 = _sha256(
        decoder_semantics_sha256,
        "side extraction result decoder_semantics_sha256",
    )
    if not isinstance(behavior_terms, list):
        raise StageAInputError("side extraction behavior terms must be a list")
    if len(behavior_terms) != len(request.regions):
        raise StageAInputError(
            "side extraction behavior count does not match the request"
        )

    regions: list[dict[str, Any]] = []
    for region, raw_term in zip(request.regions, behavior_terms, strict=True):
        term = _string(raw_term, f"side extraction behavior {region.index}")
        regions.append({
            **region.to_payload(),
            "behavior_term": term,
            "behavior_sha256": sha256_bytes(term.encode("utf-8")),
        })
    payload = {
        "format": SIDE_EXTRACTION_RESULT_FORMAT,
        "profile": STATIC_ANALYSIS_PROFILE_ID,
        "model": STATIC_ANALYSIS_MODEL_ID,
        "status": SIDE_EXTRACTION_RESULT_STATUS,
        "side": request.side,
        "binary_sha256": request.binary_sha256,
        "request_sha256": canonical_request_sha256(request),
        "decoder_semantics_sha256": decoder_sha256,
        "regions": regions,
    }
    parse_result(
        payload,
        expected_request=request,
        expected_decoder_semantics_sha256=decoder_sha256,
    )
    return payload


def parse_result(
    payload: Any,
    *,
    expected_request: SideExtractionRequest,
    expected_decoder_semantics_sha256: str,
) -> list[str]:
    if not isinstance(expected_request, SideExtractionRequest):
        raise StageAInputError("side extraction result requires a parsed request")
    expected_request = parse_request(expected_request.to_payload())
    expected_decoder_sha256 = _sha256(
        expected_decoder_semantics_sha256,
        "expected decoder semantics SHA-256",
    )
    result = _object(payload, "side extraction result")
    _exact_fields(result, _RESULT_FIELDS, "side extraction result")
    if result["format"] != SIDE_EXTRACTION_RESULT_FORMAT:
        raise StageAInputError("unsupported side extraction result format")
    if result["profile"] != STATIC_ANALYSIS_PROFILE_ID:
        raise StageAInputError("side extraction result profile mismatch")
    if result["model"] != STATIC_ANALYSIS_MODEL_ID:
        raise StageAInputError("side extraction result model mismatch")
    if result["status"] != SIDE_EXTRACTION_RESULT_STATUS:
        raise StageAInputError("side extraction result status mismatch")

    expected_identities = {
        "side": expected_request.side,
        "binary_sha256": expected_request.binary_sha256,
        "request_sha256": canonical_request_sha256(expected_request),
        "decoder_semantics_sha256": expected_decoder_sha256,
    }
    for field, expected in expected_identities.items():
        if result[field] != expected:
            raise StageAInputError(f"side extraction result {field} mismatch")

    raw_regions = result["regions"]
    if not isinstance(raw_regions, list):
        raise StageAInputError("side extraction result regions must be a list")
    if len(raw_regions) != len(expected_request.regions):
        raise StageAInputError(
            "side extraction result region count does not match the request"
        )

    behavior_terms: list[str] = []
    for expected_region, raw_region in zip(
        expected_request.regions, raw_regions, strict=True
    ):
        context = f"side extraction result region {expected_region.index}"
        region = _object(raw_region, context)
        _exact_fields(region, _RESULT_REGION_FIELDS, context)
        expected_identity = expected_region.to_payload()
        observed_identity = {
            field: region[field] for field in _REQUEST_REGION_FIELDS
        }
        if observed_identity != expected_identity:
            raise StageAInputError(
                "side extraction result regions do not match canonical request order"
            )
        term = _string(region["behavior_term"], f"{context}.behavior_term")
        behavior_sha256 = _sha256(
            region["behavior_sha256"], f"{context}.behavior_sha256"
        )
        if behavior_sha256 != sha256_bytes(term.encode("utf-8")):
            raise StageAInputError(f"{context} behavior hash mismatch")
        behavior_terms.append(term)
    return behavior_terms


def parse_result_unbound(
    payload: Any,
    *,
    expected_side: str,
    expected_binary_sha256: str,
    expected_decoder_semantics_sha256: str,
) -> tuple[SideExtractionRequest, list[str]]:
    result = _object(payload, "side extraction result")
    _exact_fields(result, _RESULT_FIELDS, "side extraction result")
    raw_regions = result.get("regions")
    if not isinstance(raw_regions, list):
        raise StageAInputError("side extraction result regions must be a list")
    request = parse_request({
        "format": SIDE_EXTRACTION_REQUEST_FORMAT,
        "profile": result.get("profile"),
        "model": result.get("model"),
        "side": result.get("side"),
        "binary_sha256": result.get("binary_sha256"),
        "regions": [
            {
                field: row.get(field)
                for field in _REQUEST_REGION_FIELDS
            }
            if isinstance(row, Mapping)
            else row
            for row in raw_regions
        ],
    })
    if request.side != expected_side:
        raise StageAInputError("side extraction result side mismatch")
    if request.binary_sha256 != _sha256(
        expected_binary_sha256, "expected side extraction binary SHA-256"
    ):
        raise StageAInputError("side extraction result binary_sha256 mismatch")
    terms = parse_result(
        result,
        expected_request=request,
        expected_decoder_semantics_sha256=expected_decoder_semantics_sha256,
    )
    return request, terms


def select_result_spans(
    payload: Any,
    *,
    expected_request: SideExtractionRequest,
    expected_decoder_semantics_sha256: str,
) -> list[str]:
    expected_request = parse_request(expected_request.to_payload())
    inventory_request, inventory_terms = parse_result_unbound(
        payload,
        expected_side=expected_request.side,
        expected_binary_sha256=expected_request.binary_sha256,
        expected_decoder_semantics_sha256=expected_decoder_semantics_sha256,
    )
    by_span: dict[tuple[int, int], str] = {}
    for region, term in zip(
        inventory_request.regions, inventory_terms, strict=True
    ):
        key = (region.span.rva_start, region.span.size)
        if key in by_span:
            raise StageAInputError(
                "side extraction result contains duplicate executable spans"
            )
        by_span[key] = term
    selected: list[str] = []
    for region in expected_request.regions:
        key = (region.span.rva_start, region.span.size)
        term = by_span.get(key)
        if term is None:
            raise StageAInputError(
                f"side extraction result omits required span {key[0]:#x}+{key[1]}"
            )
        selected.append(term)
    return selected
