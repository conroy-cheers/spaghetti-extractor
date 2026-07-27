from __future__ import annotations

import json
import re
from collections.abc import Mapping
from typing import Any

from ..artifact_formats import NORMALIZED_BEHAVIOR_FORMAT
from ..stage_binary import StageAInputError
from ..util import sha256_bytes
from .schema import (
    REGISTERS,
    RELATION_CONTRACT_FORMAT,
    STAGE_A_RELATIONAL_MODEL_ID,
    STAGE_A_RELATIONAL_PROFILE_ID,
)


PAIR_NORMALIZATION_FORMAT = "stage-a-relational-pair-normalization-v1"
PAIR_NORMALIZATION_STATUS = (
    "untrusted_proposal_requires_lean_normalization_replay"
)

_SHA256_RE = re.compile(r"[0-9a-f]{64}")
_TOP_FIELDS = {
    "format",
    "profile",
    "model",
    "status",
    "original_sha256",
    "candidate_sha256",
    "relation_contract_sha256",
    "original_extraction_sha256",
    "candidate_extraction_sha256",
    "normalizer_semantics_sha256",
    "regions",
}
_REGION_FIELDS = {
    "index",
    "id",
    "numeric_id",
    "original_term",
    "candidate_term",
    "original_term_sha256",
    "candidate_term_sha256",
    "original_ir",
    "candidate_ir",
    "original_ir_sha256",
    "candidate_ir_sha256",
}
_SPAN_FIELDS = {"rva_start", "rva_end", "size"}
_BEHAVIOR_INPUT_FIELDS = {
    "original",
    "candidate",
    "original_ir",
    "candidate_ir",
}
_SEMANTIC_IR_FIELDS = {
    "format",
    "registers",
    "x87",
    "writes",
    "flags",
    "outcome",
}
_X87_FIELDS = {"stack", "control", "status"}
_FLAG_FIELDS = {
    "auxiliary",
    "carry",
    "parity",
    "zero",
    "sign",
    "overflow",
}
_WRITE_FIELDS = {"address", "value"}


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


def _integer(value: Any, context: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
        raise StageAInputError(f"{context} must be an integer >= {minimum}")
    return value


def _nonempty_string(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageAInputError(f"{context} must be a nonempty string")
    return value


def _json_value(value: Any, context: str) -> Any:
    if value is None or isinstance(value, (bool, str)):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, (list, tuple)):
        return [
            _json_value(item, f"{context}[{index}]")
            for index, item in enumerate(value)
        ]
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise StageAInputError(f"{context} object keys must be strings")
            result[key] = _json_value(item, f"{context}.{key}")
        return result
    raise StageAInputError(f"{context} contains a non-JSON value")


def _canonical_json_bytes(value: Any, context: str) -> bytes:
    canonical = _json_value(value, context)
    try:
        return json.dumps(
            canonical,
            sort_keys=True,
            separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8")
    except (RecursionError, TypeError, ValueError) as exc:
        raise StageAInputError(f"{context} is not canonical JSON: {exc}") from exc


def _canonical_json_sha256(value: Any, context: str) -> str:
    return sha256_bytes(_canonical_json_bytes(value, context))


def _span(value: Any, context: str) -> dict[str, int]:
    span = _object(value, context)
    _exact_fields(span, _SPAN_FIELDS, context)
    start = _integer(span["rva_start"], f"{context}.rva_start")
    end = _integer(span["rva_end"], f"{context}.rva_end")
    size = _integer(span["size"], f"{context}.size", minimum=1)
    if start >= 2**32 or end > 2**32 or end != start + size:
        raise StageAInputError(f"{context} is not a valid PE32 RVA span")
    return {"rva_start": start, "rva_end": end, "size": size}


def _contract_region_identities(
    contract: Any,
) -> tuple[dict[str, Any], list[tuple[str, int]]]:
    normalized = _object(contract, "normalized relation contract")
    if normalized.get("format") != RELATION_CONTRACT_FORMAT:
        raise StageAInputError("normalized relation contract format mismatch")
    if normalized.get("model") != STAGE_A_RELATIONAL_MODEL_ID:
        raise StageAInputError("normalized relation contract model mismatch")
    canonical = _json_value(normalized, "normalized relation contract")
    raw_regions = canonical.get("regions")
    if not isinstance(raw_regions, list) or not raw_regions:
        raise StageAInputError(
            "normalized relation contract regions must be a nonempty list"
        )

    identities: list[tuple[str, int]] = []
    ids: set[str] = set()
    numeric_ids: set[int] = set()
    for index, value in enumerate(raw_regions):
        context = f"normalized relation contract region {index}"
        region = _object(value, context)
        region_id = _nonempty_string(region.get("id"), f"{context}.id")
        numeric_id = _integer(
            region.get("numeric_id"), f"{context}.numeric_id"
        )
        _span(region.get("original"), f"{context}.original")
        _span(region.get("candidate"), f"{context}.candidate")
        if region_id in ids:
            raise StageAInputError(
                "normalized relation contract region ids must be unique"
            )
        if numeric_id in numeric_ids:
            raise StageAInputError(
                "normalized relation contract region numeric ids must be unique"
            )
        ids.add(region_id)
        numeric_ids.add(numeric_id)
        identities.append((region_id, numeric_id))
    return canonical, identities


def canonical_relation_contract_sha256(contract: Mapping[str, Any]) -> str:
    """Hash a structurally valid normalized relation contract as canonical JSON."""

    canonical, _identities = _contract_region_identities(contract)
    return _canonical_json_sha256(canonical, "normalized relation contract")


def _balanced_lean_term(term: str) -> bool:
    pairs = {")": "(", "]": "[", "}": "{"}
    stack: list[str] = []
    quote: str | None = None
    escaped = False
    for character in term:
        if quote is not None:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == quote:
                quote = None
            continue
        if character in {'"', "'"}:
            quote = character
        elif character in "([{":
            stack.append(character)
        elif character in pairs:
            if not stack or stack.pop() != pairs[character]:
                return False
    return quote is None and not stack and not escaped


def _behavior_term(value: Any, context: str) -> str:
    term = _nonempty_string(value, context)
    if term != re.sub(r"\s+", " ", term).strip():
        raise StageAInputError(f"{context} is not canonically whitespace-normalized")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in term):
        raise StageAInputError(f"{context} contains control characters")
    if not term.startswith("{") or not term.endswith("}"):
        raise StageAInputError(f"{context} is not a normalized behavior structure")
    if not _balanced_lean_term(term):
        raise StageAInputError(f"{context} has unbalanced Lean delimiters")
    return term


def _expression(value: Any, context: str) -> dict[str, Any]:
    expression = _object(value, context)
    operation = expression.get("op")
    if not isinstance(operation, str) or not operation:
        raise StageAInputError(f"{context} must name a semantic operation")
    return _json_value(expression, context)


def _semantic_ir(value: Any, context: str) -> dict[str, Any]:
    ir = _object(value, context)
    _exact_fields(ir, _SEMANTIC_IR_FIELDS, context)
    if ir["format"] != NORMALIZED_BEHAVIOR_FORMAT:
        raise StageAInputError(f"{context} format mismatch")

    registers = _object(ir["registers"], f"{context}.registers")
    _exact_fields(registers, set(REGISTERS), f"{context}.registers")
    normalized_registers = {
        register: _expression(
            registers[register], f"{context}.registers.{register}"
        )
        for register in sorted(REGISTERS)
    }

    x87 = _object(ir["x87"], f"{context}.x87")
    _exact_fields(x87, _X87_FIELDS, f"{context}.x87")
    stack = x87["stack"]
    if not isinstance(stack, list):
        raise StageAInputError(f"{context}.x87.stack must be a list")
    normalized_x87 = {
        "stack": [
            _expression(item, f"{context}.x87.stack[{index}]")
            for index, item in enumerate(stack)
        ],
        "control": _expression(x87["control"], f"{context}.x87.control"),
        "status": _expression(x87["status"], f"{context}.x87.status"),
    }

    writes = ir["writes"]
    if not isinstance(writes, list):
        raise StageAInputError(f"{context}.writes must be a list")
    normalized_writes: list[dict[str, Any]] = []
    for index, value in enumerate(writes):
        write_context = f"{context}.writes[{index}]"
        write = _object(value, write_context)
        _exact_fields(write, _WRITE_FIELDS, write_context)
        normalized_writes.append({
            "address": _expression(write["address"], f"{write_context}.address"),
            "value": _expression(write["value"], f"{write_context}.value"),
        })

    flags = ir["flags"]
    normalized_flags: dict[str, Any] | None
    if flags is None:
        normalized_flags = None
    else:
        flag_values = _object(flags, f"{context}.flags")
        _exact_fields(flag_values, _FLAG_FIELDS, f"{context}.flags")
        normalized_flags = {
            flag: (
                None
                if flag_values[flag] is None
                else _expression(
                    flag_values[flag], f"{context}.flags.{flag}"
                )
            )
            for flag in sorted(_FLAG_FIELDS)
        }

    normalized = {
        "format": ir["format"],
        "registers": normalized_registers,
        "x87": normalized_x87,
        "writes": normalized_writes,
        "flags": normalized_flags,
        "outcome": _expression(ir["outcome"], f"{context}.outcome"),
    }
    return _json_value(normalized, context)


def pair_normalization_payload(
    *,
    original_sha256: str,
    candidate_sha256: str,
    relation_contract: Mapping[str, Any],
    original_extraction_sha256: str,
    candidate_extraction_sha256: str,
    normalizer_semantics_sha256: str,
    behaviors: list[Mapping[str, Any]],
) -> dict[str, Any]:
    original_hash = _sha256(original_sha256, "original binary SHA-256")
    candidate_hash = _sha256(candidate_sha256, "candidate binary SHA-256")
    original_extraction_hash = _sha256(
        original_extraction_sha256, "original side-extraction SHA-256"
    )
    candidate_extraction_hash = _sha256(
        candidate_extraction_sha256, "candidate side-extraction SHA-256"
    )
    normalizer_hash = _sha256(
        normalizer_semantics_sha256, "normalizer semantics SHA-256"
    )
    _canonical_contract, identities = _contract_region_identities(
        relation_contract
    )
    if not isinstance(behaviors, list):
        raise StageAInputError("pair normalization behaviors must be a list")
    if len(behaviors) != len(identities):
        raise StageAInputError(
            "pair normalization behavior count does not match the contract"
        )

    regions: list[dict[str, Any]] = []
    for index, ((region_id, numeric_id), value) in enumerate(
        zip(identities, behaviors, strict=True)
    ):
        context = f"pair normalization behavior {index}"
        behavior = _object(value, context)
        _exact_fields(behavior, _BEHAVIOR_INPUT_FIELDS, context)
        original_term = _behavior_term(
            behavior["original"], f"{context}.original"
        )
        candidate_term = _behavior_term(
            behavior["candidate"], f"{context}.candidate"
        )
        original_ir = _semantic_ir(
            behavior["original_ir"], f"{context}.original_ir"
        )
        candidate_ir = _semantic_ir(
            behavior["candidate_ir"], f"{context}.candidate_ir"
        )
        regions.append({
            "index": index,
            "id": region_id,
            "numeric_id": numeric_id,
            "original_term": original_term,
            "candidate_term": candidate_term,
            "original_term_sha256": sha256_bytes(original_term.encode("utf-8")),
            "candidate_term_sha256": sha256_bytes(candidate_term.encode("utf-8")),
            "original_ir": original_ir,
            "candidate_ir": candidate_ir,
            "original_ir_sha256": _canonical_json_sha256(
                original_ir, f"{context}.original_ir"
            ),
            "candidate_ir_sha256": _canonical_json_sha256(
                candidate_ir, f"{context}.candidate_ir"
            ),
        })

    payload = {
        "format": PAIR_NORMALIZATION_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": PAIR_NORMALIZATION_STATUS,
        "original_sha256": original_hash,
        "candidate_sha256": candidate_hash,
        "relation_contract_sha256": canonical_relation_contract_sha256(
            relation_contract
        ),
        "original_extraction_sha256": original_extraction_hash,
        "candidate_extraction_sha256": candidate_extraction_hash,
        "normalizer_semantics_sha256": normalizer_hash,
        "regions": regions,
    }
    parse_pair_normalization(
        payload,
        expected_original_sha256=original_hash,
        expected_candidate_sha256=candidate_hash,
        expected_relation_contract=relation_contract,
        expected_original_extraction_sha256=original_extraction_hash,
        expected_candidate_extraction_sha256=candidate_extraction_hash,
        expected_normalizer_semantics_sha256=normalizer_hash,
    )
    return payload


def parse_pair_normalization(
    payload: Any,
    *,
    expected_original_sha256: str,
    expected_candidate_sha256: str,
    expected_original_extraction_sha256: str,
    expected_candidate_extraction_sha256: str,
    expected_normalizer_semantics_sha256: str,
    expected_contract: Mapping[str, Any] | None = None,
    expected_relation_contract: Mapping[str, Any] | None = None,
) -> list[dict[str, Any]]:
    if (expected_contract is None) == (expected_relation_contract is None):
        raise StageAInputError(
            "exactly one expected relation contract must be provided"
        )
    contract = (
        expected_contract
        if expected_contract is not None
        else expected_relation_contract
    )
    assert contract is not None
    _canonical_contract, identities = _contract_region_identities(contract)

    artifact = _object(payload, "pair normalization artifact")
    _exact_fields(artifact, _TOP_FIELDS, "pair normalization artifact")
    expected_identities = {
        "format": PAIR_NORMALIZATION_FORMAT,
        "profile": STAGE_A_RELATIONAL_PROFILE_ID,
        "model": STAGE_A_RELATIONAL_MODEL_ID,
        "status": PAIR_NORMALIZATION_STATUS,
        "original_sha256": _sha256(
            expected_original_sha256, "expected original binary SHA-256"
        ),
        "candidate_sha256": _sha256(
            expected_candidate_sha256, "expected candidate binary SHA-256"
        ),
        "relation_contract_sha256": canonical_relation_contract_sha256(
            contract
        ),
        "original_extraction_sha256": _sha256(
            expected_original_extraction_sha256,
            "expected original side-extraction SHA-256",
        ),
        "candidate_extraction_sha256": _sha256(
            expected_candidate_extraction_sha256,
            "expected candidate side-extraction SHA-256",
        ),
        "normalizer_semantics_sha256": _sha256(
            expected_normalizer_semantics_sha256,
            "expected normalizer semantics SHA-256",
        ),
    }
    for field, expected in expected_identities.items():
        if artifact[field] != expected:
            raise StageAInputError(f"pair normalization artifact {field} mismatch")

    raw_regions = artifact["regions"]
    if not isinstance(raw_regions, list):
        raise StageAInputError("pair normalization artifact regions must be a list")
    if len(raw_regions) != len(identities):
        raise StageAInputError(
            "pair normalization region count does not match the contract"
        )

    behaviors: list[dict[str, Any]] = []
    for index, ((region_id, numeric_id), value) in enumerate(
        zip(identities, raw_regions, strict=True)
    ):
        context = f"pair normalization artifact region {index}"
        row = _object(value, context)
        _exact_fields(row, _REGION_FIELDS, context)
        observed_index = _integer(row["index"], f"{context}.index")
        observed_id = _nonempty_string(row["id"], f"{context}.id")
        observed_numeric_id = _integer(
            row["numeric_id"], f"{context}.numeric_id"
        )
        if observed_index != index:
            raise StageAInputError(
                "pair normalization region indices are not canonical"
            )
        if observed_id != region_id or observed_numeric_id != numeric_id:
            raise StageAInputError(
                "pair normalization regions do not match canonical contract order"
            )

        original_term = _behavior_term(
            row["original_term"], f"{context}.original_term"
        )
        candidate_term = _behavior_term(
            row["candidate_term"], f"{context}.candidate_term"
        )
        for side, term in (
            ("original", original_term),
            ("candidate", candidate_term),
        ):
            term_hash = _sha256(
                row[f"{side}_term_sha256"],
                f"{context}.{side}_term_sha256",
            )
            if term_hash != sha256_bytes(term.encode("utf-8")):
                raise StageAInputError(f"{context} {side} term hash mismatch")

        original_ir = _semantic_ir(
            row["original_ir"], f"{context}.original_ir"
        )
        candidate_ir = _semantic_ir(
            row["candidate_ir"], f"{context}.candidate_ir"
        )
        for side, ir in (("original", original_ir), ("candidate", candidate_ir)):
            ir_hash = _sha256(
                row[f"{side}_ir_sha256"], f"{context}.{side}_ir_sha256"
            )
            if ir_hash != _canonical_json_sha256(
                ir, f"{context}.{side}_ir"
            ):
                raise StageAInputError(
                    f"{context} {side} semantic IR hash mismatch"
                )

        behaviors.append({
            "original": original_term,
            "candidate": candidate_term,
            "original_ir": original_ir,
            "candidate_ir": candidate_ir,
        })
    return behaviors


__all__ = [
    "PAIR_NORMALIZATION_FORMAT",
    "PAIR_NORMALIZATION_STATUS",
    "canonical_relation_contract_sha256",
    "pair_normalization_payload",
    "parse_pair_normalization",
]
