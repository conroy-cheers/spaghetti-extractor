from __future__ import annotations

from typing import Any

from ...stage_binary import StageABinary
from ..extraction import _assembled_u32_after_register_writes
from .control import _constant_read32_address, _immutable_image_u32


RegisterRelation = str | dict[str, Any]


def _immutable_image_u32_value(binary: StageABinary, address: int) -> int | None:
    return _immutable_image_u32(binary, address)


def _paired_constant_relation(
    original_expression: dict[str, Any],
    candidate_expression: dict[str, Any],
    contract: dict[str, Any],
    original_image_base: int,
    candidate_image_base: int,
) -> RegisterRelation | None:
    if (
        original_expression.get("op") != "constant"
        or candidate_expression.get("op") != "constant"
    ):
        return None
    original_value = int(original_expression["value"]) & 0xFFFFFFFF
    candidate_value = int(candidate_expression["value"]) & 0xFFFFFFFF
    if original_value == candidate_value:
        return {"relation": "fixed_word", "value": original_value}
    if any(
        int(target["original_value"]) == original_value
        and int(target["candidate_value"]) == candidate_value
        for target in contract.get("value_targets", [])
    ):
        return "data_pointer"
    fixed_matches = [
        target_id
        for target_id, target in enumerate(contract.get("code_targets", []))
        if isinstance(target, dict)
        and target.get("id") == target_id
        and original_value in {
            original_image_base + int(rva)
            for rva in [
                target.get("original_rva", -1),
                *target.get("original_aliases", []),
            ]
        }
        and candidate_value in {
            candidate_image_base + int(rva)
            for rva in [
                target.get("candidate_rva", -1),
                *target.get("candidate_aliases", []),
            ]
        }
    ]
    if len(fixed_matches) == 1:
        return {
            "relation": "fixed_code_pointer",
            "target_id": fixed_matches[0],
        }
    if fixed_matches:
        return "code_pointer"
    return None


def _immutable_image_word_read(
    expression: dict[str, Any], binary: StageABinary,
) -> tuple[int, list[dict[str, Any]], bool, int] | None:
    """Recover a constant-address image word read and its write witnesses."""

    address = _constant_read32_address(expression)
    writes: list[dict[str, Any]] = []
    assembled = False
    if address is None:
        recovered = _assembled_u32_after_register_writes(expression)
        if recovered is None:
            return None
        address, writes = recovered
        assembled = True
    value = _immutable_image_u32_value(binary, address)
    if value is None:
        return None
    return address, writes, assembled, value


__all__ = [
    "_immutable_image_u32_value",
    "_immutable_image_word_read",
    "_paired_constant_relation",
]
