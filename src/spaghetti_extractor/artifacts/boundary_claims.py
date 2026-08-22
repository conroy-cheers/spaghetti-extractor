"""Strict authority-output projections shared with neutral boundary consumers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Mapping

from .artifact_set import ArtifactV3Error
from .io import open_artifact_reader_v3


CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA = (
    "spaghetti-extractor-call-boundary-contract-record-v3"
)
CALL_BOUNDARY_CONTRACTS_ARTIFACT_KIND_V3 = "call-boundary-contracts-v3"
CALLBACK_AUTHORITY_RECORD_V4_SCHEMA = (
    "spaghetti-extractor-callback-authority-record-v4"
)
CALLBACK_AUTHORITY_ARTIFACT_KIND_V4 = "callback-authority-v4"


@dataclass(frozen=True)
class CheckedCallBoundaryClaimV3:
    target_unit_id: str
    contract_id: str
    target_unit_sha256: str
    preserved_registers: tuple[str, ...]


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be nonempty text")
    return value


def read_checked_call_boundary_claims_v3(
    value: Path | str,
) -> tuple[dict[str, CheckedCallBoundaryClaimV3], str]:
    reader = open_artifact_reader_v3(Path(value))
    if (
        reader.manifest.artifact_kind != CALL_BOUNDARY_CONTRACTS_ARTIFACT_KIND_V3
        or reader.manifest.status != "complete"
    ):
        raise ValueError("call-boundary authority is not a complete expected artifact")
    result: dict[str, CheckedCallBoundaryClaimV3] = {}
    for source in reader.iter_records():
        row = _object(source.value.to_value(), "call-boundary authority record")
        if row.get("schema") != CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA:
            raise ValueError("call-boundary authority record schema is unsupported")
        if row.get("status") != "complete" or row.get("authorizing") is not True:
            raise ValueError("call-boundary authority record is not authorizing")
        registers = row.get("preserved_registers")
        if not isinstance(registers, list) or any(
            not isinstance(item, str) or not item for item in registers
        ):
            raise ValueError("call-boundary preserved registers are malformed")
        canonical_registers = tuple(registers)
        if canonical_registers != tuple(sorted(set(canonical_registers))):
            raise ValueError("call-boundary preserved registers are noncanonical")
        target_unit_id = _text(row.get("id"), "call-boundary target unit ID")
        claim = CheckedCallBoundaryClaimV3(
            target_unit_id=target_unit_id,
            contract_id=_text(row.get("contract_id"), "call-boundary contract ID"),
            target_unit_sha256=_text(
                row.get("target_unit_sha256"), "call-boundary target digest"
            ),
            preserved_registers=canonical_registers,
        )
        if target_unit_id in result:
            raise ValueError("call-boundary target unit is duplicated")
        result[target_unit_id] = claim
    return result, reader.manifest_sha256


def read_authorized_callback_protocols_v4(
    value: Path | str, *, authority_ids: frozenset[str]
) -> tuple[dict[str, str], str]:
    reader = open_artifact_reader_v3(Path(value))
    if (
        reader.manifest.artifact_kind != CALLBACK_AUTHORITY_ARTIFACT_KIND_V4
        or reader.manifest.status != "complete"
    ):
        raise ValueError("callback authority is not a complete expected artifact")
    result: dict[str, str] = {}
    for source in reader.iter_records():
        row = _object(source.value.to_value(), "callback authority record")
        if row.get("schema") != CALLBACK_AUTHORITY_RECORD_V4_SCHEMA:
            raise ValueError("callback authority record schema is unsupported")
        if row.get("status") != "complete" or row.get("authorizing") is not True:
            raise ValueError("callback authority inventory is not authorizing")
        callbacks = row.get("callbacks")
        if not isinstance(callbacks, list):
            raise ValueError("callback authority inventory is malformed")
        for raw in callbacks:
            callback = _object(raw, "callback authority")
            callback_id = _text(callback.get("id"), "callback authority ID")
            if callback_id not in authority_ids:
                continue
            if (
                callback.get("status") != "complete"
                or callback.get("authorizing") is not True
            ):
                raise ValueError(f"callback authority {callback_id!r} is incomplete")
            protocol = _object(callback.get("protocol"), "callback protocol")
            protocol_id = _text(protocol.get("id"), "callback protocol ID")
            prior = result.setdefault(callback_id, protocol_id)
            if prior != protocol_id:
                raise ValueError(f"callback authority {callback_id!r} is ambiguous")
    return result, reader.manifest_sha256


__all__ = [
    "CALL_BOUNDARY_CONTRACT_RECORD_V3_SCHEMA",
    "CALL_BOUNDARY_CONTRACTS_ARTIFACT_KIND_V3",
    "CALLBACK_AUTHORITY_ARTIFACT_KIND_V4",
    "CALLBACK_AUTHORITY_RECORD_V4_SCHEMA",
    "CheckedCallBoundaryClaimV3",
    "read_authorized_callback_protocols_v4",
    "read_checked_call_boundary_claims_v3",
]
