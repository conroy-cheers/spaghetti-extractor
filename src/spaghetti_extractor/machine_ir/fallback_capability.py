"""Strict non-executable fallback-lowering capability artifacts."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from ..artifacts.artifact_set import canonical_sha256_v3
from ..artifacts.formats import FALLBACK_CAPABILITY_ANALYSIS_FORMAT


_DIGEST_LENGTH = 64
_LOWERING_FIELDS = frozenset({
    "program_source_sha256",
    "interpreter_source_sha256",
    "runtime_header_sha256",
    "interpreter_header_sha256",
    "interpreter_internal_header_sha256",
})


class FallbackCapabilityAnalysisError(ValueError):
    """The fallback capability report is malformed or self-contradictory."""


def _object(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise FallbackCapabilityAnalysisError(f"{label} must be an object")
    return value


def _exact_fields(
    value: Mapping[str, Any], expected: set[str] | frozenset[str], label: str
) -> None:
    if set(value) != set(expected):
        raise FallbackCapabilityAnalysisError(
            f"{label} fields are not canonical"
        )


def _string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value or any(ord(ch) < 0x20 for ch in value):
        raise FallbackCapabilityAnalysisError(f"{label} must be a nonempty string")
    return value


def _digest(value: Any, label: str) -> str:
    result = _string(value, label)
    if len(result) != _DIGEST_LENGTH or any(ch not in "0123456789abcdef" for ch in result):
        raise FallbackCapabilityAnalysisError(
            f"{label} must be a lowercase SHA-256 digest"
        )
    return result


def _count(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise FallbackCapabilityAnalysisError(f"{label} must be nonnegative")
    return value


def _optional_string(value: Any, label: str) -> str | None:
    if value is None:
        return None
    return _string(value, label)


def _optional_u32(value: Any, label: str) -> int | None:
    if value is None:
        return None
    result = _count(value, label)
    if result > 0xFFFFFFFF:
        raise FallbackCapabilityAnalysisError(f"{label} exceeds PE32 range")
    return result


@dataclass(frozen=True)
class FallbackLoweringHashes:
    program_source_sha256: str
    interpreter_source_sha256: str
    runtime_header_sha256: str
    interpreter_header_sha256: str
    interpreter_internal_header_sha256: str

    @classmethod
    def from_payload(cls, value: Any) -> "FallbackLoweringHashes":
        row = _object(value, "fallback lowering hashes")
        _exact_fields(row, _LOWERING_FIELDS, "fallback lowering hashes")
        return cls(**{
            field: _digest(row[field], f"fallback lowering {field}")
            for field in sorted(_LOWERING_FIELDS)
        })

    def to_payload(self) -> dict[str, str]:
        return {
            "program_source_sha256": self.program_source_sha256,
            "interpreter_source_sha256": self.interpreter_source_sha256,
            "runtime_header_sha256": self.runtime_header_sha256,
            "interpreter_header_sha256": self.interpreter_header_sha256,
            "interpreter_internal_header_sha256": (
                self.interpreter_internal_header_sha256
            ),
        }


@dataclass(frozen=True)
class FallbackCapabilityBlocker:
    transfer_index: int
    transfer_id: str | None
    rva_start: int | None
    code: str
    failure_phase: str
    message: str
    next_action: str | None

    @classmethod
    def from_payload(cls, value: Any) -> "FallbackCapabilityBlocker":
        row = _object(value, "fallback capability blocker")
        _exact_fields(
            row,
            {
                "transfer_index",
                "transfer_id",
                "rva_start",
                "code",
                "failure_phase",
                "message",
                "next_action",
            },
            "fallback capability blocker",
        )
        return cls(
            transfer_index=_count(row["transfer_index"], "blocker transfer index"),
            transfer_id=_optional_string(row["transfer_id"], "blocker transfer ID"),
            rva_start=_optional_u32(row["rva_start"], "blocker RVA"),
            code=_string(row["code"], "blocker code"),
            failure_phase=_string(row["failure_phase"], "blocker failure phase"),
            message=_string(row["message"], "blocker message"),
            next_action=_optional_string(row["next_action"], "blocker next action"),
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "transfer_index": self.transfer_index,
            "transfer_id": self.transfer_id,
            "rva_start": self.rva_start,
            "code": self.code,
            "failure_phase": self.failure_phase,
            "message": self.message,
            "next_action": self.next_action,
        }


def fallback_capability_sha256(
    *,
    machine_ir_sha256: str,
    capability_id: str,
    lowerable_unit_ids: Sequence[str],
    lowering: FallbackLoweringHashes,
) -> str:
    """Hash the exact non-executable lowering identity."""

    return canonical_sha256_v3({
        "format": FALLBACK_CAPABILITY_ANALYSIS_FORMAT,
        "machine_ir_sha256": _digest(machine_ir_sha256, "machine-IR SHA-256"),
        "capability_id": _string(capability_id, "capability ID"),
        "lowerable_unit_ids": list(lowerable_unit_ids),
        "lowering": lowering.to_payload(),
    })


@dataclass(frozen=True)
class FallbackCapabilityAnalysis:
    status: Literal["complete", "incomplete"]
    machine_ir_path: str
    machine_ir_sha256: str
    capability_id: str
    capability_sha256: str
    lowering: FallbackLoweringHashes
    required_units: int
    lowerable_unit_ids: tuple[str, ...]
    unlowerable_unit_ids: tuple[str, ...]
    blockers: tuple[FallbackCapabilityBlocker, ...]
    max_word_nodes_per_transfer: int

    @property
    def complete(self) -> bool:
        return self.status == "complete"

    @classmethod
    def create(
        cls,
        *,
        machine_ir_path: str,
        machine_ir_sha256: str,
        capability_id: str,
        lowering: FallbackLoweringHashes,
        required_unit_ids: Sequence[str],
        lowerable_unit_ids: Sequence[str],
        blockers: Sequence[Mapping[str, Any]],
        max_word_nodes_per_transfer: int,
    ) -> "FallbackCapabilityAnalysis":
        required = tuple(sorted(required_unit_ids))
        lowerable = tuple(sorted(lowerable_unit_ids))
        blocker_rows = tuple(
            FallbackCapabilityBlocker.from_payload(row) for row in blockers
        )
        unlowerable = tuple(sorted(set(required) - set(lowerable)))
        status: Literal["complete", "incomplete"] = (
            "complete" if not blocker_rows and lowerable == required else "incomplete"
        )
        capability_sha256 = fallback_capability_sha256(
            machine_ir_sha256=machine_ir_sha256,
            capability_id=capability_id,
            lowerable_unit_ids=lowerable,
            lowering=lowering,
        )
        return cls(
            status=status,
            machine_ir_path=machine_ir_path,
            machine_ir_sha256=machine_ir_sha256,
            capability_id=capability_id,
            capability_sha256=capability_sha256,
            lowering=lowering,
            required_units=len(required),
            lowerable_unit_ids=lowerable,
            unlowerable_unit_ids=unlowerable,
            blockers=blocker_rows,
            max_word_nodes_per_transfer=max_word_nodes_per_transfer,
        ).validated()

    @classmethod
    def from_payload(cls, value: Any) -> "FallbackCapabilityAnalysis":
        row = _object(value, "fallback capability analysis")
        _exact_fields(
            row,
            {
                "format",
                "status",
                "machine_ir",
                "capability_id",
                "capability_sha256",
                "lowering",
                "counts",
                "lowerable_unit_ids",
                "unlowerable_unit_ids",
                "blockers",
                "trust",
            },
            "fallback capability analysis",
        )
        if row["format"] != FALLBACK_CAPABILITY_ANALYSIS_FORMAT:
            raise FallbackCapabilityAnalysisError(
                "fallback capability analysis has the wrong format"
            )
        status = row["status"]
        if status not in ("complete", "incomplete"):
            raise FallbackCapabilityAnalysisError(
                "fallback capability analysis status is invalid"
            )
        machine = _object(row["machine_ir"], "fallback machine-IR binding")
        _exact_fields(machine, {"path", "sha256"}, "fallback machine-IR binding")
        path = _string(machine["path"], "fallback machine-IR path")
        if Path(path).name != path:
            raise FallbackCapabilityAnalysisError(
                "fallback machine-IR path must be a basename"
            )
        counts = _object(row["counts"], "fallback capability counts")
        _exact_fields(
            counts,
            {
                "required_units",
                "lowerable_units",
                "blockers",
                "max_word_nodes_per_transfer",
            },
            "fallback capability counts",
        )
        trust = _object(row["trust"], "fallback capability trust policy")
        _exact_fields(
            trust,
            {
                "proof_authority",
                "candidate_executable",
                "emits_source",
                "emits_machine_code",
            },
            "fallback capability trust policy",
        )
        if any(value is not False for value in trust.values()):
            raise FallbackCapabilityAnalysisError(
                "fallback capability analysis must remain non-executable and non-authoritative"
            )
        raw_lowerable = row["lowerable_unit_ids"]
        raw_unlowerable = row["unlowerable_unit_ids"]
        raw_blockers = row["blockers"]
        if not isinstance(raw_lowerable, list) or not isinstance(raw_unlowerable, list):
            raise FallbackCapabilityAnalysisError(
                "fallback capability unit inventories must be arrays"
            )
        if not isinstance(raw_blockers, list):
            raise FallbackCapabilityAnalysisError(
                "fallback capability blockers must be an array"
            )
        result = cls(
            status=status,
            machine_ir_path=path,
            machine_ir_sha256=_digest(machine["sha256"], "machine-IR SHA-256"),
            capability_id=_string(row["capability_id"], "capability ID"),
            capability_sha256=_digest(
                row["capability_sha256"], "fallback capability SHA-256"
            ),
            lowering=FallbackLoweringHashes.from_payload(row["lowering"]),
            required_units=_count(counts["required_units"], "required unit count"),
            lowerable_unit_ids=tuple(
                _string(item, "lowerable unit ID") for item in raw_lowerable
            ),
            unlowerable_unit_ids=tuple(
                _string(item, "unlowerable unit ID") for item in raw_unlowerable
            ),
            blockers=tuple(
                FallbackCapabilityBlocker.from_payload(item)
                for item in raw_blockers
            ),
            max_word_nodes_per_transfer=_count(
                counts["max_word_nodes_per_transfer"],
                "maximum word nodes per transfer",
            ),
        )
        if counts["lowerable_units"] != len(result.lowerable_unit_ids):
            raise FallbackCapabilityAnalysisError(
                "fallback lowerable-unit count is inconsistent"
            )
        if counts["blockers"] != len(result.blockers):
            raise FallbackCapabilityAnalysisError(
                "fallback blocker count is inconsistent"
            )
        return result.validated()

    def validated(self) -> "FallbackCapabilityAnalysis":
        lowerable = self.lowerable_unit_ids
        unlowerable = self.unlowerable_unit_ids
        if (
            tuple(sorted(set(lowerable))) != lowerable
            or tuple(sorted(set(unlowerable))) != unlowerable
            or set(lowerable) & set(unlowerable)
            or self.required_units != len(lowerable) + len(unlowerable)
        ):
            raise FallbackCapabilityAnalysisError(
                "fallback capability unit inventory is malformed"
            )
        expected_status = (
            "complete"
            if not self.blockers and not unlowerable
            else "incomplete"
        )
        if self.status != expected_status:
            raise FallbackCapabilityAnalysisError(
                "fallback capability status contradicts its blockers"
            )
        expected_sha256 = fallback_capability_sha256(
            machine_ir_sha256=self.machine_ir_sha256,
            capability_id=self.capability_id,
            lowerable_unit_ids=lowerable,
            lowering=self.lowering,
        )
        if self.capability_sha256 != expected_sha256:
            raise FallbackCapabilityAnalysisError(
                "fallback capability SHA-256 is stale"
            )
        return self

    def to_payload(self) -> dict[str, Any]:
        return {
            "format": FALLBACK_CAPABILITY_ANALYSIS_FORMAT,
            "status": self.status,
            "machine_ir": {
                "path": self.machine_ir_path,
                "sha256": self.machine_ir_sha256,
            },
            "capability_id": self.capability_id,
            "capability_sha256": self.capability_sha256,
            "lowering": self.lowering.to_payload(),
            "counts": {
                "required_units": self.required_units,
                "lowerable_units": len(self.lowerable_unit_ids),
                "blockers": len(self.blockers),
                "max_word_nodes_per_transfer": self.max_word_nodes_per_transfer,
            },
            "lowerable_unit_ids": list(self.lowerable_unit_ids),
            "unlowerable_unit_ids": list(self.unlowerable_unit_ids),
            "blockers": [row.to_payload() for row in self.blockers],
            "trust": {
                "proof_authority": False,
                "candidate_executable": False,
                "emits_source": False,
                "emits_machine_code": False,
            },
        }


__all__ = [
    "FallbackCapabilityAnalysis",
    "FallbackCapabilityAnalysisError",
    "FallbackCapabilityBlocker",
    "FallbackLoweringHashes",
    "fallback_capability_sha256",
]
