"""Shared machine-IR formats, value objects, and validation primitives."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from importlib import import_module
from pathlib import Path
from typing import Any, Callable, Iterable, Mapping, Sequence

from ..stage_binary import StageAInputError
from ..util import sha256_bytes


MACHINE_IR_FORMAT = "stage-a-machine-ir-v2"
MACHINE_IR_FILENAME = "machine-ir.jsonl"
MACHINE_IR_MANIFEST_FILENAME = "machine-ir-manifest.json"
PREPARED_MACHINE_IR_FORMAT = "stage-a-prepared-machine-ir-v1"
PREPARED_MACHINE_IR_FILENAME = "prepared-machine-ir.jsonl"
PREPARED_MACHINE_IR_MANIFEST_FILENAME = "prepared-machine-ir-manifest.json"
X87_MICRO_OP_FORMAT = "stage-a-x87-micro-op-v1"
INDIRECT_TARGET_PROFILE_FORMAT = "stage-a-indirect-target-profile-v1"
DECODED_CONTROL_RECONCILIATION_FORMAT = (
    "stage-a-decoded-control-reconciliation-v1"
)

_SEMANTIC_FIELDS = (
    "pre_state",
    "register_writes",
    "flag_writes",
    "memory_events",
    "external_events",
    "faults",
    "ordered_events",
    "edge_conditions",
    "outcome",
    "stack_delta",
    "counts",
)
_RAW_INSTRUCTION_FIELDS = frozenset(
    {
        "bytes",
        "instruction_bytes",
        "opcode_bytes",
        "raw_bytes",
        "encoded_instruction",
    }
)
_DIRECT_OUTCOME_FIELDS = {
    "fallthrough": ("target_rva",),
    "jump": ("target_rva",),
    "branch": ("true_target_rva", "false_target_rva"),
}


def _default_finite_dataflow_factory() -> Callable[..., Any]:
    """Load the optional global-control engine outside exact preparation.

    Nix authority builds inject this dependency explicitly.  The lazy fallback
    keeps the historical Python API usable without making exact unit
    preparation depend on the finite-control implementation.
    """

    module = import_module("spaghetti_extractor.finite_value_domain")
    return module.FiniteU32Dataflow


class MachineIRExportError(StageAInputError):
    """The input package cannot safely cross the reconstruction boundary."""

    def __init__(
        self,
        message: str,
        *,
        code: str = "malformed_machine_ir_input",
        unit_id: str | None = None,
        rva: int | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.unit_id = unit_id
        self.rva = rva


@dataclass(frozen=True, order=True)
class RvaSpan:
    start: int
    end: int

    @property
    def size(self) -> int:
        return self.end - self.start

    def payload(self) -> dict[str, int]:
        return {"rva_start": self.start, "rva_end": self.end, "size": self.size}


@dataclass(frozen=True)
class SourceLocation:
    unit_id: str | None
    function: str | None
    block_id: str | None
    span: RvaSpan | None
    field: str | None = None

    def payload(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        if self.unit_id is not None:
            result["unit_id"] = self.unit_id
        if self.function is not None:
            result["function"] = self.function
        if self.block_id is not None:
            result["block_id"] = self.block_id
        if self.span is not None:
            result.update(self.span.payload())
        if self.field is not None:
            result["field"] = self.field
        return result


@dataclass(frozen=True)
class ExportIssue:
    status: str
    category: str
    message: str
    next_action: str
    location: SourceLocation

    def payload(self) -> dict[str, Any]:
        body = {
            "status": self.status,
            "category": self.category,
            "message": self.message,
            "next_action": self.next_action,
            "location": self.location.payload(),
        }
        body["id"] = "machine-ir-issue:" + sha256_bytes(_canonical_json(body))[:20]
        return body


@dataclass(frozen=True)
class MachineIRPackage:
    manifest: Path
    machine_ir: Path
    recovered_executable_data: Path
    status: str
    unit_count: int
    issue_count: int


@dataclass(frozen=True)
class PreparedMachineIRPackage:
    manifest: Path
    prepared_units: Path
    unit_count: int
    reused_unit_count: int


@dataclass(frozen=True)
class _Instruction:
    rva: int
    size: int
    digest: str
    mnemonic: str
    operands: tuple[dict[str, Any], ...]
    registers_read: tuple[str, ...]
    registers_written: tuple[str, ...]
    groups: tuple[str, ...]

    @property
    def end(self) -> int:
        return self.rva + self.size

    def payload(self) -> dict[str, Any]:
        return {
            "rva_start": self.rva,
            "rva_end": self.end,
            "size": self.size,
            "instruction_sha256": self.digest,
            "mnemonic": self.mnemonic,
            "operands": [copy.deepcopy(item) for item in self.operands],
            "registers_read": list(self.registers_read),
            "registers_written": list(self.registers_written),
            "groups": list(self.groups),
        }


def _validate_semantic_shape(
    row: Mapping[str, Any], identity: str, span: RvaSpan
) -> None:
    if not isinstance(row.get("status"), str) or not row.get("status"):
        raise MachineIRExportError(
            f"{identity}: semantic unit status is missing",
            code="malformed_semantic_unit_status",
            unit_id=identity,
            rva=span.start,
        )
    if not isinstance(row.get("expression_model"), str) or not row.get("expression_model"):
        raise MachineIRExportError(
            f"{identity}: expression model is missing",
            code="malformed_semantic_unit_model",
            unit_id=identity,
            rva=span.start,
        )
    if not isinstance(row.get("pre_state"), Mapping):
        raise MachineIRExportError(
            f"{identity}: pre_state must be an object",
            code="malformed_semantic_unit_effects",
            unit_id=identity,
            rva=span.start,
        )
    for field in (
        "register_writes",
        "flag_writes",
        "memory_events",
        "external_events",
        "faults",
        "ordered_events",
        "edge_conditions",
    ):
        values = row.get(field)
        if not isinstance(values, list) or any(
            not isinstance(item, Mapping) for item in values
        ):
            raise MachineIRExportError(
                f"{identity}: {field} must be a list of objects",
                code="malformed_semantic_unit_effects",
                unit_id=identity,
                rva=span.start,
            )
    outcome = row.get("outcome")
    if (
        not isinstance(outcome, Mapping)
        or not isinstance(outcome.get("kind"), str)
        or not outcome.get("kind")
    ):
        raise MachineIRExportError(
            f"{identity}: outcome must name a control kind",
            code="malformed_semantic_unit_control",
            unit_id=identity,
            rva=span.start,
        )
    stack_delta = row.get("stack_delta")
    if stack_delta is not None and not isinstance(stack_delta, Mapping):
        raise MachineIRExportError(
            f"{identity}: stack_delta must be an object or null",
            code="malformed_semantic_unit_effects",
            unit_id=identity,
            rva=span.start,
        )
    counts = row.get("counts")
    if counts is not None and not isinstance(counts, Mapping):
        raise MachineIRExportError(
            f"{identity}: counts must be an object or null",
            code="malformed_semantic_unit_effects",
            unit_id=identity,
            rva=span.start,
        )


def _merge_ranges(ranges: Iterable[RvaSpan]) -> list[RvaSpan]:
    merged: list[RvaSpan] = []
    for span in sorted(ranges):
        if not merged or span.start > merged[-1].end:
            merged.append(span)
        else:
            merged[-1] = RvaSpan(merged[-1].start, max(merged[-1].end, span.end))
    return merged


def _subtract_ranges(whole: RvaSpan, classified: Sequence[RvaSpan]) -> list[RvaSpan]:
    cursor = whole.start
    result: list[RvaSpan] = []
    for span in classified:
        if span.end <= cursor or span.start >= whole.end:
            continue
        if span.start > cursor:
            result.append(RvaSpan(cursor, min(span.start, whole.end)))
        cursor = max(cursor, span.end)
        if cursor >= whole.end:
            break
    if cursor < whole.end:
        result.append(RvaSpan(cursor, whole.end))
    return result


def _intersections(whole: RvaSpan, ranges: Sequence[RvaSpan]) -> list[RvaSpan]:
    return [
        RvaSpan(max(whole.start, span.start), min(whole.end, span.end))
        for span in ranges
        if max(whole.start, span.start) < min(whole.end, span.end)
    ]


def _optional_range(value: Any) -> RvaSpan | None:
    if not isinstance(value, Mapping):
        return None
    start = value.get("rva_start", value.get("rva"))
    end = value.get("rva_end")
    if end is None and isinstance(start, int) and isinstance(value.get("size"), int):
        end = start + value["size"]
    if (
        isinstance(start, int)
        and not isinstance(start, bool)
        and isinstance(end, int)
        and not isinstance(end, bool)
        and 0 <= start < end <= 2**32
    ):
        return RvaSpan(start, end)
    return None


def _aggregate_status(issues: Sequence[Mapping[str, Any]]) -> str:
    if any(issue.get("status") == "violated" for issue in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "qualified"


def _assert_byte_free(value: Any, path: str = "$") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            numeric_byte_count = (
                key == "bytes"
                and isinstance(item, int)
                and not isinstance(item, bool)
                and item >= 0
            )
            if key in _RAW_INSTRUCTION_FIELDS and not numeric_byte_count:
                raise AssertionError(f"raw instruction field {path}.{key} crossed the machine IR boundary")
            _assert_byte_free(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _assert_byte_free(item, f"{path}[{index}]")


def _regular_file(value: Path, label: str) -> Path:
    supplied = Path(value)
    if supplied.is_symlink() or not supplied.is_file():
        raise MachineIRExportError(f"{label} must be a regular non-symlink file")
    return supplied.resolve()


def _json_object(path: Path, label: str) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MachineIRExportError(f"cannot read {label}: {exc}") from exc
    if not isinstance(value, dict):
        raise MachineIRExportError(f"{label} must contain one JSON object")
    return value


def _canonical_json(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _required_string(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise MachineIRExportError(f"{label} must be a non-empty string")
    return value


def _optional_string(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _digest(value: Any, label: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise MachineIRExportError(f"{label} must be a lowercase SHA-256 digest")
    return value


def _u32(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 2**32:
        raise MachineIRExportError(f"{label} must be an unsigned 32-bit integer")
    return value


def _hex_bytes(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2:
        raise MachineIRExportError(f"{label} must be an even-length hexadecimal string")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise MachineIRExportError(f"{label} must be hexadecimal") from exc


def _json_scalar(value: Any, label: str) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    raise MachineIRExportError(f"{label} contains a non-JSON value {type(value).__name__}")
