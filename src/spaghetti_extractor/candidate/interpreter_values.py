"""Parsing and value helpers for Stage B interpreter lowering."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable, Mapping

from ..pe32.stage_binary import StageAInputError
from ..util import sha256_bytes
from .interpreter_model import (
    StageBInterpreterError,
    _TypedX87Program,
    _X87_CHECKED_DECODER,
    _X87_CHECKED_EXECUTOR,
)
from .x87 import extract_typed_x87_operation


def _typed_x87_program(
    *,
    contract_sha256: str,
    image_base: int,
    rva_start: int,
    rva_end: int,
    instruction_bytes: bytes,
    instruction: Mapping[str, Any],
    checked_decoder: str,
    checked_executor: str,
) -> _TypedX87Program:
    try:
        operation = extract_typed_x87_operation(
            encoded=instruction_bytes,
            instruction=instruction,
            image_base=image_base,
        )
    except StageAInputError as exc:
        raise StageBInterpreterError(
            f"typed x87 extraction failed: {exc}",
            code="unsupported_typed_x87_operation",
            next_action=(
                "add the mnemonic and operand form to the reviewed typed x87 table "
                "and qualify it against the ISA oracles"
            ),
        ) from exc
    if operation.source_size != rva_end - rva_start:
        raise StageBInterpreterError(
            "typed x87 source size differs from its checked span",
            code="malformed_typed_x87_operation",
        )
    return _TypedX87Program(
        contract_sha256=contract_sha256,
        image_base=image_base,
        rva_start=rva_start,
        rva_end=rva_end,
        operation=operation,
        checked_decoder=checked_decoder,
        checked_executor=checked_executor,
    )


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise StageBInterpreterError(f"cannot read state machine {path}") from exc
    result: list[dict[str, Any]] = []
    for number, line in enumerate(lines, 1):
        if not line.strip():
            continue
        try:
            result.append(_object(json.loads(line), f"state machine line {number}"))
        except json.JSONDecodeError as exc:
            raise StageBInterpreterError(f"invalid state machine line {number}: {exc}") from exc
    if not result:
        raise StageBInterpreterError("state machine is empty")
    return result


def _object(value: Any, field: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise StageBInterpreterError(f"{field} must be an object")
    return value


def _list(value: Any, field: str) -> list[Any]:
    if not isinstance(value, list):
        raise StageBInterpreterError(f"{field} must be a list")
    return value


def _optional_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise StageBInterpreterError(f"{field} must be a non-empty string")
    return value


def _sha256(value: Any, field: str) -> str:
    text = _string(value, field)
    if len(text) != 64 or any(char not in "0123456789abcdef" for char in text):
        raise StageBInterpreterError(f"{field} must be a lowercase SHA-256")
    return text


def _hex_bytes(value: Any, field: str) -> bytes:
    text = _string(value, field)
    if len(text) % 2 or text != text.lower() or any(
        char not in "0123456789abcdef" for char in text
    ):
        raise StageBInterpreterError(f"{field} must be lowercase even-length hex")
    try:
        return bytes.fromhex(text)
    except ValueError as exc:
        raise StageBInterpreterError(f"{field} must be lowercase even-length hex") from exc


def _x87_singleton_candidate(
    instruction_bytes: bytes, instruction: Mapping[str, Any]
) -> bool:
    """Classify only; the configured checked singleton decoder remains authoritative."""

    mnemonic = instruction.get("mnemonic")
    if not isinstance(mnemonic, str):
        return False
    mnemonic = mnemonic.lower()
    if mnemonic == "wait":
        return instruction_bytes == b"\x9b"
    if not mnemonic.startswith("f"):
        return False
    return any(0xD8 <= byte <= 0xDF for byte in instruction_bytes[:4])


def _rva_list(values: Iterable[int]) -> str:
    return "[" + ", ".join(f"0x{value:x}" for value in values) + "]"


def _u32(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 2**32:
        raise StageBInterpreterError(f"{field} must be a uint32")
    return value


def _u32_wrapping(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise StageBInterpreterError(f"{field} must be an integer")
    return value & 0xFFFFFFFF


def _nonnegative(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise StageBInterpreterError(f"{field} must be nonnegative")
    return value


def _width(value: Any) -> int:
    result = _nonnegative(value, "memory width")
    if result not in {1, 2, 4}:
        raise StageBInterpreterError(f"unsupported memory width {result}")
    return result


def _width_bits(value: Any) -> int:
    result = _nonnegative(value, "bit width")
    if result not in {8, 16, 32}:
        raise StageBInterpreterError(f"unsupported bit width {result}")
    return result


def _x87_slot(value: Any) -> int:
    result = _nonnegative(value, "x87 slot")
    if result >= 8:
        raise StageBInterpreterError("x87 slot must be below 8")
    return result


def _arity_ok(actual: int, expected: int | tuple[int, int]) -> bool:
    return actual == expected if isinstance(expected, int) else expected[0] <= actual <= expected[1]


def _canonical(value: Mapping[str, Any]) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def _memory_dependency_keys(value: Any) -> frozenset[str]:
    """Return the canonical load observations needed by an expression."""

    if isinstance(value, Mapping):
        if value.get("op") == "load":
            # A completed outer load remains its own observation even when an
            # address-producing load is observed again later.
            return frozenset((_canonical(value),))
        dependencies: set[str] = set()
        for child in value.values():
            dependencies.update(_memory_dependency_keys(child))
        return frozenset(dependencies)
    if isinstance(value, list):
        dependencies = set()
        for child in value:
            dependencies.update(_memory_dependency_keys(child))
        return frozenset(dependencies)
    return frozenset()


def _json_sha256(value: Mapping[str, Any]) -> str:
    return sha256_bytes(_canonical(value).encode("ascii"))


def _stable_slot(value: str) -> int:
    result = 2166136261
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 16777619) & 0xFFFFFFFF
    return result


def _c_string(value: str | None) -> str:
    if value is None:
        return "0"
    return json.dumps(value, ensure_ascii=True)
