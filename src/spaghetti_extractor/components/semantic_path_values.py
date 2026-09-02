# ruff: noqa: F401
"""Machine-derived finite path models for portable component refinement.

This module contains no target knowledge and accepts no expected behavior.  It
symbolically executes exact machine-IR summaries, replacing only explicitly
bound service events with shared symbolic responses.  The resulting path set
is consumed by CBMC to compare portable C against every represented machine
path.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .inductive_receipts import CheckedInductiveMachineReceiptV1
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .interface_ir import ProofKernelComponentInterface
from .machine_binding import MachineProjectionV1
from .semantic_arithmetic import (
    byte_view_offset as _byte_view_offset,
    simplify_logical_arithmetic as _simplify_logical_arithmetic,
)
from .semantic_path_errors import SemanticPathError, SemanticPathViolation
from .semantic_services import (
    BoundServiceEvent as _BoundServiceEvent,
    service_event_index as _service_event_index,
)


_TRANSFER_REGISTERS = ("eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp")
_TRANSFER_FLAGS = ("cf", "zf", "sf", "of", "pf", "df", "af")

from .semantic_path_model import (
    _State,
    _ExecutedUnit,
)

def _unit_rva(unit: Mapping[str, object]) -> int:
    source = _object(unit.get("source"), "machine unit source")
    original = _object(source.get("original"), "machine unit original range")
    rva = original.get("rva_start")
    if not isinstance(rva, int) or isinstance(rva, bool):
        raise SemanticPathError("machine unit RVA is invalid")
    return rva


def _stack_address(base: Mapping[str, object], offset: int) -> dict[str, object]:
    if offset == 0:
        return copy.deepcopy(dict(base))
    return {
        "op": "add32",
        "args": [
            copy.deepcopy(dict(base)),
            {"op": "const", "value": offset & 0xFFFFFFFF, "width": 32},
        ],
    }


def _private_stack_offset(value: object) -> int | None:
    """Recognize a bounded constant address below operation-entry ESP."""

    if not isinstance(value, Mapping):
        return None
    if (
        value.get("op") == "symbol"
        and value.get("name") == "machine_esp"
        and value.get("width") == 32
    ):
        return 0
    op = value.get("op")
    args = value.get("args")
    if op not in {"add32", "sub32"} or not isinstance(args, list) or len(args) != 2:
        return None
    left = _private_stack_offset(args[0])
    right = args[1]
    if left is None or not isinstance(right, Mapping) or right.get("op") != "const":
        return None
    constant = right.get("value")
    if (
        right.get("width") != 32
        or not isinstance(constant, int)
        or isinstance(constant, bool)
        or constant < 0
        or constant > 0xFFFFFFFF
    ):
        return None
    signed = constant if constant < 0x80000000 else constant - 0x100000000
    if abs(signed) > 65536:
        return None
    return left + signed if op == "add32" else left - signed


def _expression_key(value: object) -> str:
    def canonical(item: object) -> object:
        if isinstance(item, Mapping):
            result = {str(key): canonical(child) for key, child in item.items()}
            if result.get("op") in {"add32", "and32", "or32", "xor32"} and isinstance(
                result.get("args"), list
            ):
                result["args"] = sorted(result["args"], key=canonical_sha256_v3)
            return result
        if isinstance(item, list):
            return [canonical(child) for child in item]
        return item

    normalized = (
        _simplify_logical_arithmetic(value)
        if isinstance(value, Mapping)
        else value
    )
    return canonical_sha256_v3(canonical(normalized))


def _collect_ops(value: object, operation: str) -> list[Mapping[str, object]]:
    result: list[Mapping[str, object]] = []
    if isinstance(value, Mapping):
        if value.get("op") == operation:
            result.append(value)
        for child in value.values():
            result.extend(_collect_ops(child, operation))
    elif isinstance(value, list):
        for child in value:
            result.extend(_collect_ops(child, operation))
    return result


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise SemanticPathError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise SemanticPathError(f"{context} must be an array of objects")
    return list(value)


def _array(value: object, context: str) -> list[object]:
    if not isinstance(value, list):
        raise SemanticPathError(f"{context} must be an array")
    return value


def _strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) or not item for item in value):
        raise SemanticPathError(f"{context} must be an array of nonempty strings")
    return tuple(value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise SemanticPathError(f"{context} must be a nonempty string")
    return value


def _uint(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise SemanticPathError(f"{context} must be an unsigned integer")
    return value


def _uint_rows(value: object, context: str) -> list[int]:
    if not isinstance(value, list):
        raise SemanticPathError(f"{context} must be an array")
    return [_uint(item, context) for item in value]
