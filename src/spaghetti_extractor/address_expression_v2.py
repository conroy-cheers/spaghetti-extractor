"""Small exact address-expression helpers shared by static analyses."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any


_UINT32 = 1 << 32


def constant_u32(expression: Any) -> int | None:
    """Evaluate the supported constant-only 32-bit address fragment."""

    if not isinstance(expression, Mapping):
        return None
    op = str(expression.get("op") or "").lower()
    if op in {"const", "constant"}:
        value = expression.get("value")
        return (
            value & 0xFFFF_FFFF
            if isinstance(value, int) and not isinstance(value, bool)
            else None
        )
    arguments = expression.get("args")
    if not isinstance(arguments, Sequence) or isinstance(
        arguments, (str, bytes)
    ):
        return None
    values = [constant_u32(value) for value in arguments]
    if len(values) != 2 or any(value is None for value in values):
        return None
    left, right = values
    assert left is not None and right is not None
    if op in {"add", "add32"}:
        return (left + right) & 0xFFFF_FFFF
    if op in {"sub", "sub32"}:
        return (left - right) & 0xFFFF_FFFF
    if op in {"mul", "mul32"}:
        return (left * right) & 0xFFFF_FFFF
    return None


def affine_atom_offset(
    expression: Any,
    *,
    atom_op: str,
    atom_name: str | None = None,
) -> int | None:
    """Return the signed constant in ``atom + constant`` when exact.

    ``atom_name`` is used for named atoms such as registers.  Unnamed machine
    inputs such as ``fs_base`` are selected by operation alone.
    """

    normalized_op = atom_op.lower()
    normalized_name = None if atom_name is None else atom_name.lower()

    def affine(value: Any) -> tuple[int, int] | None:
        if not isinstance(value, Mapping):
            return None
        op = str(value.get("op", "")).lower()
        if normalized_name is None:
            if op == normalized_op:
                return 1, 0
        elif op == normalized_op:
            name = str(value.get("name", value.get("reg", ""))).lower()
            if name == normalized_name:
                return 1, 0
        if op in {"const", "constant"}:
            raw = value.get("value")
            if not isinstance(raw, int) or isinstance(raw, bool):
                return None
            signed = raw & 0xFFFF_FFFF
            if signed >= 0x8000_0000:
                signed -= _UINT32
            return 0, signed
        args = value.get("args")
        if (
            op not in {"add", "add32", "sub", "sub32"}
            or not isinstance(args, list)
            or len(args) != 2
        ):
            return None
        left = affine(args[0])
        right = affine(args[1])
        if left is None or right is None:
            return None
        sign = -1 if op in {"sub", "sub32"} else 1
        coefficient = left[0] + sign * right[0]
        if coefficient not in {0, 1}:
            return None
        return coefficient, left[1] + sign * right[1]

    result = affine(expression)
    return result[1] if result is not None and result[0] == 1 else None


def affine_register_offset(expression: Any, register: str) -> int | None:
    """Return the signed constant in ``register + constant`` when exact."""

    for operation in ("reg", "register", "input_reg"):
        result = affine_atom_offset(
            expression,
            atom_op=operation,
            atom_name=register,
        )
        if result is not None:
            return result
    return None


def affine_special_offset(expression: Any, operation: str) -> int | None:
    """Return the signed offset from an unnamed machine-input expression."""

    return affine_atom_offset(expression, atom_op=operation)


__all__ = [
    "affine_atom_offset",
    "affine_register_offset",
    "affine_special_offset",
    "constant_u32",
]
