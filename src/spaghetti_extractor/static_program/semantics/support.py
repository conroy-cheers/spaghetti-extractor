"""Small shared helpers for original-only static semantics."""

from __future__ import annotations

import re
from collections import Counter
from typing import Any, Iterable, Mapping, Protocol

from ...pe32.stage_binary import BlockSide, StageAInputError


class _StaticUnitLike(Protocol):
    source: Mapping[str, Any]


def _range_report(side: BlockSide) -> dict[str, int]:
    return {
        "rva_start": side.rva_start,
        "rva_end": side.rva_end,
        "size": side.size,
    }


def _mapping_source(unit: _StaticUnitLike) -> dict[str, Any]:
    source = unit.source.get("source")
    return dict(source) if isinstance(source, Mapping) else {}


def _parse_int(value: Any) -> int:
    if isinstance(value, bool):
        raise StageAInputError(f"expected integer or integer string, got {value!r}")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value, 0)
    raise StageAInputError(f"expected integer or integer string, got {value!r}")


def _is_conditional_jump(mnemonic: str) -> bool:
    return mnemonic in {
        "ja", "jae", "jb", "jbe", "jc", "je", "jg", "jge", "jl", "jle",
        "jna", "jnae", "jnb", "jnbe", "jnc", "jne", "jng", "jnge", "jnl",
        "jnle", "jno", "jnp", "jns", "jnz", "jo", "jp", "jpe", "jpo",
        "js", "jz",
    }


def _safe_gap_part(value: str) -> str:
    return re.sub(r"[^A-Za-z0-9_.-]+", "-", value).strip("-") or "unknown"


def _safe_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _count_by(items: Iterable[Mapping[str, Any]], key: str) -> dict[str, int]:
    return dict(sorted(Counter(str(item.get(key) or "unknown") for item in items).items()))


__all__ = [
    "_count_by",
    "_is_conditional_jump",
    "_mapping_source",
    "_parse_int",
    "_range_report",
    "_safe_gap_part",
    "_safe_int",
]
