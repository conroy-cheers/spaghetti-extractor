"""Load hash-bound external-tail/static-slot Lean authority references.

This is the narrow handoff between proposal generation and mixed-original
composition.  It never interprets report counts or statuses as proof.  A
consumer imports each returned module and supplies the qualified term where
Lean expects the exact ``ExternalTailStaticPointerSlotStaticAuthority`` type.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from .external_tail_static_pointer_slot_proposal import (
    EXTERNAL_TAIL_STATIC_POINTER_SLOT_AUTHORITY_FORMAT,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_MODULE = re.compile(
    r"StageA\.[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_QUALIFIED = re.compile(
    r"[A-Za-z_][A-Za-z0-9_']*(?:\.[A-Za-z_][A-Za-z0-9_']*)*\Z"
)
_LOCAL = re.compile(r"[A-Za-z_][A-Za-z0-9_']*\Z")
_U32_LIMIT = 1 << 32


class ExternalTailStaticPointerSlotAuthorityError(StageAInputError):
    """A generated authority inventory is malformed or bound elsewhere."""


@dataclass(frozen=True, order=True)
class ExternalTailStaticPointerSlotAuthorityKey:
    source_target_id: int
    source_rva: int
    callsite_rva: int
    wrapper_target_id: int
    wrapper_rva: int
    continuation_target_id: int
    continuation_rva: int
    slot_rva: int
    slot_target_id: int
    slot_value: int
    site_id: int
    machine_contract_id: int
    dll: str
    symbol: str | None
    ordinal: int | None
    route_kind: str
    iat_rva: int | None


@dataclass(frozen=True)
class LeanAuthorityTerm:
    module: str
    namespace: str
    symbol: str

    @property
    def qualified(self) -> str:
        return f"{self.namespace}.{self.symbol}"


@dataclass(frozen=True)
class ExternalTailStaticPointerSlotAuthorityReference:
    key: ExternalTailStaticPointerSlotAuthorityKey
    call_instruction_size: int
    term: LeanAuthorityTerm


def load_external_tail_static_pointer_slot_authorities(
    report: Path | str,
    *,
    original_sha256: str,
    state_machine_sha256: str,
    machine_import_report_sha256: str,
) -> tuple[ExternalTailStaticPointerSlotAuthorityReference, ...]:
    """Load named terms only after all producer inputs match exactly."""

    expected_hashes = {
        "original_sha256": _sha256(original_sha256, "original_sha256"),
        "state_machine_sha256": _sha256(
            state_machine_sha256, "state_machine_sha256"
        ),
        "machine_import_report_sha256": _sha256(
            machine_import_report_sha256, "machine_import_report_sha256"
        ),
    }
    path = Path(report)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"cannot read external-tail authority report: {error}"
        ) from error
    root = _mapping(payload, "authority report")
    if root.get("format") != EXTERNAL_TAIL_STATIC_POINTER_SLOT_AUTHORITY_FORMAT:
        raise ExternalTailStaticPointerSlotAuthorityError(
            "external-tail authority report has an unsupported format"
        )
    inputs = _mapping(root.get("inputs"), "authority report inputs")
    for field, expected in expected_hashes.items():
        if inputs.get(field) != expected:
            raise ExternalTailStaticPointerSlotAuthorityError(
                f"external-tail authority report {field} does not match"
            )
    rows = root.get("sites")
    if not isinstance(rows, list):
        raise ExternalTailStaticPointerSlotAuthorityError(
            "external-tail authority report sites must be a list"
        )

    references = tuple(_reference(row, index) for index, row in enumerate(rows))
    keys = [reference.key for reference in references]
    terms = [
        (
            reference.term.module,
            reference.term.namespace,
            reference.term.symbol,
        )
        for reference in references
    ]
    if len(set(keys)) != len(keys):
        raise ExternalTailStaticPointerSlotAuthorityError(
            "external-tail authority report contains duplicate site keys"
        )
    if len(set(terms)) != len(terms):
        raise ExternalTailStaticPointerSlotAuthorityError(
            "external-tail authority report reuses one Lean term"
        )
    return tuple(sorted(references, key=lambda reference: reference.key))


def _reference(
    value: Any, index: int
) -> ExternalTailStaticPointerSlotAuthorityReference:
    row = _mapping(value, f"sites[{index}]")
    if row.get("profile") != "framed_external_tail_static_pointer_slot_v1":
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}] has an unsupported authority profile"
        )
    imported = _mapping(row.get("import"), f"sites[{index}].import")
    dll = imported.get("dll")
    symbol = imported.get("symbol")
    ordinal = imported.get("ordinal")
    if not isinstance(dll, str) or not dll or not dll.isascii():
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}].import.dll must be nonempty ASCII"
        )
    if (symbol is None) == (ordinal is None):
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}].import requires exactly one symbol or ordinal"
        )
    if symbol is not None and (
        not isinstance(symbol, str) or not symbol or not symbol.isascii()
    ):
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}].import.symbol must be nonempty ASCII"
        )
    if ordinal is not None:
        ordinal = _natural(ordinal, f"sites[{index}].import.ordinal")
        if ordinal > 0xFFFF:
            raise ExternalTailStaticPointerSlotAuthorityError(
                f"sites[{index}].import.ordinal exceeds the PE16 range"
            )

    route = row.get("route_kind")
    iat = row.get("iat_rva")
    if route == "direct_import":
        if iat is not None:
            raise ExternalTailStaticPointerSlotAuthorityError(
                f"sites[{index}] direct import unexpectedly carries an IAT RVA"
            )
    elif route == "iat_indirect":
        iat = _u32(iat, f"sites[{index}].iat_rva")
    else:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}].route_kind is unsupported"
        )

    term_row = _mapping(
        row.get("authorizing_lean_term"),
        f"sites[{index}].authorizing_lean_term",
    )
    module = term_row.get("module")
    namespace = term_row.get("namespace")
    term_symbol = term_row.get("symbol")
    if not isinstance(module, str) or _MODULE.fullmatch(module) is None:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}] authority module is not canonical"
        )
    if (
        not isinstance(namespace, str)
        or _QUALIFIED.fullmatch(namespace) is None
    ):
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}] authority namespace is not canonical"
        )
    if (
        not isinstance(term_symbol, str)
        or _LOCAL.fullmatch(term_symbol) is None
    ):
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}] authority symbol is not canonical"
        )

    source_rva = _u32(row.get("source_rva"), f"sites[{index}].source_rva")
    callsite_rva = _u32(
        row.get("callsite_rva"), f"sites[{index}].callsite_rva"
    )
    call_size = _natural(
        row.get("call_instruction_size"),
        f"sites[{index}].call_instruction_size",
    )
    continuation_rva = _u32(
        row.get("continuation_rva"), f"sites[{index}].continuation_rva"
    )
    if call_size == 0 or callsite_rva + call_size != continuation_rva:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"sites[{index}] call span does not end at its continuation"
        )
    key = ExternalTailStaticPointerSlotAuthorityKey(
        source_target_id=_natural(
            row.get("source_target_id"), f"sites[{index}].source_target_id"
        ),
        source_rva=source_rva,
        callsite_rva=callsite_rva,
        wrapper_target_id=_natural(
            row.get("wrapper_target_id"), f"sites[{index}].wrapper_target_id"
        ),
        wrapper_rva=_u32(
            row.get("wrapper_rva"), f"sites[{index}].wrapper_rva"
        ),
        continuation_target_id=_natural(
            row.get("continuation_target_id"),
            f"sites[{index}].continuation_target_id",
        ),
        continuation_rva=continuation_rva,
        slot_rva=_u32(row.get("slot_rva"), f"sites[{index}].slot_rva"),
        slot_target_id=_natural(
            row.get("slot_target_id"), f"sites[{index}].slot_target_id"
        ),
        slot_value=_u32(
            row.get("slot_value"), f"sites[{index}].slot_value"
        ),
        site_id=_natural(row.get("site_id"), f"sites[{index}].site_id"),
        machine_contract_id=_natural(
            row.get("machine_contract_id"),
            f"sites[{index}].machine_contract_id",
        ),
        dll=dll.lower(),
        symbol=symbol,
        ordinal=ordinal,
        route_kind=route,
        iat_rva=iat,
    )
    return ExternalTailStaticPointerSlotAuthorityReference(
        key=key,
        call_instruction_size=call_size,
        term=LeanAuthorityTerm(
            module=module,
            namespace=namespace,
            symbol=term_symbol,
        ),
    )


def _mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"{field} must be an object"
        )
    return value


def _natural(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"{field} must be a natural number"
        )
    return value


def _u32(value: Any, field: str) -> int:
    result = _natural(value, field)
    if result >= _U32_LIMIT:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"{field} must fit an unsigned 32-bit word"
        )
    return result


def _sha256(value: str, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise ExternalTailStaticPointerSlotAuthorityError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


__all__ = [
    "ExternalTailStaticPointerSlotAuthorityError",
    "ExternalTailStaticPointerSlotAuthorityKey",
    "ExternalTailStaticPointerSlotAuthorityReference",
    "LeanAuthorityTerm",
    "load_external_tail_static_pointer_slot_authorities",
]
