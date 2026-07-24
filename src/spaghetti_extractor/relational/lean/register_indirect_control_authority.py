"""Load and consume named register-indirect-control authority terms.

Reports remain proposal-only.  This consumer verifies all input hashes and
exact site keys, requires one distinct named Lean term per site, and partitions
only matching unresolved-indirect blockers.  The transformed plan is not
returned here: shared mixed-original generation must explicitly import the
named terms before it may remove those blockers.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Mapping

from ...errors import StageAInputError
from .interpreter_mixed_original import (
    InterpreterMixedOriginalPlan,
    OriginalGenerationBlocker,
    QualifiedLeanSymbol,
)
from .register_indirect_control_proposal import AUTHORITY_FORMAT
from .relocated_writable_static_pointer_slot_proposal import (
    mixed_original_plan_sha256,
)


_SHA256 = re.compile(r"[0-9a-f]{64}\Z")
_REGISTER_CATEGORIES = {"register_function_pointer", "register_tail_target"}


class RegisterIndirectControlAuthorityError(StageAInputError):
    """A named register-control authority is malformed or stale."""


@dataclass(frozen=True, order=True)
class AuthorityKey:
    source_target_id: int
    source_rva: int
    instruction_rva: int
    transfer: str
    target_register: str
    continuation_target_id: int | None
    continuation_rva: int | None


@dataclass(frozen=True)
class AuthorityReference:
    key: AuthorityKey
    site_id: int
    instruction_bytes: bytes
    inventory_kind: str
    producer_count: int
    carry_count: int
    term: QualifiedLeanSymbol


@dataclass(frozen=True)
class ConsumedAuthorityFrontier:
    references: tuple[AuthorityReference, ...]
    authorized_blockers: tuple[OriginalGenerationBlocker, ...]
    remaining_blockers: tuple[OriginalGenerationBlocker, ...]

    @property
    def imported_modules(self) -> tuple[str, ...]:
        return tuple(sorted({reference.term.module for reference in self.references}))

    @property
    def authorizing_terms(self) -> tuple[str, ...]:
        return tuple(reference.term.qualified for reference in self.references)

    @property
    def closed_site_rvas(self) -> tuple[int, ...]:
        return tuple(reference.key.source_rva for reference in self.references)

    @property
    def closed_instruction_rvas(self) -> tuple[int, ...]:
        return tuple(reference.key.instruction_rva for reference in self.references)


def load_register_indirect_control_authorities(
    report: Path | str,
    *,
    original_sha256: str,
    state_machine_sha256: str,
    machine_import_report_sha256: str,
    mixed_original_plan: InterpreterMixedOriginalPlan,
    writable_slot_report_sha256: str | None,
) -> tuple[AuthorityReference, ...]:
    root = _mapping(
        json.loads(Path(report).read_text(encoding="utf-8")), "authority report"
    )
    if root.get("format") != AUTHORITY_FORMAT:
        raise RegisterIndirectControlAuthorityError(
            "register-indirect authority report has an unsupported format"
        )
    inputs = _mapping(root.get("inputs"), "authority inputs")
    expected = {
        "original_sha256": _digest(original_sha256, "original_sha256"),
        "state_machine_sha256": _digest(state_machine_sha256, "state_machine_sha256"),
        "machine_import_report_sha256": _digest(
            machine_import_report_sha256, "machine_import_report_sha256"
        ),
        "mixed_original_plan_sha256": mixed_original_plan_sha256(mixed_original_plan),
        "writable_slot_report_sha256": (
            None
            if writable_slot_report_sha256 is None
            else _digest(
                writable_slot_report_sha256,
                "writable_slot_report_sha256",
            )
        ),
    }
    for field, value in expected.items():
        if inputs.get(field) != value:
            raise RegisterIndirectControlAuthorityError(
                f"register-indirect authority {field} does not match"
            )
    rows = root.get("sites")
    if not isinstance(rows, list):
        raise RegisterIndirectControlAuthorityError(
            "register-indirect authority sites must be a list"
        )
    references = tuple(_reference(row, index) for index, row in enumerate(rows))
    keys = [reference.key for reference in references]
    terms = [reference.term.qualified for reference in references]
    site_ids = [reference.site_id for reference in references]
    if len(set(keys)) != len(keys):
        raise RegisterIndirectControlAuthorityError(
            "register-indirect authority reuses one exact site key"
        )
    if len(set(terms)) != len(terms):
        raise RegisterIndirectControlAuthorityError(
            "register-indirect authority reuses one Lean term"
        )
    if len(set(site_ids)) != len(site_ids):
        raise RegisterIndirectControlAuthorityError(
            "register-indirect authority has duplicate site IDs"
        )
    return tuple(sorted(references, key=lambda reference: reference.key))


def consume_register_indirect_control_authorities(
    plan: InterpreterMixedOriginalPlan,
    references: tuple[AuthorityReference, ...],
) -> ConsumedAuthorityFrontier:
    """Partition exact blockers after named-term validation.

    This does not manufacture a blocker-free ``InterpreterMixedOriginalPlan``.
    The shared generator must first emit adapters which type-check every named
    term against the corresponding decomposed source region.
    """

    by_source = {reference.key.source_rva: reference for reference in references}
    if len(by_source) != len(references):
        raise RegisterIndirectControlAuthorityError(
            "register-indirect references are not unique by source RVA"
        )
    authorized: list[OriginalGenerationBlocker] = []
    remaining: list[OriginalGenerationBlocker] = []
    seen: set[int] = set()
    for blocker in plan.blockers:
        category = _blocker_category(blocker.detail)
        if (
            blocker.reason_code == "unresolved_indirect_control"
            and category in _REGISTER_CATEGORIES
            and blocker.rva in by_source
        ):
            reference = by_source[blocker.rva]
            _validate_plan_site(plan, blocker, reference)
            authorized.append(blocker)
            seen.add(reference.key.source_rva)
        else:
            remaining.append(blocker)
    missing = sorted(set(by_source) - seen)
    if missing:
        rendered = ", ".join(f"0x{rva:x}" for rva in missing)
        raise RegisterIndirectControlAuthorityError(
            f"register-indirect authorities lack matching blockers: {rendered}"
        )
    return ConsumedAuthorityFrontier(
        references=references,
        authorized_blockers=tuple(authorized),
        remaining_blockers=tuple(remaining),
    )


def _validate_plan_site(
    plan: InterpreterMixedOriginalPlan,
    blocker: OriginalGenerationBlocker,
    reference: AuthorityReference,
) -> None:
    matches = [
        (region, site)
        for region in plan.regions
        for site in region.indirect_sites
        if site.source_rva == reference.key.source_rva
        and site.instruction_rva == reference.key.instruction_rva
    ]
    if len(matches) != 1:
        raise RegisterIndirectControlAuthorityError(
            f"authority at 0x{reference.key.source_rva:x} does not select one plan site"
        )
    region, site = matches[0]
    checks = (
        (blocker.rva == reference.key.source_rva, "blocker source RVA"),
        (region.target_id == reference.key.source_target_id, "source target ID"),
        (
            site.is_call == (reference.key.transfer == "call"),
            "transfer kind",
        ),
        (
            site.continuation_rva == reference.key.continuation_rva,
            "continuation RVA",
        ),
        (
            _target_register(site.target_expression) == reference.key.target_register,
            "target register",
        ),
    )
    for valid, field in checks:
        if not valid:
            raise RegisterIndirectControlAuthorityError(
                f"authority at 0x{reference.key.source_rva:x} disagrees on {field}"
            )


def _reference(value: object, index: int) -> AuthorityReference:
    row = _mapping(value, f"sites[{index}]")
    term = _mapping(row.get("authorizing_lean_term"), "authorizing Lean term")
    carries = row.get("carries")
    if not isinstance(carries, list):
        raise RegisterIndirectControlAuthorityError(
            f"sites[{index}].carries must be a list"
        )
    inventory = _mapping(row.get("inventory"), f"sites[{index}].inventory")
    producers = inventory.get("producers")
    if not isinstance(producers, list) or not producers:
        raise RegisterIndirectControlAuthorityError(
            f"sites[{index}].inventory.producers must be a nonempty list"
        )
    for producer_index, value in enumerate(producers):
        producer = _mapping(
            value,
            f"sites[{index}].inventory.producers[{producer_index}]",
        )
        _natural(producer.get("instruction_rva"), "producer instruction RVA")
        _hex_bytes(
            producer.get("instruction_bytes"),
            "producer instruction bytes",
        )
        _string(producer.get("register"), "producer register")
        kind = _string(producer.get("kind"), "producer kind")
        if kind not in {
            "absolute_slot",
            "memory_load",
            "resolver_call",
            "immediate_code",
        }:
            raise RegisterIndirectControlAuthorityError(
                f"sites[{index}] has unsupported producer kind"
            )
    inventory_kind = _string(inventory.get("kind"), "inventory kind")
    if inventory_kind not in {
        "internal_code",
        "imported_address",
        "resolver_result",
        "registered_callback_slot",
        "nullable_code_table",
    }:
        raise RegisterIndirectControlAuthorityError(
            f"sites[{index}].inventory.kind is unsupported"
        )
    transfer = _string(row.get("transfer"), f"sites[{index}].transfer")
    if transfer not in {"call", "jump"}:
        raise RegisterIndirectControlAuthorityError(
            f"sites[{index}].transfer is unsupported"
        )
    continuation_target_id = row.get("continuation_target_id")
    continuation_rva = row.get("continuation_rva")
    if transfer == "call":
        continuation_target_id = _natural(
            continuation_target_id, "continuation target ID"
        )
        continuation_rva = _natural(continuation_rva, "continuation RVA")
    elif continuation_target_id is not None or continuation_rva is not None:
        raise RegisterIndirectControlAuthorityError(
            f"sites[{index}] jump has a continuation"
        )
    symbol = QualifiedLeanSymbol(
        module=_string(term.get("module"), "Lean module"),
        namespace=_string(term.get("namespace"), "Lean namespace"),
        symbol=_string(term.get("symbol"), "Lean symbol"),
    )
    symbol.validate("authorizing Lean term")
    return AuthorityReference(
        key=AuthorityKey(
            source_target_id=_natural(row.get("source_target_id"), "source target ID"),
            source_rva=_natural(row.get("source_rva"), "source RVA"),
            instruction_rva=_natural(row.get("instruction_rva"), "instruction RVA"),
            transfer=transfer,
            target_register=_string(row.get("target_register"), "target register"),
            continuation_target_id=continuation_target_id,
            continuation_rva=continuation_rva,
        ),
        site_id=_natural(row.get("site_id"), "site ID"),
        instruction_bytes=_hex_bytes(row.get("instruction_bytes"), "instruction bytes"),
        inventory_kind=inventory_kind,
        producer_count=len(producers),
        carry_count=len(carries),
        term=symbol,
    )


def _target_register(expression: Mapping[str, Any] | None) -> str | None:
    if not isinstance(expression, Mapping):
        return None
    if expression.get("op") != "reg":
        return None
    name = expression.get("name")
    return name if isinstance(name, str) else None


def _blocker_category(detail: str) -> str | None:
    return detail.split(" at ", 1)[0] if " at " in detail else None


def _mapping(value: object, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise RegisterIndirectControlAuthorityError(f"{field} must be an object")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value:
        raise RegisterIndirectControlAuthorityError(
            f"{field} must be a nonempty string"
        )
    return value


def _natural(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RegisterIndirectControlAuthorityError(f"{field} must be a natural number")
    return value


def _hex_bytes(value: object, field: str) -> bytes:
    text = _string(value, field)
    try:
        decoded = bytes.fromhex(text)
    except ValueError as error:
        raise RegisterIndirectControlAuthorityError(
            f"{field} must be hexadecimal"
        ) from error
    if not decoded:
        raise RegisterIndirectControlAuthorityError(f"{field} must be nonempty")
    return decoded


def _digest(value: str, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        raise RegisterIndirectControlAuthorityError(
            f"{field} must be a lowercase SHA-256 digest"
        )
    return value


def sha256_file(path: Path | str) -> str:
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


__all__ = [
    "AuthorityKey",
    "AuthorityReference",
    "ConsumedAuthorityFrontier",
    "RegisterIndirectControlAuthorityError",
    "consume_register_indirect_control_authorities",
    "load_register_indirect_control_authorities",
    "sha256_file",
]
