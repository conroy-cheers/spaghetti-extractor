"""Exact event-bound memory-address facts from the cold v2 replay.

The interprocedural analyzer proposes finite address origins.  This module
binds those proposals to an exact PE, machine-IR unit, and memory event before
another analysis may consume them.  The resulting facts are useful evidence,
not a replacement for exact machine semantics or rooted-control closure.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence, TypeVar

from .analysis_schema_v2 import CHECKED_MEMORY_ACCESS_FACT_V2_FORMAT
from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    CanonicalJson,
    EventBinding,
    canonical_json_bytes,
)
from .machine_ir_authority_v2 import (
    MachineIRAuthorityV2Error,
    recompute_event_binding,
    recompute_unit_binding,
)
from .provenance_domain import PROVENANCE_KINDS


MEMORY_ACCESS_PROPOSAL_V2_FORMAT = "stage-a-memory-access-proposal-v2"
_MEMORY_KINDS = frozenset({"read", "write", "read_write"})
_MUTABLE_DEPENDENCY_PREFIXES = (
    "global-slot:",
    "global_slot:",
    "global-slot-invariant:",
    "global_slot_invariant:",
)


_MemoryFact = TypeVar("_MemoryFact", bound="PreparedMemoryAccessFact")


class CheckedMemoryAccessV2Error(ValueError):
    """A memory-access proposal or checked binding is malformed or stale."""


@dataclass(frozen=True)
class PreparedMemoryAccessFact:
    fact_id: str
    binding: EventBinding
    memory_kind: str
    width_bytes: int
    address_expression: CanonicalJson
    address_origins: tuple[CanonicalJson, ...]
    authority_dependencies: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.memory_kind not in _MEMORY_KINDS:
            raise AuthorityDataError("checked memory access has an invalid kind")
        if not 0 < self.width_bytes <= 4096:
            raise AuthorityDataError("checked memory access has an invalid width")
        if not self.address_origins:
            raise AuthorityDataError("checked memory access has no address origins")
        if tuple(sorted(set(self.authority_dependencies))) != self.authority_dependencies:
            raise AuthorityDataError(
                "memory-access dependencies must be sorted and unique"
            )
        if any(_mutable_dependency(value) for value in self.authority_dependencies):
            raise AuthorityDataError(
                "memory-access fact cannot depend on a mutable-slot invariant"
            )
        expected = _fact_id(self.signature_payload(include_id=False))
        if self.fact_id != expected:
            raise AuthorityDataError("checked memory-access ID is not canonical")

    def signature_payload(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "format": CHECKED_MEMORY_ACCESS_FACT_V2_FORMAT,
            "status": "complete",
            "binding": self.binding.to_payload(),
            "memory_kind": self.memory_kind,
            "width_bytes": self.width_bytes,
            "address_expression": self.address_expression.to_value(),
            "address_origins": [value.to_value() for value in self.address_origins],
            "authority_dependencies": list(self.authority_dependencies),
        }
        if include_id:
            payload["id"] = self.fact_id
        return payload


@dataclass(frozen=True)
class CheckedMemoryAccessFact(PreparedMemoryAccessFact):
    interprocedural_authority_sha256: str

    def __post_init__(self) -> None:
        super().__post_init__()
        _digest(
            self.interprocedural_authority_sha256,
            "interprocedural authority SHA-256",
        )

    def to_payload(self) -> dict[str, Any]:
        payload = {
            **self.signature_payload(),
            "interprocedural_authority_sha256": (
                self.interprocedural_authority_sha256
            ),
        }
        return {**payload, "fact_sha256": _sha256(payload)}


def prepare_checked_memory_access_facts_v2(
    proposals: Sequence[Mapping[str, Any]],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
) -> tuple[dict[str, Any], ...]:
    """Bind analyzer proposals to exact units/events, without the self hash."""

    by_id = _unit_rows(units)
    prepared: list[dict[str, Any]] = []
    seen_events: set[tuple[str, int]] = set()
    for index, raw in enumerate(proposals):
        try:
            proposal = _proposal(raw)
            unit_id = _text(proposal.get("unit_id"), "proposal unit ID")
            event_index = _uint(
                proposal.get("event_index"), "proposal event index"
            )
            event_key = (unit_id, event_index)
            if event_key in seen_events:
                raise CheckedMemoryAccessV2Error(
                    "memory-access proposals duplicate one exact event"
                )
            seen_events.add(event_key)
            unit_row = by_id.get(unit_id)
            if unit_row is None:
                raise CheckedMemoryAccessV2Error(
                    "memory-access proposal references an unknown unit"
                )
            events = _memory_events(unit_row)
            if event_index >= len(events):
                raise CheckedMemoryAccessV2Error(
                    "memory-access proposal references an unknown event"
                )
            event = events[event_index]
            unit_binding = recompute_unit_binding(unit_row, binary=binary)
            event_binding = recompute_event_binding(
                unit_binding,
                event,
                event_index=event_index,
            )
            memory_kind = _text(proposal.get("memory_kind"), "memory kind")
            width_bytes = _uint(
                proposal.get("width_bytes"), "memory width", maximum=4096
            )
            if width_bytes == 0:
                raise CheckedMemoryAccessV2Error("memory width cannot be zero")
            if (
                memory_kind != event.get("kind")
                or width_bytes != event.get("width")
                or proposal.get("address_expression") != event.get("address")
            ):
                raise CheckedMemoryAccessV2Error(
                    "memory-access proposal does not match its exact event"
                )
            origins, origin_dependencies = _origins(
                proposal.get("address_origins")
            )
            supplied_dependencies = _dependencies(
                proposal.get("authority_dependencies")
            )
            if supplied_dependencies != origin_dependencies:
                raise CheckedMemoryAccessV2Error(
                    "memory-access proposal dependency inventory is stale"
                )
            address_expression = CanonicalJson.of(event["address"])
            base = {
                "format": CHECKED_MEMORY_ACCESS_FACT_V2_FORMAT,
                "status": "complete",
                "binding": event_binding.to_payload(),
                "memory_kind": memory_kind,
                "width_bytes": width_bytes,
                "address_expression": address_expression.to_value(),
                "address_origins": [value.to_value() for value in origins],
                "authority_dependencies": list(supplied_dependencies),
            }
            fact_id = _fact_id(base)
            prepared.append({**base, "id": fact_id})
        except (AuthorityDataError, MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
            if isinstance(exc, CheckedMemoryAccessV2Error):
                raise
            raise CheckedMemoryAccessV2Error(
                f"memory-access proposal {index} is invalid: {exc}"
            ) from exc
    return tuple(sorted(prepared, key=lambda row: str(row["id"])))


def seal_checked_memory_access_facts_v2(
    prepared: Sequence[Mapping[str, Any]],
    *,
    interprocedural_authority_sha256: str,
) -> tuple[dict[str, Any], ...]:
    _digest(interprocedural_authority_sha256, "interprocedural authority SHA-256")
    result = []
    for row in prepared:
        prepared_fact = _parse_prepared(row)
        fact = CheckedMemoryAccessFact(
            **_prepared_fields(prepared_fact),
            interprocedural_authority_sha256=interprocedural_authority_sha256,
        )
        result.append(fact.to_payload())
    return tuple(sorted(result, key=lambda row: str(row["id"])))


def validate_prepared_memory_access_facts_v2(
    rows: Sequence[Mapping[str, Any]],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
) -> dict[str, PreparedMemoryAccessFact]:
    """Replay exact bindings before facts enter the interprocedural SCC."""

    parsed: list[PreparedMemoryAccessFact] = []
    for index, row in enumerate(rows):
        try:
            parsed.append(_parse_prepared(row))
        except (AuthorityDataError, MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
            if isinstance(exc, CheckedMemoryAccessV2Error):
                raise
            raise CheckedMemoryAccessV2Error(
                f"prepared memory-access fact {index} is invalid: {exc}"
            ) from exc
    return _validate_fact_bindings(
        parsed,
        units=units,
        binary=binary,
        context="prepared memory-access fact",
    )


def validate_checked_memory_access_facts_v2(
    rows: Sequence[Mapping[str, Any]],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
    interprocedural_authority_sha256: str,
) -> dict[str, CheckedMemoryAccessFact]:
    """Recompute every exact event binding and return facts by event node."""

    _digest(interprocedural_authority_sha256, "interprocedural authority SHA-256")
    parsed: list[CheckedMemoryAccessFact] = []
    for index, raw in enumerate(rows):
        try:
            fact = _parse_sealed(raw)
            if fact.interprocedural_authority_sha256 != interprocedural_authority_sha256:
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact has a stale interprocedural binding"
                )
            parsed.append(fact)
        except (AuthorityDataError, MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
            if isinstance(exc, CheckedMemoryAccessV2Error):
                raise
            raise CheckedMemoryAccessV2Error(
                f"checked memory-access fact {index} is invalid: {exc}"
            ) from exc
    return _validate_fact_bindings(
        parsed,
        units=units,
        binary=binary,
        context="checked memory-access fact",
    )


def memory_access_fact_signature_projection_v2(
    row: Mapping[str, Any],
) -> dict[str, Any]:
    """Return the non-self-referential part covered by interprocedural authority."""

    return {
        key: value
        for key, value in dict(row).items()
        if key not in {"interprocedural_authority_sha256", "fact_sha256"}
    }


def _parse_prepared(
    row: Mapping[str, Any],
) -> PreparedMemoryAccessFact:
    expected = {
        "format",
        "id",
        "status",
        "binding",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "address_origins",
        "authority_dependencies",
    }
    if not isinstance(row, Mapping) or set(row) != expected:
        raise CheckedMemoryAccessV2Error(
            "prepared memory-access fact has noncanonical fields"
        )
    if (
        row.get("format") != CHECKED_MEMORY_ACCESS_FACT_V2_FORMAT
        or row.get("status") != "complete"
    ):
        raise CheckedMemoryAccessV2Error(
            "prepared memory-access fact has an invalid format or status"
        )
    origins, origin_dependencies = _origins(row.get("address_origins"))
    dependencies = _dependencies(row.get("authority_dependencies"))
    if dependencies != origin_dependencies:
        raise CheckedMemoryAccessV2Error(
            "prepared memory-access dependency inventory is stale"
        )
    return PreparedMemoryAccessFact(
        fact_id=_text(row.get("id"), "memory-access fact ID"),
        binding=EventBinding.parse(row.get("binding")),
        memory_kind=_text(row.get("memory_kind"), "memory kind"),
        width_bytes=_uint(row.get("width_bytes"), "memory width", maximum=4096),
        address_expression=CanonicalJson.of(row.get("address_expression")),
        address_origins=origins,
        authority_dependencies=dependencies,
    )


def _parse_sealed(row: Mapping[str, Any]) -> CheckedMemoryAccessFact:
    expected = {
        "format",
        "id",
        "status",
        "binding",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "address_origins",
        "authority_dependencies",
        "interprocedural_authority_sha256",
        "fact_sha256",
    }
    if not isinstance(row, Mapping) or set(row) != expected:
        raise CheckedMemoryAccessV2Error(
            "checked memory-access fact has noncanonical fields"
        )
    payload = {key: value for key, value in row.items() if key != "fact_sha256"}
    if row.get("fact_sha256") != _sha256(payload):
        raise CheckedMemoryAccessV2Error(
            "checked memory-access fact digest is stale"
        )
    prepared = _parse_prepared(
        memory_access_fact_signature_projection_v2(row)
    )
    return CheckedMemoryAccessFact(
        **_prepared_fields(prepared),
        interprocedural_authority_sha256=_digest(
            row.get("interprocedural_authority_sha256"),
            "interprocedural authority SHA-256",
        ),
    )


def _prepared_fields(fact: PreparedMemoryAccessFact) -> dict[str, Any]:
    return {
        "fact_id": fact.fact_id,
        "binding": fact.binding,
        "memory_kind": fact.memory_kind,
        "width_bytes": fact.width_bytes,
        "address_expression": fact.address_expression,
        "address_origins": fact.address_origins,
        "authority_dependencies": fact.authority_dependencies,
    }


def _validate_fact_bindings(
    facts: Iterable[_MemoryFact],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
    context: str,
) -> dict[str, _MemoryFact]:
    by_id = _unit_rows(units)
    result: dict[str, _MemoryFact] = {}
    seen_ids: set[str] = set()
    for index, fact in enumerate(facts):
        try:
            unit_row = by_id.get(fact.binding.unit.unit_id)
            if unit_row is None:
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact references an unknown unit"
                )
            expected_unit = recompute_unit_binding(unit_row, binary=binary)
            if fact.binding.unit != expected_unit:
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact has a stale unit binding"
                )
            events = _memory_events(unit_row)
            if fact.binding.event_index >= len(events):
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact references an unknown event"
                )
            event = events[fact.binding.event_index]
            expected_event = recompute_event_binding(
                expected_unit,
                event,
                event_index=fact.binding.event_index,
            )
            if fact.binding != expected_event:
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact has a stale event binding"
                )
            if (
                fact.memory_kind != event.get("kind")
                or fact.width_bytes != event.get("width")
                or fact.address_expression.to_value() != event.get("address")
            ):
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact contradicts exact machine IR"
                )
            if fact.fact_id in seen_ids:
                raise CheckedMemoryAccessV2Error(
                    "memory-access fact ID is duplicated"
                )
            seen_ids.add(fact.fact_id)
            event_node = (
                f"event:{fact.binding.unit.unit_id}:{fact.binding.event_index}"
            )
            if event_node in result:
                raise CheckedMemoryAccessV2Error(
                    "multiple memory-access facts bind one event"
                )
            result[event_node] = fact
        except (AuthorityDataError, MachineIRAuthorityV2Error, TypeError, ValueError) as exc:
            if isinstance(exc, CheckedMemoryAccessV2Error):
                raise
            raise CheckedMemoryAccessV2Error(
                f"{context} {index} is invalid: {exc}"
            ) from exc
    return dict(sorted(result.items()))


def _proposal(value: Any) -> Mapping[str, Any]:
    expected = {
        "format",
        "status",
        "unit_id",
        "event_index",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "address_origins",
        "authority_dependencies",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise CheckedMemoryAccessV2Error(
            "memory-access proposal has noncanonical fields"
        )
    if (
        value.get("format") != MEMORY_ACCESS_PROPOSAL_V2_FORMAT
        or value.get("status") != "complete"
    ):
        raise CheckedMemoryAccessV2Error(
            "memory-access proposal has an invalid format or status"
        )
    return value


def _origins(value: Any) -> tuple[tuple[CanonicalJson, ...], tuple[str, ...]]:
    if not isinstance(value, list) or not value or len(value) > 256:
        raise CheckedMemoryAccessV2Error(
            "memory-access origins must be a nonempty bounded array"
        )
    origins: list[CanonicalJson] = []
    dependencies: set[str] = set()
    for raw in value:
        if not isinstance(raw, Mapping):
            raise CheckedMemoryAccessV2Error("memory-access origin is malformed")
        allowed = {"kind", "key", "authority_dependencies"}
        if not set(raw) <= allowed or not {"kind", "key"} <= set(raw):
            raise CheckedMemoryAccessV2Error(
                "memory-access origin has noncanonical fields"
            )
        kind = raw.get("kind")
        key = raw.get("key")
        if kind not in PROVENANCE_KINDS or not isinstance(key, list):
            raise CheckedMemoryAccessV2Error("memory-access origin is invalid")
        origin_dependencies = _dependencies(raw.get("authority_dependencies", []))
        dependencies.update(origin_dependencies)
        origins.append(CanonicalJson.of({
            "kind": kind,
            "key": key,
            **(
                {}
                if not origin_dependencies
                else {"authority_dependencies": list(origin_dependencies)}
            ),
        }))
    unique = {value.data: value for value in origins}
    if len(unique) != len(origins):
        raise CheckedMemoryAccessV2Error("memory-access origin is duplicated")
    return (
        tuple(unique[key] for key in sorted(unique)),
        tuple(sorted(dependencies)),
    )


def _dependencies(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise CheckedMemoryAccessV2Error(
            "memory-access dependencies must be an array of IDs"
        )
    result = tuple(sorted(set(value)))
    if list(result) != value:
        raise CheckedMemoryAccessV2Error(
            "memory-access dependencies must be sorted and unique"
        )
    if any(_mutable_dependency(item) for item in result):
        raise CheckedMemoryAccessV2Error(
            "memory-access fact cannot depend on a mutable-slot invariant"
        )
    return result


def _memory_events(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    semantics = unit.get("semantics")
    rows = semantics.get("memory_events") if isinstance(semantics, Mapping) else None
    if not isinstance(rows, list) or any(not isinstance(row, Mapping) for row in rows):
        raise CheckedMemoryAccessV2Error(
            "machine-IR unit has no exact memory-event inventory"
        )
    return [row for row in rows if isinstance(row, Mapping)]


def _unit_rows(
    units: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for row in units:
        if not isinstance(row, Mapping):
            raise CheckedMemoryAccessV2Error("machine-IR unit is malformed")
        unit_id = _text(row.get("id"), "machine-IR unit ID")
        if unit_id in result:
            raise CheckedMemoryAccessV2Error("machine-IR unit ID is duplicated")
        result[unit_id] = row
    return result


def _fact_id(value: Mapping[str, Any]) -> str:
    identity = {
        key: value.get(key)
        for key in (
            "format",
            "status",
            "binding",
            "memory_kind",
            "width_bytes",
            "address_expression",
        )
    }
    return (
        "memory-access:"
        + hashlib.sha256(canonical_json_bytes(identity)).hexdigest()[:20]
    )


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CheckedMemoryAccessV2Error(f"{context} is invalid")
    return value


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise CheckedMemoryAccessV2Error(f"{context} is invalid")
    return value


def _uint(value: Any, context: str, *, maximum: int = 0xFFFFFFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise CheckedMemoryAccessV2Error(f"{context} is invalid")
    return value


def _mutable_dependency(value: str) -> bool:
    lowered = value.lower()
    return any(marker in lowered for marker in _MUTABLE_DEPENDENCY_PREFIXES)


__all__ = [
    "CheckedMemoryAccessFact",
    "CheckedMemoryAccessV2Error",
    "MEMORY_ACCESS_PROPOSAL_V2_FORMAT",
    "PreparedMemoryAccessFact",
    "memory_access_fact_signature_projection_v2",
    "prepare_checked_memory_access_facts_v2",
    "seal_checked_memory_access_facts_v2",
    "validate_checked_memory_access_facts_v2",
    "validate_prepared_memory_access_facts_v2",
]
