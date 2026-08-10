"""Finite address domains proved by exhaustive contextual static replay.

Ordinary memory-origin facts record what the provenance analyzer derived, but
do not establish that their alternatives cover every execution.  This artifact
is narrower and authority-bearing: for one exact memory event, every retained
rooted call context was replayed without truncation and produced one of the
listed concrete addresses.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from .analysis_schema_v2 import CHECKED_MEMORY_ADDRESS_DOMAIN_V2_FORMAT
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


MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT = (
    "spaghetti-extractor-memory-address-domain-proposal-v2"
)
CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT = (
    "spaghetti-extractor-contextual-memory-coverage-v1"
)
_MEMORY_KINDS = frozenset({"read", "write", "read_write"})
_MUTABLE_DEPENDENCY_PREFIXES = (
    "global-slot:",
    "global_slot:",
    "global-slot-invariant:",
    "global_slot_invariant:",
)


class CheckedMemoryAddressDomainV2Error(ValueError):
    """A finite address-domain proposal or checked fact is invalid."""


@dataclass(frozen=True)
class CheckedMemoryAddressDomain:
    domain_id: str
    binding: EventBinding
    memory_kind: str
    width_bytes: int
    address_expression: CanonicalJson
    addresses: tuple[int, ...]
    authority_dependencies: tuple[str, ...]
    context_coverage: CanonicalJson
    interprocedural_authority_sha256: str

    def __post_init__(self) -> None:
        if self.memory_kind not in _MEMORY_KINDS:
            raise AuthorityDataError("memory address domain has an invalid kind")
        if not 0 < self.width_bytes <= 4096:
            raise AuthorityDataError("memory address domain has an invalid width")
        if (
            not self.addresses
            or len(self.addresses) > 256
            or tuple(sorted(set(self.addresses))) != self.addresses
            or any(not _u32(value) for value in self.addresses)
        ):
            raise AuthorityDataError(
                "memory address domain must have sorted unique u32 addresses"
            )
        if tuple(sorted(set(self.authority_dependencies))) != (
            self.authority_dependencies
        ):
            raise AuthorityDataError(
                "memory address-domain dependencies must be sorted and unique"
            )
        if any(
            dependency.startswith(_MUTABLE_DEPENDENCY_PREFIXES)
            for dependency in self.authority_dependencies
        ):
            raise AuthorityDataError(
                "memory address domain cannot depend on mutable-slot authority"
            )
        _coverage(
            self.context_coverage.to_value(),
            event_unit_id=self.binding.unit.unit_id,
        )
        _digest(
            self.interprocedural_authority_sha256,
            "interprocedural authority SHA-256",
        )
        if self.domain_id != _domain_id(self.signature_payload(include_id=False)):
            raise AuthorityDataError("memory address-domain ID is not canonical")

    def signature_payload(self, *, include_id: bool = True) -> dict[str, Any]:
        payload = {
            "format": CHECKED_MEMORY_ADDRESS_DOMAIN_V2_FORMAT,
            "status": "complete",
            "binding": self.binding.to_payload(),
            "memory_kind": self.memory_kind,
            "width_bytes": self.width_bytes,
            "address_expression": self.address_expression.to_value(),
            "addresses": list(self.addresses),
            "authority_dependencies": list(self.authority_dependencies),
            "context_coverage": self.context_coverage.to_value(),
        }
        if include_id:
            payload["id"] = self.domain_id
        return payload

    def to_payload(self) -> dict[str, Any]:
        payload = {
            **self.signature_payload(),
            "interprocedural_authority_sha256": (
                self.interprocedural_authority_sha256
            ),
        }
        return {**payload, "domain_sha256": _sha256(payload)}


def prepare_checked_memory_address_domains_v2(
    proposals: Sequence[Mapping[str, Any]],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
) -> tuple[dict[str, Any], ...]:
    """Bind exhaustive contextual proposals to exact memory events."""

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
            key = (unit_id, event_index)
            if key in seen_events:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address-domain proposals duplicate one event"
                )
            seen_events.add(key)
            unit = by_id.get(unit_id)
            if unit is None:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address-domain proposal references an unknown unit"
                )
            events = _memory_events(unit)
            if event_index >= len(events):
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address-domain proposal references an unknown event"
                )
            event = events[event_index]
            memory_kind = _text(proposal.get("memory_kind"), "memory kind")
            width_bytes = _uint(
                proposal.get("width_bytes"), "memory width", maximum=4096
            )
            if width_bytes == 0:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address-domain width cannot be zero"
                )
            if (
                memory_kind != event.get("kind")
                or width_bytes != event.get("width")
                or proposal.get("address_expression") != event.get("address")
            ):
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address-domain proposal contradicts its event"
                )
            addresses = _addresses(proposal.get("addresses"))
            dependencies = _dependencies(
                proposal.get("authority_dependencies")
            )
            coverage = _coverage(
                proposal.get("context_coverage"), event_unit_id=unit_id
            )
            unit_binding = recompute_unit_binding(unit, binary=binary)
            event_binding = recompute_event_binding(
                unit_binding, event, event_index=event_index
            )
            base = {
                "format": CHECKED_MEMORY_ADDRESS_DOMAIN_V2_FORMAT,
                "status": "complete",
                "binding": event_binding.to_payload(),
                "memory_kind": memory_kind,
                "width_bytes": width_bytes,
                "address_expression": event["address"],
                "addresses": list(addresses),
                "authority_dependencies": list(dependencies),
                "context_coverage": coverage,
            }
            prepared.append({**base, "id": _domain_id(base)})
        except (
            AuthorityDataError,
            MachineIRAuthorityV2Error,
            TypeError,
            ValueError,
        ) as exc:
            if isinstance(exc, CheckedMemoryAddressDomainV2Error):
                raise
            raise CheckedMemoryAddressDomainV2Error(
                f"memory address-domain proposal {index} is invalid: {exc}"
            ) from exc
    return tuple(sorted(prepared, key=lambda row: str(row["id"])))


def seal_checked_memory_address_domains_v2(
    prepared: Sequence[Mapping[str, Any]],
    *,
    interprocedural_authority_sha256: str,
) -> tuple[dict[str, Any], ...]:
    _digest(interprocedural_authority_sha256, "interprocedural authority SHA-256")
    return tuple(
        sorted(
            (
                _parse_prepared(
                    row,
                    interprocedural_authority_sha256=(
                        interprocedural_authority_sha256
                    ),
                ).to_payload()
                for row in prepared
            ),
            key=lambda row: str(row["id"]),
        )
    )


def validate_checked_memory_address_domains_v2(
    rows: Sequence[Mapping[str, Any]],
    *,
    units: Sequence[Mapping[str, Any]],
    binary: BinaryBinding,
    interprocedural_authority_sha256: str,
) -> dict[str, CheckedMemoryAddressDomain]:
    """Recheck exact event bindings and return domains by event node."""

    _digest(interprocedural_authority_sha256, "interprocedural authority SHA-256")
    by_id = _unit_rows(units)
    result: dict[str, CheckedMemoryAddressDomain] = {}
    seen_ids: set[str] = set()
    for index, raw in enumerate(rows):
        try:
            domain = _parse_sealed(raw)
            if (
                domain.interprocedural_authority_sha256
                != interprocedural_authority_sha256
            ):
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address domain has a stale authority binding"
                )
            unit = by_id.get(domain.binding.unit.unit_id)
            if unit is None:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address domain references an unknown unit"
                )
            expected_unit = recompute_unit_binding(unit, binary=binary)
            if domain.binding.unit != expected_unit:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address domain has a stale unit binding"
                )
            events = _memory_events(unit)
            if domain.binding.event_index >= len(events):
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address domain references an unknown event"
                )
            event = events[domain.binding.event_index]
            expected_event = recompute_event_binding(
                expected_unit,
                event,
                event_index=domain.binding.event_index,
            )
            if domain.binding != expected_event:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address domain has a stale event binding"
                )
            if (
                domain.memory_kind != event.get("kind")
                or domain.width_bytes != event.get("width")
                or domain.address_expression.to_value() != event.get("address")
            ):
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address domain contradicts exact machine IR"
                )
            if domain.domain_id in seen_ids:
                raise CheckedMemoryAddressDomainV2Error(
                    "memory address-domain ID is duplicated"
                )
            seen_ids.add(domain.domain_id)
            node = f"event:{domain.binding.unit.unit_id}:{domain.binding.event_index}"
            if node in result:
                raise CheckedMemoryAddressDomainV2Error(
                    "multiple memory address domains bind one event"
                )
            result[node] = domain
        except (
            AuthorityDataError,
            MachineIRAuthorityV2Error,
            TypeError,
            ValueError,
        ) as exc:
            if isinstance(exc, CheckedMemoryAddressDomainV2Error):
                raise
            raise CheckedMemoryAddressDomainV2Error(
                f"checked memory address domain {index} is invalid: {exc}"
            ) from exc
    return dict(sorted(result.items()))


def memory_address_domain_signature_projection_v2(
    row: Mapping[str, Any],
) -> dict[str, Any]:
    return {
        key: value
        for key, value in dict(row).items()
        if key not in {"interprocedural_authority_sha256", "domain_sha256"}
    }


def _parse_prepared(
    row: Mapping[str, Any],
    *,
    interprocedural_authority_sha256: str,
) -> CheckedMemoryAddressDomain:
    expected = {
        "format",
        "id",
        "status",
        "binding",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "addresses",
        "authority_dependencies",
        "context_coverage",
    }
    if not isinstance(row, Mapping) or set(row) != expected:
        raise CheckedMemoryAddressDomainV2Error(
            "prepared memory address domain has noncanonical fields"
        )
    if (
        row.get("format") != CHECKED_MEMORY_ADDRESS_DOMAIN_V2_FORMAT
        or row.get("status") != "complete"
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "prepared memory address domain has an invalid format or status"
        )
    binding = EventBinding.parse(row.get("binding"))
    return CheckedMemoryAddressDomain(
        domain_id=_text(row.get("id"), "memory address-domain ID"),
        binding=binding,
        memory_kind=_text(row.get("memory_kind"), "memory kind"),
        width_bytes=_uint(row.get("width_bytes"), "memory width", maximum=4096),
        address_expression=CanonicalJson.of(row.get("address_expression")),
        addresses=_addresses(row.get("addresses")),
        authority_dependencies=_dependencies(
            row.get("authority_dependencies")
        ),
        context_coverage=CanonicalJson.of(
            _coverage(
                row.get("context_coverage"),
                event_unit_id=binding.unit.unit_id,
            )
        ),
        interprocedural_authority_sha256=interprocedural_authority_sha256,
    )


def _parse_sealed(row: Mapping[str, Any]) -> CheckedMemoryAddressDomain:
    expected = {
        "format",
        "id",
        "status",
        "binding",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "addresses",
        "authority_dependencies",
        "context_coverage",
        "interprocedural_authority_sha256",
        "domain_sha256",
    }
    if not isinstance(row, Mapping) or set(row) != expected:
        raise CheckedMemoryAddressDomainV2Error(
            "checked memory address domain has noncanonical fields"
        )
    payload = {key: value for key, value in row.items() if key != "domain_sha256"}
    if row.get("domain_sha256") != _sha256(payload):
        raise CheckedMemoryAddressDomainV2Error(
            "checked memory address-domain digest is stale"
        )
    return _parse_prepared(
        memory_address_domain_signature_projection_v2(row),
        interprocedural_authority_sha256=_digest(
            row.get("interprocedural_authority_sha256"),
            "interprocedural authority SHA-256",
        ),
    )


def _proposal(value: Any) -> Mapping[str, Any]:
    expected = {
        "format",
        "status",
        "unit_id",
        "event_index",
        "memory_kind",
        "width_bytes",
        "address_expression",
        "addresses",
        "authority_dependencies",
        "context_coverage",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise CheckedMemoryAddressDomainV2Error(
            "memory address-domain proposal has noncanonical fields"
        )
    if (
        value.get("format") != MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT
        or value.get("status") != "complete"
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "memory address-domain proposal has an invalid format or status"
        )
    return value


def _coverage(value: Any, *, event_unit_id: str) -> dict[str, Any]:
    expected = {
        "format",
        "status",
        "root_unit_ids",
        "relevant_unit_ids",
        "context_states",
        "context_depth",
        "contexts_per_unit",
        "truncated_calls",
        "dropped_contexts",
        "work_budget_exceeded",
    }
    if not isinstance(value, Mapping) or set(value) != expected:
        raise CheckedMemoryAddressDomainV2Error(
            "contextual memory coverage has noncanonical fields"
        )
    roots = _ids(value.get("root_unit_ids"), "coverage roots")
    relevant = _ids(value.get("relevant_unit_ids"), "coverage units")
    if (
        value.get("format") != CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT
        or value.get("status") != "complete"
        or not roots
        or event_unit_id not in relevant
        or _positive(value.get("context_states")) is None
        or _positive(value.get("context_depth")) is None
        or _positive(value.get("contexts_per_unit")) is None
        or _nonnegative(value.get("truncated_calls")) is None
        or value.get("dropped_contexts") != 0
        or value.get("work_budget_exceeded") is not False
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "contextual memory coverage is not exhaustive"
        )
    return {
        "format": CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT,
        "status": "complete",
        "root_unit_ids": list(roots),
        "relevant_unit_ids": list(relevant),
        "context_states": int(value["context_states"]),
        "context_depth": int(value["context_depth"]),
        "contexts_per_unit": int(value["contexts_per_unit"]),
        "truncated_calls": int(value["truncated_calls"]),
        "dropped_contexts": 0,
        "work_budget_exceeded": False,
    }


def _addresses(value: Any) -> tuple[int, ...]:
    if (
        not isinstance(value, list)
        or not value
        or len(value) > 256
        or any(not _u32(item) for item in value)
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "memory address-domain values must be bounded u32 addresses"
        )
    result = tuple(sorted(set(int(item) for item in value)))
    if list(result) != value:
        raise CheckedMemoryAddressDomainV2Error(
            "memory address-domain values must be sorted and unique"
        )
    return result


def _dependencies(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "memory address-domain dependencies must be an array of IDs"
        )
    result = tuple(sorted(set(value)))
    if list(result) != value:
        raise CheckedMemoryAddressDomainV2Error(
            "memory address-domain dependencies must be sorted and unique"
        )
    if any(
        item.startswith(_MUTABLE_DEPENDENCY_PREFIXES) for item in result
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "memory address domain cannot depend on mutable-slot authority"
        )
    return result


def _ids(value: Any, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise CheckedMemoryAddressDomainV2Error(f"{context} must be an ID array")
    result = tuple(sorted(set(value)))
    if list(result) != value:
        raise CheckedMemoryAddressDomainV2Error(
            f"{context} must be sorted and unique"
        )
    return result


def _unit_rows(
    units: Sequence[Mapping[str, Any]],
) -> dict[str, Mapping[str, Any]]:
    result: dict[str, Mapping[str, Any]] = {}
    for row in units:
        unit_id = row.get("id") if isinstance(row, Mapping) else None
        if not isinstance(unit_id, str) or not unit_id or unit_id in result:
            raise CheckedMemoryAddressDomainV2Error(
                "machine-IR unit inventory is malformed or duplicated"
            )
        result[unit_id] = row
    return result


def _memory_events(unit: Mapping[str, Any]) -> list[Mapping[str, Any]]:
    semantics = unit.get("semantics")
    events = semantics.get("memory_events") if isinstance(semantics, Mapping) else None
    if not isinstance(events, list) or any(
        not isinstance(event, Mapping) for event in events
    ):
        raise CheckedMemoryAddressDomainV2Error(
            "machine-IR memory event inventory is malformed"
        )
    return list(events)


def _domain_id(payload: Mapping[str, Any]) -> str:
    return "memory-address-domain:" + hashlib.sha256(
        canonical_json_bytes(payload)
    ).hexdigest()[:24]


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


def _digest(value: Any, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise CheckedMemoryAddressDomainV2Error(
            f"{context} must be a lowercase SHA-256 digest"
        )
    return value


def _text(value: Any, context: str) -> str:
    if not isinstance(value, str) or not value or len(value) > 256:
        raise CheckedMemoryAddressDomainV2Error(f"{context} must be bounded text")
    return value


def _uint(value: Any, context: str, *, maximum: int = 0xFFFF_FFFF) -> int:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= maximum
    ):
        raise CheckedMemoryAddressDomainV2Error(
            f"{context} must be an unsigned integer"
        )
    return value


def _positive(value: Any) -> int | None:
    return (
        int(value)
        if isinstance(value, int) and not isinstance(value, bool) and value > 0
        else None
    )


def _nonnegative(value: Any) -> int | None:
    return (
        int(value)
        if isinstance(value, int) and not isinstance(value, bool) and value >= 0
        else None
    )


def _u32(value: Any) -> bool:
    return (
        isinstance(value, int)
        and not isinstance(value, bool)
        and 0 <= value <= 0xFFFF_FFFF
    )


__all__ = [
    "CONTEXTUAL_MEMORY_COVERAGE_V1_FORMAT",
    "MEMORY_ADDRESS_DOMAIN_PROPOSAL_V2_FORMAT",
    "CheckedMemoryAddressDomain",
    "CheckedMemoryAddressDomainV2Error",
    "memory_address_domain_signature_projection_v2",
    "prepare_checked_memory_address_domains_v2",
    "seal_checked_memory_address_domains_v2",
    "validate_checked_memory_address_domains_v2",
]
