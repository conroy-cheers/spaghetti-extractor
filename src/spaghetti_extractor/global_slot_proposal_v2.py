"""Cold-replayed promotion of mutable-slot evidence to v2 authority."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .authority_bindings_v2 import ImageSpanBinding, UnitBinding
from .authority_record_core_v2 import MAX_FINITE_ALTERNATIVES, FiniteAlternatives
from .global_slot_contract_v2 import GlobalSlotInvariant


_WRITE_CLASSIFICATIONS = frozenset({"initializer", "bounded_alternatives"})


class GlobalSlotProposalV2Error(ValueError):
    """A caller option, rather than submitted evidence, is invalid."""


@dataclass(frozen=True, order=True)
class EvidenceSite:
    """One stable machine-IR event identity used by replay evidence."""

    unit_id: str
    event_index: int
    instruction_rva: int | None = None

    def payload(self) -> dict[str, Any]:
        return {
            "unit_id": self.unit_id,
            "event_index": self.event_index,
            "instruction_rva": self.instruction_rva,
        }


def propose_global_slot_invariant(
    evidence: Mapping[str, Any],
    *,
    interface_slot: Mapping[str, Any] | None,
    unit_bindings: Mapping[str, UnitBinding] | None = None,
    image_span_bindings: Mapping[int, ImageSpanBinding] | None = None,
    image_base: int = 0,
    size_of_image: int = 0x1_0000_0000,
    rejected_tainted: bool = False,
    alternative_budget: int = 32,
) -> dict[str, Any]:
    """Check one replay inventory and return a proposal only when complete.

    Evidence failures are report data, not exceptions.  A missing inventory,
    classification, finite bound, or domination witness is ``incomplete``.
    Conflicting site records, stale provenance alternatives, and malformed
    values are ``violated``.
    """

    if not isinstance(alternative_budget, int) or isinstance(
        alternative_budget, bool
    ) or not 0 < alternative_budget <= MAX_FINITE_ALTERNATIVES:
        raise GlobalSlotProposalV2Error(
            f"alternative budget must be between 1 and {MAX_FINITE_ALTERNATIVES}"
        )

    issues: list[dict[str, Any]] = []
    if not isinstance(evidence, Mapping):
        return _slot_check(
            address=None,
            issues=[_issue("incomplete", "global_slot_replay_missing")],
        )
    address = _uint32(evidence.get("address"))
    if address is None:
        return _slot_check(
            address=None,
            issues=[_issue("violated", "global_slot_address_corrupt")],
        )
    if evidence.get("width", 4) != 4:
        issues.append(_issue(
            "violated",
            "global_slot_width_corrupt",
            address=address,
            observed=evidence.get("width"),
        ))

    provenance_alternatives: list[Any] | None = None
    if interface_slot is None:
        issues.append(_issue(
            "incomplete", "global_slot_provenance_missing", address=address
        ))
    elif _uint32(interface_slot.get("address")) != address:
        issues.append(_issue(
            "violated", "global_slot_provenance_address_mismatch", address=address
        ))
    else:
        raw_origins = interface_slot.get("origins")
        if not isinstance(raw_origins, list) or not raw_origins:
            issues.append(_issue(
                "incomplete", "global_slot_alternatives_missing", address=address
            ))
        else:
            provenance_alternatives = _normalize_alternatives(
                raw_origins,
                context="interface-provenance alternatives",
                issues=issues,
                address=address,
            )
        if interface_slot.get("tainted") is True:
            rejected_tainted = True

    if rejected_tainted:
        issues.append(_issue(
            "incomplete", "global_slot_tainted_by_provenance", address=address
        ))

    launch_initializer = _launch_initializer(
        evidence.get("launch_initializer"),
        address=address,
        issues=issues,
    )

    inventory = evidence.get("reachable_write_inventory")
    if isinstance(inventory, Mapping):
        inventory_status = inventory.get("status")
        writes = inventory.get("writes")
        unknown_writes = inventory.get("unknown_writes")
        aliasing_writes = inventory.get("aliasing_writes")
    else:
        inventory_status = evidence.get("reachable_writes_status")
        writes = evidence.get("reachable_writes")
        unknown_writes = evidence.get("unknown_writes")
        aliasing_writes = evidence.get("aliasing_writes")

    if inventory_status != "complete":
        if inventory_status not in {None, "incomplete"}:
            issues.append(_issue(
                "violated",
                "global_slot_write_inventory_status_corrupt",
                address=address,
                observed=inventory_status,
            ))
        else:
            issues.append(_issue(
                "incomplete", "global_slot_write_inventory_incomplete", address=address
            ))
    if not isinstance(writes, list) or (
        not writes and launch_initializer is None
    ):
        issues.append(_issue(
            "incomplete", "global_slot_reachable_writes_missing", address=address
        ))
        writes = []
    if not isinstance(unknown_writes, list):
        issues.append(_issue(
            "incomplete", "global_slot_unknown_write_inventory_missing", address=address
        ))
        unknown_writes = []
    if not isinstance(aliasing_writes, list):
        issues.append(_issue(
            "incomplete", "global_slot_aliasing_write_inventory_missing", address=address
        ))
        aliasing_writes = []
    if unknown_writes:
        issues.append(_issue(
            "incomplete",
            "global_slot_unknown_write_taint",
            address=address,
            writes=_safe_details(unknown_writes),
        ))
    if aliasing_writes:
        issues.append(_issue(
            "incomplete",
            "global_slot_aliasing_write_taint",
            address=address,
            writes=_safe_details(aliasing_writes),
        ))

    normalized_writes: list[dict[str, Any]] = []
    write_sites: dict[EvidenceSite, dict[str, Any]] = {}
    initializers: list[EvidenceSite] = []
    replay_alternatives: list[Any] = (
        []
        if launch_initializer is None
        else [launch_initializer["value_origin"]]
    )
    for index, raw in enumerate(writes):
        if not isinstance(raw, Mapping):
            issues.append(_issue(
                "violated",
                "global_slot_write_record_corrupt",
                address=address,
                write_index=index,
            ))
            continue
        site = _site(raw.get("site", raw), issues=issues, context="write")
        classification = raw.get("classification")
        if classification not in _WRITE_CLASSIFICATIONS:
            issues.append(_issue(
                "incomplete"
                if classification in {None, "unknown", "may_alias"}
                else "violated",
                "global_slot_write_unclassified",
                address=address,
                write_index=index,
                observed=classification,
            ))
            continue
        alternatives = _normalize_alternatives(
            raw.get("alternatives"),
            context=f"write {index} alternatives",
            issues=issues,
            address=address,
        )
        if site is None or alternatives is None:
            continue
        normalized = {
            "site": site.payload(),
            "classification": classification,
            "alternatives": alternatives,
        }
        previous = write_sites.get(site)
        if previous is not None and previous != normalized:
            issues.append(_issue(
                "violated",
                "global_slot_write_site_contradiction",
                address=address,
                site=site.payload(),
            ))
            continue
        if previous is not None:
            issues.append(_issue(
                "violated",
                "global_slot_write_site_duplicated",
                address=address,
                site=site.payload(),
            ))
            continue
        write_sites[site] = normalized
        normalized_writes.append(normalized)
        replay_alternatives.extend(alternatives)
        if classification == "initializer":
            initializers.append(site)

    initializer_count = len(initializers) + (launch_initializer is not None)
    if initializer_count != 1:
        issues.append(_issue(
            "incomplete" if initializer_count == 0 else "violated",
            "global_slot_initializer_not_unique",
            address=address,
            initializer_count=initializer_count,
        ))
    initializer = (
        initializers[0]
        if launch_initializer is None and len(initializers) == 1
        else None
    )

    normalized_alternatives = _deduplicate_json(replay_alternatives)
    if len(normalized_alternatives) > alternative_budget:
        issues.append(_issue(
            "incomplete",
            "global_slot_alternative_budget_exceeded",
            address=address,
            alternatives=len(normalized_alternatives),
            budget=alternative_budget,
        ))
    if (
        provenance_alternatives is not None
        and normalized_alternatives
        and _canonical_json(provenance_alternatives)
        != _canonical_json(normalized_alternatives)
    ):
        issues.append(_issue(
            "violated",
            "global_slot_replay_provenance_contradiction",
            address=address,
            provenance=provenance_alternatives,
            replay=normalized_alternatives,
        ))

    reads = evidence.get("relevant_reads")
    if not isinstance(reads, list):
        issues.append(_issue(
            "incomplete", "global_slot_read_inventory_missing", address=address
        ))
        reads = []
    normalized_reads: list[dict[str, Any]] = []
    read_sites: dict[EvidenceSite, dict[str, Any]] = {}
    for index, raw in enumerate(reads):
        if not isinstance(raw, Mapping):
            issues.append(_issue(
                "violated",
                "global_slot_read_record_corrupt",
                address=address,
                read_index=index,
            ))
            continue
        site = _site(raw.get("site", raw), issues=issues, context="read")
        raw_dominator = raw.get("dominated_by")
        launch_dominator = (
            launch_initializer is not None
            and isinstance(raw_dominator, Mapping)
            and raw_dominator.get("kind") == "launch_image"
            and _uint32(raw_dominator.get("address")) == address
        )
        dominator = (
            None
            if launch_dominator
            else _site(
                raw_dominator,
                issues=issues,
                context="read domination witness",
                missing_status="incomplete",
            )
        )
        if site is None or (not launch_dominator and dominator is None):
            continue
        normalized_dominator = (
            {"kind": "launch_image", "address": address}
            if launch_dominator
            else dominator.payload()
        )
        normalized = {
            "site": site.payload(),
            "dominated_by": normalized_dominator,
        }
        previous = read_sites.get(site)
        if previous is not None:
            issues.append(_issue(
                "violated",
                "global_slot_read_site_contradiction"
                if previous != normalized
                else "global_slot_read_site_duplicated",
                address=address,
                site=site.payload(),
            ))
            continue
        read_sites[site] = normalized
        normalized_reads.append(normalized)
        if (
            launch_initializer is not None
            and not launch_dominator
        ) or (
            launch_initializer is None
            and initializer is not None
            and dominator != initializer
        ):
            issues.append(_issue(
                "incomplete",
                "global_slot_initialization_does_not_dominate_read",
                address=address,
                read_site=site.payload(),
                observed_dominator=normalized_dominator,
                initializer=(
                    {"kind": "launch_image", "address": address}
                    if launch_initializer is not None
                    else initializer.payload()
                ),
            ))

    issues = _deduplicate_issues(issues)
    initializer_binding = (
        None
        if initializer is None or unit_bindings is None
        else unit_bindings.get(initializer.unit_id)
    )
    if launch_initializer is not None:
        initializer_binding = (
            None
            if image_span_bindings is None
            else image_span_bindings.get(address)
        )
    if initializer_binding is None:
        issues = _deduplicate_issues([
            *issues,
            _issue(
                "incomplete",
                "global_slot_initializer_binding_missing",
                address=address,
                unit_id=None if initializer is None else initializer.unit_id,
                initializer_kind=(
                    "launch_image"
                    if launch_initializer is not None
                    else "machine_write"
                ),
            ),
        ])
    slot_rva = (address - image_base) & 0xFFFFFFFF
    if not 0 <= slot_rva < size_of_image or slot_rva + 4 > size_of_image:
        issues = _deduplicate_issues([
            *issues,
            _issue(
                "violated",
                "global_slot_outside_image",
                address=address,
                image_base=image_base,
                size_of_image=size_of_image,
            ),
        ])
    if issues:
        return _slot_check(address=address, issues=issues)
    assert initializer_binding is not None
    invariant = GlobalSlotInvariant(
        binding=initializer_binding,
        slot_rva=slot_rva,
        width_bytes=4,
        invariant_kind="finite_set",
        alternatives=FiniteAlternatives.of(
            normalized_alternatives, maximum=alternative_budget
        ),
    )
    return {
        "address": address,
        "status": "complete",
        "tainted": False,
        "proposal": invariant.to_payload(),
        "replay": {
            "initializer": (
                copy.deepcopy(launch_initializer)
                if launch_initializer is not None
                else initializer.payload()
            ),
            "reachable_writes": sorted(
                normalized_writes, key=lambda row: _site_sort_key(row["site"])
            ),
            "relevant_reads": sorted(
                normalized_reads, key=lambda row: _site_sort_key(row["site"])
            ),
        },
        "issues": [],
    }


def _slot_check(
    *, address: int | None, issues: Sequence[Mapping[str, Any]]
) -> dict[str, Any]:
    normalized = _deduplicate_issues(issues)
    return {
        "address": address,
        "status": _aggregate_status(normalized),
        "tainted": any("taint" in str(issue.get("code")) for issue in normalized),
        "proposal": None,
        "issues": normalized,
    }


def _launch_initializer(
    raw: Any,
    *,
    address: int,
    issues: list[dict[str, Any]],
) -> dict[str, Any] | None:
    if raw is None:
        return None
    if (
        not isinstance(raw, Mapping)
        or raw.get("kind") != "launch_image"
        or _uint32(raw.get("address")) != address
    ):
        issues.append(
            _issue(
                "violated",
                "global_slot_launch_initializer_corrupt",
                address=address,
            )
        )
        return None
    alternatives = _normalize_alternatives(
        [raw.get("value_origin")],
        context="launch initializer value",
        issues=issues,
        address=address,
    )
    if alternatives is None or len(alternatives) != 1:
        return None
    return {
        "kind": "launch_image",
        "address": address,
        "value_origin": alternatives[0],
    }


def _normalize_alternatives(
    raw: Any,
    *,
    context: str,
    issues: list[dict[str, Any]],
    address: int,
) -> list[Any] | None:
    if not isinstance(raw, list) or not raw:
        issues.append(_issue(
            "incomplete", "global_slot_alternatives_missing", address=address, context=context
        ))
        return None
    values: list[Any] = []
    for index, value in enumerate(raw):
        if not isinstance(value, Mapping) or not isinstance(value.get("kind"), str) or not value.get("kind"):
            issues.append(_issue(
                "violated",
                "global_slot_alternative_corrupt",
                address=address,
                context=context,
                index=index,
            ))
            continue
        try:
            values.append(_json_clone(dict(value)))
        except (TypeError, ValueError):
            issues.append(_issue(
                "violated",
                "global_slot_alternative_corrupt",
                address=address,
                context=context,
                index=index,
            ))
    deduplicated = _deduplicate_json(values)
    if len(deduplicated) != len(values):
        issues.append(_issue(
            "violated", "global_slot_alternative_duplicated", address=address, context=context
        ))
    return deduplicated


def _site(
    raw: Any,
    *,
    issues: list[dict[str, Any]],
    context: str,
    missing_status: str = "violated",
) -> EvidenceSite | None:
    if not isinstance(raw, Mapping):
        issues.append(_issue(missing_status, "global_slot_site_missing", context=context))
        return None
    unit_id = raw.get("unit_id")
    event_index = _uint32(raw.get("event_index"))
    instruction_rva = raw.get("instruction_rva")
    if instruction_rva is not None:
        instruction_rva = _uint32(instruction_rva)
    if (
        not isinstance(unit_id, str)
        or not unit_id
        or event_index is None
        or (raw.get("instruction_rva") is not None and instruction_rva is None)
    ):
        issues.append(_issue("violated", "global_slot_site_corrupt", context=context))
        return None
    return EvidenceSite(unit_id, event_index, instruction_rva)


def _site_sort_key(value: Mapping[str, Any]) -> tuple[str, int, int]:
    return (
        str(value.get("unit_id") or ""),
        int(value.get("event_index") or 0),
        int(value.get("instruction_rva") or 0),
    )


def _aggregate_status(issues: Sequence[Mapping[str, Any]]) -> str:
    if any(issue.get("status") == "violated" for issue in issues):
        return "violated"
    if issues:
        return "incomplete"
    return "complete"


def _issue(status: str, code: str, **details: Any) -> dict[str, Any]:
    return {
        "status": status,
        "code": code,
        "details": _safe_details(details),
    }


def _safe_details(value: Any) -> Any:
    try:
        return _json_clone(value)
    except (TypeError, ValueError):
        return {"corrupt_details": repr(value)}


def _deduplicate_issues(
    issues: Iterable[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    by_json = {
        _canonical_json(issue): _json_clone(dict(issue)) for issue in issues
    }
    return sorted(
        by_json.values(),
        key=lambda issue: (
            0 if issue.get("status") == "violated" else 1,
            str(issue.get("code") or ""),
            _canonical_json(issue.get("details", {})),
        ),
    )


def _deduplicate_json(values: Iterable[Any]) -> list[Any]:
    by_json = {_canonical_json(value): _json_clone(value) for value in values}
    return [by_json[key] for key in sorted(by_json)]


def _json_clone(value: Any) -> Any:
    return json.loads(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
            allow_nan=False,
        )
    )


def _canonical_json(value: Any) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        allow_nan=False,
    )


def _uint32(value: Any) -> int | None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        return None
    return value


__all__ = ["GlobalSlotProposalV2Error", "propose_global_slot_invariant"]
