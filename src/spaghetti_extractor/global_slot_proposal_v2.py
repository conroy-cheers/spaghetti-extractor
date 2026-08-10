"""Cold-replayed promotion of mutable-slot evidence to v2 authority."""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

from .authority_bindings_v2 import (
    AuthorityDataError,
    EventBinding,
    ImageSpanBinding,
    UnitBinding,
)
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
    event_bindings: Mapping[tuple[str, int], EventBinding] | None = None,
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
    read_checks = _propose_read_invariants(
        evidence,
        address=address,
        slot_rva=slot_rva,
        event_bindings=event_bindings,
        normalized_writes=normalized_writes,
        launch_initializer=launch_initializer,
        slot_alternatives=normalized_alternatives,
        alternative_budget=alternative_budget,
    )
    if issues:
        return _slot_check(
            address=address,
            issues=issues,
            read_checks=read_checks,
        )
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
        "read_checks": read_checks,
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
    *,
    address: int | None,
    issues: Sequence[Mapping[str, Any]],
    read_checks: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    normalized = _deduplicate_issues(issues)
    return {
        "address": address,
        "status": _aggregate_status(normalized),
        "tainted": any("taint" in str(issue.get("code")) for issue in normalized),
        "proposal": None,
        "read_checks": [_json_clone(dict(check)) for check in read_checks],
        "issues": normalized,
    }


def _propose_read_invariants(
    evidence: Mapping[str, Any],
    *,
    address: int,
    slot_rva: int,
    event_bindings: Mapping[tuple[str, int], EventBinding] | None,
    normalized_writes: Sequence[Mapping[str, Any]],
    launch_initializer: Mapping[str, Any] | None,
    slot_alternatives: Sequence[Any],
    alternative_budget: int,
) -> list[dict[str, Any]]:
    raw_reads = evidence.get("read_inventory")
    if raw_reads is None:
        return []
    if not isinstance(raw_reads, list):
        return [_read_check(
            address=address,
            read_index=None,
            site=None,
            issues=[_issue(
                "violated",
                "global_slot_per_read_inventory_corrupt",
                address=address,
            )],
        )]

    dependency_index, dependency_issues = _replay_dependency_index(
        evidence.get("dependencies"), address=address
    )
    writes_by_site = {
        site: dict(row)
        for row in normalized_writes
        for site in (_site_without_issues(row.get("site")),)
        if site is not None
    }
    relevant_read_sites, incoming_by_site = _relevant_read_details(
        evidence.get("relevant_reads")
    )
    seen_sites: set[EvidenceSite] = set()
    checks: list[dict[str, Any]] = []
    for read_index, raw in enumerate(raw_reads):
        local_issues = [dict(issue) for issue in dependency_issues]
        if not isinstance(raw, Mapping):
            checks.append(_read_check(
                address=address,
                read_index=read_index,
                site=None,
                issues=[
                    *local_issues,
                    _issue(
                        "violated",
                        "global_slot_per_read_record_corrupt",
                        address=address,
                        read_index=read_index,
                    ),
                ],
            ))
            continue

        site = _site(
            raw.get("site"),
            issues=local_issues,
            context=f"read inventory {read_index}",
        )
        if site is not None and site in seen_sites:
            local_issues.append(_issue(
                "violated",
                "global_slot_per_read_site_duplicated",
                address=address,
                site=site.payload(),
            ))
        elif site is not None:
            seen_sites.add(site)
        if site is not None and site not in relevant_read_sites:
            local_issues.append(_issue(
                "violated",
                "global_slot_per_read_site_mismatch",
                address=address,
                read_index=read_index,
                site=site.payload(),
            ))

        per_read_status = raw.get("status")
        if per_read_status is not None:
            if per_read_status == "incomplete":
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_status_incomplete",
                    address=address,
                    read_index=read_index,
                ))
            elif per_read_status == "violated":
                local_issues.append(_issue(
                    "violated",
                    "global_slot_per_read_status_violated",
                    address=address,
                    read_index=read_index,
                ))
            elif per_read_status != "complete":
                local_issues.append(_issue(
                    "violated",
                    "global_slot_per_read_status_corrupt",
                    address=address,
                    read_index=read_index,
                    observed=per_read_status,
                ))

        classification = raw.get("classification")
        if classification not in {"exact", "conditional_exact"}:
            local_issues.append(_issue(
                (
                    "incomplete"
                    if classification in {None, "alias", "unknown", "may_alias"}
                    else "violated"
                ),
                "global_slot_per_read_classification_not_exact",
                address=address,
                read_index=read_index,
                observed=classification,
            ))

        state = raw.get("state")
        state_alternatives: list[Any] | None = None
        tainted = False
        if not isinstance(state, Mapping):
            local_issues.append(_issue(
                "incomplete" if state is None else "violated",
                "global_slot_per_read_state_missing"
                if state is None
                else "global_slot_per_read_state_corrupt",
                address=address,
                read_index=read_index,
            ))
        else:
            for field in ("initialized", "tainted", "overflow"):
                if field not in state:
                    local_issues.append(_issue(
                        "incomplete",
                        "global_slot_per_read_state_field_missing",
                        address=address,
                        read_index=read_index,
                        field=field,
                    ))
                elif not isinstance(state[field], bool):
                    local_issues.append(_issue(
                        "violated",
                        "global_slot_per_read_state_field_corrupt",
                        address=address,
                        read_index=read_index,
                        field=field,
                    ))
            if "reachable" in state and not isinstance(state["reachable"], bool):
                local_issues.append(_issue(
                    "violated",
                    "global_slot_per_read_state_field_corrupt",
                    address=address,
                    read_index=read_index,
                    field="reachable",
                ))
            elif state.get("reachable") is False:
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_unreachable",
                    address=address,
                    read_index=read_index,
                ))
            if state.get("initialized") is False:
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_uninitialized",
                    address=address,
                    read_index=read_index,
                ))
            if state.get("tainted") is True:
                tainted = True
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_tainted",
                    address=address,
                    read_index=read_index,
                ))
            if state.get("overflow") is True:
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_alternative_budget_exceeded",
                    address=address,
                    read_index=read_index,
                    budget=alternative_budget,
                ))
            state_alternatives = _normalize_alternatives(
                state.get("alternatives"),
                context=f"read inventory {read_index} state alternatives",
                issues=local_issues,
                address=address,
            )
            if (
                state_alternatives is not None
                and len(state_alternatives) > alternative_budget
            ):
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_alternative_budget_exceeded",
                    address=address,
                    read_index=read_index,
                    alternatives=len(state_alternatives),
                    budget=alternative_budget,
                ))

        explicit_alternatives = raw.get("alternatives")
        if explicit_alternatives is not None:
            normalized_explicit = _normalize_alternatives(
                explicit_alternatives,
                context=f"read inventory {read_index} alternatives",
                issues=local_issues,
                address=address,
            )
            if (
                normalized_explicit is not None
                and state_alternatives is not None
                and _canonical_json(normalized_explicit)
                != _canonical_json(state_alternatives)
            ):
                local_issues.append(_issue(
                    "violated",
                    "global_slot_per_read_alternatives_mismatch",
                    address=address,
                    read_index=read_index,
                ))
        if state_alternatives is not None and not _json_subset(
            state_alternatives, slot_alternatives
        ):
            local_issues.append(_issue(
                "violated",
                "global_slot_per_read_alternatives_mismatch",
                address=address,
                read_index=read_index,
            ))

        _check_read_dependencies(
            raw.get("dependencies"),
            dependency_index=dependency_index,
            issues=local_issues,
            address=address,
            read_index=read_index,
            context="read",
        )
        incoming = incoming_by_site.get(site) if site is not None else None
        _check_read_incoming_copy(
            raw,
            incoming=incoming,
            issues=local_issues,
            address=address,
            read_index=read_index,
        )
        reaching_alternatives, reaching_tainted = _check_reaching_writes(
            raw,
            address=address,
            read_index=read_index,
            writes_by_site=writes_by_site,
            launch_initializer=launch_initializer,
            incoming=incoming,
            event_bindings=event_bindings,
            dependency_index=dependency_index,
            issues=local_issues,
        )
        tainted = tainted or reaching_tainted
        if (
            reaching_alternatives is not None
            and state_alternatives is not None
            and _canonical_json(reaching_alternatives)
            != _canonical_json(state_alternatives)
        ):
            local_issues.append(_issue(
                "violated",
                "global_slot_per_read_reaching_alternatives_mismatch",
                address=address,
                read_index=read_index,
                reaching=reaching_alternatives,
                state=state_alternatives,
            ))

        binding = None
        if site is not None:
            binding = (
                None
                if event_bindings is None
                else event_bindings.get((site.unit_id, site.event_index))
            )
            if not isinstance(binding, EventBinding):
                local_issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_event_binding_missing",
                    address=address,
                    read_index=read_index,
                    site=site.payload(),
                ))
            else:
                if binding.event_kind not in {"read", "read_write"}:
                    local_issues.append(_issue(
                        "violated",
                        "global_slot_per_read_event_kind_mismatch",
                        address=address,
                        read_index=read_index,
                        observed=binding.event_kind,
                    ))
                if site.instruction_rva is None:
                    local_issues.append(_issue(
                        "incomplete",
                        "global_slot_per_read_instruction_rva_missing",
                        address=address,
                        read_index=read_index,
                    ))
                elif site.instruction_rva != binding.instruction_rva:
                    local_issues.append(_issue(
                        "violated",
                        "global_slot_per_read_event_binding_mismatch",
                        address=address,
                        read_index=read_index,
                        observed_instruction_rva=site.instruction_rva,
                        expected_instruction_rva=binding.instruction_rva,
                    ))
                _check_submitted_event_binding(
                    raw,
                    expected=binding,
                    issues=local_issues,
                    address=address,
                    read_index=read_index,
                )

        local_issues = _deduplicate_issues(local_issues)
        if local_issues or binding is None or state_alternatives is None:
            checks.append(_read_check(
                address=address,
                read_index=read_index,
                site=site,
                issues=local_issues,
                tainted=tainted,
            ))
            continue
        invariant = GlobalSlotInvariant(
            binding=binding,
            slot_rva=slot_rva,
            width_bytes=4,
            invariant_kind="finite_set_at_read",
            alternatives=FiniteAlternatives.of(
                state_alternatives, maximum=alternative_budget
            ),
        )
        checks.append(_read_check(
            address=address,
            read_index=read_index,
            site=site,
            issues=(),
            proposal=invariant.to_payload(),
        ))
    return sorted(checks, key=_read_check_sort_key)


def _read_check(
    *,
    address: int,
    read_index: int | None,
    site: EvidenceSite | None,
    issues: Sequence[Mapping[str, Any]],
    tainted: bool = False,
    proposal: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    normalized = _deduplicate_issues(issues)
    return {
        "address": address,
        "read_index": read_index,
        "site": None if site is None else site.payload(),
        "status": _aggregate_status(normalized),
        "tainted": tainted,
        "proposal": None if proposal is None else _json_clone(dict(proposal)),
        "issues": normalized,
    }


def _read_check_sort_key(check: Mapping[str, Any]) -> tuple[str, int, int, int]:
    site = check.get("site")
    if not isinstance(site, Mapping):
        return ("", -1, -1, int(check.get("read_index") or 0))
    unit_id, event_index, instruction_rva = _site_sort_key(site)
    return (
        unit_id,
        event_index,
        instruction_rva,
        int(check.get("read_index") or 0),
    )


def _replay_dependency_index(
    raw: Any, *, address: int
) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if not isinstance(raw, list):
        return {}, [_issue(
            "incomplete" if raw is None else "violated",
            "global_slot_dependency_inventory_missing"
            if raw is None
            else "global_slot_dependency_inventory_corrupt",
            address=address,
        )]
    result: dict[str, dict[str, Any]] = {}
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping):
            issues.append(_issue(
                "violated",
                "global_slot_dependency_record_corrupt",
                address=address,
                dependency_index=index,
            ))
            continue
        identity = item.get("id")
        kind = item.get("kind")
        digest = item.get("sha256")
        if (
            not isinstance(identity, str)
            or not identity
            or not isinstance(kind, str)
            or not kind
            or not _digest(digest)
        ):
            issues.append(_issue(
                "violated",
                "global_slot_dependency_record_corrupt",
                address=address,
                dependency_index=index,
            ))
            continue
        normalized = _json_clone(dict(item))
        previous = result.get(identity)
        if previous is not None:
            issues.append(_issue(
                "violated",
                "global_slot_dependency_duplicated"
                if previous == normalized
                else "global_slot_dependency_contradiction",
                address=address,
                dependency_id=identity,
            ))
            continue
        result[identity] = normalized
    return result, _deduplicate_issues(issues)


def _check_read_dependencies(
    raw: Any,
    *,
    dependency_index: Mapping[str, Mapping[str, Any]],
    issues: list[dict[str, Any]],
    address: int,
    read_index: int,
    context: str,
) -> None:
    if not isinstance(raw, list):
        issues.append(_issue(
            "incomplete" if raw is None else "violated",
            "global_slot_per_read_dependencies_missing"
            if raw is None
            else "global_slot_per_read_dependencies_corrupt",
            address=address,
            read_index=read_index,
            context=context,
        ))
        return
    if any(not isinstance(value, str) or not value for value in raw):
        issues.append(_issue(
            "violated",
            "global_slot_per_read_dependencies_corrupt",
            address=address,
            read_index=read_index,
            context=context,
        ))
        return
    if len(raw) != len(set(raw)):
        issues.append(_issue(
            "violated",
            "global_slot_per_read_dependency_duplicated",
            address=address,
            read_index=read_index,
            context=context,
        ))
    missing = sorted(set(raw) - set(dependency_index))
    if missing:
        issues.append(_issue(
            "incomplete",
            "global_slot_per_read_dependency_missing",
            address=address,
            read_index=read_index,
            context=context,
            dependency_ids=missing,
        ))


def _check_reaching_writes(
    read: Mapping[str, Any],
    *,
    address: int,
    read_index: int,
    writes_by_site: Mapping[EvidenceSite, Mapping[str, Any]],
    launch_initializer: Mapping[str, Any] | None,
    incoming: Mapping[str, Any] | None,
    event_bindings: Mapping[tuple[str, int], EventBinding] | None,
    dependency_index: Mapping[str, Mapping[str, Any]],
    issues: list[dict[str, Any]],
) -> tuple[list[Any] | None, bool]:
    tainted = False
    raw_inventory = read.get("reaching_write_inventory")
    if raw_inventory is not None and not isinstance(raw_inventory, Mapping):
        issues.append(_issue(
            "violated",
            "global_slot_per_read_reaching_write_inventory_corrupt",
            address=address,
            read_index=read_index,
            field="reaching_write_inventory",
        ))
        return None, tainted

    inventory = raw_inventory if isinstance(raw_inventory, Mapping) else read
    for field, code in (
        ("unknown_writes", "global_slot_per_read_unknown_write_taint"),
        ("aliasing_writes", "global_slot_per_read_aliasing_write_taint"),
    ):
        raw_writes = inventory.get(field)
        if raw_writes is None:
            if raw_inventory is not None:
                issues.append(_issue(
                    "incomplete",
                    "global_slot_per_read_reaching_write_inventory_missing",
                    address=address,
                    read_index=read_index,
                    field=field,
                ))
            continue
        if not isinstance(raw_writes, list):
            issues.append(_issue(
                "violated",
                "global_slot_per_read_reaching_write_inventory_corrupt",
                address=address,
                read_index=read_index,
                field=field,
            ))
            continue
        if raw_writes:
            tainted = True
            issues.append(_issue(
                "incomplete",
                code,
                address=address,
                read_index=read_index,
                writes=_safe_details(raw_writes),
            ))
        for write_index, raw_write in enumerate(raw_writes):
            if not isinstance(raw_write, Mapping):
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_reaching_write_record_corrupt",
                    address=address,
                    read_index=read_index,
                    field=field,
                    write_index=write_index,
                ))
                continue
            if "dependencies" in raw_write:
                _check_read_dependencies(
                    raw_write.get("dependencies"),
                    dependency_index=dependency_index,
                    issues=issues,
                    address=address,
                    read_index=read_index,
                    context=field,
                )

    raw_reaching = (
        inventory.get("writes")
        if raw_inventory is not None
        else read.get("reaching_writes")
    )
    if raw_reaching is None:
        if raw_inventory is not None:
            issues.append(_issue(
                "incomplete",
                "global_slot_per_read_reaching_write_inventory_missing",
                address=address,
                read_index=read_index,
                field="writes",
            ))
        return None, tainted
    if not isinstance(raw_reaching, list):
        issues.append(_issue(
            "violated",
            "global_slot_per_read_reaching_write_inventory_corrupt",
            address=address,
            read_index=read_index,
            field="reaching_writes",
        ))
        return None, tainted
    incoming_launch = (
        incoming.get("launch_initializer")
        if isinstance(incoming, Mapping)
        else None
    )
    launch_alternatives: list[Any] = []
    if incoming_launch is not None:
        if incoming_launch != launch_initializer:
            issues.append(_issue(
                "violated",
                "global_slot_per_read_launch_initializer_mismatch",
                address=address,
                read_index=read_index,
            ))
        elif launch_initializer is not None:
            launch_alternatives.append(
                _json_clone(launch_initializer["value_origin"])
            )
    if not raw_reaching and not launch_alternatives:
        issues.append(_issue(
            "incomplete",
            "global_slot_per_read_reaching_writes_missing",
            address=address,
            read_index=read_index,
        ))
        return [], tainted

    alternatives: list[Any] = launch_alternatives
    seen: set[str] = set()
    for write_index, raw_write in enumerate(raw_reaching):
        if not isinstance(raw_write, Mapping):
            issues.append(_issue(
                "violated",
                "global_slot_per_read_reaching_write_record_corrupt",
                address=address,
                read_index=read_index,
                write_index=write_index,
            ))
            continue
        raw_site = raw_write.get("site", raw_write)
        if (
            raw_write.get("kind") == "launch_image"
            or isinstance(raw_site, Mapping)
            and raw_site.get("kind") == "launch_image"
        ):
            candidate = (
                raw_write
                if raw_write.get("kind") == "launch_image"
                else raw_site
            )
            if launch_initializer is None or any(
                candidate.get(key) != launch_initializer.get(key)
                for key in ("kind", "address", "value_origin")
                if key in candidate
            ):
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_reaching_write_mismatch",
                    address=address,
                    read_index=read_index,
                    write_index=write_index,
                ))
                continue
            identity = _canonical_json(launch_initializer)
            if identity in seen:
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_reaching_write_duplicated",
                    address=address,
                    read_index=read_index,
                    write_index=write_index,
                ))
                continue
            seen.add(identity)
            alternatives.append(_json_clone(launch_initializer["value_origin"]))
            continue

        local_site_issues: list[dict[str, Any]] = []
        site = _site(
            raw_site,
            issues=local_site_issues,
            context=f"read inventory {read_index} reaching write {write_index}",
        )
        issues.extend(local_site_issues)
        expected = writes_by_site.get(site) if site is not None else None
        if expected is None:
            write_binding = (
                None
                if event_bindings is None or site is None
                else event_bindings.get((site.unit_id, site.event_index))
            )
            if (
                not isinstance(write_binding, EventBinding)
                or write_binding.event_kind not in {"write", "read_write"}
                or site is None
                or site.instruction_rva != write_binding.instruction_rva
            ):
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_reaching_write_mismatch",
                    address=address,
                    read_index=read_index,
                    write_index=write_index,
                ))
                continue
            classification = raw_write.get("classification")
            submitted = _normalize_alternatives(
                raw_write.get("alternatives"),
                context=(
                    f"read inventory {read_index} reaching write "
                    f"{write_index} alternatives"
                ),
                issues=issues,
                address=address,
            )
            if classification not in _WRITE_CLASSIFICATIONS:
                issues.append(_issue(
                    "incomplete"
                    if classification in {None, "unknown", "may_alias"}
                    else "violated",
                    "global_slot_per_read_reaching_write_unclassified",
                    address=address,
                    read_index=read_index,
                    write_index=write_index,
                    observed=classification,
                ))
            if submitted is None:
                continue
            expected = {
                "site": site.payload(),
                "classification": classification,
                "alternatives": submitted,
            }
        identity = _canonical_json(expected["site"])
        if identity in seen:
            issues.append(_issue(
                "violated",
                "global_slot_per_read_reaching_write_duplicated",
                address=address,
                read_index=read_index,
                write_index=write_index,
            ))
            continue
        seen.add(identity)
        if (
            "classification" in raw_write
            and raw_write.get("classification") != expected.get("classification")
        ):
            issues.append(_issue(
                "violated",
                "global_slot_per_read_reaching_write_mismatch",
                address=address,
                read_index=read_index,
                write_index=write_index,
            ))
        if "alternatives" in raw_write:
            submitted = _normalize_alternatives(
                raw_write.get("alternatives"),
                context=(
                    f"read inventory {read_index} reaching write "
                    f"{write_index} alternatives"
                ),
                issues=issues,
                address=address,
            )
            if submitted is not None and _canonical_json(submitted) != _canonical_json(
                expected.get("alternatives")
            ):
                issues.append(_issue(
                    "violated",
                    "global_slot_per_read_reaching_write_mismatch",
                    address=address,
                    read_index=read_index,
                    write_index=write_index,
                ))
        if "dependencies" in raw_write:
            _check_read_dependencies(
                raw_write.get("dependencies"),
                dependency_index=dependency_index,
                issues=issues,
                address=address,
                read_index=read_index,
                context="reaching_writes",
            )
        alternatives.extend(expected.get("alternatives", ()))
    return _deduplicate_json(alternatives), tainted


def _relevant_read_details(
    raw: Any,
) -> tuple[set[EvidenceSite], dict[EvidenceSite, dict[str, Any]]]:
    if not isinstance(raw, list):
        return set(), {}
    sites: set[EvidenceSite] = set()
    incoming: dict[EvidenceSite, dict[str, Any]] = {}
    for row in raw:
        if not isinstance(row, Mapping):
            continue
        site = _site_without_issues(row.get("site"))
        if site is None:
            continue
        sites.add(site)
        if isinstance(row.get("incoming"), Mapping) and site not in incoming:
            incoming[site] = dict(row["incoming"])
    return sites, incoming


def _check_read_incoming_copy(
    read: Mapping[str, Any],
    *,
    incoming: Mapping[str, Any] | None,
    issues: list[dict[str, Any]],
    address: int,
    read_index: int,
) -> None:
    if incoming is None:
        return
    state = read.get("state")
    if isinstance(state, Mapping):
        copied_state = {
            key: incoming.get(key)
            for key in (
                "reachable",
                "initialized",
                "tainted",
                "overflow",
                "alternatives",
            )
        }
        if dict(state) != copied_state:
            issues.append(_issue(
                "violated",
                "global_slot_per_read_state_copy_mismatch",
                address=address,
                read_index=read_index,
            ))
    if read.get("status") is not None and read.get("status") != incoming.get("status"):
        issues.append(_issue(
            "violated",
            "global_slot_per_read_status_copy_mismatch",
            address=address,
            read_index=read_index,
        ))
    inventory = read.get("reaching_write_inventory")
    if isinstance(inventory, Mapping):
        incoming_inventory = {
            key: incoming.get(key)
            for key in ("writes", "unknown_writes", "aliasing_writes")
        }
        if dict(inventory) != incoming_inventory:
            issues.append(_issue(
                "violated",
                "global_slot_per_read_reaching_inventory_copy_mismatch",
                address=address,
                read_index=read_index,
            ))


def _check_submitted_event_binding(
    read: Mapping[str, Any],
    *,
    expected: EventBinding,
    issues: list[dict[str, Any]],
    address: int,
    read_index: int,
) -> None:
    supplied = [
        (field, read[field])
        for field in ("binding", "event_binding")
        if field in read
    ]
    for field, raw in supplied:
        try:
            observed = EventBinding.parse(raw)
        except (AuthorityDataError, TypeError, ValueError):
            issues.append(_issue(
                "violated",
                "global_slot_per_read_event_binding_corrupt",
                address=address,
                read_index=read_index,
                field=field,
            ))
            continue
        if observed != expected:
            issues.append(_issue(
                "violated",
                "global_slot_per_read_event_binding_mismatch",
                address=address,
                read_index=read_index,
                field=field,
            ))


def _site_without_issues(raw: Any) -> EvidenceSite | None:
    issues: list[dict[str, Any]] = []
    return _site(raw, issues=issues, context="write")


def _json_subset(values: Sequence[Any], candidates: Sequence[Any]) -> bool:
    return {
        _canonical_json(value) for value in values
    } <= {
        _canonical_json(value) for value in candidates
    }


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


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
