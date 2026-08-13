"""Binary-bound external-site proposals for strict v2 replay.

Legacy completeness may supply normalized site candidates, but never authority.
This artifact records those candidates with exact binary and machine-IR
bindings. The v2 static authority checker independently replays every event,
ABI, target, and profile binding before constructing CheckedExternalSite.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping, Sequence

from .checked_external_site_contract import (
    CheckedExternalSiteContractError,
    ExternalSiteIdentity,
    checked_external_site_contract_from_event,
    parse_checked_external_site_contract,
)
from .external_profile_authority_v2 import (
    ExternalProfileAuthorityV2,
    ExternalProfileEntry,
)
from .authority_bindings_v2 import canonical_json_bytes


EXTERNAL_SITE_PROPOSALS_V2_FORMAT = (
    "spaghetti-extractor-external-site-proposals-v2"
)


class ExternalSiteProposalsV2Error(ValueError):
    """External-site proposal evidence is malformed or stale."""


def build_external_site_proposals_v2(
    *,
    checked_sites: Sequence[Mapping[str, Any]],
    pe_sha256: str,
    machine_ir_sha256: str,
    source_diagnostic_sha256: str | None = None,
    analysis_issues: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    issues: list[dict[str, str]] = []
    sites: list[dict[str, Any]] = []
    seen: set[tuple[str, int, int]] = set()
    for index, raw in enumerate(checked_sites):
        try:
            unit_id = raw.get("unit_id")
            event_index = raw.get("event_index")
            alternative_index = raw.get("target_alternative_index")
            alternative_sha256 = raw.get("target_alternative_sha256")
            contract = raw.get("contract")
            if (
                not isinstance(unit_id, str)
                or not unit_id
                or not isinstance(event_index, int)
                or isinstance(event_index, bool)
                or not isinstance(alternative_index, int)
                or isinstance(alternative_index, bool)
                or alternative_index < 0
                or not isinstance(alternative_sha256, str)
                or len(alternative_sha256) != 64
                or any(
                    character not in "0123456789abcdef"
                    for character in alternative_sha256
                )
                or not isinstance(contract, Mapping)
            ):
                raise CheckedExternalSiteContractError(
                    "site wrapper has no exact unit/event identity"
                )
            parsed = parse_checked_external_site_contract(contract)
            payload = {
                "unit_id": unit_id,
                "event_index": event_index,
                "target_alternative_index": alternative_index,
                "target_alternative_sha256": alternative_sha256,
                "contract": parsed.payload(),
            }
        except (CheckedExternalSiteContractError, TypeError, ValueError) as exc:
            issues.append({
                "status": "violated",
                "code": "external_site_proposal_corrupt",
                "detail": f"site {index}: {exc}",
            })
            continue
        key = (
            str(payload["unit_id"]),
            int(payload["event_index"]),
            int(payload["target_alternative_index"]),
        )
        if key in seen:
            issues.append({
                "status": "violated",
                "code": "external_site_proposal_duplicated",
                "detail": (
                    f"site {key[0]} event {key[1]} alternative {key[2]}"
                ),
            })
            continue
        seen.add(key)
        sites.append(payload)
    sites.sort(key=lambda row: (
        str(row["unit_id"]),
        int(row["event_index"]),
        int(row["target_alternative_index"]),
    ))
    for raw in analysis_issues:
        if not isinstance(raw, Mapping):
            issues.append({
                "status": "violated",
                "code": "external_site_analysis_issue_corrupt",
                "detail": "analysis issue is not an object",
            })
            continue
        status_value = raw.get("status")
        code = raw.get("code")
        if status_value not in {"incomplete", "violated"} or not isinstance(code, str):
            issues.append({
                "status": "violated",
                "code": "external_site_analysis_issue_corrupt",
                "detail": "analysis issue has invalid status or code",
            })
            continue
        issues.append(dict(raw))
    status = (
        "violated"
        if any(issue.get("status") == "violated" for issue in issues)
        else "incomplete" if issues else "complete"
    )
    body = {
        "format": EXTERNAL_SITE_PROPOSALS_V2_FORMAT,
        "status": status,
        "authority": "untrusted_proposals_replayed_by_static_authority_v2",
        "binary": {
            "pe_sha256": _digest(pe_sha256, "PE SHA-256"),
            "machine_ir_sha256": _digest(
                machine_ir_sha256, "machine-IR SHA-256"
            ),
        },
        "source_diagnostic_sha256": (
            None
            if source_diagnostic_sha256 is None
            else _digest(source_diagnostic_sha256, "diagnostic SHA-256")
        ),
        "sites": sites,
        "issues": issues,
    }
    return {**body, "content_sha256": _sha256(body)}


def parse_external_site_proposals_v2(
    value: Mapping[str, Any],
    *,
    pe_sha256: str,
    machine_ir_sha256: str,
) -> tuple[Mapping[str, Any], ...]:
    if value.get("format") != EXTERNAL_SITE_PROPOSALS_V2_FORMAT:
        raise ExternalSiteProposalsV2Error(
            "external-site proposals are not a v2 artifact"
        )
    body = dict(value)
    observed = body.pop("content_sha256", None)
    if observed != _sha256(body):
        raise ExternalSiteProposalsV2Error(
            "external-site proposal content hash is stale"
        )
    binary = value.get("binary")
    if not isinstance(binary, Mapping) or binary != {
        "pe_sha256": pe_sha256,
        "machine_ir_sha256": machine_ir_sha256,
    }:
        raise ExternalSiteProposalsV2Error(
            "external-site proposals bind different binary artifacts"
        )
    if value.get("status") == "violated":
        raise ExternalSiteProposalsV2Error(
            "external-site proposal construction is violated"
        )
    rows = value.get("sites")
    if not isinstance(rows, list):
        raise ExternalSiteProposalsV2Error(
            "external-site proposal inventory is malformed"
        )
    replayed = build_external_site_proposals_v2(
        checked_sites=rows,
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
        source_diagnostic_sha256=value.get("source_diagnostic_sha256"),
        analysis_issues=(
            value.get("issues", ())
            if value.get("status") == "incomplete"
            else ()
        ),
    )
    if replayed != value:
        raise ExternalSiteProposalsV2Error(
            "external-site proposal artifact does not replay exactly"
        )
    return tuple(rows)


def derive_external_site_proposals_v2(
    *,
    machine_ir_rows: Sequence[Mapping[str, Any]],
    interprocedural: Mapping[str, Any],
    profile_authority: ExternalProfileAuthorityV2,
    pe_sha256: str,
    machine_ir_sha256: str,
    reachable_unit_ids: Sequence[str],
) -> dict[str, Any]:
    """Construct sites after target recovery, without consulting v1 reports."""

    reachable = frozenset(str(value) for value in reachable_unit_ids)
    recoveries = {
        (str(row.get("source_unit_id")), row.get("source_event_index")): row
        for row in interprocedural.get("recovered_targets", ())
        if isinstance(row, Mapping)
        and isinstance(row.get("source_unit_id"), str)
        and isinstance(row.get("source_event_index"), int)
    }
    provenance = interprocedural.get("operation_provenance")
    callbacks = {
        (str(row.get("unit_id")), row.get("event_index")): row
        for row in (
            provenance.get("callback_registrations", ())
            if isinstance(provenance, Mapping)
            else ()
        )
        if isinstance(row, Mapping)
        and isinstance(row.get("unit_id"), str)
        and isinstance(row.get("event_index"), int)
    }
    sites: list[dict[str, Any]] = []
    issues: list[dict[str, Any]] = []
    for row in machine_ir_rows:
        unit_id = str(row.get("id"))
        if unit_id not in reachable:
            continue
        semantics = row.get("semantics")
        events = semantics.get("external_events") if isinstance(semantics, Mapping) else None
        if not isinstance(events, list):
            issues.append(_site_issue(
                "violated", "external_event_inventory_malformed", unit_id, None
            ))
            continue
        for event_index, event in enumerate(events):
            if not isinstance(event, Mapping):
                issues.append(_site_issue(
                    "violated", "external_event_malformed", unit_id, event_index
                ))
                continue
            kind = event.get("kind")
            if kind not in {
                "external_call", "external_jump", "indirect_call", "indirect_jump"
            }:
                continue
            targets: list[Mapping[str, Any] | None] = [None]
            if kind in {"indirect_call", "indirect_jump"}:
                recovery = recoveries.get((unit_id, event_index))
                alternatives = (
                    recovery.get("external_targets")
                    if isinstance(recovery, Mapping)
                    and recovery.get("status") == "recovered"
                    else None
                )
                if alternatives is None or alternatives == []:
                    continue
                if not isinstance(alternatives, list) or any(
                    not isinstance(target, Mapping) for target in alternatives
                ):
                    issues.append(_site_issue(
                        "violated",
                        "external_target_alternatives_malformed",
                        unit_id,
                        event_index,
                    ))
                    continue
                targets = sorted(
                    alternatives,
                    key=lambda target: _sha256(target),
                )
            transfer = "jump" if str(kind).endswith("jump") else "call"
            for alternative_index, target in enumerate(targets):
                try:
                    identity = _event_identity(
                        event,
                        target=target,
                        context=f"{unit_id}:{event_index}:{alternative_index}",
                    )
                    alternative_sha256 = _sha256(
                        identity.payload() if target is None else target
                    )
                    entry = _select_profile_entry(
                        identity=identity,
                        event=event,
                        target=target,
                        transfer=transfer,
                        authority=profile_authority,
                    )
                    if entry is None:
                        issues.append(_site_issue(
                            "incomplete",
                            "external_profile_entry_unresolved",
                            unit_id,
                            event_index,
                            alternative_index=alternative_index,
                        ))
                        continue
                    contract = checked_external_site_contract_from_event(
                        event=event,
                        identity=identity,
                        transfer_kind=transfer,
                        disposition="tail_jump" if transfer == "jump" else "returns_here",
                        protocol_target=target,
                        callback_evidence=callbacks.get((unit_id, event_index)),
                        resolved_machine_contract=_resolved_profile_contract(entry),
                        context=f"{unit_id}:{event_index}:{alternative_index}",
                    )
                    replay = profile_authority.replay_lookup(
                        contract,
                        context=f"{unit_id}:{event_index}:{alternative_index}",
                    )
                    if replay.status != "complete" or replay.entry != entry:
                        issues.append(_site_issue(
                            replay.status,
                            replay.reason_code or "external_profile_replay_failed",
                            unit_id,
                            event_index,
                            alternative_index=alternative_index,
                            detail=replay.message,
                        ))
                        continue
                    sites.append({
                        "unit_id": unit_id,
                        "event_index": event_index,
                        "target_alternative_index": alternative_index,
                        "target_alternative_sha256": alternative_sha256,
                        "contract": contract.payload(),
                    })
                except (CheckedExternalSiteContractError, TypeError, ValueError) as exc:
                    issues.append(_site_issue(
                        "incomplete",
                        "external_site_contract_incomplete",
                        unit_id,
                        event_index,
                        alternative_index=alternative_index,
                        detail=str(exc),
                    ))
    return build_external_site_proposals_v2(
        checked_sites=sites,
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
        analysis_issues=issues,
    )


def _event_identity(
    event: Mapping[str, Any],
    *,
    target: Mapping[str, Any] | None,
    context: str,
) -> ExternalSiteIdentity:
    if target is None:
        return ExternalSiteIdentity.imported(event, context=context)
    imported = target.get("import")
    if isinstance(imported, Mapping):
        return ExternalSiteIdentity.imported(imported, context=context)
    protocol = target.get("external_protocol")
    if isinstance(protocol, Mapping):
        return ExternalSiteIdentity.interface(protocol, context=context)
    raise CheckedExternalSiteContractError(
        f"{context} recovered target has no canonical external identity"
    )


def _select_profile_entry(
    *,
    identity: ExternalSiteIdentity,
    event: Mapping[str, Any],
    target: Mapping[str, Any] | None,
    transfer: str,
    authority: ExternalProfileAuthorityV2,
) -> ExternalProfileEntry | None:
    binding: Any = None
    abi = event.get("abi_contract")
    if isinstance(abi, Mapping):
        binding = abi.get("profile_binding")
    if target is not None:
        binding = target.get("profile_binding", binding)
        protocol = target.get("external_protocol")
        if isinstance(protocol, Mapping):
            binding = protocol.get("profile_binding", binding)
            if binding is None and isinstance(protocol.get("profile_id"), str):
                binding = {
                    "profile_id": protocol.get("profile_id"),
                    "profile_sha256": protocol.get("profile_sha256"),
                }
    candidates = [
        entry
        for entry in authority.entries
        if entry.complete
        and transfer in entry.allowed_transfers
        and entry.identity == identity.payload()
    ]
    if isinstance(binding, Mapping):
        candidates = [
            entry for entry in candidates
            if entry.profile_id == binding.get("profile_id")
            and entry.profile_sha256 == binding.get("profile_sha256")
        ]
        if binding.get("entry_key") is not None or binding.get("entry_index") is not None:
            candidates = [
                entry for entry in candidates
                if entry.entry_key == binding.get("entry_key")
                and entry.entry_index == binding.get("entry_index")
            ]
    return candidates[0] if len(candidates) == 1 else None


def _resolved_profile_contract(entry: ExternalProfileEntry) -> dict[str, Any]:
    contract = dict(entry.contract)
    source = contract.get("source_contract")
    if isinstance(source, Mapping):
        for field in (
            "callback_source", "callback_abi", "callback_behavior", "callback_lifetime"
        ):
            if field in source:
                contract[field] = source[field]
    return {
        "id": contract.get("contract_id"),
        "arity": {"kind": "fixed", "words": contract.get("argument_words")},
        "abi_template": contract.get("abi_template"),
        "profile_binding": entry.profile_binding,
        "disposition": contract.get("profile_disposition", "returns"),
        "result_register_relations": contract.get("result_register_relations", []),
        "memory_effect": contract.get("memory_effect"),
        "memory_footprints": contract.get("memory_footprints", []),
        "world_effect": contract.get("world_effect"),
        "callback_effect": contract.get("callback_effect"),
        "out_pointer_relations": contract.get("out_pointer_relations", []),
        "out_interface_relations": contract.get("out_interface_relations", []),
        **{
            field: contract[field]
            for field in (
                "callback_source", "callback_abi", "callback_behavior", "callback_lifetime"
            )
            if field in contract
        },
    }


def _site_issue(
    status: str,
    code: str,
    unit_id: str,
    event_index: int | None,
    *,
    alternative_index: int | None = None,
    detail: str | None = None,
) -> dict[str, Any]:
    return {
        "status": status,
        "code": code,
        "unit_id": unit_id,
        "event_index": event_index,
        "target_alternative_index": alternative_index,
        "detail": detail,
    }


def _digest(value: str, context: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ExternalSiteProposalsV2Error(f"{context} is malformed")
    return value


def _sha256(value: Any) -> str:
    return hashlib.sha256(canonical_json_bytes(value)).hexdigest()


__all__ = [
    "EXTERNAL_SITE_PROPOSALS_V2_FORMAT",
    "ExternalSiteProposalsV2Error",
    "build_external_site_proposals_v2",
    "derive_external_site_proposals_v2",
    "parse_external_site_proposals_v2",
]
