"""Checked entry-state contracts for independent behavioral roots.

The interface-provenance pass deliberately emits diagnostic finite-value
proposals.  This module is the stricter boundary that may promote one of those
proposals to a global-slot invariant.  Promotion requires an exact replay
inventory for every reachable write and a domination witness for every relevant
read.  Unknown or aliasing writes taint the slot and are never exported.

PE roots and registered callbacks have different entry authorities.  PE roots
receive only immutable PE/IAT facts and explicitly supplied launch invariants.
Callback roots are reconstructed from one complete registration record, its
exact callback ABI, registration-captured resources, and the complete promoted
global-slot inventory.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass
from hashlib import sha256
from typing import Any, Iterable, Mapping, Sequence

from .behavioral_roots import (
    BEHAVIORAL_ROOTS_FORMAT,
    behavioral_roots_sha256,
)
from .callback_contracts import parse_callback_abi
from .authority_bindings_v2 import (
    AuthorityDataError,
    BinaryBinding,
    EventBinding,
    UnitBinding,
)
from .authority_record_core_v2 import (
    MAX_FINITE_ALTERNATIVES,
    AuthorityDependency,
    EvidenceIssue,
    EvidenceIssueKind,
    FiniteAlternatives,
)
from .global_slot_contract_v2 import (
    GLOBAL_SLOT_INVARIANT_FORMAT,
    GlobalSlotInvariant,
    global_slot_binding_binary,
)
from .global_slot_proposal_v2 import (
    EvidenceSite,
    propose_global_slot_invariant,
)
from .machine_ir_authority_v2 import recompute_unit_binding
from .entry_state_contract_v2 import (
    ENTRY_STATE_CONTRACT_FORMAT,
    EntryStateContract,
)
from .stage_binary import StageAInputError


ENTRY_STATE_ANALYSIS_V2_FORMAT = "stage-a-entry-state-analysis-v2"
CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT = (
    "spaghetti-extractor-callback-entry-state-analysis-v2"
)
ROOT_ENTRY_STATE_CONTRACT_V2_FORMAT = ENTRY_STATE_CONTRACT_FORMAT
GLOBAL_SLOT_INVARIANT_V2_FORMAT = GLOBAL_SLOT_INVARIANT_FORMAT

_INTERFACE_PROVENANCE_FORMAT = "stage-a-external-interface-provenance-v1"
_CALLBACK_REGISTRATION_FORMAT = "stage-a-callback-registration-provenance-v1"
_PE_ROOT_KINDS = frozenset({"pe_entrypoint", "pe_export", "pe_tls_callback"})
_HEX = frozenset("0123456789abcdef")
_IAT_FIELDS = frozenset(
    {
        "kind",
        "dll",
        "symbol",
        "ordinal",
        "iat_rva",
        "iat_va",
        "rva",
        "address",
        "slot_rva",
        "slot_va",
        "initial_value",
    }
)


class EntryStateAnalysisV2Error(ValueError):
    """The construction API was called with an invalid non-evidence option."""




def construct_entry_state_analysis_v2(
    *,
    behavioral_roots: Mapping[str, Any],
    interface_provenance: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]] = (),
    machine_ir_sha256: str | None = None,
    global_slot_evidence: Sequence[Mapping[str, Any]] = (),
    callback_entry_state: Mapping[str, Any] | None = None,
    launch_invariants: Mapping[str, Sequence[Mapping[str, Any]]] | None = None,
    iat_facts: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None = None,
    alternative_budget: int = 32,
) -> dict[str, Any]:
    """Construct exact root contracts without mutating integration artifacts."""

    if not isinstance(alternative_budget, int) or isinstance(
        alternative_budget, bool
    ) or not 0 < alternative_budget <= MAX_FINITE_ALTERNATIVES:
        raise EntryStateAnalysisV2Error(
            f"alternative budget must be between 1 and {MAX_FINITE_ALTERNATIVES}"
        )

    global_issues: list[dict[str, Any]] = []
    roots, pe = _checked_behavioral_roots(behavioral_roots, global_issues)
    behavioral_binding_issues = copy.deepcopy(global_issues)
    unit_bindings, units_by_rva = _checked_unit_bindings(
        units,
        machine_ir_sha256=machine_ir_sha256,
        pe=pe,
        issues=global_issues,
    )
    machine_binding_issues = copy.deepcopy(
        global_issues[len(behavioral_binding_issues):]
    )
    issue_offset = len(global_issues)
    normalized_iat = _checked_iat_facts(iat_facts, pe=pe, issues=global_issues)
    iat_binding_issues = copy.deepcopy(global_issues[issue_offset:])
    issue_offset = len(global_issues)
    provenance_slots, rejected_slots = _interface_slots(
        interface_provenance, global_issues
    )
    interface_binding_issues = copy.deepcopy(global_issues[issue_offset:])

    evidence_by_address: dict[int, Mapping[str, Any]] = {}
    for index, evidence in enumerate(global_slot_evidence):
        if not isinstance(evidence, Mapping):
            global_issues.append(_issue(
                "violated", "global_slot_evidence_record_corrupt", index=index
            ))
            continue
        address = _uint32(evidence.get("address"))
        if address is None:
            global_issues.append(_issue(
                "violated", "global_slot_evidence_address_corrupt", index=index
            ))
            continue
        if address in evidence_by_address:
            global_issues.append(_issue(
                "violated", "global_slot_evidence_duplicated", address=address
            ))
            continue
        evidence_by_address[address] = evidence

    # Replay evidence is authority only for slots used by checked provenance.
    # Exploratory evidence for unrelated writable locations remains diagnostic.
    slot_addresses = sorted(set(provenance_slots) | set(rejected_slots))
    slot_checks: list[dict[str, Any]] = []
    invariants: list[dict[str, Any]] = []
    for address in slot_addresses:
        evidence = evidence_by_address.get(address)
        if evidence is None:
            check = _slot_check(
                address=address,
                issues=[_issue(
                    "incomplete", "global_slot_replay_missing", address=address
                )],
            )
        else:
            check = propose_global_slot_invariant(
                evidence,
                interface_slot=provenance_slots.get(address),
                unit_bindings=unit_bindings,
                image_base=0 if pe is None else int(pe["image_base"]),
                size_of_image=(
                    0x1_0000_0000 if pe is None else int(pe["size_of_image"])
                ),
                rejected_tainted=address in rejected_slots,
                alternative_budget=alternative_budget,
            )
        slot_checks.append(check)
        if check["proposal"] is not None:
            invariants.append(check["proposal"])

    slot_failures = [
        issue for check in slot_checks for issue in check.get("issues", [])
    ]

    root_checks: list[dict[str, Any]] = []
    normalized_launch = launch_invariants if isinstance(launch_invariants, Mapping) else {}
    if launch_invariants is None:
        global_issues.append(_issue("incomplete", "launch_invariant_inventory_missing"))
    elif not isinstance(launch_invariants, Mapping):
        global_issues.append(_issue("violated", "launch_invariant_inventory_corrupt"))

    if pe is not None:
        for root in roots:
            local_issues = copy.deepcopy(
                [
                    *behavioral_binding_issues,
                    *machine_binding_issues,
                    *iat_binding_issues,
                ]
            )
            invariants_for_root = _launch_invariants_for_root(
                normalized_launch, root=root, issues=local_issues
            )
            facts = {
                "authority": "immutable_pe_launch_v1",
                "immutable_pe": copy.deepcopy(pe),
                "immutable_iat": copy.deepcopy(normalized_iat),
                "launch_invariants": invariants_for_root,
            }
            root_checks.append(_root_contract(
                root=root,
                entry=units_by_rva.get(int(root["rva"])),
                entry_facts=facts,
                issues=local_issues,
            ))

    registrations = _checked_callback_registrations(
        interface_provenance,
        pe=pe,
        unit_bindings=unit_bindings,
        issues=global_issues,
    )
    legacy_callback_checks = _derive_callback_root_checks(
        registrations=registrations,
        units_by_rva=units_by_rva,
        global_slot_invariants=invariants,
        base_issues=[
            *behavioral_binding_issues,
            *machine_binding_issues,
            *interface_binding_issues,
        ],
    )
    legacy_callback_diagnostics = [
        _legacy_callback_diagnostic(check) for check in legacy_callback_checks
    ]
    callback_authority: dict[str, Any]
    if callback_entry_state is None and registrations:
        global_issues.append(_issue(
            "incomplete", "callback_entry_state_artifact_missing"
        ))
        callback_authority = {
            "source": "missing",
            "status": "incomplete",
            "analysis_sha256": None,
        }
    elif callback_entry_state is None:
        callback_authority = {
            "source": "not_applicable",
            "status": "complete",
            "analysis_sha256": None,
        }
    else:
        try:
            parsed_callback = parse_callback_entry_state_contracts_v2(
                callback_entry_state
            )
        except (EntryStateAnalysisV2Error, TypeError, ValueError) as exc:
            global_issues.append(_issue(
                "violated",
                "callback_entry_state_artifact_corrupt",
                detail=str(exc),
            ))
            callback_authority = {
                "source": "strict_callback_entry_artifact_v2",
                "status": "violated",
                "analysis_sha256": None,
            }
        else:
            replay = validate_callback_entry_state_contracts_v2(
                parsed_callback,
                pe_sha256=("" if pe is None else str(pe["sha256"])),
                image_base=(0 if pe is None else int(pe["image_base"])),
                size_of_image=(0 if pe is None else int(pe["size_of_image"])),
                interface_provenance=interface_provenance,
                units=units,
                machine_ir_sha256=(machine_ir_sha256 or ""),
                global_slot_invariants=invariants,
            )
            if replay["status"] == "violated":
                global_issues.extend(copy.deepcopy(replay["issues"]))
                global_issues.append(_issue(
                    "violated", "callback_entry_state_replay_mismatch"
                ))
            else:
                root_checks.extend(copy.deepcopy(parsed_callback["checks"]))
                global_issues.extend(copy.deepcopy(parsed_callback["issues"]))
            callback_authority = {
                "source": "strict_callback_entry_artifact_v2",
                "status": replay["status"],
                "analysis_sha256": parsed_callback["analysis_sha256"],
            }

    root_contracts = [
        check["proposal"]
        for check in root_checks
        if check.get("proposal") is not None
    ]
    all_issues = _deduplicate_issues(
        [
            *global_issues,
            *(issue for check in root_checks for issue in check["issues"]),
            *slot_failures,
        ]
    )
    status = _aggregate_status(all_issues)
    root_checks.sort(key=_root_sort_key)
    root_contracts.sort(key=lambda row: str(row["content_id"]))
    invariants.sort(key=lambda row: int(row["slot_rva"]))
    slot_checks.sort(
        key=lambda row: (
            row.get("address") is None,
            -1 if row.get("address") is None else int(row["address"]),
        )
    )
    body = {
        "format": ENTRY_STATE_ANALYSIS_V2_FORMAT,
        "status": status,
        "authority": "checked_static_replay_v2",
        "proof_authority": False,
        "root_contracts": root_contracts,
        "root_checks": root_checks,
        "callback_authority": callback_authority,
        "legacy_callback_diagnostics": {
            "authority": "compatibility_diagnostic_only",
            "proof_authority": False,
            "status": _aggregate_status([
                issue
                for check in legacy_callback_diagnostics
                for issue in check["issues"]
            ]),
            "root_checks": legacy_callback_diagnostics,
            "counts": {"callback_roots": len(legacy_callback_diagnostics)},
        },
        "global_slot_invariants": invariants,
        "authority_records": sorted(
            [*root_contracts, *invariants], key=lambda row: str(row["content_id"])
        ),
        "global_slot_checks": slot_checks,
        "issues": all_issues,
        "counts": {
            "pe_roots": sum(
                check["root"]["kind"] in _PE_ROOT_KINDS
                for check in root_checks
            ),
            "callback_roots": sum(
                check["root"]["kind"] == "registered_callback"
                for check in root_checks
            ),
            "legacy_callback_diagnostics": len(legacy_callback_diagnostics),
            "complete_root_contracts": sum(
                contract["status"] == "complete" for contract in root_contracts
            ),
            "global_slot_invariants": len(invariants),
            "tainted_global_slots": sum(
                check.get("tainted") is True for check in slot_checks
            ),
            "issues": len(all_issues),
        },
    }
    return {**body, "analysis_sha256": _canonical_sha256(body)}


def build_entry_state_analysis_v2(**kwargs: Any) -> dict[str, Any]:
    """Compatibility spelling for the primary construction API."""

    return construct_entry_state_analysis_v2(**kwargs)


def derive_callback_entry_state_contracts_v2(
    *,
    pe_sha256: str,
    image_base: int,
    size_of_image: int,
    interface_provenance: Mapping[str, Any],
    units: Sequence[Mapping[str, Any]],
    machine_ir_sha256: str,
    global_slot_invariants: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Derive callback entry contracts before a launch profile exists.

    Callback state is bound to one checked registration and to only the global
    invariants explicitly named by that registration.  The returned callback
    roots can subsequently be finalized into a PE32 launch profile.
    """

    pe = {
        "sha256": pe_sha256,
        "image_base": image_base,
        "size_of_image": size_of_image,
    }
    issues: list[dict[str, Any]] = []
    if not _digest(pe_sha256):
        issues.append(_issue("violated", "callback_pe_digest_corrupt"))
    if _uint32(image_base) is None or _uint32(size_of_image) in {None, 0}:
        issues.append(_issue("violated", "callback_pe_layout_corrupt"))
    if not isinstance(interface_provenance, Mapping):
        issues.append(_issue("incomplete", "interface_provenance_missing"))
    elif interface_provenance.get("format") != _INTERFACE_PROVENANCE_FORMAT:
        issues.append(_issue("violated", "interface_provenance_format_corrupt"))
    elif interface_provenance.get("proof_authority") is not False:
        issues.append(_issue("violated", "interface_provenance_authority_corrupt"))
    unit_bindings, units_by_rva = _checked_unit_bindings(
        units,
        machine_ir_sha256=machine_ir_sha256,
        pe=pe if not issues else None,
        issues=issues,
    )
    registrations = _checked_callback_registrations(
        interface_provenance,
        pe=pe if not issues else None,
        unit_bindings=unit_bindings,
        issues=issues,
    )
    checked_invariants = _checked_global_slot_invariant_records(
        global_slot_invariants,
        pe_sha256=pe_sha256,
        machine_ir_sha256=machine_ir_sha256,
        issues=issues,
    )
    checks = _derive_callback_root_checks(
        registrations=registrations,
        units_by_rva=units_by_rva,
        global_slot_invariants=checked_invariants,
        base_issues=(),
    )
    contracts = sorted(
        (
            check["proposal"]
            for check in checks
            if isinstance(check.get("proposal"), Mapping)
        ),
        key=lambda row: str(row["content_id"]),
    )
    callback_roots: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check.get("proposal"), Mapping):
            continue
        root = _callback_launch_root_from_check(check)
        if root is not None:
            callback_roots.append(root)
    callback_roots.sort(key=_canonical_json)
    all_issues = _deduplicate_issues([
        *issues,
        *(issue for check in checks for issue in check["issues"]),
    ])
    body = {
        "format": CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT,
        "schema_version": 2,
        "authority": "checked_callback_entry_replay_v2",
        "status": _aggregate_status(all_issues),
        "binary": {
            "pe_sha256": pe_sha256,
            "machine_ir_sha256": machine_ir_sha256,
            "image_base": image_base,
            "size_of_image": size_of_image,
        },
        "contracts": contracts,
        "callback_roots": callback_roots,
        "checks": sorted(checks, key=_root_sort_key),
        "global_slot_invariants": sorted(
            checked_invariants.values(), key=lambda row: str(row["content_id"])
        ),
        "global_slot_invariant_ids": sorted(checked_invariants),
        "issues": all_issues,
        "counts": {
            "registrations": len(registrations),
            "callback_roots": len(callback_roots),
            "complete_contracts": sum(
                contract["status"] == "complete" for contract in contracts
            ),
            "global_slot_invariants": len(checked_invariants),
            "issues": len(all_issues),
        },
    }
    return {**body, "analysis_sha256": _canonical_sha256(body)}


def parse_callback_entry_state_contracts_v2(value: Any) -> dict[str, Any]:
    """Strictly parse callback-entry output and replay its internal bindings."""

    if not isinstance(value, Mapping):
        raise EntryStateAnalysisV2Error("callback entry-state artifact is not an object")
    row = _json_clone(value)
    expected_fields = {
        "format", "schema_version", "authority", "status", "binary",
        "contracts", "callback_roots", "checks", "global_slot_invariants",
        "global_slot_invariant_ids", "issues", "counts", "analysis_sha256",
    }
    if set(row) != expected_fields:
        raise EntryStateAnalysisV2Error("callback entry-state artifact has noncanonical fields")
    if (
        row["format"] != CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT
        or row["schema_version"] != 2
        or row["authority"] != "checked_callback_entry_replay_v2"
    ):
        raise EntryStateAnalysisV2Error("callback entry-state authority is unsupported")
    binary = row.get("binary")
    if not isinstance(binary, Mapping) or set(binary) != {
        "pe_sha256", "machine_ir_sha256", "image_base", "size_of_image"
    }:
        raise EntryStateAnalysisV2Error("callback entry-state binary binding is corrupt")
    if (
        not _digest(binary.get("pe_sha256"))
        or not _digest(binary.get("machine_ir_sha256"))
        or _uint32(binary.get("image_base")) is None
        or _uint32(binary.get("size_of_image")) in {None, 0}
    ):
        raise EntryStateAnalysisV2Error("callback entry-state binary binding is corrupt")
    contracts_raw = row.get("contracts")
    roots_raw = row.get("callback_roots")
    invariants_raw = row.get("global_slot_invariants")
    if (
        not isinstance(contracts_raw, list)
        or not isinstance(roots_raw, list)
        or not isinstance(invariants_raw, list)
    ):
        raise EntryStateAnalysisV2Error("callback entry-state inventory is corrupt")
    contracts: dict[str, EntryStateContract] = {}
    invariants: dict[str, GlobalSlotInvariant] = {}
    rooted_contracts: set[str] = set()
    try:
        for raw in invariants_raw:
            invariant = GlobalSlotInvariant.parse(raw)
            invariant_binary = global_slot_binding_binary(invariant.binding)
            if (
                invariant.status.value != "complete"
                or invariant_binary.pe_sha256 != binary["pe_sha256"]
                or invariant_binary.machine_ir_sha256
                != binary["machine_ir_sha256"]
            ):
                raise EntryStateAnalysisV2Error(
                    "callback global invariant has an invalid exact binding"
                )
            if invariant.content_id in invariants:
                raise EntryStateAnalysisV2Error("callback global invariant is duplicated")
            invariants[invariant.content_id] = invariant
        for raw in contracts_raw:
            contract = EntryStateContract.parse(raw)
            if contract.content_id in contracts:
                raise EntryStateAnalysisV2Error("callback entry contract is duplicated")
            contracts[contract.content_id] = contract
            for dependency in contract.dependencies:
                if dependency.role == "global_slot" and dependency.content_id not in invariants:
                    raise EntryStateAnalysisV2Error(
                        "callback entry contract names a missing global invariant"
                    )
        for raw in roots_raw:
            _check_callback_launch_root_binding(raw, contracts=contracts, binary=binary)
            content_id = raw["entry_contract_content_id"]
            if content_id in rooted_contracts:
                raise EntryStateAnalysisV2Error("callback launch root is duplicated")
            rooted_contracts.add(content_id)
    except (AuthorityDataError, TypeError, ValueError) as exc:
        raise EntryStateAnalysisV2Error(str(exc)) from exc
    complete_contracts = {
        content_id
        for content_id, contract in contracts.items()
        if contract.status.value == "complete"
    }
    if not complete_contracts <= rooted_contracts:
        raise EntryStateAnalysisV2Error(
            "a complete callback entry contract has no launch root"
        )
    body = dict(row)
    observed_hash = body.pop("analysis_sha256")
    if observed_hash != _canonical_sha256(body):
        raise EntryStateAnalysisV2Error("callback entry-state hash is stale")
    issues = row.get("issues")
    if not isinstance(issues, list) or row.get("status") != _aggregate_status(issues):
        raise EntryStateAnalysisV2Error("callback entry-state status is stale")
    checks = row.get("checks")
    invariant_ids = row.get("global_slot_invariant_ids")
    counts = row.get("counts")
    expected_counts = {
        "registrations": counts.get("registrations") if isinstance(counts, Mapping) else None,
        "callback_roots": len(roots_raw),
        "complete_contracts": sum(
            contract.status.value == "complete" for contract in contracts.values()
        ),
        "global_slot_invariants": len(invariants),
        "issues": len(issues) if isinstance(issues, list) else -1,
    }
    if (
        not isinstance(checks, list)
        or not isinstance(counts, Mapping)
        or not isinstance(counts.get("registrations"), int)
        or isinstance(counts.get("registrations"), bool)
        or counts.get("registrations", -1) < 0
        or dict(counts) != expected_counts
    ):
        raise EntryStateAnalysisV2Error("callback entry-state counts are stale")
    if (
        not isinstance(invariant_ids, list)
        or invariant_ids != sorted(set(invariant_ids))
        or invariant_ids != sorted(invariants)
        or contracts_raw != sorted(contracts_raw, key=lambda item: str(item["content_id"]))
        or roots_raw != sorted(roots_raw, key=_canonical_json)
        or invariants_raw != sorted(
            invariants_raw, key=lambda item: str(item["content_id"])
        )
    ):
        raise EntryStateAnalysisV2Error("callback entry-state ordering is noncanonical")
    return row


def validate_callback_entry_state_contracts_v2(
    value: Any,
    **inputs: Any,
) -> dict[str, Any]:
    """Replay derivation against exact inputs and classify any mismatch."""

    try:
        parsed = parse_callback_entry_state_contracts_v2(value)
    except (EntryStateAnalysisV2Error, TypeError, ValueError) as exc:
        return {
            "status": "violated",
            "usable": False,
            "issues": [_issue("violated", "callback_entry_artifact_corrupt", detail=str(exc))],
        }
    expected = derive_callback_entry_state_contracts_v2(**inputs)
    if parsed != expected:
        return {
            "status": "violated",
            "usable": False,
            "issues": [_issue("violated", "callback_entry_replay_mismatch")],
        }
    return {
        "status": parsed["status"],
        "usable": parsed["status"] == "complete",
        "issues": copy.deepcopy(parsed["issues"]),
    }


def _checked_global_slot_invariant_records(
    values: Sequence[Mapping[str, Any]],
    *,
    pe_sha256: str,
    machine_ir_sha256: str,
    issues: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    if not isinstance(values, Sequence) or isinstance(values, (str, bytes)):
        issues.append(_issue("violated", "callback_global_invariant_inventory_corrupt"))
        return {}
    result: dict[str, dict[str, Any]] = {}
    for index, value in enumerate(values):
        try:
            invariant = GlobalSlotInvariant.parse(value)
        except (AuthorityDataError, TypeError, ValueError) as exc:
            issues.append(_issue(
                "violated",
                "callback_global_invariant_corrupt",
                index=index,
                detail=str(exc),
            ))
            continue
        invariant_binary = global_slot_binding_binary(invariant.binding)
        if (
            invariant_binary.pe_sha256 != pe_sha256
            or invariant_binary.machine_ir_sha256 != machine_ir_sha256
        ):
            issues.append(_issue(
                "violated",
                "callback_global_invariant_binary_contradiction",
                content_id=invariant.content_id,
            ))
            continue
        if invariant.status.value != "complete":
            issues.append(_issue(
                "incomplete",
                "callback_global_invariant_incomplete",
                content_id=invariant.content_id,
            ))
            continue
        if invariant.content_id in result:
            issues.append(_issue(
                "violated",
                "callback_global_invariant_duplicated",
                content_id=invariant.content_id,
            ))
            continue
        result[invariant.content_id] = invariant.to_payload()
    return result


def _derive_callback_root_checks(
    *,
    registrations: Sequence[Mapping[str, Any]],
    units_by_rva: Mapping[int, UnitBinding],
    global_slot_invariants: Sequence[Mapping[str, Any]] | Mapping[str, Mapping[str, Any]],
    base_issues: Sequence[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    invariant_by_id = (
        dict(global_slot_invariants)
        if isinstance(global_slot_invariants, Mapping)
        else {
            str(row["content_id"]): dict(row)
            for row in global_slot_invariants
            if isinstance(row, Mapping) and isinstance(row.get("content_id"), str)
        }
    )
    result: list[dict[str, Any]] = []
    ordered_registrations = sorted(
        registrations,
        key=lambda row: (
            str(row.get("unit_id", "")),
            int(row.get("event_index", 0)),
            int(row.get("instruction_rva", 0)),
            _canonical_json(row.get("target_rvas", [])),
        ),
    )
    for registration in ordered_registrations:
        for target_rva in registration.get("target_rvas", []):
            if not isinstance(target_rva, int) or isinstance(target_rva, bool):
                continue
            local_issues = copy.deepcopy(list(base_issues))
            local_issues.extend(copy.deepcopy(registration.get("_issues", [])))

            required_ids = registration.get("global_slot_invariant_ids")
            if not isinstance(required_ids, list):
                required_ids = []
            selected: list[dict[str, Any]] = []
            for content_id in required_ids:
                invariant = invariant_by_id.get(content_id)
                if invariant is None:
                    local_issues.append(_issue(
                        "incomplete",
                        "callback_global_invariant_missing",
                        target_rva=target_rva,
                        content_id=content_id,
                    ))
                else:
                    selected.append({
                        "slot_rva": invariant["slot_rva"],
                        "content_id": invariant["content_id"],
                    })

            registration_event = _registration_event_binding(registration)
            if registration_event is None:
                local_issues.append(_issue(
                    "incomplete", "callback_registration_event_binding_missing",
                    target_rva=target_rva,
                ))
            root = {
                "kind": "registered_callback",
                "identity": (
                    f"registered-callback:rva:{target_rva}:source:"
                    f"{registration.get('unit_id')}:{registration.get('event_index')}"
                ),
                "rva": target_rva,
            }
            entry = units_by_rva.get(target_rva)
            target_ids = registration.get("target_unit_ids")
            if (
                entry is not None
                and isinstance(target_ids, list)
                and entry.unit_id not in target_ids
            ):
                local_issues.append(_issue(
                    "violated",
                    "callback_target_unit_binding_contradiction",
                    target_rva=target_rva,
                    observed_unit_id=entry.unit_id,
                    registered_unit_ids=target_ids,
                ))
            entry_facts = {
                "authority": "checked_callback_registration_v2",
                "registration": _registration_binding(registration),
                "registration_event": (
                    None
                    if registration_event is None
                    else registration_event.to_payload()
                ),
                "callback_abi": copy.deepcopy(registration.get("callback_abi")),
                "callback_arguments": _callback_arguments(registration),
                "captured_resources": _captured_resources(registration),
                "global_slot_invariants": sorted(selected, key=_canonical_json),
            }
            result.append(_root_contract(
                root=root,
                entry=entry,
                entry_event=registration_event,
                entry_facts=entry_facts,
                issues=local_issues,
                dependencies=tuple(sorted(
                    AuthorityDependency("global_slot", row["content_id"])
                    for row in selected
                )),
            ))
    return result


def _registration_event_binding(
    registration: Mapping[str, Any],
) -> EventBinding | None:
    raw_binding = registration.get("_source_unit_binding")
    event_index = _uint32(registration.get("event_index"))
    instruction_rva = _uint32(registration.get("instruction_rva"))
    if not isinstance(raw_binding, Mapping) or event_index is None or instruction_rva is None:
        return None
    try:
        unit = UnitBinding.parse(raw_binding)
        identity = {
            "unit": unit.to_payload(),
            "event_index": event_index,
            "event_kind": "external_call",
            "instruction_rva": instruction_rva,
        }
        return EventBinding(
            unit=unit,
            event_index=event_index,
            event_kind="external_call",
            instruction_rva=instruction_rva,
            event_sha256=_canonical_sha256(identity),
        )
    except (AuthorityDataError, TypeError, ValueError):
        return None


def _callback_launch_root_from_check(
    check: Mapping[str, Any],
) -> dict[str, Any] | None:
    proposal = check["proposal"]
    facts = proposal["alternatives"]["values"][0]
    if not isinstance(facts.get("registration_event"), Mapping):
        return None
    return {
        "rva": proposal["binding"]["rva_start"],
        "registration_event": copy.deepcopy(facts["registration_event"]),
        "entry_contract_content_id": proposal["content_id"],
    }


def _check_callback_launch_root_binding(
    value: Any,
    *,
    contracts: Mapping[str, EntryStateContract],
    binary: Mapping[str, Any],
) -> None:
    if not isinstance(value, Mapping) or set(value) != {
        "rva", "registration_event", "entry_contract_content_id"
    }:
        raise EntryStateAnalysisV2Error("callback launch root is noncanonical")
    rva = _uint32(value.get("rva"))
    content_id = value.get("entry_contract_content_id")
    if rva in {None, 0} or not isinstance(content_id, str):
        raise EntryStateAnalysisV2Error("callback launch root binding is corrupt")
    contract = contracts.get(content_id)
    if contract is None or contract.entry_kind != "registered_callback":
        raise EntryStateAnalysisV2Error("callback launch root has no entry contract")
    try:
        event = EventBinding.parse(value.get("registration_event"))
    except AuthorityDataError as exc:
        raise EntryStateAnalysisV2Error(str(exc)) from exc
    if (
        contract.entry.rva_start != rva
        or contract.entry.binary.pe_sha256 != binary["pe_sha256"]
        or contract.entry.binary.machine_ir_sha256 != binary["machine_ir_sha256"]
        or event.unit.binary != contract.entry.binary
    ):
        raise EntryStateAnalysisV2Error("callback launch root binary binding contradicts its contract")
    if contract.alternatives is None or len(contract.alternatives.values) != 1:
        raise EntryStateAnalysisV2Error("callback entry contract lacks one exact alternative")
    facts = contract.alternatives.values[0].to_value()
    if not isinstance(facts, Mapping) or facts.get("registration_event") != event.to_payload():
        raise EntryStateAnalysisV2Error("callback registration event contradicts its entry contract")
    root = facts.get("root")
    if not isinstance(root, Mapping) or root.get("rva") != rva:
        raise EntryStateAnalysisV2Error("callback root contradicts its entry contract")


def _checked_behavioral_roots(
    payload: Mapping[str, Any], issues: list[dict[str, Any]]
) -> tuple[list[dict[str, Any]], dict[str, Any] | None]:
    if not isinstance(payload, Mapping):
        issues.append(_issue("incomplete", "behavioral_roots_missing"))
        return [], None
    if payload.get("format") != BEHAVIORAL_ROOTS_FORMAT:
        issues.append(_issue("violated", "behavioral_roots_format_corrupt"))
        return [], None
    if payload.get("authority") != "independent_exact_pe_metadata":
        issues.append(_issue("violated", "behavioral_roots_authority_corrupt"))
    observed_hash = payload.get("contract_sha256")
    if observed_hash is None:
        issues.append(_issue("incomplete", "behavioral_roots_hash_missing"))
    elif not _digest(observed_hash):
        issues.append(_issue("violated", "behavioral_roots_hash_corrupt"))
    else:
        try:
            expected_hash = behavioral_roots_sha256(payload)
        except (StageAInputError, TypeError, ValueError):
            expected_hash = None
        if expected_hash is None or observed_hash != expected_hash:
            issues.append(_issue("violated", "behavioral_roots_hash_mismatch"))
    if payload.get("status") != "complete":
        issues.append(_issue("incomplete", "behavioral_roots_incomplete"))

    raw_pe = payload.get("pe")
    if not isinstance(raw_pe, Mapping):
        issues.append(_issue("incomplete", "behavioral_roots_pe_missing"))
        pe = None
    else:
        pe = _json_mapping(raw_pe, issues, code="behavioral_roots_pe_corrupt")
        required = {
            "sha256", "file_size", "machine", "bitness", "image_base",
            "size_of_image", "entrypoint_rva",
        }
        if pe is not None and set(pe) != required:
            issues.append(_issue("violated", "behavioral_roots_pe_schema_corrupt"))
            pe = None
        elif pe is not None and (
            not _digest(pe.get("sha256"))
            or _uint32(pe.get("image_base")) is None
            or _uint32(pe.get("size_of_image")) in {None, 0}
        ):
            issues.append(_issue("violated", "behavioral_roots_pe_value_corrupt"))
            pe = None

    raw_roots = payload.get("roots")
    if not isinstance(raw_roots, list):
        issues.append(_issue("incomplete", "behavioral_root_inventory_missing"))
        return [], pe
    roots: list[dict[str, Any]] = []
    identities: set[str] = set()
    for index, raw in enumerate(raw_roots):
        if not isinstance(raw, Mapping):
            issues.append(_issue("violated", "behavioral_root_corrupt", index=index))
            continue
        kind = raw.get("kind")
        identity = raw.get("identity")
        rva = _uint32(raw.get("rva"))
        if (
            kind not in _PE_ROOT_KINDS
            or not isinstance(identity, str)
            or not identity
            or rva in {None, 0}
        ):
            issues.append(_issue("violated", "behavioral_root_corrupt", index=index))
            continue
        if identity in identities:
            issues.append(_issue(
                "violated", "behavioral_root_identity_duplicated", identity=identity
            ))
            continue
        identities.add(identity)
        normalized_root = _json_mapping(
            raw, issues, code="behavioral_root_corrupt", index=index
        )
        if normalized_root is not None:
            roots.append(normalized_root)
    counts = payload.get("counts")
    if isinstance(counts, Mapping) and counts.get("roots") != len(raw_roots):
        issues.append(_issue("violated", "behavioral_root_counts_corrupt"))
    return roots, pe


def _checked_unit_bindings(
    units: Sequence[Mapping[str, Any]],
    *,
    machine_ir_sha256: str | None,
    pe: Mapping[str, Any] | None,
    issues: list[dict[str, Any]],
) -> tuple[dict[str, UnitBinding], dict[int, UnitBinding]]:
    if machine_ir_sha256 is None:
        issues.append(_issue("incomplete", "machine_ir_digest_missing"))
        return {}, {}
    if not _digest(machine_ir_sha256):
        issues.append(_issue("violated", "machine_ir_digest_corrupt"))
        return {}, {}
    if pe is None:
        issues.append(_issue("incomplete", "machine_ir_binary_binding_missing"))
        return {}, {}
    if not isinstance(units, Sequence) or isinstance(units, (str, bytes)) or not units:
        issues.append(_issue("incomplete", "machine_ir_unit_inventory_missing"))
        return {}, {}
    binary = BinaryBinding(
        pe_sha256=str(pe["sha256"]),
        machine_ir_sha256=machine_ir_sha256,
    )
    by_id: dict[str, UnitBinding] = {}
    by_rva: dict[int, UnitBinding] = {}
    for index, raw in enumerate(units):
        if not isinstance(raw, Mapping):
            issues.append(_issue("violated", "machine_ir_unit_corrupt", index=index))
            continue
        try:
            binding = recompute_unit_binding(raw, binary=binary)
        except (TypeError, ValueError):
            issues.append(_issue("violated", "machine_ir_unit_binding_corrupt", index=index))
            continue
        unit_id = binding.unit_id
        rva_start = binding.rva_start
        if unit_id in by_id:
            issues.append(_issue("violated", "machine_ir_unit_id_duplicated", unit_id=unit_id))
            continue
        if rva_start in by_rva:
            issues.append(_issue("violated", "machine_ir_unit_rva_duplicated", rva=rva_start))
            continue
        by_id[unit_id] = binding
        by_rva[rva_start] = binding
    return by_id, by_rva


def _checked_iat_facts(
    raw: Sequence[Mapping[str, Any]] | Mapping[str, Any] | None,
    *,
    pe: Mapping[str, Any] | None,
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    if raw is None:
        issues.append(_issue("incomplete", "immutable_iat_inventory_missing"))
        return []
    if isinstance(raw, Mapping):
        if raw.get("status") != "complete":
            issues.append(_issue("incomplete", "immutable_iat_inventory_incomplete"))
        entries = raw.get("entries")
    else:
        entries = raw
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes)):
        issues.append(_issue("violated", "immutable_iat_inventory_corrupt"))
        return []
    result: list[dict[str, Any]] = []
    by_location: dict[int, dict[str, Any]] = {}
    image_base = None if pe is None else _uint32(pe.get("image_base"))
    for index, entry in enumerate(entries):
        if not isinstance(entry, Mapping) or not set(entry) <= _IAT_FIELDS:
            issues.append(_issue("violated", "immutable_iat_fact_corrupt", index=index))
            continue
        normalized = _json_mapping(
            entry, issues, code="immutable_iat_fact_corrupt", index=index
        )
        if normalized is None:
            continue
        dll = normalized.get("dll")
        symbol = normalized.get("symbol")
        ordinal = normalized.get("ordinal")
        if not isinstance(dll, str) or not dll or (
            (isinstance(symbol, str) and bool(symbol))
            == (isinstance(ordinal, int) and not isinstance(ordinal, bool))
        ):
            issues.append(_issue("violated", "immutable_iat_identity_corrupt", index=index))
            continue
        rva = next(
            (
                value for value in (
                    _uint32(normalized.get("iat_rva")),
                    _uint32(normalized.get("slot_rva")),
                    _uint32(normalized.get("rva")),
                ) if value is not None
            ),
            None,
        )
        address = next(
            (
                value for value in (
                    _uint32(normalized.get("iat_va")),
                    _uint32(normalized.get("slot_va")),
                    _uint32(normalized.get("address")),
                ) if value is not None
            ),
            None,
        )
        if rva is None and address is None:
            issues.append(_issue("incomplete", "immutable_iat_location_missing", index=index))
            continue
        if image_base is not None:
            if rva is None:
                assert address is not None
                rva = (address - image_base) & 0xFFFFFFFF
            if address is None:
                assert rva is not None
                address = (image_base + rva) & 0xFFFFFFFF
            if address != (image_base + rva) & 0xFFFFFFFF:
                issues.append(_issue("violated", "immutable_iat_location_contradiction", index=index))
                continue
        assert address is not None or rva is not None
        location = address if address is not None else rva
        assert location is not None
        canonical = {
            "dll": dll.lower(),
            "symbol": symbol if isinstance(symbol, str) else None,
            "ordinal": ordinal if isinstance(ordinal, int) else None,
            "iat_rva": rva,
            "iat_va": address,
            "initial_value": normalized.get("initial_value"),
        }
        if location in by_location and by_location[location] != canonical:
            issues.append(_issue("violated", "immutable_iat_fact_contradiction", location=location))
            continue
        if location in by_location:
            issues.append(_issue("violated", "immutable_iat_fact_duplicated", location=location))
            continue
        by_location[location] = canonical
        result.append(canonical)
    return sorted(result, key=lambda row: (row["iat_rva"] is None, row["iat_rva"] or 0))


def _interface_slots(
    payload: Mapping[str, Any], issues: list[dict[str, Any]]
) -> tuple[dict[int, dict[str, Any]], set[int]]:
    if not isinstance(payload, Mapping):
        issues.append(_issue("incomplete", "interface_provenance_missing"))
        return {}, set()
    if payload.get("format") != _INTERFACE_PROVENANCE_FORMAT:
        issues.append(_issue("violated", "interface_provenance_format_corrupt"))
        return {}, set()
    if payload.get("proof_authority") is not False:
        issues.append(_issue("violated", "interface_provenance_authority_corrupt"))
    slots: dict[int, dict[str, Any]] = {}
    raw_slots = payload.get("static_interface_slots")
    if not isinstance(raw_slots, list):
        issues.append(_issue("incomplete", "interface_static_slot_inventory_missing"))
        raw_slots = []
    for index, raw in enumerate(raw_slots):
        if not isinstance(raw, Mapping) or _uint32(raw.get("address")) is None:
            issues.append(_issue("violated", "interface_static_slot_corrupt", index=index))
            continue
        address = int(raw["address"])
        normalized = _json_mapping(
            raw, issues, code="interface_static_slot_corrupt", index=index
        )
        if normalized is None:
            continue
        if address in slots and slots[address] != normalized:
            issues.append(_issue("violated", "interface_static_slot_contradiction", address=address))
            continue
        if address in slots:
            issues.append(_issue("violated", "interface_static_slot_duplicated", address=address))
            continue
        slots[address] = normalized
    rejected: set[int] = set()
    raw_rejected = payload.get("rejected_tainted_slots")
    if not isinstance(raw_rejected, list):
        issues.append(_issue("incomplete", "interface_tainted_slot_inventory_missing"))
        raw_rejected = []
    for index, raw in enumerate(raw_rejected):
        if not isinstance(raw, Mapping) or raw.get("kind") != "static":
            continue
        address = _uint32(raw.get("address"))
        if address is None:
            issues.append(_issue("violated", "interface_tainted_slot_corrupt", index=index))
            continue
        rejected.add(address)
    return slots, rejected


def _checked_callback_registrations(
    payload: Mapping[str, Any],
    *,
    pe: Mapping[str, Any] | None,
    unit_bindings: Mapping[str, UnitBinding],
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    raw_records = payload.get("callback_registrations") if isinstance(payload, Mapping) else None
    if not isinstance(raw_records, list):
        issues.append(_issue("incomplete", "callback_registration_inventory_missing"))
        return []
    result: list[dict[str, Any]] = []
    seen_sources: dict[tuple[str, int], str] = {}
    for index, raw in enumerate(raw_records):
        local: list[dict[str, Any]] = []
        if not isinstance(raw, Mapping):
            issues.append(_issue("violated", "callback_registration_corrupt", index=index))
            continue
        record = _json_mapping(
            raw, issues, code="callback_registration_corrupt", index=index
        )
        if record is None:
            continue
        if record.get("format") != _CALLBACK_REGISTRATION_FORMAT:
            local.append(_issue("violated", "callback_registration_format_corrupt", index=index))
        if (
            record.get("record_kind") != "callback_registration"
            or record.get("proof_authority") is not False
        ):
            local.append(_issue("violated", "callback_registration_authority_corrupt", index=index))
        unit_id = record.get("unit_id")
        event_index = record.get("event_index")
        normalized_event_index = _uint32(event_index)
        if not isinstance(unit_id, str) or not unit_id or normalized_event_index is None:
            local.append(_issue("violated", "callback_registration_source_corrupt", index=index))
        source_key = (str(unit_id), normalized_event_index if normalized_event_index is not None else -1)
        source_binding = unit_bindings.get(source_key[0])
        instruction_rva = _uint32(record.get("instruction_rva"))
        if source_binding is None:
            local.append(_issue(
                "incomplete",
                "callback_registration_unit_binding_missing",
                index=index,
                unit_id=source_key[0],
            ))
        elif instruction_rva is None:
            local.append(_issue(
                "incomplete",
                "callback_registration_instruction_rva_missing",
                index=index,
            ))
        elif not source_binding.rva_start <= instruction_rva < source_binding.rva_end:
            local.append(_issue(
                "violated",
                "callback_registration_instruction_binding_contradiction",
                index=index,
                instruction_rva=instruction_rva,
                unit_id=source_binding.unit_id,
            ))
        record["_source_unit_binding"] = (
            None if source_binding is None else source_binding.to_payload()
        )
        canonical = _canonical_json(record)
        if source_key in seen_sources:
            local.append(_issue(
                "violated",
                "callback_registration_source_duplicated"
                if seen_sources[source_key] == canonical
                else "callback_registration_source_contradiction",
                unit_id=source_key[0],
                event_index=source_key[1],
            ))
        seen_sources[source_key] = canonical
        if record.get("status") != "complete":
            local.append(_issue("incomplete", "callback_registration_incomplete", index=index))
        elif record.get("failure") is not None:
            local.append(_issue("violated", "callback_registration_status_contradiction", index=index))

        source = record.get("callback_source")
        if not _valid_callback_source(source):
            local.append(_issue("violated", "callback_source_corrupt", index=index))
        try:
            abi = parse_callback_abi(record, context=f"callback registration {index}")
        except StageAInputError:
            abi = None
            local.append(_issue("violated", "callback_abi_corrupt", index=index))
        lifetime = record.get("callback_lifetime")
        if not isinstance(lifetime, (str, Mapping)) or not lifetime:
            local.append(_issue("incomplete", "callback_lifetime_missing", index=index))

        invariant_ids = record.get("global_slot_invariant_ids")
        if invariant_ids is None:
            record["global_slot_invariant_ids"] = []
        elif (
            not isinstance(invariant_ids, list)
            or any(not _global_slot_content_id(item) for item in invariant_ids)
            or invariant_ids != sorted(set(invariant_ids))
        ):
            local.append(_issue(
                "violated",
                "callback_global_invariant_inventory_corrupt",
                index=index,
            ))

        targets = record.get("target_rvas")
        if not isinstance(targets, list) or not targets:
            local.append(_issue("incomplete", "callback_target_inventory_missing", index=index))
            targets = []
        target_values: set[int] = set()
        for item in targets:
            target_value = _uint32(item)
            if target_value not in {None, 0}:
                assert target_value is not None
                target_values.add(target_value)
        normalized_targets = sorted(target_values)
        if len(normalized_targets) != len(targets):
            local.append(_issue("violated", "callback_target_inventory_corrupt", index=index))
        target_unit_ids = record.get("target_unit_ids")
        if (
            not isinstance(target_unit_ids, list)
            or any(not isinstance(value, str) or not value for value in target_unit_ids)
            or len(set(target_unit_ids)) != len(target_unit_ids)
            or len(target_unit_ids) != len(normalized_targets)
        ):
            local.append(_issue("incomplete", "callback_target_unit_binding_incomplete", index=index))

        origins = record.get("origins")
        exact_addresses: set[int] = set()
        if not isinstance(origins, list) or not origins:
            local.append(_issue("incomplete", "callback_target_origins_missing", index=index))
        else:
            for origin in origins:
                value = _exact_origin_value(origin)
                if value is None:
                    local.append(_issue("violated", "callback_target_origin_corrupt", index=index))
                    continue
                if value != 0:
                    exact_addresses.add(value)
        if pe is not None:
            image_base = int(pe["image_base"])
            origin_targets = sorted((value - image_base) & 0xFFFFFFFF for value in exact_addresses)
            if origin_targets != normalized_targets:
                local.append(_issue(
                    "violated",
                    "callback_target_origin_contradiction",
                    index=index,
                    origin_target_rvas=origin_targets,
                    target_rvas=normalized_targets,
                ))
        if abi is not None and not abi.nullable and not exact_addresses:
            local.append(_issue("violated", "callback_nonnullable_target_missing", index=index))

        _check_callback_entry_arguments(record, abi=abi, index=index, issues=local)
        _check_nested_callback(record, abi=abi, index=index, issues=local)
        record["target_rvas"] = normalized_targets
        record["_issues"] = _deduplicate_issues(local)
        record["_checked_status"] = _aggregate_status(record["_issues"])
        record["_canonical"] = canonical
        result.append(record)
        issues.extend(copy.deepcopy(record["_issues"]))
    return result


def _check_callback_entry_arguments(
    record: Mapping[str, Any],
    *,
    abi: Any,
    index: int,
    issues: list[dict[str, Any]],
) -> None:
    raw_arguments = record.get("callback_entry_arguments", [])
    if (
        not isinstance(raw_arguments, list)
        or abi is None
        or len(raw_arguments) > abi.argument_words
    ):
        issues.append(_issue(
            "violated", "callback_entry_argument_inventory_corrupt", index=index
        ))
        return
    protocols = record.get("profile_binding")
    protocol_rows = (
        protocols.get("interface_protocols")
        if isinstance(protocols, Mapping)
        else None
    )
    declared_origins = {
        (
            str(protocol.get("profile_sha256")),
            argument.get("argument_index"),
            str(argument.get("interface_id")),
        )
        for protocol in protocol_rows
        if isinstance(protocol, Mapping)
        and isinstance(protocol.get("profile_sha256"), str)
        for argument in protocol.get("callback_arguments", [])
        if isinstance(argument, Mapping)
        and argument.get("kind") == "interface_object"
        and isinstance(argument.get("interface_id"), str)
    } if isinstance(protocol_rows, list) else set()
    seen: set[int] = set()
    canonical_arguments: list[dict[str, Any]] = []
    for raw in raw_arguments:
        if not isinstance(raw, Mapping) or set(raw) != {"argument_index", "origins"}:
            issues.append(_issue(
                "violated", "callback_entry_argument_corrupt", index=index
            ))
            continue
        argument_index = _uint32(raw.get("argument_index"))
        origins = raw.get("origins")
        if (
            argument_index is None
            or argument_index >= abi.argument_words
            or argument_index in seen
            or not isinstance(origins, list)
            or not 1 <= len(origins) <= MAX_FINITE_ALTERNATIVES
        ):
            issues.append(_issue(
                "violated", "callback_entry_argument_corrupt", index=index
            ))
            continue
        seen.add(argument_index)
        for origin in origins:
            key = origin.get("key") if isinstance(origin, Mapping) else None
            if (
                not isinstance(origin, Mapping)
                or set(origin) != {"kind", "key"}
                or origin.get("kind") != "interface_object"
                or not isinstance(key, list)
                or len(key) != 2
                or not isinstance(key[0], str)
                or not isinstance(key[1], str)
                or not key[1]
                or (key[0], argument_index, key[1]) not in declared_origins
            ):
                issues.append(_issue(
                    "violated",
                    "callback_entry_argument_origin_corrupt",
                    index=index,
                    argument_index=argument_index,
                ))
        canonical_arguments.append({
            "argument_index": argument_index,
            "origins": copy.deepcopy(origins),
        })
    if canonical_arguments != sorted(
        canonical_arguments, key=lambda row: int(row["argument_index"])
    ):
        issues.append(_issue(
            "violated", "callback_entry_argument_order_corrupt", index=index
        ))


def _check_nested_callback(
    record: Mapping[str, Any],
    *,
    abi: Any,
    index: int,
    issues: list[dict[str, Any]],
) -> None:
    behavior = record.get("callback_behavior")
    if behavior is None or behavior == "registration":
        return
    if not isinstance(behavior, Mapping) or abi is None:
        issues.append(_issue("violated", "callback_behavior_corrupt", index=index))
        return
    required = {
        "kind", "provider_relation", "delivery", "activation", "message_argument",
        "message_values", "resource_argument", "instance_binding", "payload_arguments",
    }
    if set(behavior) != required or behavior.get("kind") != "nested_native_callback_v1":
        issues.append(_issue("violated", "callback_behavior_corrupt", index=index))
        return
    raw_payload_arguments = behavior.get("payload_arguments")
    payload_arguments = (
        raw_payload_arguments if isinstance(raw_payload_arguments, list) else [None]
    )
    roles = [
        behavior.get("message_argument"),
        behavior.get("resource_argument"),
        *(
            [behavior.get("instance_binding", {}).get("callback_argument")]
            if isinstance(behavior.get("instance_binding"), Mapping)
            else [None]
        ),
        *payload_arguments,
    ]
    if (
        any(_uint32(value) is None for value in roles)
        or len(set(roles)) != len(roles)
        or set(roles) != set(range(abi.argument_words))
    ):
        issues.append(_issue("violated", "callback_argument_roles_corrupt", index=index))
    activation = behavior.get("activation")
    activation_evidence = record.get("callback_activation")
    if (
        not isinstance(activation, Mapping)
        or not isinstance(activation_evidence, Mapping)
        or activation_evidence.get("status") != "complete"
        or activation_evidence.get("failure") is not None
        or activation_evidence.get("kind") != activation.get("kind")
        or activation_evidence.get("argument_index") != activation.get("argument")
        or activation_evidence.get("mask") != activation.get("mask")
        or activation_evidence.get("expected_value") != activation.get("value")
        or activation_evidence.get("masked_value") != activation.get("value")
    ):
        issues.append(_issue("violated", "callback_activation_contradiction", index=index))
    instance = behavior.get("instance_binding")
    instance_evidence = record.get("callback_instance")
    if (
        not isinstance(instance, Mapping)
        or not isinstance(instance_evidence, Mapping)
        or instance_evidence.get("registration_argument") != instance.get("registration_argument")
        or instance_evidence.get("callback_argument") != instance.get("callback_argument")
        or not isinstance(instance_evidence.get("origins"), list)
        or not instance_evidence.get("origins")
    ):
        issues.append(_issue("violated", "callback_instance_contradiction", index=index))
    elif any(not _valid_origin(origin) for origin in instance_evidence["origins"]):
        issues.append(_issue("violated", "callback_instance_origin_corrupt", index=index))


def _launch_invariants_for_root(
    inventory: Mapping[str, Sequence[Mapping[str, Any]]],
    *,
    root: Mapping[str, Any],
    issues: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    identity = str(root["identity"])
    kind = str(root["kind"])
    present = identity in inventory or kind in inventory
    raw = inventory.get(identity, inventory.get(kind))
    if not present:
        issues.append(_issue(
            "incomplete", "root_launch_invariants_missing", root_identity=identity
        ))
        return []
    if not isinstance(raw, Sequence) or isinstance(raw, (str, bytes)):
        issues.append(_issue(
            "violated", "root_launch_invariants_corrupt", root_identity=identity
        ))
        return []
    result: list[dict[str, Any]] = []
    for index, item in enumerate(raw):
        if not isinstance(item, Mapping) or set(item) not in (
            {"kind", "value"}, {"kind", "value", "source"}
        ):
            issues.append(_issue(
                "violated", "root_launch_invariant_corrupt", root_identity=identity, index=index
            ))
            continue
        if not isinstance(item.get("kind"), str) or not item.get("kind"):
            issues.append(_issue(
                "violated", "root_launch_invariant_corrupt", root_identity=identity, index=index
            ))
            continue
        if item.get("source", "explicit") != "explicit":
            issues.append(_issue(
                "violated", "root_launch_invariant_not_explicit", root_identity=identity, index=index
            ))
            continue
        try:
            value = _json_clone(item.get("value"))
        except (TypeError, ValueError):
            issues.append(_issue(
                "violated", "root_launch_invariant_corrupt", root_identity=identity, index=index
            ))
            continue
        result.append({"kind": item["kind"], "value": value, "source": "explicit"})
    return sorted(result, key=_canonical_json)


def _callback_arguments(registration: Mapping[str, Any]) -> list[dict[str, Any]]:
    abi = registration.get("callback_abi")
    words = abi.get("argument_words") if isinstance(abi, Mapping) else 0
    if not isinstance(words, int) or isinstance(words, bool):
        return []
    behavior = registration.get("callback_behavior")
    roles: dict[int, tuple[str, Any]] = {}
    if isinstance(behavior, Mapping):
        roles[int(behavior["message_argument"])] = (
            "message",
            {"values": copy.deepcopy(behavior["message_values"])},
        )
        roles[int(behavior["resource_argument"])] = (
            "provider_resource",
            {"provider_relation": behavior["provider_relation"]},
        )
        instance = behavior["instance_binding"]
        roles[int(instance["callback_argument"])] = (
            "registered_instance",
            {"registration_argument": instance["registration_argument"]},
        )
        for argument in behavior["payload_arguments"]:
            roles[int(argument)] = ("payload", None)
    typed_arguments = registration.get("callback_entry_arguments")
    if isinstance(typed_arguments, Sequence) and not isinstance(
        typed_arguments, (str, bytes)
    ):
        for raw in typed_arguments:
            if not isinstance(raw, Mapping):
                continue
            argument_index = raw.get("argument_index")
            origins = raw.get("origins")
            if (
                isinstance(argument_index, int)
                and not isinstance(argument_index, bool)
                and 0 <= argument_index < words
                and isinstance(origins, list)
                and origins
            ):
                roles[argument_index] = (
                    "profile_value_origin",
                    {"origins": copy.deepcopy(origins)},
                )
    return [
        {
            "index": index,
            "stack_offset": 4 + index * 4,
            "width": 4,
            "role": roles.get(index, ("abi_argument", None))[0],
            "constraints": roles.get(index, ("abi_argument", None))[1],
        }
        for index in range(words)
    ]


def _captured_resources(registration: Mapping[str, Any]) -> list[dict[str, Any]]:
    behavior = registration.get("callback_behavior")
    if not isinstance(behavior, Mapping):
        return []
    instance = behavior.get("instance_binding")
    evidence = registration.get("callback_instance")
    if not isinstance(instance, Mapping) or not isinstance(evidence, Mapping):
        return []
    return [
        {
            "kind": "registered_instance_capture_v1",
            "registration_argument": instance.get("registration_argument"),
            "callback_argument": instance.get("callback_argument"),
            "origins": copy.deepcopy(evidence.get("origins")),
        }
    ]


def _registration_binding(registration: Mapping[str, Any]) -> dict[str, Any]:
    fields = (
        "format", "unit_id", "event_index", "instruction_rva", "import",
        "contract_id", "profile_binding", "callback_source", "callback_lifetime",
        "source_locations", "origins", "target_rvas", "target_unit_ids",
        "callback_activation", "callback_instance",
        "global_slot_invariant_ids",
    )
    return {
        **{field: copy.deepcopy(registration.get(field)) for field in fields},
        "source_unit_binding": copy.deepcopy(
            registration.get("_source_unit_binding")
        ),
    }


def _legacy_callback_diagnostic(check: Mapping[str, Any]) -> dict[str, Any]:
    """Retain repair evidence without embedding a reusable authority record."""

    proposal = check.get("proposal")
    entry_binding = None
    entry_facts = None
    proposed_content_id = None
    if isinstance(proposal, Mapping):
        entry_binding = copy.deepcopy(proposal.get("binding"))
        proposed_content_id = proposal.get("content_id")
        alternatives = proposal.get("alternatives")
        values = alternatives.get("values") if isinstance(alternatives, Mapping) else None
        if isinstance(values, list) and len(values) == 1:
            entry_facts = copy.deepcopy(values[0])
    return {
        "root": copy.deepcopy(check.get("root")),
        "status": check.get("status"),
        "proof_authority": False,
        "proposed_content_id": proposed_content_id,
        "entry_binding": entry_binding,
        "entry_facts": entry_facts,
        "issues": copy.deepcopy(check.get("issues", [])),
    }


def _root_contract(
    *,
    root: Mapping[str, Any],
    entry: UnitBinding | None,
    entry_facts: Mapping[str, Any],
    issues: Sequence[Mapping[str, Any]],
    entry_event: EventBinding | None = None,
    dependencies: tuple[AuthorityDependency, ...] = (),
) -> dict[str, Any]:
    normalized_issues = _deduplicate_issues(issues)
    if entry is None:
        normalized_issues = _deduplicate_issues([
            *normalized_issues,
            _issue(
                "incomplete",
                "root_unit_binding_missing",
                root_identity=root.get("identity"),
                root_rva=root.get("rva"),
            ),
        ])
        proposal = None
    else:
        alternatives = FiniteAlternatives.of(
            [{"root": _json_clone(dict(root)), **_json_clone(dict(entry_facts))}],
            maximum=1,
        )
        authority_issues = _authority_issues(normalized_issues)
        record = EntryStateContract(
            entry=entry,
            entry_kind=str(root["kind"]),
            alternatives=alternatives,
            entry_event=entry_event,
            dependencies=tuple(sorted(dependencies)),
            issues=authority_issues,
        )
        proposal = record.to_payload()
    return {
        "root": _json_clone(dict(root)),
        "status": (
            _aggregate_status(normalized_issues)
            if proposal is None
            else str(proposal["status"])
        ),
        "proposal": proposal,
        "issues": normalized_issues,
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


def _valid_callback_source(value: Any) -> bool:
    if not isinstance(value, Mapping):
        return False
    kind = value.get("kind")
    argument = _uint32(value.get("argument"))
    if kind == "argument_word":
        return set(value) == {"kind", "argument"} and argument is not None
    if kind == "argument_pointee":
        return (
            set(value) == {"kind", "argument", "offset"}
            and argument is not None
            and _uint32(value.get("offset")) is not None
        )
    return False


def _exact_origin_value(value: Any) -> int | None:
    if not isinstance(value, Mapping) or value.get("kind") != "exact":
        return None
    key = value.get("key")
    if not isinstance(key, list) or len(key) != 1:
        return None
    return _uint32(key[0])


def _valid_origin(value: Any) -> bool:
    return (
        isinstance(value, Mapping)
        and isinstance(value.get("kind"), str)
        and bool(value.get("kind"))
        and isinstance(value.get("key"), list)
    )


def _root_sort_key(contract: Mapping[str, Any]) -> tuple[int, int, str]:
    raw_root = contract.get("root")
    root: Mapping[str, Any] = raw_root if isinstance(raw_root, Mapping) else {}
    kind = str(root.get("kind"))
    order = {
        "pe_entrypoint": 0,
        "pe_export": 1,
        "pe_tls_callback": 2,
        "registered_callback": 3,
    }
    return (order.get(kind, 4), int(root.get("rva") or 0), str(root.get("identity") or ""))


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


def _authority_issues(
    issues: Sequence[Mapping[str, Any]],
) -> tuple[EvidenceIssue, ...]:
    result: set[EvidenceIssue] = set()
    for issue in issues:
        status = issue.get("status")
        code = str(issue.get("code") or "evidence_corrupt")
        details = _canonical_json(issue.get("details", {}))
        if len(details) > 512:
            details = details[:509] + "..."
        kind = (
            EvidenceIssueKind.MISSING
            if status == "incomplete"
            else EvidenceIssueKind.CONTRADICTORY
            if "contradiction" in code
            else EvidenceIssueKind.CORRUPT
        )
        result.add(EvidenceIssue(kind=kind, code=code, detail=details))
    return tuple(
        sorted(result, key=lambda item: (item.kind.value, item.code, item.detail))
    )


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


def _json_mapping(
    value: Mapping[str, Any],
    issues: list[dict[str, Any]],
    *,
    code: str,
    **details: Any,
) -> dict[str, Any] | None:
    try:
        return _json_clone(dict(value))
    except (TypeError, ValueError):
        issues.append(_issue("violated", code, **details))
        return None


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


def _canonical_sha256(value: Any) -> str:
    return sha256(_canonical_json(value).encode("ascii")).hexdigest()


def _uint32(value: Any) -> int | None:
    if (
        not isinstance(value, int)
        or isinstance(value, bool)
        or not 0 <= value <= 0xFFFFFFFF
    ):
        return None
    return value


def _digest(value: Any) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and set(value) <= _HEX
    )


def _global_slot_content_id(value: Any) -> bool:
    prefix = "hybrid-authority-v2:global_slot_invariant:"
    return (
        isinstance(value, str)
        and value.startswith(prefix)
        and _digest(value[len(prefix):])
    )


__all__ = [
    "ENTRY_STATE_ANALYSIS_V2_FORMAT",
    "CALLBACK_ENTRY_STATE_ANALYSIS_V2_FORMAT",
    "ROOT_ENTRY_STATE_CONTRACT_V2_FORMAT",
    "GLOBAL_SLOT_INVARIANT_V2_FORMAT",
    "EntryStateAnalysisV2Error",
    "EvidenceSite",
    "GlobalSlotInvariant",
    "propose_global_slot_invariant",
    "derive_callback_entry_state_contracts_v2",
    "parse_callback_entry_state_contracts_v2",
    "validate_callback_entry_state_contracts_v2",
    "construct_entry_state_analysis_v2",
    "build_entry_state_analysis_v2",
]
