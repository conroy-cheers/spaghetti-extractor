"""Closed V2 classification of semantic holes and analysis frontiers.

The V1 fixed point was intentionally conservative, but exposed every loss of
must-provenance as an execution blocker.  V2 keeps those diagnostics while
separating them from unknown machine semantics.  This module is deliberately
small and closed: a diagnostic is reclassified only when its exact transfer
operation and provider contract can be checked.  All other rows remain
semantic holes.

This is the first migration seam for ``linked-semantic-module-v2``.  It has no
execution-authority API and does not select providers.
"""

from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3


_CLASSIFIABLE_CODES = frozenset({
    "unresolved_callee_effect_instantiation",
    "unresolved_external_memory_write_footprint",
    "unresolved_reachable_indirect_target",
})


def _mapping(value: object, context: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ValueError(f"{context} must be an object")
    return value


def _nonnegative(value: object, context: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{context} must be a nonnegative integer")
    return value


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{context} must be nonempty text")
    return value


def _canonical_rows(rows: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    return sorted(
        {canonical_sha256_v3(dict(row)): dict(row) for row in rows}.values(),
        key=canonical_sha256_v3,
    )


def _site_call_index(site: object, instruction_rva: int) -> int | None:
    if not isinstance(site, str):
        return None
    pieces = site.split(":")
    if len(pieces) != 3 or pieces[0] != "call" or not pieces[2].isdigit():
        return None
    try:
        encoded_instruction = int(pieces[1], 16)
    except ValueError:
        return None
    if encoded_instruction != instruction_rva:
        return None
    return int(pieces[2])


def _transfer_index(
    transfers: Sequence[Mapping[str, Any]],
) -> dict[int, Mapping[str, Any]]:
    result: dict[int, Mapping[str, Any]] = {}
    for raw in transfers:
        row = _mapping(raw, "transfer")
        source = _mapping(row.get("source"), "transfer source")
        rva = _nonnegative(source.get("rva_start"), "transfer source RVA")
        if rva in result:
            raise ValueError("transfer source RVAs are duplicated")
        result[rva] = row
    return result


def _call_at(
    transfer: Mapping[str, Any], call_index: int,
) -> Mapping[str, Any] | None:
    calls = transfer.get("calls")
    if not isinstance(calls, list):
        return None
    matches = [
        row for raw in calls
        for row in (_mapping(raw, "transfer call"),)
        if row.get("id") == call_index
    ]
    return matches[0] if len(matches) == 1 else None


def _external_contract(
    contracts: Sequence[Mapping[str, Any]], *, dll: str, identity: str,
) -> Mapping[str, Any] | None:
    matches = []
    for raw in contracts:
        row = _mapping(raw, "external contract")
        raw_identity = row.get("identity")
        if isinstance(raw_identity, Mapping):
            key = _import_identity_key(raw_identity)
            matches_identity = key == (dll.lower(), identity)
        else:
            matches_identity = (
                isinstance(row.get("dll"), str)
                and str(row["dll"]).lower() == dll.lower()
                and raw_identity == identity
            )
        if matches_identity:
            matches.append(row)
    return matches[0] if len(matches) == 1 else None


def _obligation(
    *, obligation_class: str, subjects: Sequence[str],
    contract: Mapping[str, Any], admitted_domain: Mapping[str, Any],
    evidence_dependencies: Sequence[str],
) -> dict[str, Any]:
    core = {
        "class": obligation_class,
        "subjects": sorted(set(subjects)),
        "semantic_contract_sha256": canonical_sha256_v3(dict(contract)),
        "admitted_domain": dict(admitted_domain),
        "evidence_dependencies": sorted(set(evidence_dependencies)),
        "allowed_provider_kinds": ["qualified_runtime"],
    }
    return {
        "obligation_id": f"residual-obligation-v2:{canonical_sha256_v3(core)}",
        **core,
    }


def _dispatch_domain(
    entry_targets: Sequence[int],
    transfers_by_rva: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    targets = sorted(set(entry_targets))
    if not targets or any(
        not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
        or rva not in transfers_by_rva
        for rva in targets
    ):
        raise ValueError("transfer-entry dispatch domain is malformed")
    core = {
        "kind": "frame_compatible_transfer_entry_rvas",
        "physical_frame": "logical_machine_state_v2",
        "targets": targets,
    }
    return {**core, "domain_sha256": canonical_sha256_v3(core)}


def _callable_domain(
    *, entry_targets: Sequence[int],
    transfers_by_rva: Mapping[int, Mapping[str, Any]],
    external_contracts: Sequence[Mapping[str, Any]],
    interface_method_catalogs: Sequence[Mapping[str, Any]],
    resolved_environment_sha256: str,
) -> dict[str, Any]:
    """Build the finite runtime domain for x86 indirect code dispatch.

    Both an indirect call and an indirect jump may select another guest entry
    or a loader-owned callable address (a tail call is the important latter
    case).  The site contract retains the call-versus-jump disposition; this
    shared domain only states which code identities may be selected.  Runtime
    matching rejects zero or multiple identities and enters an external match
    only through its checked physical frame.  This is deliberately a may
    over-approximation: optional provenance may narrow diagnostics, but cannot
    remove a target from the executable domain.
    """

    _text(resolved_environment_sha256, "resolved-environment identity")
    guest = _dispatch_domain(entry_targets, transfers_by_rva)
    external_targets: list[dict[str, Any]] = []
    identities: set[tuple[str, str]] = set()
    for raw in external_contracts:
        contract = _mapping(raw, "external callable contract")
        identity = contract.get("identity")
        boundary = contract.get("boundary")
        frame = (
            boundary.get("physical_call_frame_v3")
            if isinstance(boundary, Mapping) else None
        )
        key = (
            _import_identity_key(identity)
            if isinstance(identity, Mapping) else None
        )
        if key is None or not isinstance(frame, Mapping):
            raise ValueError("external callable contract has no checked frame")
        frame_id = frame.get("id")
        if not isinstance(frame_id, str) or not frame_id:
            raise ValueError("external callable frame has no stable identity")
        if key in identities:
            raise ValueError("external callable identities are duplicated")
        identities.add(key)
        external_targets.append({
            "identity": dict(identity),
            "import_kind": contract.get("import_kind"),
            "cell_index": contract.get("cell_index"),
            "iat_rva": contract.get("iat_rva"),
            "contract_sha256": canonical_sha256_v3(dict(contract)),
            "physical_frame_id": frame_id,
            "physical_frame_sha256": canonical_sha256_v3(dict(frame)),
        })
    external_targets.sort(key=canonical_sha256_v3)
    interface_targets: list[dict[str, Any]] = []
    interface_keys: set[tuple[str, str, int]] = set()
    for raw_catalog in interface_method_catalogs:
        catalog = _mapping(raw_catalog, "interface-method catalog")
        profile_id = _text(catalog.get("profile_id"), "interface profile ID")
        profile_sha256 = _text(
            catalog.get("profile_sha256"), "interface profile identity"
        )
        interface_id = _text(
            catalog.get("interface_id"), "interface identity"
        )
        methods = catalog.get("methods")
        if (
            len(profile_sha256) != 64
            or any(character not in "0123456789abcdef" for character in profile_sha256)
            or not isinstance(methods, list)
            or not methods
        ):
            raise ValueError("interface-method catalog is malformed")
        for raw_method in methods:
            method = dict(_mapping(raw_method, "interface method"))
            protocol = _mapping(
                method.get("external_protocol"), "interface method protocol"
            )
            slot = protocol.get("slot")
            offset = protocol.get("offset")
            key = (profile_sha256, interface_id, slot)
            if (
                protocol.get("kind") != "pe32-interface-method"
                or protocol.get("profile_id") != profile_id
                or protocol.get("profile_sha256") != profile_sha256
                or protocol.get("interface_id") != interface_id
                or not isinstance(slot, int)
                or isinstance(slot, bool)
                or slot < 0
                or offset != slot * 4
                or key in interface_keys
            ):
                raise ValueError("interface method protocol is stale or duplicated")
            interface_keys.add(key)
            core = {
                "profile_id": profile_id,
                "profile_sha256": profile_sha256,
                "interface_id": interface_id,
                "method": method,
            }
            interface_targets.append({
                **core,
                "method_contract_sha256": canonical_sha256_v3(core),
            })
    interface_targets.sort(key=canonical_sha256_v3)
    core = {
        "kind": "checked_indirect_callable_targets_v3",
        "logical_guest_frame": "logical_machine_state_v2",
        "resolved_environment_sha256": resolved_environment_sha256,
        "guest_transfer_entry_rvas": list(guest["targets"]),
        "external_loader_targets": external_targets,
        "external_interface_targets": interface_targets,
        "selection": {
            "guest": "active_code_capability_address",
            "external": "checked_loader_code_capability",
            "interface": "live_factory_interface_vtable_method_capability",
            "ambiguity": "reject",
            "no_match": "reject",
        },
    }
    return {**core, "domain_sha256": canonical_sha256_v3(core)}


def _domain_reference(domain: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "kind": "catalog_reference",
        "domain_sha256": str(domain["domain_sha256"]),
    }


def _import_identity_key(value: Mapping[str, Any]) -> tuple[str, str] | None:
    dll = value.get("dll")
    symbol = value.get("symbol")
    ordinal = value.get("ordinal")
    if not isinstance(dll, str) or not dll:
        return None
    if isinstance(symbol, str) and symbol:
        return dll.lower(), symbol
    if isinstance(ordinal, int) and not isinstance(ordinal, bool) and ordinal >= 0:
        return dll.lower(), f"ordinal:{ordinal}"
    return None


def _callback_domain(
    *, protocol: Mapping[str, Any], entry_targets: Sequence[int],
    transfers_by_rva: Mapping[int, Mapping[str, Any]],
) -> dict[str, Any]:
    targets = sorted(set(entry_targets))
    if not targets or any(
        not isinstance(rva, int) or isinstance(rva, bool) or rva < 0
        or rva not in transfers_by_rva
        for rva in targets
    ):
        raise ValueError("callback transfer-entry domain is malformed")
    signature = protocol.get("signature")
    if not isinstance(signature, Mapping):
        raise ValueError("callback protocol has no physical signature")
    protocol_sha256 = canonical_sha256_v3(dict(protocol))
    core = {
        "kind": "checked_callback_transfer_entry_rvas",
        "protocol_id": str(protocol["id"]),
        "protocol_sha256": protocol_sha256,
        "physical_signature_sha256": canonical_sha256_v3(dict(signature)),
        "targets": targets,
    }
    return {**core, "domain_sha256": canonical_sha256_v3(core)}


def _callback_contract_problem(
    *, code: str, transfer: Mapping[str, Any], call: Mapping[str, Any],
    contract: Mapping[str, Any] | None,
) -> dict[str, Any]:
    return {
        "code": code,
        "source_rva": _mapping(transfer.get("source"), "transfer source").get(
            "rva_start"
        ),
        "transfer_id": transfer.get("identity"),
        "call_id": call.get("id"),
        "instruction_rva": call.get("instruction_rva"),
        "external_identity": {
            key: call.get(key) for key in ("dll", "symbol", "ordinal")
        },
        "external_contract_sha256": (
            None if contract is None
            else canonical_sha256_v3(dict(contract))
        ),
    }


def _frontier(
    *, frontier_class: str, blocker: Mapping[str, Any],
    obligation_id: str,
) -> dict[str, Any]:
    diagnostic_sha256 = canonical_sha256_v3(dict(blocker))
    core = {
        "class": frontier_class,
        "subject": f"fixed-point-diagnostic:{diagnostic_sha256}",
        "diagnostic_sha256": diagnostic_sha256,
        "obligation_ids": [obligation_id],
    }
    return {
        "frontier_id": f"analysis-frontier-v2:{canonical_sha256_v3(core)}",
        **core,
    }


def _hole(blocker: Mapping[str, Any], *, origin: str) -> dict[str, Any]:
    evidence_sha256 = canonical_sha256_v3(dict(blocker))
    core = {
        "code": str(blocker.get("code", "unknown_semantic_blocker")),
        "subject": f"{origin}:{evidence_sha256}",
        "evidence_sha256": evidence_sha256,
    }
    return {
        "hole_id": f"semantic-hole-v2:{canonical_sha256_v3(core)}",
        **core,
    }


def _classify_one(
    blocker: Mapping[str, Any], *,
    transfers_by_rva: Mapping[int, Mapping[str, Any]],
    callable_domain: Mapping[str, Any],
    external_contracts: Sequence[Mapping[str, Any]],
    transfer_plan_sha256: str,
) -> tuple[dict[str, Any], dict[str, Any]] | None:
    code = blocker.get("code")
    if code not in _CLASSIFIABLE_CODES:
        return None
    source_rva = blocker.get("source_rva")
    if not isinstance(source_rva, int) or isinstance(source_rva, bool):
        return None
    transfer = transfers_by_rva.get(source_rva)
    if transfer is None:
        return None
    transfer_id = transfer.get("identity")
    if not isinstance(transfer_id, str) or not transfer_id:
        return None

    evidence = [f"executable-transfer-plan-v2:{transfer_plan_sha256}"]
    if (
        code == "unresolved_reachable_indirect_target"
        and blocker.get("site") == "terminator"
    ):
        terminator = transfer.get("terminator")
        if not isinstance(terminator, Mapping):
            return None
        operands = terminator.get("operands")
        if (
            terminator.get("op") != "outcome_indirect"
            or not isinstance(operands, list) or len(operands) != 1
            or not isinstance(operands[0], int) or isinstance(operands[0], bool)
        ):
            return None
        obligation = _obligation(
            obligation_class="internal_code_dispatch",
            subjects=[f"{transfer_id}:terminator"],
            contract={
                "kind": "logical_machine_state_indirect_dispatch_v2",
                "terminator": dict(terminator),
                "target_expression_node": operands[0],
            },
            admitted_domain=_domain_reference(callable_domain),
            evidence_dependencies=[
                *evidence,
                "resolved-external-environment-v1:"
                + str(callable_domain["resolved_environment_sha256"]),
            ],
        )
        return obligation, _frontier(
            frontier_class="code_target_provenance",
            blocker=blocker,
            obligation_id=obligation["obligation_id"],
        )

    call_index = blocker.get("call_index")
    instruction_rva = blocker.get("instruction_rva")
    if code == "unresolved_reachable_indirect_target":
        site = blocker.get("site")
        if not isinstance(site, str):
            return None
        pieces = site.split(":")
        if len(pieces) != 3:
            return None
        try:
            instruction_rva = int(pieces[1], 16)
        except ValueError:
            return None
        call_index = _site_call_index(site, instruction_rva)
    if (
        not isinstance(call_index, int) or isinstance(call_index, bool)
        or not isinstance(instruction_rva, int) or isinstance(instruction_rva, bool)
    ):
        return None
    call = _call_at(transfer, call_index)
    if call is None or call.get("instruction_rva") != instruction_rva:
        return None

    subject = f"{transfer_id}:call:{call_index}"
    if code == "unresolved_callee_effect_instantiation":
        callee_rva = blocker.get("callee_function_rva")
        if (
            call.get("kind") != "internal_call"
            or not isinstance(callee_rva, int) or isinstance(callee_rva, bool)
            or call.get("target_rva") != callee_rva
            or callee_rva not in transfers_by_rva
        ):
            return None
        obligation = _obligation(
            obligation_class="object_reference_resolution",
            subjects=[subject, str(transfers_by_rva[callee_rva]["identity"])],
            contract={
                "kind": "direct_internal_call_runtime_reference_binding_v2",
                "caller_transfer": transfer_id,
                "callee_transfer": transfers_by_rva[callee_rva]["identity"],
                "call": dict(call),
            },
            admitted_domain={
                "kind": "checked_runtime_reference_values",
                "callee_rva": callee_rva,
            },
            evidence_dependencies=evidence,
        )
        return obligation, _frontier(
            frontier_class="callee_summary_binding",
            blocker=blocker,
            obligation_id=obligation["obligation_id"],
        )

    if code == "unresolved_external_memory_write_footprint":
        dll, identity = call.get("dll"), call.get("symbol")
        if identity is None and isinstance(call.get("ordinal"), int):
            identity = f"ordinal:{call['ordinal']}"
        if (
            call.get("kind") != "external_call"
            or not isinstance(dll, str) or not dll
            or not isinstance(identity, str) or not identity
        ):
            return None
        contract = _external_contract(
            external_contracts, dll=dll, identity=identity
        )
        targets = blocker.get("external_targets")
        if contract is None or not isinstance(targets, list) or not targets:
            return None
        if any(
            not isinstance(raw, Mapping)
            or str(raw.get("dll", "")).lower() != dll.lower()
            or raw.get("identity") != identity
            for raw in targets
        ):
            return None
        obligation = _obligation(
            obligation_class="external_write_validation",
            subjects=[subject],
            contract={
                "kind": "checked_external_write_transaction_v2",
                "call": dict(call),
                "external_contract": dict(contract),
            },
            admitted_domain={
                "kind": "runtime_checked_object_ranges",
                "permissions": ["write"],
            },
            evidence_dependencies=[
                *evidence,
                f"external-contract:{canonical_sha256_v3(dict(contract))}",
            ],
        )
        return obligation, _frontier(
            frontier_class="write_boundary_provenance",
            blocker=blocker,
            obligation_id=obligation["obligation_id"],
        )

    if call.get("kind") != "indirect_call" or call.get("target_node") is None:
        return None
    obligation = _obligation(
        obligation_class="indirect_external_callthrough",
        subjects=[subject],
        contract={
            "kind": "checked_indirect_callable_dispatch_v2",
            "call": dict(call),
            "target_expression_node": call["target_node"],
        },
        admitted_domain=_domain_reference(callable_domain),
        evidence_dependencies=[
            *evidence,
            "resolved-external-environment-v1:"
            + str(callable_domain["resolved_environment_sha256"]),
        ],
    )
    return obligation, _frontier(
        frontier_class="code_target_provenance",
        blocker=blocker,
        obligation_id=obligation["obligation_id"],
    )


def classify_semantic_frontiers_v2(
    *, fixed_point_blockers: Sequence[Mapping[str, Any]],
    linked_blockers: Sequence[Mapping[str, Any]],
    transfers: Sequence[Mapping[str, Any]], entry_targets: Sequence[int],
    external_contracts: Sequence[Mapping[str, Any]],
    interface_method_catalogs: Sequence[Mapping[str, Any]] = (),
    transfer_plan_sha256: str, resolved_environment_sha256: str,
) -> dict[str, list[dict[str, Any]]]:
    """Classify exact V1 diagnostics for the V2 semantic-module compiler.

    ``linked_blockers`` includes the fixed-point rows in V1.  Matching is by
    canonical content and multiplicity so a same-code linker blocker cannot be
    accidentally discharged.  Invalid or unknown rows are retained as holes.
    """

    _text(transfer_plan_sha256, "transfer-plan identity")
    transfers_by_rva = _transfer_index(transfers)
    callable_domain = _callable_domain(
        entry_targets=entry_targets,
        transfers_by_rva=transfers_by_rva,
        external_contracts=external_contracts,
        interface_method_catalogs=interface_method_catalogs,
        resolved_environment_sha256=resolved_environment_sha256,
    )
    fixed_counts = Counter(
        canonical_sha256_v3(dict(_mapping(row, "fixed-point blocker")))
        for row in fixed_point_blockers
    )
    non_fixed: list[Mapping[str, Any]] = []
    for raw in linked_blockers:
        row = _mapping(raw, "linked blocker")
        digest = canonical_sha256_v3(dict(row))
        if fixed_counts[digest]:
            fixed_counts[digest] -= 1
        else:
            non_fixed.append(row)

    holes = [_hole(row, origin="linked-blocker") for row in non_fixed]
    obligations: list[dict[str, Any]] = []
    frontiers: list[dict[str, Any]] = []
    for raw in fixed_point_blockers:
        blocker = _mapping(raw, "fixed-point blocker")
        classified = _classify_one(
            blocker,
            transfers_by_rva=transfers_by_rva,
            callable_domain=callable_domain,
            external_contracts=external_contracts,
            transfer_plan_sha256=transfer_plan_sha256,
        )
        if classified is None:
            holes.append(_hole(blocker, origin="fixed-point-blocker"))
            continue
        obligation, frontier = classified
        obligations.append(obligation)
        frontiers.append(frontier)

    referenced_domains = {
        str(row["admitted_domain"].get("domain_sha256"))
        for row in obligations
        if row["admitted_domain"].get("kind") == "catalog_reference"
    }
    admitted_domains = [
        domain for domain in (callable_domain,)
        if domain["domain_sha256"] in referenced_domains
    ]
    return {
        "semantic_holes": _canonical_rows(holes),
        "residual_obligations": _canonical_rows(obligations),
        "analysis_frontiers": _canonical_rows(frontiers),
        "admitted_domains": admitted_domains,
    }


def derive_internal_dispatch_obligations_v2(
    *, transfers: Sequence[Mapping[str, Any]], entry_targets: Sequence[int],
    active_transfer_ids: Sequence[str], transfer_plan_sha256: str,
    machine_import_contracts: Sequence[Mapping[str, Any]],
    interface_method_catalogs: Sequence[Mapping[str, Any]] = (),
    resolved_environment_sha256: str,
) -> dict[str, list[dict[str, Any]]]:
    """Inventory every dynamic-call or guest-dispatch site in the may universe.

    Unlike :func:`classify_semantic_frontiers_v2`, this is not driven by an
    optional fixed-point diagnostic.  Once a transfer is admitted by may
    reachability, each indirect call or outcome needs a runtime obligation
    even when must-analysis never visited the transfer.
    """

    transfers_by_rva = _transfer_index(transfers)
    callable_domain = _callable_domain(
        entry_targets=entry_targets,
        transfers_by_rva=transfers_by_rva,
        external_contracts=machine_import_contracts,
        interface_method_catalogs=interface_method_catalogs,
        resolved_environment_sha256=resolved_environment_sha256,
    )
    active = set(active_transfer_ids)
    known_ids = {
        str(row.get("identity")) for row in transfers_by_rva.values()
    }
    if not active <= known_ids:
        raise ValueError("active transfer inventory names an unknown transfer")
    transfer_evidence = [
        f"executable-transfer-plan-v2:{transfer_plan_sha256}"
    ]
    call_evidence = sorted({
        *transfer_evidence,
        f"resolved-external-environment-v1:{resolved_environment_sha256}",
    })
    obligations = []
    effects = []
    for rva in sorted(transfers_by_rva):
        transfer = transfers_by_rva[rva]
        transfer_id = str(transfer["identity"])
        if transfer_id not in active:
            continue
        calls = transfer.get("calls")
        if not isinstance(calls, list):
            raise ValueError("transfer calls must be an array")
        for raw in calls:
            call = _mapping(raw, "transfer call")
            if call.get("kind") != "indirect_call":
                continue
            call_id = call.get("id")
            target_node = call.get("target_node")
            if (
                not isinstance(call_id, int) or isinstance(call_id, bool)
                or not isinstance(target_node, int) or isinstance(target_node, bool)
            ):
                raise ValueError("indirect call has no exact target expression")
            semantic_contract = {
                "kind": "checked_indirect_callable_dispatch_v2",
                "call": dict(call),
                "target_expression_node": target_node,
            }
            obligation = _obligation(
                obligation_class="indirect_external_callthrough",
                subjects=[f"{transfer_id}:call:{call_id}"],
                contract=semantic_contract,
                admitted_domain=_domain_reference(callable_domain),
                evidence_dependencies=call_evidence,
            )
            obligations.append(obligation)
            effect = {
                "kind": "checked_indirect_callable_dispatch_v2",
                "source_symbol_id": f"original:function:{transfer_id}",
                "source_transfer_id": transfer_id,
                "site_kind": "call",
                "call_id": call_id,
                "instruction_rva": call.get("instruction_rva"),
                "semantic_contract": semantic_contract,
                "admitted_domain": _domain_reference(callable_domain),
                "obligation_id": obligation["obligation_id"],
            }
            effects.append({
                "effect_id": (
                    "indirect-callable-effect-v2:"
                    + canonical_sha256_v3(effect)
                ),
                **effect,
            })
        terminator = transfer.get("terminator")
        if not isinstance(terminator, Mapping):
            raise ValueError("transfer terminator must be an object")
        if terminator.get("op") != "outcome_indirect":
            continue
        operands = terminator.get("operands")
        if (
            not isinstance(operands, list) or len(operands) != 1
            or not isinstance(operands[0], int) or isinstance(operands[0], bool)
        ):
            raise ValueError("indirect outcome has no exact target expression")
        semantic_contract = {
            "kind": "logical_machine_state_indirect_dispatch_v2",
            "terminator": dict(terminator),
            "target_expression_node": operands[0],
        }
        obligation = _obligation(
            obligation_class="internal_code_dispatch",
            subjects=[f"{transfer_id}:terminator"],
            contract=semantic_contract,
            admitted_domain=_domain_reference(callable_domain),
            evidence_dependencies=call_evidence,
        )
        obligations.append(obligation)
        effect = {
            "kind": "logical_machine_state_indirect_dispatch_v2",
            "source_symbol_id": f"original:function:{transfer_id}",
            "source_transfer_id": transfer_id,
            "site_kind": "terminator",
            "call_id": None,
            "instruction_rva": rva,
            "semantic_contract": semantic_contract,
            "admitted_domain": _domain_reference(callable_domain),
            "obligation_id": obligation["obligation_id"],
        }
        effects.append({
            "effect_id": (
                "internal-dispatch-effect-v2:"
                + canonical_sha256_v3(effect)
            ),
            **effect,
        })
    return {
        "residual_obligations": _canonical_rows(obligations),
        "admitted_domains": [
            item for item in (callable_domain,)
            if any(
                row["admitted_domain"].get("domain_sha256")
                == item["domain_sha256"]
                for row in obligations
            )
        ],
        "effects": sorted(effects, key=lambda row: str(row["effect_id"])),
    }


def derive_callback_capability_obligations_v2(
    *, transfers: Sequence[Mapping[str, Any]], entry_targets: Sequence[int],
    active_transfer_ids: Sequence[str],
    machine_import_contracts: Sequence[Mapping[str, Any]],
    transfer_plan_sha256: str, resolved_environment_sha256: str,
) -> dict[str, list[dict[str, Any]]]:
    """Inventory every checked callback-publication site in the may universe.

    This derivation deliberately does not ask the optional provenance fixed
    point for a callback value.  The checked callback protocol identifies the
    physical argument location and its sentinels.  At runtime the selected
    provider must either observe a declared sentinel or publish a capability
    whose logical target belongs to the finite protocol-specific domain.

    Therefore a callback site remains executable when its exact target is not
    statically known, but it can never silently disappear from the runtime
    plan.  A malformed explicit callback contract is a semantic hole rather
    than an analysis frontier.
    """

    _text(transfer_plan_sha256, "transfer-plan identity")
    _text(resolved_environment_sha256, "resolved-environment identity")
    transfers_by_rva = _transfer_index(transfers)
    active = set(active_transfer_ids)
    known_ids = {
        str(row.get("identity")) for row in transfers_by_rva.values()
    }
    if not active <= known_ids:
        raise ValueError("active callback inventory names an unknown transfer")

    contracts: dict[tuple[str, str], Mapping[str, Any]] = {}
    explicit_keys: set[tuple[str, str]] = set()
    for raw in machine_import_contracts:
        contract = _mapping(raw, "machine-import contract")
        identity = contract.get("identity")
        key = (
            _import_identity_key(identity)
            if isinstance(identity, Mapping) else None
        )
        if key is None:
            raise ValueError("machine-import contract identity is malformed")
        if key in contracts:
            raise ValueError("machine-import contract identity is duplicated")
        contracts[key] = contract
        material = contract.get("contract")
        payload = (
            material.get("payload")
            if isinstance(material, Mapping) else None
        )
        if (
            isinstance(payload, Mapping)
            and payload.get("callback_effect") == "explicit"
        ):
            explicit_keys.add(key)

    obligations: list[dict[str, Any]] = []
    effects: list[dict[str, Any]] = []
    domains: dict[str, dict[str, Any]] = {}
    holes: list[dict[str, Any]] = []
    evidence = [
        f"executable-transfer-plan-v2:{transfer_plan_sha256}",
        f"resolved-external-environment-v1:{resolved_environment_sha256}",
    ]
    for rva in sorted(transfers_by_rva):
        transfer = transfers_by_rva[rva]
        transfer_id = str(transfer["identity"])
        if transfer_id not in active:
            continue
        calls = transfer.get("calls")
        if not isinstance(calls, list):
            raise ValueError("transfer calls must be an array")
        for raw_call in calls:
            call = _mapping(raw_call, "transfer call")
            if call.get("kind") != "external_call":
                continue
            key = _import_identity_key(call)
            if key not in explicit_keys:
                continue
            contract = contracts[key]
            material = _mapping(
                contract.get("contract"), "callback machine contract"
            )
            payload = _mapping(
                material.get("payload"), "callback contract payload"
            )
            boundary = contract.get("boundary")
            protocol = (
                boundary.get("callback_protocol")
                if isinstance(boundary, Mapping) else None
            )
            payload_protocol = payload.get("callback_protocol")
            source = (
                protocol.get("source")
                if isinstance(protocol, Mapping) else None
            )
            lifetime = (
                protocol.get("lifetime")
                if isinstance(protocol, Mapping) else None
            )
            lifetime_kind = (
                lifetime.get("kind")
                if isinstance(lifetime, Mapping) else None
            )
            lifetime_end_event = (
                lifetime.get("end_event")
                if isinstance(lifetime, Mapping) else None
            )
            delivery = (
                protocol.get("delivery")
                if isinstance(protocol, Mapping) else None
            )
            instance = (
                protocol.get("instance")
                if isinstance(protocol, Mapping) else None
            )
            sentinels = (
                source.get("sentinels") if isinstance(source, Mapping) else None
            )
            argument = (
                source.get("argument") if isinstance(source, Mapping) else None
            )
            call_id = call.get("id")
            instruction_rva = call.get("instruction_rva")
            malformed = (
                not isinstance(protocol, Mapping)
                or not isinstance(payload_protocol, Mapping)
                or dict(protocol) != dict(payload_protocol)
                or not isinstance(protocol.get("id"), str)
                or not protocol.get("id")
                or not isinstance(protocol.get("action"), str)
                or not isinstance(protocol.get("signature"), Mapping)
                or not isinstance(source, Mapping)
                or source.get("kind") not in {
                    "argument_word", "argument_pointee",
                }
                or not isinstance(argument, int) or isinstance(argument, bool)
                or argument < 0
                or not isinstance(sentinels, list)
                or any(
                    not isinstance(item, Mapping)
                    or not isinstance(item.get("word"), int)
                    or isinstance(item.get("word"), bool)
                    for item in sentinels
                )
                or not isinstance(lifetime, Mapping)
                or not isinstance(lifetime_kind, str)
                or not lifetime_kind
                or (
                    lifetime_kind == "until_resource_event_or_process_exit"
                    and (
                        not isinstance(lifetime_end_event, str)
                        or not lifetime_end_event
                    )
                )
                or (
                    lifetime_kind != "until_resource_event_or_process_exit"
                    and lifetime_end_event is not None
                )
                or not isinstance(delivery, Mapping)
                or not isinstance(delivery.get("thread"), str)
                or not isinstance(delivery.get("timing"), str)
                or not isinstance(instance, Mapping)
                or not isinstance(instance.get("kind"), str)
                or not isinstance(call_id, int) or isinstance(call_id, bool)
                or not isinstance(instruction_rva, int)
                or isinstance(instruction_rva, bool)
            )
            if malformed:
                problem = _callback_contract_problem(
                    code="callback_capability_protocol_incomplete",
                    transfer=transfer, call=call, contract=contract,
                )
                holes.append(_hole(problem, origin="callback-site"))
                continue
            try:
                domain = _callback_domain(
                    protocol=protocol,
                    entry_targets=entry_targets,
                    transfers_by_rva=transfers_by_rva,
                )
            except (KeyError, TypeError, ValueError):
                problem = _callback_contract_problem(
                    code="callback_capability_domain_incompatible",
                    transfer=transfer, call=call, contract=contract,
                )
                holes.append(_hole(problem, origin="callback-site"))
                continue
            domain_id = str(domain["domain_sha256"])
            domains[domain_id] = domain
            direct_node: int | None = None
            argument_nodes = call.get("argument_nodes")
            if (
                isinstance(argument_nodes, list)
                and argument < len(argument_nodes)
                and isinstance(argument_nodes[argument], int)
                and not isinstance(argument_nodes[argument], bool)
            ):
                direct_node = int(argument_nodes[argument])
            if direct_node is None and source.get("kind") == "argument_word":
                matches = [
                    row for row in call.get("stack_inputs", [])
                    if isinstance(row, list) and len(row) == 3
                    and row[0] == argument * 4 and row[1] == 4
                    and isinstance(row[2], int) and not isinstance(row[2], bool)
                ]
                if len(matches) == 1:
                    direct_node = int(matches[0][2])
            contract_sha256 = canonical_sha256_v3(dict(contract))
            protocol_sha256 = canonical_sha256_v3(dict(protocol))
            subject = f"{transfer_id}:call:{call_id}"
            effect_core = {
                "kind": "checked_callback_capability_publication_v2",
                "source_symbol_id": f"original:function:{transfer_id}",
                "source_transfer_id": transfer_id,
                "call_id": call_id,
                "instruction_rva": instruction_rva,
                "external_identity": {
                    "dll": str(call["dll"]).lower(),
                    "symbol": call.get("symbol"),
                    "ordinal": call.get("ordinal"),
                },
                "external_contract_sha256": contract_sha256,
                "callback_protocol_id": str(protocol["id"]),
                "callback_protocol_sha256": protocol_sha256,
                "callback_source": {
                    **dict(source),
                    "direct_expression_node": direct_node,
                },
                "action": str(protocol["action"]),
                # The end event is part of capability authority, not merely
                # profile documentation.  Dropping it here made a checked
                # resource-scoped lifetime impossible to realize once the
                # compact callback runtime finally consumed the effect.
                "lifetime": (
                    str(lifetime_kind)
                    if lifetime_end_event is None else
                    f"{lifetime_kind}:{lifetime_end_event}"
                ),
                "delivery": dict(delivery),
                "instance": dict(instance),
                "admitted_domain": _domain_reference(domain),
            }
            obligation = _obligation(
                obligation_class="callback_capability_publication",
                subjects=[subject],
                contract=effect_core,
                admitted_domain=_domain_reference(domain),
                evidence_dependencies=[
                    *evidence,
                    f"external-contract:{contract_sha256}",
                ],
            )
            obligations.append(obligation)
            effect = {
                **effect_core,
                "obligation_id": obligation["obligation_id"],
            }
            effects.append({
                "effect_id": (
                    "callback-publication-effect-v2:"
                    + canonical_sha256_v3(effect)
                ),
                **effect,
            })
    return {
        "residual_obligations": _canonical_rows(obligations),
        "admitted_domains": sorted(
            domains.values(), key=lambda row: str(row["domain_sha256"])
        ),
        "semantic_holes": _canonical_rows(holes),
        "effects": sorted(effects, key=lambda row: str(row["effect_id"])),
    }


__all__ = [
    "classify_semantic_frontiers_v2",
    "derive_callback_capability_obligations_v2",
    "derive_internal_dispatch_obligations_v2",
]
