"""Canonical native external-site and termination planning."""

from __future__ import annotations

from dataclasses import replace
from typing import Any, Iterable, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.contracts import CheckedExternalSiteContract
from ..transfer.model import _Call, _Transfer, TransferPlanError
from ..transfer.call_sites import external_tail_call
from .module_runtime_plan import (
    NativeCodeCapabilityBinding,
    NativeCodeCapabilityRegistration,
    NativeCompactCodeCapabilityDomain,
    NativeCompactCodeCapabilityPublication,
    NativeExternalSite,
    NativeGuestDispatchDomain,
    NativeGuestDispatchSite,
    NativeImportBinding,
    NativeTerminationImport,
)
from .runtime_canonical_common import (
    _CallbackCapabilityAuthority,
    _call_key,
    _callback_escape_index,
    _checked_contract,
    _checked_interface_method_contract,
    _environment_import_index,
    _identity_key,
    _indirect_external_index,
    _loader_service_index,
)
from .runtime_canonical_errors import CanonicalRuntimeError

def _external_sites(
    *,
    transfers: Iterable[_Transfer],
    environment: Mapping[str, Any],
    closure: Mapping[str, Any],
    image_base: int,
    environment_sha256: str,
    capability_authority: _CallbackCapabilityAuthority,
    guest_dispatch_domains: tuple[NativeGuestDispatchDomain, ...] = (),
    guest_dispatch_sites: tuple[NativeGuestDispatchSite, ...] = (),
) -> tuple[
    tuple[NativeExternalSite, ...],
    tuple[NativeImportBinding, ...],
    tuple[NativeCodeCapabilityBinding, ...],
    tuple[NativeCodeCapabilityRegistration, ...],
    tuple[NativeCompactCodeCapabilityDomain, ...],
    tuple[NativeCompactCodeCapabilityPublication, ...],
]:
    imports = _environment_import_index(environment)
    loader_services = _loader_service_index(environment)
    indirect = _indirect_external_index(closure)
    escapes = _callback_escape_index(closure)
    domains_by_id = {
        domain.domain_sha256: domain for domain in guest_dispatch_domains
    }
    linked_indirect: dict[
        str, tuple[tuple[str, object, Mapping[str, Any]], ...]
    ] = {}
    linked_indirect_jumps: dict[
        int,
        tuple[
            NativeGuestDispatchSite,
            tuple[tuple[str, object, Mapping[str, Any]], ...],
        ],
    ] = {}
    linked_domain_by_site: dict[str, str] = {}
    for site in guest_dispatch_sites:
        domain = domains_by_id.get(site.domain_sha256)
        if domain is None:
            raise CanonicalRuntimeError(
                "runtime indirect site has no admitted-domain contract"
            )
        members = []
        for raw_target in domain.external_loader_targets:
            identity = raw_target.get("identity")
            if not isinstance(identity, Mapping):
                raise CanonicalRuntimeError(
                    "runtime callable domain has a malformed external identity"
                )
            key = _identity_key(identity)
            members.append(("loader", key, raw_target))
        for raw_target in domain.external_interface_targets:
            method_sha256 = raw_target.get("method_contract_sha256")
            if not isinstance(method_sha256, str):
                raise CanonicalRuntimeError(
                    "runtime callable domain has a malformed interface method"
                )
            members.append(("interface", method_sha256, raw_target))
        canonical_members = tuple(sorted(
            members,
            key=lambda item: (
                item[0], str(item[1]), canonical_sha256_v3(item[2])
            ),
        ))
        linked_domain_by_site[
            f"{site.kind}:{site.source_rva:08x}:"
            f"{site.instruction_rva or 0:08x}:{site.event_index or 0}"
        ] = site.domain_sha256
        if site.kind == "indirect_call":
            linked_indirect[site.site] = canonical_members
        elif site.kind == "indirect_jump":
            if site.source_rva in linked_indirect_jumps:
                raise CanonicalRuntimeError(
                    "runtime indirect-jump source is ambiguous"
                )
            linked_indirect_jumps[site.source_rva] = (site, canonical_members)
        else:
            raise CanonicalRuntimeError(
                "runtime indirect site has an unsupported kind"
            )

    protocol_escape_targets: dict[str, set[int]] = {}
    for (_instruction_rva, protocol_id), escape in escapes.items():
        targets = escape.get("targets")
        if not isinstance(targets, list):
            continue
        protocol_escape_targets.setdefault(protocol_id, set()).update(
            int(target) for target in targets
        )
    interface_callback_protocols: dict[str, Mapping[str, Any]] = {}
    for raw_catalog in environment.get("canonical_boundaries", []):
        if (
            not isinstance(raw_catalog, Mapping)
            or raw_catalog.get("kind") != "checked_interface_callback"
        ):
            continue
        identity = raw_catalog.get("identity")
        callback_sha256 = (
            identity.get("callback_contract_sha256")
            if isinstance(identity, Mapping) else None
        )
        protocol = raw_catalog.get("callback_protocol")
        if (
            not isinstance(callback_sha256, str)
            or not isinstance(protocol, Mapping)
            or callback_sha256 in interface_callback_protocols
        ):
            raise CanonicalRuntimeError(
                "resolved interface callback catalog is malformed or ambiguous"
            )
        interface_callback_protocols[callback_sha256] = protocol
    sites: list[NativeExternalSite] = []
    used_callbacks: list[tuple[_Call, CheckedExternalSiteContract, str]] = []
    used_interface_callbacks: list[
        tuple[_Call, CheckedExternalSiteContract, str, str]
    ] = []
    for transfer in transfers:
        try:
            tail_call = external_tail_call(transfer)
        except TransferPlanError as exc:
            raise CanonicalRuntimeError(str(exc)) from exc
        routed_calls: list[
            tuple[
                _Call,
                bool,
                tuple[
                    tuple[str, object, Mapping[str, Any]], ...
                ] | None,
                str | None,
            ]
        ] = [
            (call, call is tail_call, None, None)
            for call in transfer.calls
        ]
        jump_route = linked_indirect_jumps.get(transfer.rva_start)
        if jump_route is not None:
            jump_site, jump_members = jump_route
            if (
                jump_site.instruction_rva != transfer.rva_start
                or not transfer.actions
                or transfer.actions[-1].op != "outcome_indirect"
                or len(transfer.actions[-1].args) != 1
            ):
                raise CanonicalRuntimeError(
                    "runtime indirect-jump route differs from its transfer"
                )
            routed_calls.append((
                _Call(
                    kind="indirect_call",
                    instruction_rva=transfer.rva_start,
                    call_index=0,
                    target_node=transfer.actions[-1].args[0],
                    target_rva=0,
                    return_rva=0,
                    dll=None,
                    symbol=None,
                    ordinal=None,
                    register_nodes=(),
                    flag_nodes=(),
                    argument_nodes=(),
                    stack_inputs=(),
                ),
                True,
                jump_members,
                jump_site.domain_sha256,
            ))
        for call, forced_tail_jump, forced_members, forced_domain in routed_calls:
            key: tuple[str, str, str | int] | None
            dynamic = call.kind == "indirect_call"
            if call.kind == "external_call":
                key = _call_key(call)
                target_members: tuple[
                    tuple[str, object, Mapping[str, Any] | None], ...
                ] = (("loader", key, None),)
            elif dynamic:
                site_id = f"call:{call.instruction_rva:08x}:{call.call_index}"
                if forced_members is not None:
                    target_members = forced_members
                elif site_id in linked_indirect:
                    target_members = linked_indirect[site_id]
                else:
                    target_members = tuple(
                        ("loader", target_key, None)
                        for target_key in indirect.get(site_id, ())
                    )
                if not target_members:
                    continue
            else:
                continue
            for target_kind, target_key, admitted_member in target_members:
                if target_kind == "interface":
                    if admitted_member is None:
                        raise CanonicalRuntimeError(
                            "interface callthrough has no admitted method contract"
                        )
                    method = admitted_member.get("method")
                    if not isinstance(method, Mapping):
                        raise CanonicalRuntimeError(
                            "interface callthrough has no method contract"
                        )
                    callback_effect = method.get("callback_effect")
                    callback_protocol = None
                    callback_targets: tuple[int, ...] = ()
                    callback_sha256 = None
                    if callback_effect == "explicit":
                        callback_core = {
                            "abi": dict(method.get("callback_abi", {})),
                            "arguments": list(method.get("callback_arguments", [])),
                            "lifetime": method.get("callback_lifetime"),
                            "source": dict(method.get("callback_source", {})),
                        }
                        callback_sha256 = canonical_sha256_v3(callback_core)
                        callback_protocol = interface_callback_protocols.get(
                            callback_sha256
                        )
                        native_publication = (
                            capability_authority.interface_compact.get(
                                str(admitted_member.get(
                                    "method_contract_sha256"
                                ))
                            )
                        )
                        if callback_protocol is None or native_publication is None:
                            raise CanonicalRuntimeError(
                                "interface callback method lacks checked native authority"
                            )
                        native_domain = next(
                            (
                                row for row in capability_authority.compact_runtime.domains
                                if row.identity == native_publication.get("domain_id")
                            ),
                            None,
                        )
                        if native_domain is None:
                            raise CanonicalRuntimeError(
                                "interface callback publication has no native domain"
                            )
                        callback_targets = tuple(
                            row.target_rva for row in native_domain.targets
                        )
                    elif callback_effect != "none":
                        raise CanonicalRuntimeError(
                            "interface callthrough callback effect is malformed"
                        )
                    checked = _checked_interface_method_contract(
                        target=admitted_member,
                        call=call,
                        tail_jump=forced_tail_jump,
                        callback_protocol=callback_protocol,
                        callback_target_rvas=callback_targets,
                    )
                    method_sha256 = admitted_member.get(
                        "method_contract_sha256"
                    )
                    if target_key != method_sha256:
                        raise CanonicalRuntimeError(
                            "interface callthrough member identity is stale"
                        )
                    sites.append(NativeExternalSite(
                        id=len(sites),
                        transfer_id=transfer.identity,
                        event_index=call.call_index,
                        instruction_rva=call.instruction_rva,
                        return_rva=call.return_rva,
                        source_instruction_sha256=(
                            transfer.instruction_bytes_sha256
                        ),
                        # A physical indirect site may admit loader targets,
                        # live-interface methods, and guest capabilities in
                        # one canonical domain.  Target kind belongs to the
                        # checked target contract, not the physical site.
                        site_kind="dynamic_target",
                        dll=None,
                        symbol=None,
                        ordinal=None,
                        disposition=checked.disposition,
                        iat_rva=None,
                        transfer_sha256=transfer.contract_sha256,
                        event_identity_sha256=canonical_sha256_v3({
                            "transfer": transfer.identity,
                            "call": call.call_index,
                            "instruction_rva": call.instruction_rva,
                            "interface_method_sha256": method_sha256,
                        }),
                        abi_metadata_sha256=canonical_sha256_v3(
                            checked.profile_effect_payload()
                        ),
                        target_expression=(
                            None if call.target_node is None else {
                                "kind": "transfer_expression_node",
                                "node": call.target_node,
                            }
                        ),
                        callback_source_kind=(
                            str(checked.callback_adapter.source["kind"])
                            if checked.callback_adapter is not None else None
                        ),
                        callback_argument_index=(
                            int(checked.callback_adapter.source["argument"])
                            if checked.callback_adapter is not None else None
                        ),
                        callback_argument_offset=(
                            checked.argument_base_offset
                            + 4 * int(checked.callback_adapter.source["argument"])
                            if checked.callback_adapter is not None else None
                        ),
                        callback_pointee_offset=(
                            int(checked.callback_adapter.source.get("offset", 0))
                            if checked.callback_adapter is not None else 0
                        ),
                        callback_nullable=(
                            0 in checked.callback_adapter.source.get(
                                "non_callback_sentinel_words", []
                            )
                            if checked.callback_adapter is not None else False
                        ),
                        checked_external_contract=checked,
                        target_resolution_evidence={
                            "kind": "resolved-external-environment-v1",
                            "sha256": environment_sha256,
                            "identity": [
                                str(admitted_member.get("profile_id")),
                                "interface",
                                str(checked.identity.operation),
                            ],
                            "admitted_domain_sha256": (
                                forced_domain
                                or linked_domain_by_site[
                                    "indirect_call:"
                                    f"{transfer.rva_start:08x}:"
                                    f"{call.instruction_rva:08x}:"
                                    f"{call.call_index}"
                                ]
                            ),
                            "admitted_member_sha256": method_sha256,
                        },
                    ))
                    if callback_effect == "explicit":
                        assert callback_protocol is not None
                        used_interface_callbacks.append((
                            call,
                            checked,
                            str(callback_protocol["id"]),
                            str(method_sha256),
                        ))
                    continue
                if target_kind != "loader" or not isinstance(
                    target_key, tuple
                ):
                    raise CanonicalRuntimeError(
                        "runtime callable member kind is unsupported"
                    )
                key = target_key
                row = imports.get(key)
                if row is None:
                    raise CanonicalRuntimeError(
                        f"canonical transfer external call {key!r} has no resolved contract"
                    )
                boundary = row.get("boundary")
                if not isinstance(boundary, Mapping):
                    raise CanonicalRuntimeError(
                        f"resolved semantic import {key!r} has no checked boundary"
                    )
                callback_protocol = boundary.get("callback_protocol")
                checked_escapes = escapes
                if isinstance(callback_protocol, Mapping):
                    protocol_id = str(callback_protocol.get("id"))
                    escape_key = (call.instruction_rva, protocol_id)
                    if escape_key not in checked_escapes:
                        fallback_targets = sorted(
                            protocol_escape_targets.get(protocol_id, ())
                        )
                        if not fallback_targets:
                            raise CanonicalRuntimeError(
                                "admitted external callback target has no checked "
                                "callback capability domain"
                            )
                        checked_escapes = dict(checked_escapes)
                        checked_escapes[escape_key] = {
                            "instruction_rva": call.instruction_rva,
                            "protocol_id": protocol_id,
                            "targets": fallback_targets,
                        }
                checked = _checked_contract(
                    row=row,
                    call=call,
                    escape_index=checked_escapes,
                    tail_jump=forced_tail_jump,
                )
                iat_rva = row.get("iat_rva")
                dynamic_export = row.get("import_kind") == "dynamic_export"
                if dynamic_export:
                    if iat_rva is not None:
                        raise CanonicalRuntimeError(
                            "resolved dynamic export unexpectedly has an IAT RVA"
                        )
                elif (
                    not isinstance(iat_rva, int)
                    or isinstance(iat_rva, bool)
                    or iat_rva <= 0
                ):
                    raise CanonicalRuntimeError(
                        "resolved semantic import has no exact IAT RVA"
                    )
                if admitted_member is not None:
                    frame = boundary.get("physical_call_frame_v3")
                    if (
                        admitted_member.get("iat_rva") != iat_rva
                        or admitted_member.get("import_kind")
                        != row.get("import_kind")
                        or admitted_member.get("contract_sha256")
                        != canonical_sha256_v3(dict(row))
                        or not isinstance(frame, Mapping)
                        or admitted_member.get("physical_frame_id") != frame.get("id")
                        or admitted_member.get("physical_frame_sha256")
                        != canonical_sha256_v3(dict(frame))
                    ):
                        raise CanonicalRuntimeError(
                            "runtime external route differs from its admitted member"
                        )
                adapter = checked.callback_adapter
                callback_source = adapter.source if adapter is not None else None
                sites.append(NativeExternalSite(
                    id=len(sites),
                    transfer_id=transfer.identity,
                    event_index=call.call_index,
                    instruction_rva=call.instruction_rva,
                    return_rva=call.return_rva,
                    source_instruction_sha256=transfer.instruction_bytes_sha256,
                    site_kind="dynamic_target" if dynamic else "direct_import",
                    dll=key[0],
                    symbol=str(key[2]) if key[1] == "symbol" else None,
                    ordinal=int(key[2]) if key[1] == "ordinal" else None,
                    disposition=checked.disposition,
                    iat_rva=iat_rva,
                    transfer_sha256=transfer.contract_sha256,
                    event_identity_sha256=canonical_sha256_v3({
                        "transfer": transfer.identity,
                        "call": call.call_index,
                        "instruction_rva": call.instruction_rva,
                        "identity": list(key),
                    }),
                    abi_metadata_sha256=canonical_sha256_v3(
                        checked.profile_effect_payload()
                    ),
                    target_expression=(
                        None if call.target_node is None else {
                            "kind": "transfer_expression_node",
                            "node": call.target_node,
                        }
                    ),
                    callback_source_kind=(
                        str(callback_source["kind"])
                        if isinstance(callback_source, Mapping) else None
                    ),
                    callback_argument_index=(
                        int(callback_source["argument"])
                        if isinstance(callback_source, Mapping) else None
                    ),
                    callback_argument_offset=(
                        checked.argument_base_offset
                        + 4 * int(callback_source["argument"])
                        if isinstance(callback_source, Mapping) else None
                    ),
                    callback_pointee_offset=(
                        int(callback_source.get("offset", 0))
                        if isinstance(callback_source, Mapping) else 0
                    ),
                    callback_nullable=(
                        0 in callback_source.get("non_callback_sentinel_words", [])
                        if isinstance(callback_source, Mapping) else False
                    ),
                    checked_external_contract=checked,
                    loader_service=loader_services.get(key),
                    target_resolution_evidence={
                        "kind": "resolved-external-environment-v1",
                        "sha256": environment_sha256,
                        "identity": list(key),
                        **({
                            "admitted_domain_sha256": (
                                forced_domain
                                or linked_domain_by_site[
                                    "indirect_call:"
                                    f"{transfer.rva_start:08x}:"
                                    f"{call.instruction_rva:08x}:"
                                    f"{call.call_index}"
                                ]
                            ),
                            "admitted_member_sha256": canonical_sha256_v3(
                                dict(admitted_member)
                            ),
                        } if admitted_member is not None else {}),
                    },
                ))
                if adapter is not None:
                    assert isinstance(callback_protocol, Mapping)
                    used_callbacks.append((
                        call, checked, str(callback_protocol["id"]),
                    ))
    sites.sort(key=lambda item: (item.instruction_rva, item.event_index))
    sites = [replace(item, id=index) for index, item in enumerate(sites)]
    bindings = []
    for key, row in sorted(imports.items()):
        iat_rva = row.get("iat_rva")
        if row.get("import_kind") == "dynamic_export":
            if iat_rva is not None:
                raise CanonicalRuntimeError(
                    "resolved dynamic export unexpectedly has an IAT RVA"
                )
            # A checked dynamic export is part of the common callable catalog,
            # but it is published by its loader-service receipt rather than by
            # a loader-written import slot.
            continue
        if (
            not isinstance(iat_rva, int)
            or isinstance(iat_rva, bool)
            or iat_rva <= 0
        ):
            raise CanonicalRuntimeError(
                f"resolved semantic import {key!r} has no exact IAT RVA"
            )
        bindings.append(NativeImportBinding(
            slot_id=f"iat:{iat_rva:08x}",
            image_id=str(environment.get("bindings", {}).get("module_pe_sha256")),
            descriptor_index=int(row.get("descriptor_index", 0)),
            cell_index=int(row.get("cell_index", 0)),
            dll=key[0],
            symbol=str(key[2]) if key[1] == "symbol" else None,
            ordinal=int(key[2]) if key[1] == "ordinal" else None,
            iat_va=image_base + iat_rva,
            iat_rva=iat_rva,
        ))
    capability_bindings: list[NativeCodeCapabilityBinding] = []
    registrations: list[NativeCodeCapabilityRegistration] = []
    compact_domains: dict[str, NativeCompactCodeCapabilityDomain] = {}
    compact_publications: list[NativeCompactCodeCapabilityPublication] = []
    seen: set[tuple[int, int, int]] = set()
    seen_compact_publications: set[tuple[int, str, str]] = set()
    for call, checked, protocol_id in sorted(
        used_callbacks, key=lambda item: item[0].instruction_rva
    ):
        adapter = checked.callback_adapter
        assert adapter is not None
        source = adapter.source
        argument = int(source["argument"])
        compact_publication = capability_authority.compact.get(
            (call.instruction_rva, protocol_id)
        )
        if compact_publication is None:
            matching_domains = [
                domain
                for domain in capability_authority.compact_runtime.domains
                if domain.protocol_id == protocol_id
                and tuple(target.target_rva for target in domain.targets)
                == adapter.target_rvas
            ]
            if len(matching_domains) == 1:
                domain = matching_domains[0]
                publication_core = {
                    "kind": "admitted-indirect-callback-publication-v2",
                    "domain_id": domain.identity,
                    "instruction_rva": call.instruction_rva,
                    "protocol_id": protocol_id,
                    "checked_external_contract_sha256": canonical_sha256_v3(
                        checked.payload()
                    ),
                }
                compact_publication = {
                    "id": "compact-callback-publication-v2:"
                    + canonical_sha256_v3(publication_core),
                    "domain_id": domain.identity,
                }
        if compact_publication is not None:
            domain_id = str(compact_publication["domain_id"])
            domain = next(
                row for row in capability_authority.compact_runtime.domains
                if row.identity == domain_id
            )
            compact_domains.setdefault(
                domain_id,
                NativeCompactCodeCapabilityDomain(
                    domain_id=domain.identity,
                    protocol_id=domain.protocol_id,
                    target_rvas=tuple(
                        target.target_rva for target in domain.targets
                    ),
                    trampoline_table_symbol=domain.trampoline_table_symbol,
                    trampoline_stride_bytes=domain.trampoline_stride_bytes,
                    flat_first=domain.flat_first,
                ),
            )
            checked_sha256 = canonical_sha256_v3(checked.payload())
            publication_key = (
                call.instruction_rva, protocol_id, checked_sha256,
            )
            if publication_key in seen_compact_publications:
                continue
            seen_compact_publications.add(publication_key)
            compact_publications.append(
                NativeCompactCodeCapabilityPublication(
                    publication_id=str(compact_publication["id"]),
                    domain_id=domain_id,
                    authority_kind="checked_external_site_contract",
                    authority_sha256=checked_sha256,
                    instruction_rva=call.instruction_rva,
                    argument_index=argument,
                    lifetime=adapter.lifetime,
                    invocation=adapter.invocation,
                )
            )
            continue
        for target in adapter.target_rvas:
            key = (call.instruction_rva, argument, target)
            if key in seen:
                raise CanonicalRuntimeError(
                    "canonical callback capability registration is duplicated"
                )
            seen.add(key)
            capability_id = capability_authority.eager.get(
                (call.instruction_rva, protocol_id, target)
            )
            if capability_id is None:
                raise CanonicalRuntimeError(
                    "runtime callback registration lacks exact native capability authority"
                )
            capability_bindings.append(NativeCodeCapabilityBinding(
                id=len(capability_bindings),
                instruction_rva=call.instruction_rva,
                argument_index=argument,
                original_rva=target,
                code_target_rva=target,
                capability_id=capability_id,
            ))
            registrations.append(NativeCodeCapabilityRegistration(
                instruction_rva=call.instruction_rva,
                argument_index=argument,
                logical_target_rva=target,
                code_target_rva=target,
                capability_id=capability_id,
                checked_external_contract_sha256=canonical_sha256_v3(
                    checked.payload()
                ),
                lifetime=adapter.lifetime,
                invocation=adapter.invocation,
            ))
    seen_interface_publications: dict[str, tuple[str, int, Any, str]] = {}
    for call, checked, protocol_id, method_sha256 in sorted(
        used_interface_callbacks,
        key=lambda item: (item[0].instruction_rva, item[3]),
    ):
        adapter = checked.callback_adapter
        assert adapter is not None
        native_publication = capability_authority.interface_compact.get(
            method_sha256
        )
        if native_publication is None:
            raise CanonicalRuntimeError(
                "interface callback method lost its native publication"
            )
        domain_id = str(native_publication["domain_id"])
        domain = next(
            row for row in capability_authority.compact_runtime.domains
            if row.identity == domain_id
        )
        if domain.protocol_id != protocol_id:
            raise CanonicalRuntimeError(
                "interface callback method and native domain disagree"
            )
        compact_domains.setdefault(
            domain_id,
            NativeCompactCodeCapabilityDomain(
                domain_id=domain.identity,
                protocol_id=domain.protocol_id,
                target_rvas=tuple(row.target_rva for row in domain.targets),
                trampoline_table_symbol=domain.trampoline_table_symbol,
                trampoline_stride_bytes=domain.trampoline_stride_bytes,
                flat_first=domain.flat_first,
            ),
        )
        publication_facts = (
            domain_id,
            int(adapter.source["argument"]),
            adapter.lifetime,
            adapter.invocation,
        )
        previous_publication = seen_interface_publications.get(method_sha256)
        if previous_publication is not None:
            if previous_publication != publication_facts:
                raise CanonicalRuntimeError(
                    "interface callback method publication is ambiguous"
                )
            continue
        seen_interface_publications[method_sha256] = publication_facts
        compact_publications.append(
            NativeCompactCodeCapabilityPublication(
                publication_id=str(native_publication["id"]),
                domain_id=domain_id,
                authority_kind="interface_method_contract",
                authority_sha256=method_sha256,
                instruction_rva=0,
                argument_index=int(adapter.source["argument"]),
                lifetime=adapter.lifetime,
                invocation=adapter.invocation,
            )
        )
    return (
        tuple(sites), tuple(bindings), tuple(capability_bindings),
        tuple(registrations),
        tuple(compact_domains[key] for key in sorted(compact_domains)),
        tuple(compact_publications),
    )


def _termination_import(
    *,
    environment: Mapping[str, Any],
    image_base: int,
) -> NativeTerminationImport | None:
    support = environment.get("generated_runtime_support_imports")
    if not isinstance(support, list):
        raise CanonicalRuntimeError("runtime support import inventory is malformed")
    rows = [row for row in support if row.get("support") == "process_termination"]
    if not rows:
        return None
    if len(rows) != 1 or not isinstance(rows[0].get("identity"), Mapping):
        raise CanonicalRuntimeError("process termination support identity is ambiguous")
    key = _identity_key(rows[0]["identity"])
    original = _environment_import_index(environment).get(key)
    if original is None:
        raise CanonicalRuntimeError(
            "process termination support import has no linked IAT realization"
        )
    iat_rva = int(original["iat_rva"])
    return NativeTerminationImport(
        dll=key[0],
        symbol=str(key[2]) if key[1] == "symbol" else None,
        ordinal=int(key[2]) if key[1] == "ordinal" else None,
        iat_va=image_base + iat_rva,
        slot_id=f"iat:{iat_rva:08x}",
    )
