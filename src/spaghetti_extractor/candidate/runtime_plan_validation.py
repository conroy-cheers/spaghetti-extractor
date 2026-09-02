"""Canonical module-runtime plan and external-contract validation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .formats import MODULE_RUNTIME_PLAN_FORMAT
from .module_runtime_plan import _canonical_sha256
from .runtime_model import (
    NativeGuestDispatchDomain,
    NativeGuestDispatchSite,
    NativeImplementationDispatch,
    CandidateRuntimeError,
    _TransferBinding,
)
from .runtime_receipts import (
    _validate_implementation_dispatch_receipt,
)
from ..calls.frame import PhysicalCallFrameV2
from ..external.service_protocols import (
    CheckedExternalServiceProtocolError,
    parse_checked_external_service_protocol_v1,
)
from .runtime_values import (
    _required_count,
    _required_list,
    _required_object,
    _required_sha256,
    _required_string,
    _required_u32,
)


_EXTERNAL_TARGET_CONTRACT_FIELDS = {
    "target_contract_id",
    "abi_metadata_sha256",
    "callback_registration",
    "checked_external_contract",
    "checked_external_contract_sha256",
    "target_resolution_evidence",
    "loader_service",
    "iat_rva",
    "import",
}
_NORMALIZED_EXTERNAL_SITE_FIELDS = {
    "id",
    "transfer_id",
    "event_index",
    "instruction_rva",
    "return_rva",
    "source_encoding_sha256",
    "target_expression",
    "disposition",
    "transfer_sha256",
    "continuation_evidence",
    "site_kind",
    "checked_domain_sha256",
    "site_identity_sha256",
}


@dataclass(frozen=True)
class ValidatedExternalInventoryV8:
    """Validated in-memory view of the canonical V8 catalog and domains."""

    target_contracts: Mapping[str, Mapping[str, Any]]
    contract_domains: Mapping[str, tuple[str, ...]]
    sites: tuple[Mapping[str, Any], ...]

    @property
    def target_pair_count(self) -> int:
        return sum(
            len(self.contract_domains[str(site["checked_domain_sha256"])])
            for site in self.sites
        )

    def iter_site_targets(
        self,
        *,
        only_target_ids: frozenset[str] | None = None,
    ) -> Iterator[tuple[int, Mapping[str, Any], str, Mapping[str, Any]]]:
        selected_domains = (
            self.contract_domains
            if only_target_ids is None
            else {
                identity: tuple(
                    member for member in members
                    if member in only_target_ids
                )
                for identity, members in self.contract_domains.items()
            }
        )
        for site_index, site in enumerate(self.sites):
            for member in selected_domains[
                str(site["checked_domain_sha256"])
            ]:
                yield site_index, site, member, self.target_contracts[member]

    def expanded_sites(self) -> Iterator[dict[str, Any]]:
        for _site_index, site, _member, target in self.iter_site_targets():
            common = {
                key: value for key, value in site.items()
                if key not in {
                    "id", "checked_domain_sha256", "site_identity_sha256"
                }
            }
            resolution = target["target_resolution_evidence"]
            target_identity = resolution["identity"]
            event_identity = canonical_sha256_v3({
                "transfer": common["transfer_id"],
                "call": common["event_index"],
                "instruction_rva": common["instruction_rva"],
                "identity": target_identity,
            })
            yield {
                "id": 0,
                **common,
                "event_identity_sha256": event_identity,
                **target,
            }


def validated_external_inventory_v8(
    payload: Mapping[str, Any],
) -> ValidatedExternalInventoryV8:
    """Validate the compact V8 inventory without expanding site x target."""

    callback_target_domains: dict[str, tuple[int, ...]] = {}
    previous_callback_domain: str | None = None
    for index, raw in enumerate(_required_list(
        payload.get("callback_target_domains"),
        "module-runtime callback target domains",
    )):
        row = _required_object(raw, f"callback target domain {index}")
        if set(row) != {"domain_sha256", "target_rvas"}:
            raise CandidateRuntimeError(
                "module-runtime callback target-domain fields differ"
            )
        identity = _required_sha256(
            row.get("domain_sha256"),
            f"callback target domain {index} identity",
        )
        targets = tuple(
            _required_u32(value, f"callback target domain {index} target")
            for value in _required_list(
                row.get("target_rvas"),
                f"callback target domain {index} targets",
            )
        )
        if (
            list(targets) != sorted(set(targets))
            or identity != _canonical_sha256({"target_rvas": list(targets)})
            or identity in callback_target_domains
            or previous_callback_domain is not None
            and identity <= previous_callback_domain
        ):
            raise CandidateRuntimeError(
                "module-runtime callback target domain is stale, duplicated, "
                "or noncanonical"
            )
        callback_target_domains[identity] = targets
        previous_callback_domain = identity

    catalog: dict[str, dict[str, Any]] = {}
    previous_target: str | None = None
    for index, raw in enumerate(_required_list(
        payload.get("external_target_contracts"),
        "module-runtime external target-contract catalog",
    )):
        row = _required_object(raw, f"external target contract {index}")
        if set(row) != _EXTERNAL_TARGET_CONTRACT_FIELDS:
            raise CandidateRuntimeError(
                "module-runtime external target-contract fields differ"
            )
        identity = _required_sha256(
            row.get("target_contract_id"),
            f"external target contract {index} identity",
        )
        serialized_body = {
            key: value for key, value in row.items()
            if key != "target_contract_id"
        }
        if (
            identity != _canonical_sha256(serialized_body)
            or identity in catalog
            or previous_target is not None and identity <= previous_target
        ):
            raise CandidateRuntimeError(
                "module-runtime external target-contract catalog is stale, "
                "duplicated, or noncanonical"
            )
        body = dict(serialized_body)
        expected_contract_sha256 = body.pop(
            "checked_external_contract_sha256"
        )
        raw_contract = body.get("checked_external_contract")
        if raw_contract is None:
            if expected_contract_sha256 is not None:
                raise CandidateRuntimeError(
                    "module-runtime absent external contract has a digest"
                )
        else:
            contract = dict(_required_object(
                raw_contract,
                f"external target contract {index} checked contract",
            ))
            body["checked_external_contract"] = contract
            expected_contract_sha256 = _required_sha256(
                expected_contract_sha256,
                f"external target contract {index} checked contract",
            )
            raw_adapter = contract.get("callback_adapter")
            if raw_adapter is not None:
                adapter = dict(_required_object(
                    raw_adapter,
                    f"external target contract {index} callback adapter",
                ))
                contract["callback_adapter"] = adapter
                if "target_rvas" in adapter or "target_domain_sha256" not in adapter:
                    raise CandidateRuntimeError(
                        "module-runtime callback contract is not normalized"
                    )
                callback_domain_sha256 = _required_sha256(
                    adapter.pop("target_domain_sha256"),
                    f"external target contract {index} callback domain",
                )
                targets = callback_target_domains.get(
                    callback_domain_sha256
                )
                if targets is None:
                    raise CandidateRuntimeError(
                        "module-runtime callback contract names an unknown target domain"
                    )
                adapter["target_rvas"] = list(targets)
            if _canonical_sha256(contract) != expected_contract_sha256:
                raise CandidateRuntimeError(
                    "module-runtime checked external contract digest is stale"
                )
        resolution = body.get("target_resolution_evidence")
        if not isinstance(resolution, Mapping):
            raise CandidateRuntimeError(
                "module-runtime external target contract has no resolution evidence"
            )
        target_identity = resolution.get("identity")
        if not isinstance(target_identity, list) or len(target_identity) != 3:
            raise CandidateRuntimeError(
                "module-runtime external target contract identity is malformed"
            )
        catalog[identity] = body
        previous_target = identity

    domains: dict[str, tuple[str, ...]] = {}
    previous_domain: str | None = None
    for index, raw in enumerate(_required_list(
        payload.get("external_contract_domains"),
        "module-runtime external contract domains",
    )):
        row = _required_object(raw, f"external contract domain {index}")
        if set(row) != {"domain_sha256", "target_contract_ids"}:
            raise CandidateRuntimeError(
                "module-runtime external contract-domain fields differ"
            )
        identity = _required_sha256(
            row.get("domain_sha256"),
            f"external contract domain {index} identity",
        )
        members = tuple(
            _required_sha256(member, f"external contract domain {index} member")
            for member in _required_list(
                row.get("target_contract_ids"),
                f"external contract domain {index} members",
            )
        )
        if (
            not members
            or members != tuple(sorted(set(members)))
            or any(member not in catalog for member in members)
            or identity != _canonical_sha256({"target_contract_ids": list(members)})
            or identity in domains
            or previous_domain is not None and identity <= previous_domain
        ):
            raise CandidateRuntimeError(
                "module-runtime external contract domain is stale, empty, "
                "duplicated, or noncanonical"
            )
        domains[identity] = members
        previous_domain = identity

    validated_sites: list[dict[str, Any]] = []
    sites = _required_list(payload.get("external_sites"),
                           "module-runtime external sites")
    for index, raw in enumerate(sites):
        site = _required_object(raw, f"module-runtime external site {index}")
        if set(site) != _NORMALIZED_EXTERNAL_SITE_FIELDS or site.get("id") != index:
            raise CandidateRuntimeError(
                "module-runtime normalized external site fields or identity differ"
            )
        domain_sha256 = _required_sha256(
            site.get("checked_domain_sha256"),
            f"module-runtime external site {index} checked domain",
        )
        members = domains.get(domain_sha256)
        if members is None:
            raise CandidateRuntimeError(
                "module-runtime external site names an unknown checked domain"
            )
        identity_body = {
            "transfer_id": site.get("transfer_id"),
            "event_index": site.get("event_index"),
            "instruction_rva": site.get("instruction_rva"),
            "site_kind": site.get("site_kind"),
            "checked_domain_sha256": domain_sha256,
        }
        if site.get("site_identity_sha256") != _canonical_sha256(identity_body):
            raise CandidateRuntimeError(
                "module-runtime normalized external site identity is stale"
            )
        validated_sites.append(dict(site))
    return ValidatedExternalInventoryV8(
        target_contracts=catalog,
        contract_domains=domains,
        sites=tuple(validated_sites),
    )


def expanded_external_sites_v8(payload: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Compatibility projection of the validated compact V8 inventory."""

    expanded = list(validated_external_inventory_v8(payload).expanded_sites())
    for index, site in enumerate(expanded):
        site["id"] = index
    return expanded


def _validate_native_plan(
    payload: dict[str, Any],
    *,
    state_machine_sha256: str,
    input_mode: str,
    transfer_rvas: tuple[int, ...],
    transfer_bindings: tuple[_TransferBinding, ...],
    ingress_descriptors: tuple[dict[str, Any], ...],
    ingress_callback_domains: tuple[dict[str, Any], ...],
    ingress_callback_publications: tuple[dict[str, Any], ...],
    ingress_plan_id: str,
) -> tuple[
    dict[str, Any],
    tuple[NativeImplementationDispatch, ...],
    tuple[tuple[int, int], ...],
    tuple[NativeGuestDispatchDomain, ...],
    tuple[NativeGuestDispatchSite, ...],
    ValidatedExternalInventoryV8,
]:
    expected_plan_fields = {
        "format",
        "status",
        "state_machine_sha256",
        "input_mode",
        "native_ingress_plan_id",
        "counts",
        "external_target_contracts",
        "external_contract_domains",
        "callback_target_domains",
        "external_sites",
        "external_service_routes",
        "guest_dispatch",
        "import_bindings",
        "code_capability_bindings",
        "code_capability_registrations",
        "compact_code_capability_domains",
        "compact_code_capability_publications",
        "implementation_dispatch_receipt",
        "x87_mode",
        "x87_operations",
        "termination_import",
        "recovered_executable_data",
        "blockers",
    }
    if set(payload) != expected_plan_fields:
        raise CandidateRuntimeError("module-runtime plan fields differ")
    if payload.get("format") != MODULE_RUNTIME_PLAN_FORMAT:
        raise CandidateRuntimeError("module-runtime plan has an unsupported format")
    if payload.get("status") != "ready":
        raise CandidateRuntimeError("module-runtime plan is not ready")
    if payload.get("state_machine_sha256") != state_machine_sha256:
        raise CandidateRuntimeError(
            "module-runtime and module-runtime packages bind different state machines"
        )
    if payload.get("input_mode") != input_mode:
        raise CandidateRuntimeError(
            "module-runtime plan and packages bind different semantic input modes"
        )
    if _required_list(payload.get("blockers"), "module-runtime blockers"):
        raise CandidateRuntimeError("ready module-runtime plan contains blockers")
    external_inventory = validated_external_inventory_v8(payload)
    external_service_routes = _required_list(
        payload.get("external_service_routes"),
        "module-runtime external service routes",
    )
    previous_service_obligation: str | None = None
    service_sites: set[tuple[str, int, int]] = set()
    for index, raw_route in enumerate(external_service_routes):
        route = _required_object(
            raw_route, f"module-runtime external service route {index}"
        )
        if set(route) != {
            "obligation_id", "obligation_class",
            "semantic_contract_sha256", "admitted_domain",
            "implementation", "route_sha256",
        }:
            raise CandidateRuntimeError(
                "module-runtime external service route fields differ"
            )
        route_body = {
            key: value for key, value in route.items()
            if key != "route_sha256"
        }
        if route.get("route_sha256") != canonical_sha256_v3(route_body):
            raise CandidateRuntimeError(
                "module-runtime external service route identity is stale"
            )
        obligation_id = _required_string(
            route.get("obligation_id"),
            f"external service route {index} obligation",
        )
        if (
            not obligation_id.startswith("residual-obligation-v2:")
            or len(obligation_id.removeprefix("residual-obligation-v2:")) != 64
            or previous_service_obligation is not None
            and obligation_id <= previous_service_obligation
        ):
            raise CandidateRuntimeError(
                "module-runtime external service routes are not canonical"
            )
        previous_service_obligation = obligation_id
        _required_sha256(
            route.get("semantic_contract_sha256"),
            f"external service route {index} semantic contract",
        )
        admitted = _required_object(
            route.get("admitted_domain"),
            f"external service route {index} admitted domain",
        )
        if set(admitted) != {
            "kind", "contract_sha256", "identity", "sites", "protocol",
        } or admitted.get("kind") != "checked_external_service_protocol_v1":
            raise CandidateRuntimeError(
                "module-runtime external service admitted domain differs"
            )
        _required_sha256(
            admitted.get("contract_sha256"),
            f"external service route {index} checked contract",
        )
        identity = _required_object(
            admitted.get("identity"),
            f"external service route {index} identity",
        )
        if set(identity) != {"dll", "symbol", "ordinal"}:
            raise CandidateRuntimeError(
                "module-runtime external service identity differs"
            )
        _required_string(
            identity.get("dll"), f"external service route {index} DLL"
        )
        _required_string(
            identity.get("symbol"), f"external service route {index} symbol"
        )
        if identity.get("ordinal") is not None:
            raise CandidateRuntimeError(
                "module-runtime checked external service must use a named import"
            )
        implementation = _required_string(
            route.get("implementation"),
            f"external service route {index} implementation",
        )
        protocol = _required_object(
            admitted.get("protocol"),
            f"external service route {index} protocol",
        )
        argument_words = 1 if protocol.get(
            "kind"
        ) == "unhandled_exception_filter" else 4
        try:
            parsed_protocol = parse_checked_external_service_protocol_v1(
                protocol,
                argument_words=argument_words,
                context=f"external service route {index} protocol",
            )
        except CheckedExternalServiceProtocolError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        supported_service = (
            parsed_protocol is not None
            and (
                (
                    parsed_protocol.get("id") == "win32-rtl-unwind-v1"
                    and parsed_protocol.get("kind") == "nonlocal_unwind"
                    and route.get("obligation_class")
                    == "checked_external_nonlocal_service"
                    and identity.get("symbol") == "RtlUnwind"
                )
                or (
                    parsed_protocol.get("id")
                    == "win32-unhandled-exception-filter-v1"
                    and parsed_protocol.get("kind")
                    == "unhandled_exception_filter"
                    and route.get("obligation_class")
                    == "checked_external_exception_object_service"
                    and identity.get("symbol")
                    == "UnhandledExceptionFilter"
                )
            )
        )
        if implementation != "checked_runtime" or not supported_service:
            raise CandidateRuntimeError(
                "ready module-runtime plan contains an unrealized or "
                "unsupported external service"
            )
        sites = _required_list(
            admitted.get("sites"),
            f"external service route {index} sites",
        )
        if not sites:
            raise CandidateRuntimeError(
                "module-runtime external service route has no sites"
            )
        for site_index, raw_site in enumerate(sites):
            site = _required_object(
                raw_site,
                f"external service route {index} site {site_index}",
            )
            transfer_id = _required_string(
                site.get("transfer_id"),
                f"external service route {index} site transfer",
            )
            instruction_rva = _required_u32(
                site.get("instruction_rva"),
                f"external service route {index} site instruction RVA",
            )
            call_id = _required_count(
                site.get("call_id"),
                f"external service route {index} site call ID",
            )
            key = (transfer_id, instruction_rva, call_id)
            if key in service_sites:
                raise CandidateRuntimeError(
                    "module-runtime external service sites are duplicated"
                )
            service_sites.add(key)
    implementation_dispatch_receipt, implementation_dispatches = (
        _validate_implementation_dispatch_receipt(
            payload,
            state_machine_sha256=state_machine_sha256,
            transfer_bindings=transfer_bindings,
        )
    )
    if payload.get("native_ingress_plan_id") != ingress_plan_id:
        raise CandidateRuntimeError(
            "module-runtime plan binds a different native ingress plan"
        )
    module_entries = tuple(
        row for row in ingress_descriptors
        if row.get("role") in {"process_entry", "dll_entry"}
    )
    if len(module_entries) != 1:
        raise CandidateRuntimeError(
            "native ingress plan must contain exactly one module entry"
        )
    entry_rva = _required_u32(
        module_entries[0].get("target_rva"), "native ingress module entry RVA"
    )
    callback_rows = tuple(
        row for row in ingress_descriptors
        if row.get("role") in {"callback", "tls_callback"}
    )
    callback_targets = tuple(sorted({
        _required_u32(row.get("target_rva"), "native ingress callback RVA")
        for row in callback_rows
    }))
    if callback_targets != tuple(sorted(set(callback_targets))):
        raise CandidateRuntimeError(
            "module-runtime callback RVAs must be sorted and unique"
        )
    if any(target not in transfer_rvas for target in callback_targets):
        raise CandidateRuntimeError(
            "runtime callback lacks a checked executable transfer"
        )
    recovered_data = _required_object(
        payload.get("recovered_executable_data"),
        "module-runtime recovered executable data",
    )
    if recovered_data.get("dispatch_policy") != "fail_closed_as_noncode":
        raise CandidateRuntimeError(
            "module-runtime recovered executable data is not fail-closed"
        )
    recovered_ranges: list[tuple[int, int]] = []
    for index, raw in enumerate(
        _required_list(
            recovered_data.get("ranges"),
            "module-runtime recovered executable-data ranges",
        )
    ):
        row = _required_object(raw, f"recovered executable-data range {index}")
        _required_string(row.get("id"), f"recovered executable-data range {index} id")
        _required_sha256(
            row.get("bytes_sha256"),
            f"recovered executable-data range {index} SHA-256",
        )
        start = _required_u32(
            row.get("rva_start"), f"recovered executable-data range {index} start"
        )
        end = _required_u32(
            row.get("rva_end"), f"recovered executable-data range {index} end"
        )
        if end <= start:
            raise CandidateRuntimeError(
                "module-runtime recovered executable-data range is empty"
            )
        if recovered_ranges and start < recovered_ranges[-1][1]:
            raise CandidateRuntimeError(
                "module-runtime recovered executable-data ranges overlap or are unsorted"
            )
        recovered_ranges.append((start, end))
    if any(
        start <= target < end
        for target in (entry_rva, *callback_targets)
        for start, end in recovered_ranges
    ):
        raise CandidateRuntimeError(
            "native entry or callback target overlaps recovered executable data"
        )
    for index, row in enumerate(callback_rows):
        frame = _required_object(
            row.get("physical_frame"), f"native ingress callback frame {index}"
        )
        try:
            transport = PhysicalCallFrameV2.parse(frame.get("transport"))
        except Exception as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        cleanup = transport.stack.cleanup_bytes
        if row.get("role") == "tls_callback" and cleanup != 12:
            raise CandidateRuntimeError(
                "PE32 TLS callback ingress must clean exactly 12 stack bytes"
            )
    capability_registrations = _required_list(
        payload.get("code_capability_registrations"),
        "module-runtime code capability registrations",
    )
    compact_domains = _required_list(
        payload.get("compact_code_capability_domains"),
        "module-runtime compact code capability domains",
    )
    compact_publications = _required_list(
        payload.get("compact_code_capability_publications"),
        "module-runtime compact code capability publications",
    )
    callback_capabilities: dict[str, int] = {}
    for index, row in enumerate(callback_rows):
        if row.get("role") != "callback":
            continue
        capability_id = _required_string(
            row.get("capability_id"),
            f"native callback ingress {index} capability identity",
        )
        target = _required_u32(
            row.get("target_rva"), f"native callback ingress {index} target"
        )
        if capability_id in callback_capabilities:
            raise CandidateRuntimeError(
                "native ingress callback capability identity is duplicated"
            )
        callback_capabilities[capability_id] = target
    seen_registrations: set[tuple[int, int, int, str]] = set()
    expected_registrations: dict[
        tuple[int, int, int, str], dict[str, Any]
    ] = {}
    expected_interface_publications: dict[str, dict[str, Any]] = {}
    callback_or_loader_targets = frozenset(
        target_id
        for target_id, target in external_inventory.target_contracts.items()
        if target.get("loader_service") is not None
        or (
            isinstance(target.get("checked_external_contract"), Mapping)
            and target["checked_external_contract"].get("callback_effect")
            == "explicit"
        )
    )
    for site_index, site, _target_id, target in (
        external_inventory.iter_site_targets(
            only_target_ids=callback_or_loader_targets
        )
    ):
        contract = target.get("checked_external_contract")
        loader_service = target.get("loader_service")
        if loader_service is not None:
            loader = _required_object(
                loader_service,
                f"module-runtime external site {site_index} loader service",
            )
            if not isinstance(contract, Mapping):
                raise CandidateRuntimeError(
                    "module-runtime loader service has no checked external contract"
                )
            arity = _required_object(
                contract.get("arity"),
                f"module-runtime external site {site_index} arity",
            )
            if arity.get("kind") == "fixed":
                argument_words = _required_count(
                    arity.get("words"),
                    f"module-runtime external site {site_index} argument words",
                )
            elif arity.get("kind") == "variadic":
                argument_words = _required_count(
                    arity.get("minimum_words"),
                    f"module-runtime external site {site_index} minimum argument words",
                )
            else:
                raise CandidateRuntimeError(
                    "module-runtime loader service has unsupported call arity"
                )
            kind = loader.get("kind")
            if kind == "module_handle":
                if set(loader) != {
                    "kind", "module_name_argument", "nullable_module_name",
                    "wide_name", "contract_sha256",
                }:
                    raise CandidateRuntimeError(
                        "module-runtime module-handle service fields are not canonical"
                    )
                argument = _required_count(
                    loader.get("module_name_argument"),
                    f"module-runtime external site {site_index} module-name argument",
                )
                if (
                    argument >= argument_words
                    or not isinstance(loader.get("nullable_module_name"), bool)
                    or not isinstance(loader.get("wide_name"), bool)
                ):
                    raise CandidateRuntimeError(
                        "module-runtime module-handle service contradicts its call frame"
                    )
            elif kind == "dynamic_export_resolution":
                if set(loader) != {
                    "kind", "module_handle_argument", "export_name_argument",
                    "contract_sha256",
                }:
                    raise CandidateRuntimeError(
                        "module-runtime export-resolution service fields are not canonical"
                    )
                module_argument = _required_count(
                    loader.get("module_handle_argument"),
                    f"module-runtime external site {site_index} module-handle argument",
                )
                export_argument = _required_count(
                    loader.get("export_name_argument"),
                    f"module-runtime external site {site_index} export-name argument",
                )
                if module_argument >= argument_words or export_argument >= argument_words:
                    raise CandidateRuntimeError(
                        "module-runtime export-resolution service contradicts its call frame"
                    )
            else:
                raise CandidateRuntimeError(
                    "module-runtime loader service kind is unsupported"
                )
            _required_sha256(
                loader.get("contract_sha256"),
                f"module-runtime external site {site_index} loader-service contract",
            )
        if not isinstance(contract, Mapping) or contract.get("callback_effect") != "explicit":
            continue
        adapter = _required_object(
            contract.get("callback_adapter"),
            f"module-runtime external site {site_index} callback adapter",
        )
        source = _required_object(
            adapter.get("source"),
            f"module-runtime external site {site_index} callback source",
        )
        argument_index = _required_count(
            source.get("argument"),
            f"module-runtime external site {site_index} callback argument",
        )
        instruction_rva = _required_u32(
            site.get("instruction_rva"),
            f"module-runtime external site {site_index} instruction",
        )
        checked_contract_sha256 = canonical_sha256_v3(contract)
        contract_identity = _required_object(
            contract.get("identity"),
            f"module-runtime external site {site_index} contract identity",
        )
        is_interface_callback = contract_identity.get("kind") == "interface"
        method_sha256 = None
        if is_interface_callback:
            resolution = _required_object(
                target.get("target_resolution_evidence"),
                f"module-runtime external site {site_index} target resolution",
            )
            method_sha256 = _required_sha256(
                resolution.get("admitted_member_sha256"),
                f"module-runtime external site {site_index} interface method",
            )
        target_rvas: list[int] = []
        for raw_target in _required_list(
            adapter.get("target_rvas"),
            f"module-runtime external site {site_index} callback targets",
        ):
            target = _required_u32(
                raw_target,
                f"module-runtime external site {site_index} callback target",
            )
            target_rvas.append(target)
            if is_interface_callback:
                continue
            key = (
                instruction_rva, argument_index, target,
                checked_contract_sha256,
            )
            expected = {
                "lifetime": adapter.get("lifetime"),
                "invocation": adapter.get("invocation"),
                "checked_external_contract_sha256": checked_contract_sha256,
            }
            prior = expected_registrations.get(key)
            if prior is not None and prior != expected:
                raise CandidateRuntimeError(
                    "module-runtime callback capability authority is ambiguous"
                )
            # A single checked instruction occurrence may have several exact
            # transfer entry slices (for example, an original cutpoint and a
            # recovered interior-entry cutpoint).  They do not create several
            # callback publications: identical authority for the same
            # instruction, argument, target, and contract is one fact.
            expected_registrations[key] = expected
        if method_sha256 is not None:
            expected_interface = {
                "argument_index": argument_index,
                "target_rvas": target_rvas,
                "lifetime": adapter.get("lifetime"),
                "invocation": adapter.get("invocation"),
            }
            prior_interface = expected_interface_publications.get(method_sha256)
            if prior_interface is not None and prior_interface != expected_interface:
                raise CandidateRuntimeError(
                    "module-runtime interface callback authority is ambiguous"
                )
            expected_interface_publications[method_sha256] = expected_interface
    expected_registration_fields = {
        "instruction_rva",
        "argument_index",
        "logical_target_rva",
        "code_target_rva",
        "capability_id",
        "lifetime",
        "invocation",
        "checked_external_contract_sha256",
    }
    expected_compact_domains: dict[str, dict[str, Any]] = {}
    flat_first = 0
    for index, raw in enumerate(ingress_callback_domains):
        if not isinstance(raw, Mapping):
            raise CandidateRuntimeError(
                f"native ingress compact callback domain {index} is malformed"
            )
        identity = _required_string(
            raw.get("id"), f"native ingress callback domain {index} identity"
        )
        targets = tuple(
            _required_u32(value, "native ingress compact callback target")
            for value in _required_list(
                raw.get("target_rvas"),
                f"native ingress callback domain {index} targets",
            )
        )
        expected_compact_domains[identity] = {
            "domain_id": identity,
            "protocol_id": _required_string(
                raw.get("protocol_id"),
                f"native ingress callback domain {index} protocol",
            ),
            "target_rvas": list(targets),
            "trampoline_table_symbol": _required_string(
                raw.get("trampoline_table_symbol"),
                f"native ingress callback domain {index} table symbol",
            ),
            "trampoline_stride_bytes": _required_count(
                raw.get("trampoline_stride_bytes"),
                f"native ingress callback domain {index} table stride",
            ),
            "flat_first": flat_first,
        }
        flat_first += len(targets)
    observed_compact_domains: dict[str, dict[str, Any]] = {}
    expected_compact_domain_fields = {
        "domain_id", "protocol_id", "target_rvas",
        "trampoline_table_symbol", "trampoline_stride_bytes", "flat_first",
    }
    for index, raw in enumerate(compact_domains):
        domain = _required_object(raw, f"compact code capability domain {index}")
        identity = _required_string(
            domain.get("domain_id"),
            f"compact code capability domain {index} identity",
        )
        if (
            set(domain) != expected_compact_domain_fields
            or identity in observed_compact_domains
            or dict(domain) != expected_compact_domains.get(identity)
        ):
            raise CandidateRuntimeError(
                "compact code capability domain differs from native ingress"
            )
        observed_compact_domains[identity] = dict(domain)
    if observed_compact_domains != expected_compact_domains:
        raise CandidateRuntimeError(
            "module-runtime compact capability domains omit native ingress authority"
        )

    ingress_publications: dict[str, Mapping[str, Any]] = {}
    interface_ingress_publications: set[str] = set()
    for index, raw in enumerate(ingress_callback_publications):
        if not isinstance(raw, Mapping):
            raise CandidateRuntimeError(
                f"native ingress compact callback publication {index} is malformed"
            )
        identity = _required_string(
            raw.get("id"),
            f"native ingress callback publication {index} identity",
        )
        if identity in ingress_publications:
            raise CandidateRuntimeError(
                "native ingress compact callback publication is duplicated"
            )
        ingress_publications[identity] = raw
        if raw.get("source_kind") == "interface_method":
            source_id = raw.get("source_id")
            if (
                not isinstance(source_id, str)
                or raw.get("escape_id")
                != "interface-method-callback-v1:" + source_id
                or raw.get("instruction_rva") != 0
            ):
                raise CandidateRuntimeError(
                    "native ingress interface callback publication is malformed"
                )
            interface_ingress_publications.add(identity)
    expected_compact_publication_fields = {
        "publication_id", "domain_id", "authority_kind", "authority_sha256",
        "instruction_rva", "argument_index", "lifetime", "invocation",
    }
    seen_compact_publications: set[str] = set()
    seen_interface_publications: set[str] = set()
    for index, raw in enumerate(compact_publications):
        publication = _required_object(
            raw, f"compact code capability publication {index}"
        )
        identity = _required_string(
            publication.get("publication_id"),
            f"compact code capability publication {index} identity",
        )
        ingress_publication = ingress_publications.get(identity)
        domain_id = _required_string(
            publication.get("domain_id"),
            f"compact code capability publication {index} domain",
        )
        instruction_rva = _required_u32(
            publication.get("instruction_rva"),
            f"compact code capability publication {index} instruction",
        )
        argument_index = _required_count(
            publication.get("argument_index"),
            f"compact code capability publication {index} argument",
        )
        authority_kind = _required_string(
            publication.get("authority_kind"),
            f"compact code capability publication {index} authority kind",
        )
        authority_sha256 = _required_sha256(
            publication.get("authority_sha256"),
            f"compact code capability publication {index} authority",
        )
        domain = expected_compact_domains.get(domain_id)
        if (
            set(publication) != expected_compact_publication_fields
            or identity in seen_compact_publications
            or (
                ingress_publication is not None
                and (
                    ingress_publication.get("domain_id") != domain_id
                    or ingress_publication.get("instruction_rva")
                    != instruction_rva
                )
            )
            or (
                ingress_publication is None
                and not identity.startswith("compact-callback-publication-v2:")
            )
            or domain is None
        ):
            raise CandidateRuntimeError(
                "compact code capability publication differs from native ingress"
            )
        lifetime = _required_object(
            publication.get("lifetime"),
            f"compact code capability publication {index} lifetime",
        )
        invocation = _required_string(
            publication.get("invocation"),
            f"compact code capability publication {index} invocation",
        )
        if authority_kind == "interface_method_contract":
            expected_interface = expected_interface_publications.get(
                authority_sha256
            )
            if (
                ingress_publication is None
                or ingress_publication.get("source_kind") != "interface_method"
                or ingress_publication.get("source_id") != authority_sha256
                or instruction_rva != 0
                or expected_interface is None
                or authority_sha256 in seen_interface_publications
                or argument_index != expected_interface["argument_index"]
                or list(domain["target_rvas"])
                != expected_interface["target_rvas"]
                or dict(lifetime) != expected_interface["lifetime"]
                or invocation != expected_interface["invocation"]
            ):
                raise CandidateRuntimeError(
                    "compact code capability publication changes callback authority"
                )
            seen_interface_publications.add(authority_sha256)
        elif authority_kind == "checked_external_site_contract":
            for target in domain["target_rvas"]:
                key = (
                    instruction_rva, argument_index, int(target),
                    authority_sha256,
                )
                expected = expected_registrations.get(key)
                if expected is None or (
                    dict(lifetime) != expected["lifetime"]
                    or invocation != expected["invocation"]
                    or authority_sha256
                    != expected["checked_external_contract_sha256"]
                    or key in seen_registrations
                ):
                    raise CandidateRuntimeError(
                        "compact code capability publication changes callback authority"
                    )
                seen_registrations.add(key)
        else:
            raise CandidateRuntimeError(
                "compact code capability publication authority is unsupported"
            )
        seen_compact_publications.add(identity)
    if seen_interface_publications != set(expected_interface_publications):
        raise CandidateRuntimeError(
            "module-runtime interface callback publications are incomplete"
        )
    if not (
        set(ingress_publications) - interface_ingress_publications
    ).issubset(seen_compact_publications):
        raise CandidateRuntimeError(
            "module-runtime compact capability publications omit native ingress authority"
        )
    for index, raw in enumerate(capability_registrations):
        registration = _required_object(
            raw, f"code capability registration {index}"
        )
        if set(registration) != expected_registration_fields:
            raise CandidateRuntimeError(
                "code capability registration fields are not canonical"
            )
        target = _required_u32(
            registration.get("code_target_rva"),
            f"code capability registration {index} target",
        )
        capability_id = _required_string(
            registration.get("capability_id"),
            f"code capability registration {index} identity",
        )
        if callback_capabilities.get(capability_id) != target:
            raise CandidateRuntimeError(
                "code capability registration does not bind its exact callback ingress"
            )
        logical_target = _required_u32(
            registration.get("logical_target_rva"),
            f"code capability registration {index} logical target",
        )
        if logical_target != target:
            raise CandidateRuntimeError(
                "code capability registration logical and code targets differ"
            )
        instruction_rva = _required_u32(
            registration.get("instruction_rva"),
            f"code capability registration {index} instruction",
        )
        argument_index = _required_count(
            registration.get("argument_index"),
            f"code capability registration {index} argument",
        )
        contract_sha256 = _required_sha256(
            registration.get("checked_external_contract_sha256"),
            f"code capability registration {index} contract SHA-256",
        )
        key = (instruction_rva, argument_index, target, contract_sha256)
        if key in seen_registrations:
            raise CandidateRuntimeError("code capability registration is duplicated")
        seen_registrations.add(key)
        invocation = _required_string(
            registration.get("invocation"),
            f"code capability registration {index} invocation",
        )
        lifetime = _required_object(
            registration.get("lifetime"),
            f"code capability registration {index} lifetime",
        )
        _required_string(
            lifetime.get("kind"),
            f"code capability registration {index} lifetime kind",
        )
        expected = expected_registrations.get(key)
        if expected is None or (
            dict(lifetime) != expected["lifetime"]
            or invocation != expected["invocation"]
            or contract_sha256 != expected["checked_external_contract_sha256"]
        ):
            raise CandidateRuntimeError(
                "code capability registration does not match checked callback authority"
            )
    if seen_registrations != set(expected_registrations):
        raise CandidateRuntimeError(
            "module-runtime code capability registrations omit or add checked callback authority"
        )
    registration_by_key = {
        (
            int(row["instruction_rva"]), int(row["argument_index"]),
            int(row["code_target_rva"]), str(row["capability_id"]),
        ): row
        for row in capability_registrations
    }
    capability_bindings = _required_list(
        payload.get("code_capability_bindings"),
        "module-runtime code capability bindings",
    )
    expected_binding_fields = {
        "id", "instruction_rva", "argument_index", "original_rva",
        "code_target_rva", "capability_id", "matching",
    }
    seen_binding_keys: set[tuple[int, int, int, str]] = set()
    for index, raw in enumerate(capability_bindings):
        binding = _required_object(raw, f"code capability binding {index}")
        if set(binding) != expected_binding_fields or binding.get("id") != index:
            raise CandidateRuntimeError(
                "code capability binding fields or identity are not canonical"
            )
        instruction_rva = _required_u32(
            binding.get("instruction_rva"),
            f"code capability binding {index} instruction",
        )
        argument_index = _required_count(
            binding.get("argument_index"),
            f"code capability binding {index} argument",
        )
        original_rva = _required_u32(
            binding.get("original_rva"),
            f"code capability binding {index} original target",
        )
        target = _required_u32(
            binding.get("code_target_rva"),
            f"code capability binding {index} code target",
        )
        capability_id = _required_string(
            binding.get("capability_id"),
            f"code capability binding {index} capability identity",
        )
        key = (instruction_rva, argument_index, target, capability_id)
        if (
            original_rva != target
            or binding.get("matching") != "logical-image-base-plus-rva"
            or key in seen_binding_keys
            or key not in registration_by_key
            or callback_capabilities.get(capability_id) != target
        ):
            raise CandidateRuntimeError(
                "code capability binding is stale, duplicate, or unauthorized"
            )
        seen_binding_keys.add(key)
    if seen_binding_keys != set(registration_by_key):
        raise CandidateRuntimeError(
            "code capability bindings do not cover registrations exactly"
        )
    if entry_rva not in transfer_rvas:
        raise CandidateRuntimeError(
            "runtime entry RVA is absent from the executable transfer table"
        )
    counts = _required_object(payload.get("counts"), "module-runtime counts")
    expected_count_fields = {
        "transfers",
        "guest_dispatch_sites",
        "guest_dispatch_domains",
        "guest_dispatch_domain_targets",
        "recovered_executable_data_ranges",
        "external_sites",
        "external_site_target_pairs",
        "external_target_contracts",
        "external_contract_domains",
        "external_contract_domain_members",
        "callback_target_domains",
        "external_service_routes",
        "import_bindings",
        "code_capability_registrations",
        "code_capability_bindings",
        "compact_code_capability_domains",
        "compact_code_capability_domain_targets",
        "compact_code_capability_publications",
        "implementation_dispatch_entries",
        "x87_operations",
        "blockers",
    }
    if set(counts) != expected_count_fields:
        raise CandidateRuntimeError("module-runtime plan count fields differ")
    if _required_count(counts.get("transfers"), "module-runtime transfer count") != len(
        transfer_rvas
    ):
        raise CandidateRuntimeError(
            "runtime and executable transfer counts differ"
        )
    if _required_count(
        counts.get("code_capability_bindings"),
        "module-runtime code capability binding count",
    ) != len(capability_bindings):
        raise CandidateRuntimeError(
            "module-runtime code capability binding count differs from its inventory"
        )
    if _required_count(
        counts.get("code_capability_registrations"),
        "module-runtime code capability registration count",
    ) != len(capability_registrations):
        raise CandidateRuntimeError(
            "module-runtime code capability registration count differs from its inventory"
        )
    if _required_count(
        counts.get("compact_code_capability_domains"),
        "module-runtime compact capability domain count",
    ) != len(compact_domains):
        raise CandidateRuntimeError(
            "module-runtime compact capability domain count differs"
        )
    if _required_count(
        counts.get("compact_code_capability_domain_targets"),
        "module-runtime compact capability target count",
    ) != sum(len(row["target_rvas"]) for row in compact_domains):
        raise CandidateRuntimeError(
            "module-runtime compact capability target count differs"
        )
    if _required_count(
        counts.get("compact_code_capability_publications"),
        "module-runtime compact capability publication count",
    ) != len(compact_publications):
        raise CandidateRuntimeError(
            "module-runtime compact capability publication count differs"
        )
    guest_dispatch = _required_object(
        payload.get("guest_dispatch"), "module-runtime guest dispatch"
    )
    if (
        guest_dispatch.get("policy")
        != "content_addressed_admitted_domains_v2"
        or guest_dispatch.get("unknown_site") != "fail_closed"
    ):
        raise CandidateRuntimeError(
            "module-runtime guest dispatch is not exact and fail-closed"
        )
    guest_domains: list[NativeGuestDispatchDomain] = []
    domain_by_sha256: dict[str, NativeGuestDispatchDomain] = {}
    previous_domain_sha256: str | None = None
    domain_fields = {"domain_sha256", "contract", "authority"}
    for index, raw in enumerate(_required_list(
        guest_dispatch.get("domains"), "module-runtime guest dispatch domains"
    )):
        row = _required_object(raw, f"guest dispatch domain {index}")
        if set(row) != domain_fields:
            raise CandidateRuntimeError(
                "guest dispatch domain fields are not canonical"
            )
        domain_sha256 = _required_sha256(
            row.get("domain_sha256"), f"guest dispatch domain {index} identity"
        )
        contract = _required_object(
            row.get("contract"), f"guest dispatch domain {index} contract"
        )
        if domain_sha256 != canonical_sha256_v3(contract):
            raise CandidateRuntimeError("guest dispatch domain identity is stale")
        raw_targets = contract.get(
            "guest_transfer_entry_rvas", contract.get("targets")
        )
        targets = tuple(
            _required_u32(target, f"guest dispatch domain {index} target RVA")
            for target in _required_list(
                raw_targets, f"guest dispatch domain {index} targets"
            )
        )
        if targets != tuple(sorted(set(targets))) or any(
            target not in transfer_rvas for target in targets
        ):
            raise CandidateRuntimeError(
                "guest dispatch domain is not a sorted executable-transfer subset"
            )
        authority = _required_string(
            row.get("authority"), f"guest dispatch domain {index} authority"
        )
        if authority not in {
            "checked_module_execution_closure", "linked_semantic_module_v2",
        }:
            raise CandidateRuntimeError(
                "guest dispatch domain has unsupported authority"
            )
        domain = NativeGuestDispatchDomain(
            domain_sha256=domain_sha256,
            contract=dict(contract),
            authority=authority,
        )
        if (
            domain_sha256 in domain_by_sha256
            or previous_domain_sha256 is not None
            and domain_sha256 <= previous_domain_sha256
        ):
            raise CandidateRuntimeError(
                "guest dispatch domains are duplicated or noncanonical"
            )
        domain_by_sha256[domain_sha256] = domain
        guest_domains.append(domain)
        previous_domain_sha256 = domain_sha256

    guest_sites: list[NativeGuestDispatchSite] = []
    seen_guest_sites: set[tuple[str, int]] = set()
    previous_sort_key: tuple[int, int, int, int] | None = None
    expected_fields = {
        "site", "kind", "source_rva", "instruction_rva", "event_index",
        "domain_sha256",
    }
    for index, raw in enumerate(_required_list(
        guest_dispatch.get("sites"), "module-runtime guest dispatch sites"
    )):
        row = _required_object(raw, f"guest dispatch site {index}")
        if set(row) != expected_fields:
            raise CandidateRuntimeError("guest dispatch site fields are not canonical")
        site = _required_string(row.get("site"), f"guest dispatch site {index} id")
        kind = _required_string(row.get("kind"), f"guest dispatch site {index} kind")
        source_rva = _required_u32(
            row.get("source_rva"), f"guest dispatch site {index} source RVA"
        )
        if source_rva not in transfer_rvas:
            raise CandidateRuntimeError(
                "guest dispatch source is absent from the executable transfer table"
            )
        if kind == "indirect_jump":
            instruction_rva = _required_u32(
                row.get("instruction_rva"),
                f"guest dispatch site {index} instruction RVA",
            )
            if (
                site != "terminator"
                or instruction_rva != source_rva
                or row.get("event_index") is not None
            ):
                raise CandidateRuntimeError("guest indirect-jump site is malformed")
            event_index = None
            kind_code = 1
        elif kind == "indirect_call":
            instruction_rva = _required_u32(
                row.get("instruction_rva"),
                f"guest dispatch site {index} instruction RVA",
            )
            event_index = _required_count(
                row.get("event_index"), f"guest dispatch site {index} event index"
            )
            if site != f"call:{instruction_rva:08x}:{event_index}":
                raise CandidateRuntimeError("guest indirect-call site is malformed")
            kind_code = 0
        else:
            raise CandidateRuntimeError("guest dispatch site kind is unsupported")
        domain_sha256 = _required_sha256(
            row.get("domain_sha256"), f"guest dispatch site {index} domain"
        )
        if domain_sha256 not in domain_by_sha256:
            raise CandidateRuntimeError(
                "guest dispatch site names an unknown admitted domain"
            )
        identity = (site, source_rva)
        sort_key = (
            source_rva, kind_code, instruction_rva or 0, event_index or 0
        )
        if identity in seen_guest_sites or (
            previous_sort_key is not None and sort_key <= previous_sort_key
        ):
            raise CandidateRuntimeError(
                "guest dispatch sites are duplicated or not canonically sorted"
            )
        seen_guest_sites.add(identity)
        previous_sort_key = sort_key
        guest_sites.append(NativeGuestDispatchSite(
            site=site,
            kind=kind,
            source_rva=source_rva,
            instruction_rva=instruction_rva,
            event_index=event_index,
            domain_sha256=domain_sha256,
        ))
    if _required_count(
        counts.get("guest_dispatch_sites"),
        "module-runtime guest dispatch site count",
    ) != len(guest_sites) or _required_count(
        counts.get("guest_dispatch_domains"),
        "module-runtime guest dispatch domain count",
    ) != len(guest_domains) or _required_count(
        counts.get("guest_dispatch_domain_targets"),
        "module-runtime guest dispatch domain target count",
    ) != sum(len(domain.target_rvas) for domain in guest_domains):
        raise CandidateRuntimeError(
            "module-runtime guest dispatch counts differ from their inventory"
        )
    expected_counts = {
        "transfers": len(transfer_rvas),
        "guest_dispatch_sites": len(guest_sites),
        "guest_dispatch_domains": len(guest_domains),
        "guest_dispatch_domain_targets": sum(
            len(domain.target_rvas) for domain in guest_domains
        ),
        "recovered_executable_data_ranges": len(recovered_ranges),
        "external_sites": len(
            _required_list(
                payload.get("external_sites"),
                "module-runtime external sites",
            )
        ),
        "external_site_target_pairs": external_inventory.target_pair_count,
        "external_target_contracts": len(_required_list(
            payload.get("external_target_contracts"),
            "module-runtime external target contracts",
        )),
        "external_contract_domains": len(_required_list(
            payload.get("external_contract_domains"),
            "module-runtime external contract domains",
        )),
        "external_contract_domain_members": sum(
            len(_required_list(
                domain.get("target_contract_ids"),
                "module-runtime external contract domain members",
            ))
            for domain in _required_list(
                payload.get("external_contract_domains"),
                "module-runtime external contract domains",
            )
        ),
        "callback_target_domains": len(_required_list(
            payload.get("callback_target_domains"),
            "module-runtime callback target domains",
        )),
        "external_service_routes": len(external_service_routes),
        "import_bindings": len(
            _required_list(
                payload.get("import_bindings"),
                "module-runtime import bindings",
            )
        ),
        "code_capability_registrations": len(capability_registrations),
        "code_capability_bindings": len(capability_bindings),
        "compact_code_capability_domains": len(compact_domains),
        "compact_code_capability_domain_targets": sum(
            len(row["target_rvas"]) for row in compact_domains
        ),
        "compact_code_capability_publications": len(compact_publications),
        "implementation_dispatch_entries": len(implementation_dispatches),
        "x87_operations": len(
            _required_list(
                payload.get("x87_operations"),
                "module-runtime typed x87 operations",
            )
        ),
        "blockers": 0,
    }
    canonical_counts = {
        key: _required_count(counts.get(key), f"module-runtime {key} count")
        for key in expected_count_fields
    }
    if canonical_counts != expected_counts:
        raise CandidateRuntimeError(
            "module-runtime plan counts differ from their exact inventories"
        )
    return (
        implementation_dispatch_receipt,
        implementation_dispatches,
        tuple(recovered_ranges),
        tuple(guest_domains),
        tuple(guest_sites),
        external_inventory,
    )


def _validate_native_termination(value: Any) -> bool:
    if value is None:
        return False
    payload = _required_object(value, "module-runtime termination import")
    _required_string(payload.get("dll"), "termination import DLL")
    symbol = payload.get("symbol")
    ordinal = payload.get("ordinal")
    if (symbol is None) == (ordinal is None):
        raise CandidateRuntimeError(
            "termination import must provide exactly one symbol or ordinal"
        )
    if symbol is not None:
        _required_string(symbol, "termination import symbol")
    else:
        _required_u32(ordinal, "termination import ordinal")
    _required_u32(payload.get("iat_va"), "termination import IAT VA")
    if (
        payload.get("transfer") != "tail_jump"
        or payload.get("argument_source") != "cdecl-stack-word-0-from-eax"
        or payload.get("required_disposition") != "terminates"
    ):
        raise CandidateRuntimeError(
            "module-runtime termination import policy is unsupported"
        )
    return True
