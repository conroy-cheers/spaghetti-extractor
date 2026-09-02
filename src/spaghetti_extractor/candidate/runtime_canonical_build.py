"""Build canonical module runtime plans from checked semantic artifacts."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.formats import (
    CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT,
    RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT,
)
from ..semantic_link.formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from ..semantic_link.module_v2 import LinkedSemanticModuleV2
from ..transfer.closure import validate_module_execution_closure_v1
from ..transfer.plan import load_executable_transfer_plan
from ..util import sha256_file
from .formats import NATIVE_INGRESS_PLAN_FORMAT
from .module_runtime_plan import (
    ModuleRuntimePlan,
    NativeExternalServiceRoute,
    NativeX87Operation,
)
from .runtime_implementation_receipt import implementation_receipt
from .runtime_canonical import (
    CanonicalRuntimeError,
    _TRANSFER_PLAN_INPUT_MODE,
    _callback_capability_index,
    _closed_content_id,
    _external_sites,
    _guest_dispatch_sites,
    _object,
    _recovered_ranges,
    _termination_import,
    guest_dispatch_from_linked_module_v2,
)


def external_service_runtime_routes_v2(
    linked_payload: Mapping[str, Any],
) -> tuple[NativeExternalServiceRoute, ...]:
    """Project checked services directly from the linked semantic module.

    This is intentionally obligation-scoped rather than external-site scoped.
    Indirect callthrough may admit thousands of loader targets at one site,
    while a checked service obligation already carries the exact service sites
    and protocol as one content-bound domain.
    """

    obligations = linked_payload.get("residual_obligations")
    if not isinstance(obligations, list):
        raise CanonicalRuntimeError(
            "linked semantic module has no residual-obligation inventory"
        )
    routes: list[NativeExternalServiceRoute] = []
    seen_obligations: set[str] = set()
    class_by_kind = {
        "nonlocal_unwind": "checked_external_nonlocal_service",
        "unhandled_exception_filter": (
            "checked_external_exception_object_service"
        ),
    }
    checked_runtime_protocols = {
        "win32-rtl-unwind-v1",
        "win32-unhandled-exception-filter-v1",
    }
    for raw_obligation in obligations:
        if not isinstance(raw_obligation, Mapping):
            raise CanonicalRuntimeError(
                "linked semantic residual obligation is malformed"
            )
        obligation_class = raw_obligation.get("class")
        if obligation_class not in {
            "checked_external_nonlocal_service",
            "checked_external_exception_object_service",
        }:
            continue
        admitted = raw_obligation.get("admitted_domain")
        protocol = (
            admitted.get("protocol")
            if isinstance(admitted, Mapping) else None
        )
        if (
            not isinstance(protocol, Mapping)
            or not isinstance(protocol.get("id"), str)
            or not isinstance(protocol.get("kind"), str)
            or protocol.get("format")
            != CHECKED_EXTERNAL_SERVICE_PROTOCOL_FORMAT
        ):
            raise CanonicalRuntimeError(
                "external-service obligation has no checked protocol"
            )
        obligation_id = raw_obligation.get("obligation_id")
        semantic_contract_sha256 = raw_obligation.get(
            "semantic_contract_sha256"
        )
        identity = admitted.get("identity") if isinstance(admitted, Mapping) else None
        sites = admitted.get("sites") if isinstance(admitted, Mapping) else None
        contract_sha256 = (
            admitted.get("contract_sha256")
            if isinstance(admitted, Mapping) else None
        )
        if (
            not isinstance(obligation_id, str)
            or not obligation_id.startswith("residual-obligation-v2:")
            or len(obligation_id.removeprefix("residual-obligation-v2:")) != 64
            or obligation_id in seen_obligations
            or not isinstance(semantic_contract_sha256, str)
            or len(semantic_contract_sha256) != 64
            or not isinstance(contract_sha256, str)
            or len(contract_sha256) != 64
            or admitted.get("kind") != "checked_external_service_protocol_v1"
            or class_by_kind.get(str(protocol["kind"])) != obligation_class
            or not isinstance(identity, Mapping)
            or not isinstance(identity.get("dll"), str)
            or not isinstance(sites, list)
            or not sites
            or any(not isinstance(site, Mapping) for site in sites)
            or raw_obligation.get("allowed_provider_kinds")
            != ["qualified_runtime"]
        ):
            raise CanonicalRuntimeError(
                "external-service obligation has no canonical runtime route"
            )
        seen_obligations.add(obligation_id)
        routes.append(NativeExternalServiceRoute(
            obligation_id=obligation_id,
            obligation_class=str(obligation_class),
            semantic_contract_sha256=semantic_contract_sha256,
            admitted_domain=dict(admitted),
            implementation=(
                "checked_runtime"
                if protocol["id"] in checked_runtime_protocols
                else "blocked"
            ),
        ))
    return tuple(sorted(routes, key=lambda row: row.obligation_id))


def external_service_runtime_blockers_v2(
    linked_payload: Mapping[str, Any],
) -> list[dict[str, Any]]:
    """Return exact blockers for checked services not yet realized natively."""

    return [
        route.blocker()
        for route in external_service_runtime_routes_v2(linked_payload)
        if not route.realized
    ]


def interface_callback_runtime_blockers_v1(
    *,
    domains: tuple[Any, ...],
    sites: tuple[Any, ...],
) -> list[dict[str, Any]]:
    """Describe interface callback callthrough not yet realized by runtime.

    Callback-bearing methods remain members of the canonical callable domain.
    The current native interface bridge cannot publish their callback
    capabilities yet, so source generation must stop with an exact method- and
    site-bound blocker rather than pruning those methods or raising an
    unstructured planner exception.
    """

    site_count_by_domain: dict[str, int] = {}
    for site in sites:
        site_count_by_domain[site.domain_sha256] = (
            site_count_by_domain.get(site.domain_sha256, 0) + 1
        )
    methods: dict[str, dict[str, Any]] = {}
    for domain in domains:
        for target in domain.external_interface_targets:
            method = target.get("method")
            method_sha256 = target.get("method_contract_sha256")
            if not isinstance(method, Mapping) or not isinstance(
                method_sha256, str
            ):
                raise CanonicalRuntimeError(
                    "interface callable domain has a malformed method"
                )
            callback_effect = method.get("callback_effect")
            if callback_effect == "none":
                continue
            if callback_effect != "explicit":
                raise CanonicalRuntimeError(
                    "interface callable domain has a malformed callback effect"
                )
            protocol = method.get("external_protocol")
            callback_abi = method.get("callback_abi")
            callback_source = method.get("callback_source")
            callback_arguments = method.get("callback_arguments")
            callback_lifetime = method.get("callback_lifetime")
            if (
                not isinstance(protocol, Mapping)
                or not isinstance(callback_abi, Mapping)
                or not isinstance(callback_source, Mapping)
                or not isinstance(callback_arguments, list)
                or not isinstance(callback_lifetime, str)
            ):
                raise CanonicalRuntimeError(
                    "interface callback method contract is incomplete"
                )
            callback_contract_sha256 = canonical_sha256_v3({
                "abi": dict(callback_abi),
                "arguments": list(callback_arguments),
                "lifetime": callback_lifetime,
                "source": dict(callback_source),
            })
            row = methods.setdefault(method_sha256, {
                "category": "interface_callback_callthrough_runtime_unsupported",
                "method_contract_sha256": method_sha256,
                "callback_contract_sha256": callback_contract_sha256,
                "profile_id": target.get("profile_id"),
                "profile_sha256": target.get("profile_sha256"),
                "interface_id": target.get("interface_id"),
                "method": protocol.get("method"),
                "callback_lifetime": callback_lifetime,
                "admitted_domain_sha256s": [],
                "site_count": 0,
                "required_realization": (
                    "checked_interface_callback_capability_publication_v1"
                ),
            })
            if (
                row["callback_contract_sha256"] != callback_contract_sha256
                or row["profile_sha256"] != target.get("profile_sha256")
                or row["interface_id"] != target.get("interface_id")
                or row["method"] != protocol.get("method")
            ):
                raise CanonicalRuntimeError(
                    "interface callback method identity is ambiguous"
                )
            row["admitted_domain_sha256s"].append(domain.domain_sha256)
            row["site_count"] += site_count_by_domain.get(
                domain.domain_sha256, 0
            )
    return [
        methods[key]
        for key in sorted(methods)
    ]


def plan_module_runtime_from_canonical(
    *,
    transfer_plan: Path,
    execution_closure: Path | Mapping[str, Any],
    resolved_external_environment: Path,
    native_ingress_plan: Path,
    recovered_executable_data: Path | None = None,
) -> ModuleRuntimePlan:
    """Compile the bridge model once from the canonical semantic universe."""

    transfer_path = Path(transfer_plan)
    transfer_payload, transfer_rows = load_executable_transfer_plan(
        transfer_path, require_complete=True
    )
    transfers = tuple(transfer_rows)
    closure_path: Path | None
    if isinstance(execution_closure, Mapping):
        closure_path = None
        closure = dict(execution_closure)
        semantic_authority_sha256 = closure.get(
            "linked_semantic_module_sha256"
        )
        if not isinstance(semantic_authority_sha256, str) or len(
            semantic_authority_sha256
        ) != 64:
            raise CanonicalRuntimeError(
                "linked execution semantics has no module identity"
            )
        raw_v2 = closure.get("_linked_semantic_module_v2")
        linked_v2 = (
            None
            if raw_v2 is None
            else LinkedSemanticModuleV2.parse(
                raw_v2, require_complete=True
            )
        )
        if (
            linked_v2 is not None
            and (
                linked_v2.payload.get("format")
                != LINKED_SEMANTIC_MODULE_V2_FORMAT
                or linked_v2.identity != semantic_authority_sha256
            )
        ):
            raise CanonicalRuntimeError(
                "linked V2 execution semantics changes module identity"
            )
    else:
        closure_path = Path(execution_closure)
        closure = _object(closure_path, "module execution closure")
        validate_module_execution_closure_v1(closure)
        semantic_authority_sha256 = sha256_file(closure_path)
        linked_v2 = None
    if closure.get("status") != "complete" or closure.get("blockers") != []:
        raise CanonicalRuntimeError("module execution closure is incomplete")
    environment_path = Path(resolved_external_environment)
    environment = _object(environment_path, "resolved external environment")
    if environment.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT:
        raise CanonicalRuntimeError("resolved external environment format is unsupported")
    _closed_content_id(
        environment, field="resolved_environment_sha256",
        label="resolved external environment",
    )
    if environment.get("status") != "complete" or environment.get("blockers") != []:
        raise CanonicalRuntimeError("resolved external environment is incomplete")
    bindings = closure["bindings"]
    expected_bindings = {
        "executable_transfer_plan_sha256": sha256_file(transfer_path),
        "resolved_external_environment_sha256": sha256_file(environment_path),
    }
    if any(bindings.get(key) != value for key, value in expected_bindings.items()):
        raise CanonicalRuntimeError(
            "module execution closure does not bind the canonical runtime inputs"
        )
    ingress_path = Path(native_ingress_plan)
    ingress = _object(ingress_path, "native ingress plan")
    if ingress.get("format") != NATIVE_INGRESS_PLAN_FORMAT:
        raise CanonicalRuntimeError("native ingress plan format is unsupported")
    ingress_id = _closed_content_id(
        ingress, field="plan_sha256", label="native ingress plan"
    )
    if ingress.get("status") != "complete" or ingress.get("blockers") != []:
        raise CanonicalRuntimeError("native ingress plan is incomplete")
    module = ingress.get("module")
    expected_ingress_bindings = {
        "executable_transfer_plan_sha256": sha256_file(transfer_path),
        "resolved_external_environment_sha256": sha256_file(environment_path),
        **({
            "linked_semantic_module_sha256": semantic_authority_sha256,
        } if closure_path is None else {
            "module_execution_closure_sha256": semantic_authority_sha256,
        }),
    }
    if not isinstance(module, Mapping) or any(
        module.get(key) != value
        for key, value in expected_ingress_bindings.items()
    ):
        raise CanonicalRuntimeError("native ingress plan binds another execution universe")
    image_base = module.get("image_base")
    if not isinstance(image_base, int) or isinstance(image_base, bool):
        raise CanonicalRuntimeError("native ingress image base is malformed")
    image_id = module.get("image_id")
    if not isinstance(image_id, str) or not image_id:
        raise CanonicalRuntimeError("native ingress image identity is malformed")
    machine_ir_sha256 = transfer_payload.get("bindings", {}).get("machine_ir_sha256")
    if not isinstance(machine_ir_sha256, str) or len(machine_ir_sha256) != 64:
        raise CanonicalRuntimeError("transfer plan machine-IR binding is malformed")
    receipt = implementation_receipt(
        transfers=transfers,
        closure=closure,
        machine_ir_sha256=machine_ir_sha256,
        closure_file_sha256=semantic_authority_sha256,
    )
    capability_authority = _callback_capability_index(
        closure=closure, ingress=ingress, image_id=image_id,
    )
    if linked_v2 is None:
        guest_dispatch_domains, guest_dispatch_sites = _guest_dispatch_sites(
            transfers=transfers,
            closure=closure,
        )
    else:
        guest_dispatch_domains, guest_dispatch_sites = (
            guest_dispatch_from_linked_module_v2(
                transfers=transfers,
                linked_module=linked_v2.payload,
            )
        )
    (
        sites,
        import_bindings,
        capability_bindings,
        registrations,
        compact_capability_domains,
        compact_capability_publications,
    ) = _external_sites(
        transfers=transfers,
        environment=environment,
        closure=closure,
        image_base=image_base,
        environment_sha256=sha256_file(environment_path),
        capability_authority=capability_authority,
        guest_dispatch_domains=guest_dispatch_domains,
        guest_dispatch_sites=guest_dispatch_sites,
    )
    # Callback-bearing interface members now pass through _external_sites only
    # after an exact checked interface-callback boundary, compact native
    # domain, and site-bound publication have all joined successfully.  That
    # join raises fail closed; retaining the former blanket blocker here would
    # reject authority that has already been realized by the common callback
    # machinery.
    interface_callback_blockers: list[dict[str, Any]] = []
    ingress_rows = ingress.get("ingresses")
    if not isinstance(ingress_rows, list):
        raise CanonicalRuntimeError("native ingress descriptors are malformed")
    module_entries = [
        row for row in ingress_rows
        if row.get("role") in {"process_entry", "dll_entry"}
    ]
    if len(module_entries) != 1:
        raise CanonicalRuntimeError("native ingress must contain one module entry")
    ingress_callback_rvas = {
        int(row["target_rva"]) for row in ingress_rows
        if row.get("role") == "callback"
    }
    compact_callback_rvas = {
        target
        for domain in compact_capability_domains
        for target in domain.target_rvas
    }
    if (
        {row.code_target_rva for row in capability_bindings}
        != ingress_callback_rvas
        or compact_callback_rvas != {
            target.target_rva
            for target in capability_authority.compact_runtime.targets
        }
    ):
        raise CanonicalRuntimeError(
            "runtime callback capabilities differ from native ingress"
        )
    x87_operations = []
    blockers: list[dict[str, Any]] = []
    blockers.extend(interface_callback_blockers)
    external_service_routes: tuple[NativeExternalServiceRoute, ...] = ()
    if linked_v2 is not None:
        external_service_routes = external_service_runtime_routes_v2(
            linked_v2.payload
        )
        blockers.extend(
            route.blocker()
            for route in external_service_routes
            if not route.realized
        )
        service_site_keys: set[tuple[str, int, int]] = set()
        external_site_keys = {
            (site.transfer_id, site.instruction_rva, site.event_index): site
            for site in sites
        }
        for route in external_service_routes:
            identity = route.admitted_domain["identity"]
            for service_site in route.admitted_domain["sites"]:
                key = (
                    str(service_site["transfer_id"]),
                    int(service_site["instruction_rva"]),
                    int(service_site["call_id"]),
                )
                external_site = external_site_keys.get(key)
                if (
                    key in service_site_keys
                    or external_site is None
                    or external_site.dll is None
                    or external_site.dll.lower() != str(identity["dll"]).lower()
                    or external_site.symbol != identity.get("symbol")
                    or external_site.ordinal != identity.get("ordinal")
                ):
                    raise CanonicalRuntimeError(
                        "external-service route site is duplicate, stale, or "
                        "not bound to its checked external call"
                    )
                service_site_keys.add(key)
    termination_import = _termination_import(
        environment=environment, image_base=image_base,
    )
    if (
        module_entries[0].get("role") == "process_entry"
        and termination_import is None
    ):
        blockers.append({
            "category": "process_entry_termination_support_missing",
            "role": "process_entry",
            "detail": (
                "process entry outcomes require one resolved process-termination "
                "support import"
            ),
        })
    for transfer in sorted(transfers, key=lambda item: item.rva_start):
        for operation in transfer.x87_operations:
            absolute = operation.operation.operand.image_rva
            x87_operations.append(NativeX87Operation(
                id=len(x87_operations),
                transfer_id=transfer.identity,
                contract_sha256=operation.contract_sha256,
                image_base=operation.image_base,
                rva_start=operation.rva_start,
                rva_end=operation.rva_end,
                operation=operation.operation,
                target_rva=absolute,
                # The reviewed renderer emits ``___ImageBase + RVA``.  This
                # creates a normal linker relocation in the runtime object;
                # native realization must bind that relocation in its exact
                # linked inventory before deployment.  Source generation does
                # not need the not-yet-created linked relocation inventory.
                fixed_image_base=(operation.image_base if absolute is not None else None),
            ))
    return ModuleRuntimePlan(
        input_mode=_TRANSFER_PLAN_INPUT_MODE,
        native_ingress_plan_id=ingress_id,
        transfer_count=len(transfers),
        guest_dispatch_domains=guest_dispatch_domains,
        guest_dispatch_sites=guest_dispatch_sites,
        external_sites=sites,
        external_service_routes=external_service_routes,
        import_bindings=import_bindings,
        code_capability_bindings=capability_bindings,
        code_capability_registrations=registrations,
        compact_code_capability_domains=compact_capability_domains,
        compact_code_capability_publications=compact_capability_publications,
        implementation_dispatch_receipt=receipt,
        x87_operations=tuple(x87_operations),
        termination_import=termination_import,
        recovered_executable_data_ranges=_recovered_ranges(
            path=recovered_executable_data,
            transfer_payload=transfer_payload,
            image_base=image_base,
        ),
        blockers=tuple(blockers),
    )
