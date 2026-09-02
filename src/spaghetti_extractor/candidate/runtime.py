"""Generate the shared behavioral-C module runtime package."""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any, Mapping

from ..transfer.plan import load_executable_transfer_plan
from ..transfer.closure import validate_module_execution_closure_v1
from ..transfer.model import TransferPlanError
from ..artifacts.artifact_set import canonical_sha256_v3
from ..external.machine_import_profiles import (
    MachineImportProfileError,
    load_machine_import_profile_set,
)
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..semantic_objects.object_authority import (
    MachineObjectAuthorityError,
    MachineObjectAuthorityV2,
)
from ..semantic_link.errors import LinkedSemanticModuleError
from ..semantic_link.formats import LINKED_SEMANTIC_MODULE_V2_FORMAT
from ..semantic_link.module_v2 import (
    LinkedSemanticModuleV2,
    linked_execution_view_v2,
)
from ..util import sha256_file, write_json
from .formats import (
    BEHAVIORAL_C_PACKAGE_FORMAT,
    NATIVE_INGRESS_PLAN_FORMAT,
    SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
)
from .runtime_model import (
    DEFINEDNESS_USE_FORMAT,
    NATIVE_RUNTIME_BINDINGS_FILENAME,
    NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME,
    NATIVE_RUNTIME_HEADER_FILENAME,
    NATIVE_RUNTIME_MANIFEST_FILENAME,
    NATIVE_RUNTIME_OBJECT_AUTHORITY_FILENAME,
    NATIVE_RUNTIME_SOURCE_FILENAME,
    SharedModuleRuntimePlan,
    NativeExternalRangeRule,
    NativeNonlocalTransition,
    NativeObjectAuthorityRule,
    NativeUndefinedPolicy,
    CandidateRuntimeError,
)
from .runtime_external_range_validation import _external_range_rules
from .runtime_plan_validation import (
    _validate_native_plan,
    _validate_native_termination,
)
from .runtime_program_validation import (
    _validate_typed_x87_operations,
    validate_transfer_plan_runtime_metadata,
)
from .runtime_render import (
    _native_runtime_bindings_source,
    _native_runtime_header,
    _native_runtime_source,
)
from .runtime_values import (
    _manifest_path,
    _read_json_object,
    _required_list,
    _required_object,
    _required_sha256,
    _verify_artifact_inventory,
)


def _bind_dynamic_external_object_rules(
    object_rules: list[NativeObjectAuthorityRule],
    external_range_rules: tuple[NativeExternalRangeRule, ...],
    blockers: list[dict[str, Any]],
) -> list[NativeObjectAuthorityRule]:
    """Bind allocation/resource locators to one checked range contract."""

    allocation_contracts: dict[str, list[int]] = {}
    for index, range_rule in enumerate(external_range_rules):
        if range_rule.action in {
            "add_result_range",
            "add_result_pointee_ranges",
            "add_argument_pointee_ranges",
            "add_argument_interface_ranges",
        }:
            allocation_contracts.setdefault(range_rule.contract_id, []).append(
                index + 1
            )
    resolved: list[NativeObjectAuthorityRule] = []
    for rule in object_rules:
        if rule.locator_kind not in {"external_allocation", "resource"}:
            resolved.append(rule)
            continue
        matches = allocation_contracts.get(rule.locator_identity, [])
        if len(matches) != 1:
            blockers.append({
                "category": (
                    "runtime_external_allocation_locator_unresolved"
                    if rule.locator_kind == "external_allocation"
                    else "runtime_resource_locator_unresolved"
                ),
                "rule_id": rule.identity,
                "allocation_id": rule.locator_identity,
                "matching_range_rules": len(matches),
            })
            resolved.append(rule)
            continue
        resolved.append(replace(rule, locator_subject_rva=matches[0]))
    allocation_authorities: dict[int, list[int]] = {}
    for index, rule in enumerate(resolved):
        if (
            rule.locator_kind in {"external_allocation", "resource"}
            and rule.locator_subject_rva != 0
        ):
            allocation_authorities.setdefault(
                rule.locator_subject_rva, []
            ).append(index)
    ambiguous = {
        index
        for indexes in allocation_authorities.values()
        if len(indexes) != 1
        for index in indexes
    }
    for index in sorted(ambiguous):
        rule = resolved[index]
        blockers.append({
            "category": (
                "runtime_external_allocation_authority_ambiguous"
                if rule.locator_kind == "external_allocation"
                else "runtime_resource_authority_ambiguous"
            ),
            "rule_id": rule.identity,
            "allocation_id": rule.locator_identity,
        })
        resolved[index] = replace(rule, locator_subject_rva=0)
    return resolved


def plan_shared_module_runtime(
    *,
    behavioral_c_package: Path | str,
    transfer_plan: Path | str,
    runtime_plan: Path | str,
    native_ingress_plan: Path | str,
    execution_closure: Path | str | Mapping[str, Any],
    resolved_external_environment: Path | str,
    object_authority: Path | str,
    external_profile: Path | str | None = None,
) -> SharedModuleRuntimePlan:
    """Validate and bind one exact behavioral-C backend and canonical runtime plan."""
    backend_manifest_path = _manifest_path(
        behavioral_c_package,
        "behavioral-c-package.json",
        "behavioral-C package",
    )
    backend = _read_json_object(
        backend_manifest_path, "behavioral-C package manifest"
    )
    if (
        backend.get("format") != BEHAVIORAL_C_PACKAGE_FORMAT
        or backend.get("status") != "ready"
        or backend.get("blockers") != []
    ):
        raise CandidateRuntimeError("behavioral-C lowering package is not ready")
    executable_plan_path = Path(transfer_plan)
    transfer_payload, checked_transfers = load_executable_transfer_plan(
        executable_plan_path, require_complete=True
    )
    transfer_binding = _required_object(
        backend.get("executable_transfer_plan"),
        "behavioral-C executable transfer plan",
    )
    if (
        transfer_binding.get("sha256") != sha256_file(executable_plan_path)
        or transfer_binding.get("plan_sha256")
        != transfer_payload.get("plan_sha256")
    ):
        raise CandidateRuntimeError("behavioral-C transfer-plan binding is stale")
    state_machine_sha256 = _required_sha256(
        transfer_payload.get("bindings", {}).get("machine_ir_sha256"),
        "behavioral-C machine-IR SHA-256",
    )
    (
        transfer_rvas,
        transfer_bindings,
        undefined_policies,
        definedness_metadata_sha256,
    ) = validate_transfer_plan_runtime_metadata(
        transfer_payload, checked_transfers
    )
    backend_kind = "generated_behavioral_c"
    execution_closure_path: Path | None
    if isinstance(execution_closure, Mapping):
        execution_closure_path = None
        closure_payload = dict(execution_closure)
        linked_semantic_module_sha256 = closure_payload.get(
            "linked_semantic_module_sha256"
        )
        if not isinstance(linked_semantic_module_sha256, str) or len(
            linked_semantic_module_sha256
        ) != 64:
            raise CandidateRuntimeError(
                "linked execution semantics has no module identity"
            )
        execution_semantics_sha256 = str(
            closure_payload.get("source_execution_closure_sha256")
            or linked_semantic_module_sha256
        )
        if len(execution_semantics_sha256) != 64:
            raise CandidateRuntimeError(
                "linked execution semantics identity is malformed"
            )
    else:
        execution_closure_path = Path(execution_closure)
        linked_semantic_module_sha256 = None
        closure_payload = _read_json_object(
            execution_closure_path, "module execution closure"
        )
        try:
            validate_module_execution_closure_v1(closure_payload)
        except TransferPlanError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        execution_semantics_sha256 = sha256_file(execution_closure_path)
    if closure_payload["bindings"].get(
        "executable_transfer_plan_sha256"
    ) != sha256_file(executable_plan_path):
        raise CandidateRuntimeError(
            "module execution closure does not bind the exact transfer plan"
        )
    nonlocal_transitions = tuple(
        NativeNonlocalTransition(
            identity=str(row["id"]),
            source_rva=int(row["source_rva"]),
            target_rva=int(row["target_rva"]),
            target_function_entry_rva=int(
                row["target_function_entry_rva"]
            ),
        )
        for row in closure_payload["nonlocal_transitions"]
    )
    route_targets: dict[tuple[int, int], set[int]] = {}
    for transition in nonlocal_transitions:
        route_targets.setdefault(
            (transition.source_rva, transition.target_rva), set()
        ).add(transition.target_function_entry_rva)
    ambiguous_routes = {
        route: sorted(targets)
        for route, targets in route_targets.items()
        if len(targets) != 1
    }
    if ambiguous_routes:
        raise CandidateRuntimeError(
            "module execution closure has context-ambiguous nonlocal routes: "
            f"{ambiguous_routes!r}"
        )
    sources = _verify_artifact_inventory(
        backend_manifest_path.parent,
        backend.get("sources"),
        "behavioral-C source",
        require_role=True,
    )
    runtime_header_path = sources.get("runtime_header")
    if runtime_header_path is None:
        raise CandidateRuntimeError("semantic backend has no runtime_header role")
    try:
        runtime_header = runtime_header_path.read_text(encoding="ascii")
    except (OSError, UnicodeError) as exc:
        raise CandidateRuntimeError("cannot read the bound runtime header") from exc
    backend_has_typed_x87_abi = "execute_typed_x87_operation" in runtime_header

    native_plan_path = Path(runtime_plan)
    native_plan = _read_json_object(
        native_plan_path, "canonical module runtime plan"
    )
    native_input_mode = str(native_plan.get("input_mode"))
    if native_plan.get("state_machine_sha256") != state_machine_sha256:
        raise CandidateRuntimeError(
            "behavioral backend and canonical runtime plan bind different semantic inputs"
        )
    ingress_plan_path = Path(native_ingress_plan)
    ingress_payload = _read_json_object(ingress_plan_path, "native ingress plan")
    ingress_core = {
        key: value for key, value in ingress_payload.items()
        if key != "plan_sha256"
    }
    if (
        ingress_payload.get("format") != NATIVE_INGRESS_PLAN_FORMAT
        or ingress_payload.get("status") != "complete"
        or ingress_payload.get("plan_sha256") != canonical_sha256_v3(ingress_core)
        or (
        )
    ):
        raise CandidateRuntimeError("native ingress plan is stale or incomplete")
    raw_ingresses = ingress_payload.get("ingresses")
    if not isinstance(raw_ingresses, list) or any(
        not isinstance(row, dict) for row in raw_ingresses
    ):
        raise CandidateRuntimeError("native ingress descriptor inventory is malformed")
    ingress_plan_sha256 = sha256_file(ingress_plan_path)
    ingress_plan_id = str(ingress_payload["plan_sha256"])
    ingress_descriptors = tuple(dict(row) for row in raw_ingresses)
    raw_callback_domains = ingress_payload.get("callback_domains", [])
    raw_callback_publications = ingress_payload.get(
        "callback_publications", []
    )
    if (
        not isinstance(raw_callback_domains, list)
        or any(not isinstance(row, dict) for row in raw_callback_domains)
        or not isinstance(raw_callback_publications, list)
        or any(not isinstance(row, dict) for row in raw_callback_publications)
    ):
        raise CandidateRuntimeError(
            "native ingress compact callback inventory is malformed"
        )
    ingress_callback_domains = tuple(
        dict(row) for row in raw_callback_domains
    )
    ingress_callback_publications = tuple(
        dict(row) for row in raw_callback_publications
    )
    raw_tls_layout = ingress_payload.get("tls_layout")
    requirements = ingress_payload.get("runtime_requirements")
    if not isinstance(raw_tls_layout, dict) or not isinstance(requirements, dict):
        raise CandidateRuntimeError("native ingress runtime layout is malformed")
    raw_features = requirements.get("features")
    if not isinstance(raw_features, list) or any(
        not isinstance(item, str) or not item for item in raw_features
    ):
        raise CandidateRuntimeError("native ingress runtime feature inventory is malformed")
    ingress_tls_layout = dict(raw_tls_layout)
    ingress_runtime_features = tuple(raw_features)

    resolved_environment_path = Path(resolved_external_environment)
    resolved_environment_payload = _read_json_object(
        resolved_environment_path, "resolved external environment"
    )
    if (
        resolved_environment_payload.get("format")
        != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
        or resolved_environment_payload.get("status") != "complete"
        or resolved_environment_payload.get("blockers") != []
    ):
        raise CandidateRuntimeError("resolved external environment is incomplete")
    resolved_environment_sha256 = sha256_file(resolved_environment_path)

    object_authority_path = Path(object_authority)
    object_authority_payload = _read_json_object(
        object_authority_path, "machine object authority V2"
    )
    try:
        parsed_object_authority = MachineObjectAuthorityV2.parse(
            object_authority_payload
        )
    except MachineObjectAuthorityError as exc:
        raise CandidateRuntimeError(str(exc)) from exc
    ingress_authority_id = ingress_payload.get("module", {}).get(
        "object_authority_sha256"
    )
    if ingress_authority_id != parsed_object_authority.authority_sha256:
        raise CandidateRuntimeError(
            "native ingress and shared runtime bind different object authority"
        )
    module_image_id = ingress_payload.get("module", {}).get("image_id")
    runtime_regions = ingress_tls_layout.get("runtime_regions")
    if not isinstance(runtime_regions, dict) or not runtime_regions:
        raise CandidateRuntimeError("native ingress TLS region inventory is malformed")
    try:
        tls_total_bytes = int(ingress_tls_layout["runtime_offset"]) + max(
            int(region["offset"]) + int(region["extent"])
            for region in runtime_regions.values()
            if isinstance(region, dict)
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise CandidateRuntimeError(
            "native ingress TLS region geometry is malformed"
        ) from exc
    object_authority_rules: list[NativeObjectAuthorityRule] = []
    object_authority_blockers: list[dict[str, Any]] = []
    physical_frame_ids = tuple(sorted({
        str(row.get("physical_frame_id"))
        for row in ingress_descriptors
        if isinstance(row.get("physical_frame_id"), str)
        and row.get("physical_frame_id")
    }))
    physical_frame_selectors = {
        identity: index + 1
        for index, identity in enumerate(physical_frame_ids)
    }
    resolved_import_slots: dict[str, int] = {}
    raw_import_contracts = resolved_environment_payload.get(
        "machine_import_contracts"
    )
    if isinstance(raw_import_contracts, list):
        for contract in raw_import_contracts:
            if not isinstance(contract, dict):
                continue
            iat_rva = contract.get("iat_rva")
            if (
                isinstance(iat_rva, int)
                and not isinstance(iat_rva, bool)
                and 0 < iat_rva <= 0xFFFFFFFF
            ):
                resolved_import_slots[
                    f"{module_image_id}:iat:{iat_rva:08x}"
                ] = iat_rva
    for rule in parsed_object_authority.rules:
        locator = rule.locator
        locator_subject_rva = 0
        if locator.kind not in {
            "image_rva", "tls_offset", "resolved_data_import",
            "captured_stack", "external_allocation", "resource",
        }:
            object_authority_blockers.append({
                "category": "runtime_object_locator_unsupported",
                "rule_id": rule.identity,
                "locator_kind": locator.kind,
            })
        elif (
            locator.kind in {"image_rva", "tls_offset"}
            and locator.identity != module_image_id
        ):
            object_authority_blockers.append({
                "category": "runtime_object_locator_identity_mismatch",
                "rule_id": rule.identity,
                "locator_kind": locator.kind,
                "locator_identity": locator.identity,
                "module_image_id": module_image_id,
            })
        elif locator.kind == "resolved_data_import":
            locator_subject_rva = resolved_import_slots.get(locator.identity, 0)
            if locator_subject_rva == 0:
                object_authority_blockers.append({
                    "category": "runtime_data_import_locator_unresolved",
                    "rule_id": rule.identity,
                    "slot_id": locator.identity,
                })
        elif locator.kind == "captured_stack":
            locator_subject_rva = physical_frame_selectors.get(
                locator.identity, 0
            )
            if locator_subject_rva == 0:
                object_authority_blockers.append({
                    "category": "runtime_captured_stack_frame_unresolved",
                    "rule_id": rule.identity,
                    "frame_id": locator.identity,
                })
            if rule.kind != "stack" or rule.lifetime != "invocation":
                object_authority_blockers.append({
                    "category": "runtime_captured_stack_policy_unsupported",
                    "rule_id": rule.identity,
                    "object_kind": rule.kind,
                    "lifetime": rule.lifetime,
                })
        elif locator.kind == "external_allocation":
            if rule.kind != "external" or rule.lifetime != "allocation":
                object_authority_blockers.append({
                    "category": "runtime_external_allocation_policy_unsupported",
                    "rule_id": rule.identity,
                    "object_kind": rule.kind,
                    "lifetime": rule.lifetime,
                })
        elif locator.kind == "resource":
            if rule.kind != "resource" or rule.lifetime != "resource":
                object_authority_blockers.append({
                    "category": "runtime_resource_policy_unsupported",
                    "rule_id": rule.identity,
                    "object_kind": rule.kind,
                    "lifetime": rule.lifetime,
                })
        if rule.permissions > 0xFFFFFFFF:
            object_authority_blockers.append({
                "category": "runtime_object_permission_width_unsupported",
                "rule_id": rule.identity,
                "permissions": rule.permissions,
            })
        if (
            locator.kind == "tls_offset"
            and (
                locator.offset > tls_total_bytes
                or rule.extent > tls_total_bytes - locator.offset
            )
        ):
            object_authority_blockers.append({
                "category": "runtime_tls_object_out_of_bounds",
                "rule_id": rule.identity,
                "locator_offset": locator.offset,
                "extent": rule.extent,
                "tls_total_bytes": tls_total_bytes,
            })
        object_authority_rules.append(NativeObjectAuthorityRule(
            identity=rule.identity,
            domain=rule.domain,
            object_id=rule.object_id,
            generation=rule.generation,
            extent=rule.extent,
            permissions=rule.permissions,
            lifetime=rule.lifetime,
            locator_kind=locator.kind,
            locator_identity=locator.identity,
            locator_offset=locator.offset,
            locator_subject_rva=locator_subject_rva,
            interior_pointers=rule.interior_pointers,
        ))
    operations = _required_list(
        native_plan.get("x87_operations"), "module-runtime typed x87 operations"
    )
    _validate_typed_x87_operations(operations)
    x87_handler_mode = "typed" if operations else "none"
    if x87_handler_mode == "typed" and not backend_has_typed_x87_abi:
        raise CandidateRuntimeError(
            "module-runtime typed x87 operations require the behavioral backend typed ABI"
        )
    (
        implementation_dispatch_receipt,
        implementation_dispatches,
        recovered_executable_data_ranges,
        guest_dispatch_domains,
        guest_dispatch_sites,
        _validated_external_inventory,
    ) = _validate_native_plan(
        native_plan,
        state_machine_sha256=state_machine_sha256,
        input_mode=native_input_mode,
        transfer_rvas=transfer_rvas,
        transfer_bindings=transfer_bindings,
        ingress_descriptors=ingress_descriptors,
        ingress_callback_domains=ingress_callback_domains,
        ingress_callback_publications=ingress_callback_publications,
        ingress_plan_id=ingress_plan_id,
    )
    has_modeled_termination = _validate_native_termination(
        native_plan.get("termination_import")
    )
    external_profile_path = (
        None if external_profile is None else Path(external_profile).resolve()
    )
    if external_profile_path is None:
        external_profile_graph: tuple[tuple[Path, str, str], ...] = ()
    else:
        try:
            profile_set = load_machine_import_profile_set([external_profile_path])
        except MachineImportProfileError as exc:
            raise CandidateRuntimeError(str(exc)) from exc
        profile_root = external_profile_path.parent
        graph: list[tuple[Path, str, str]] = []
        for profile in profile_set.profiles:
            try:
                profile.path.relative_to(profile_root)
            except ValueError as exc:
                raise CandidateRuntimeError(
                    "external profile includes must remain beneath the root profile directory"
                ) from exc
            graph.append((profile.path, profile.profile_id, profile.sha256))
        external_profile_graph = tuple(graph)
    (
        external_range_rules,
        authorized_external_site_rvas,
        blocked_external_sites,
    ) = _external_range_rules(
        native_plan,
        external_profile_path,
        resolved_environment_sha256=resolved_environment_sha256,
        guest_dispatch_domains=guest_dispatch_domains,
        external_inventory=_validated_external_inventory,
    )
    object_authority_rules = _bind_dynamic_external_object_rules(
        object_authority_rules,
        external_range_rules,
        object_authority_blockers,
    )

    return SharedModuleRuntimePlan(
        transfer_rvas=transfer_rvas,
        guest_dispatch_domains=guest_dispatch_domains,
        guest_dispatch_sites=guest_dispatch_sites,
        nonlocal_transitions=nonlocal_transitions,
        recovered_executable_data_ranges=recovered_executable_data_ranges,
        implementation_dispatch_receipt=implementation_dispatch_receipt,
        implementation_dispatches=implementation_dispatches,
        external_range_rules=external_range_rules,
        authorized_external_site_rvas=authorized_external_site_rvas,
        blocked_external_sites=blocked_external_sites,
        external_profile_path=external_profile_path,
        external_profile_sha256=(
            None
            if external_profile_path is None
            else sha256_file(external_profile_path)
        ),
        external_profile_graph=external_profile_graph,
        undefined_policies=undefined_policies,
        definedness_metadata_sha256=definedness_metadata_sha256,
        state_machine_sha256=state_machine_sha256,
        semantic_backend_kind=backend_kind,
        semantic_backend_manifest_path=backend_manifest_path,
        semantic_backend_manifest_sha256=sha256_file(backend_manifest_path),
        executable_plan_path=executable_plan_path,
        executable_plan_sha256=sha256_file(executable_plan_path),
        module_runtime_plan_path=native_plan_path,
        module_runtime_plan_sha256=sha256_file(native_plan_path),
        native_ingress_plan_path=ingress_plan_path,
        native_ingress_plan_sha256=ingress_plan_sha256,
        ingress_descriptors=ingress_descriptors,
        ingress_tls_layout=ingress_tls_layout,
        ingress_runtime_features=ingress_runtime_features,
        x87_handler_mode=x87_handler_mode,
        has_modeled_termination=has_modeled_termination,
        execution_closure_path=execution_closure_path,
        execution_closure_sha256=execution_semantics_sha256,
        linked_semantic_module_sha256=linked_semantic_module_sha256,
        resolved_environment_path=resolved_environment_path,
        resolved_environment_sha256=resolved_environment_sha256,
        object_authority_path=object_authority_path,
        object_authority_sha256=sha256_file(object_authority_path),
        object_authority_id=parsed_object_authority.authority_sha256,
        object_authority_rules=tuple(object_authority_rules),
        object_authority_blockers=tuple(object_authority_blockers),
    )


def write_shared_module_runtime_package(
    *,
    behavioral_c_package: Path | str,
    transfer_plan: Path | str,
    execution_closure: Path | str | Mapping[str, Any],
    resolved_external_environment: Path | str,
    native_ingress_plan: Path | str,
    object_authority: Path | str,
    recovered_executable_data: Path | str | None = None,
    external_profile: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Write deterministic freestanding runtime sources and their manifest."""

    out_path = Path(out)
    out_path.mkdir(parents=True, exist_ok=True)
    canonical_source_rows: list[dict[str, Any]] = []
    from .runtime_sources import render_canonical_runtime_sources

    _core_plan, _ingress, _transfer, canonical_sources = (
        render_canonical_runtime_sources(
            transfer_plan=Path(transfer_plan),
            execution_closure=(
                dict(execution_closure)
                if isinstance(execution_closure, Mapping)
                else Path(execution_closure)
            ),
            resolved_external_environment=Path(resolved_external_environment),
            native_ingress_plan=Path(native_ingress_plan),
            out=out_path,
            recovered_executable_data=(
                None
                if recovered_executable_data is None
                else Path(recovered_executable_data)
            ),
        )
    )
    if _core_plan.status != "ready":
        blockers = [dict(row) for row in _core_plan.blockers]
        result = {
            "format": SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
            "status": "incomplete",
            "acceptance_authority": False,
            "inputs": {
                "module_runtime_plan": {
                    "path": "module-runtime-plan.json",
                    "sha256": sha256_file(
                        out_path / "module-runtime-plan.json"
                    ),
                },
                "native_ingress_plan": {
                    "path": "native-ingress-plan.json",
                    "sha256": sha256_file(
                        out_path / "native-ingress-plan.json"
                    ),
                },
            },
            "sources": [
                {
                    "role": "module_runtime_plan",
                    "path": "module-runtime-plan.json",
                    "sha256": sha256_file(
                        out_path / "module-runtime-plan.json"
                    ),
                },
                {
                    "role": "native_ingress_plan",
                    "path": "native-ingress-plan.json",
                    "sha256": sha256_file(
                        out_path / "native-ingress-plan.json"
                    ),
                },
            ],
            "counts": {"blockers": len(blockers)},
            "blockers": blockers,
            "policy": {
                "realization": "fail_closed_before_source_generation",
                "native_ingress": "internal_lowering_member",
            },
            "authority": (
                "candidate generation only; candidate assurance remains required"
            ),
        }
        write_json(out_path / NATIVE_RUNTIME_MANIFEST_FILENAME, result)
        return result
    plan = plan_shared_module_runtime(
        behavioral_c_package=behavioral_c_package,
        transfer_plan=transfer_plan,
        runtime_plan=out_path / "module-runtime-plan.json",
        native_ingress_plan=out_path / "native-ingress-plan.json",
        execution_closure=execution_closure,
        resolved_external_environment=resolved_external_environment,
        object_authority=object_authority,
        external_profile=external_profile,
    )
    canonical_source_rows = [
        {"role": role, "path": path.name, "sha256": sha256_file(path)}
        for role, path in canonical_sources
        if role != "native_ingress_header"
    ]
    canonical_source_rows.extend((
        {
            "role": "module_runtime_plan",
            "path": "module-runtime-plan.json",
            "sha256": sha256_file(out_path / "module-runtime-plan.json"),
        },
        {
            "role": "native_ingress_plan",
            "path": "native-ingress-plan.json",
            "sha256": sha256_file(out_path / "native-ingress-plan.json"),
        },
    ))
    header_path = out_path / NATIVE_RUNTIME_HEADER_FILENAME
    source_path = out_path / NATIVE_RUNTIME_SOURCE_FILENAME
    bindings_path = out_path / NATIVE_RUNTIME_BINDINGS_FILENAME
    ingress_header_path = out_path / "native-ingress-runtime.h"
    header_path.write_text(_native_runtime_header(), encoding="ascii")
    source_path.write_text(_native_runtime_source(plan), encoding="ascii")
    bindings_path.write_text(_native_runtime_bindings_source(plan), encoding="ascii")
    authority_path = out_path / NATIVE_RUNTIME_OBJECT_AUTHORITY_FILENAME
    try:
        authority_path.write_bytes(plan.object_authority_path.read_bytes())
    except OSError as exc:
        raise CandidateRuntimeError(
            "cannot copy machine object authority into the runtime package"
        ) from exc
    if sha256_file(authority_path) != plan.object_authority_sha256:
        raise CandidateRuntimeError(
            "copied machine object authority SHA-256 mismatch"
        )
    profile_source: dict[str, Any] | None = None
    profile_dependencies: list[dict[str, Any]] = []
    if plan.external_profile_path is not None:
        profile_path = out_path / NATIVE_RUNTIME_EXTERNAL_PROFILE_FILENAME
        try:
            profile_path.write_bytes(plan.external_profile_path.read_bytes())
        except OSError as exc:
            raise CandidateRuntimeError(
                "cannot copy the external environment profile into the runtime package"
            ) from exc
        if sha256_file(profile_path) != plan.external_profile_sha256:
            raise CandidateRuntimeError(
                "copied external environment profile SHA-256 mismatch"
            )
        profile_source = {
            "role": "external_profile",
            "path": profile_path.name,
            "sha256": plan.external_profile_sha256,
        }
        profile_root = plan.external_profile_path.parent
        for index, (source, _profile_id, expected_sha256) in enumerate(
            plan.external_profile_graph
        ):
            if source == plan.external_profile_path:
                continue
            relative = source.relative_to(profile_root)
            target = out_path / relative
            if target.exists():
                raise CandidateRuntimeError(
                    f"included external profile collides with package artifact {relative}"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                target.write_bytes(source.read_bytes())
            except OSError as exc:
                raise CandidateRuntimeError(
                    "cannot copy an included external profile into the runtime package"
                ) from exc
            if sha256_file(target) != expected_sha256:
                raise CandidateRuntimeError(
                    "copied included external profile SHA-256 mismatch"
                )
            profile_dependencies.append({
                "role": f"external_profile_dependency_{index:03d}",
                "path": str(relative),
                "sha256": expected_sha256,
            })
    implemented_feature_set = {
            "checked_exception_object_resumption_v1",
            "checked_process_root_termination_v1",
            "checked_seh_gateway_v1",
            "checked_transfer_unwind_effects_v1",
            "code_capability_registry_v1",
            "compact_callback_domains_v1",
            "exceptional_outcome_dispatch_v1",
            "host_thread_concurrency_v1",
            "loader_lifecycle_generations_v1",
            "loader_lock_safe_bootstrap_v1",
            "outgoing_bridge_pe_tls_state_v1",
            "per_thread_ingress_frame_chain_v1",
            "physical_boundary_lifecycle_transducer_v1",
            "same_thread_reentrancy_v1",
            "seh_unwind_frame_cleanup_v1",
            "tls_private_stack_v1",
            "transactional_boundary_writeback_v1",
        }
    required_base_features = {
        "code_capability_registry_v1",
        "host_thread_concurrency_v1",
        "loader_lock_safe_bootstrap_v1",
        "outgoing_bridge_pe_tls_state_v1",
        "per_thread_ingress_frame_chain_v1",
        "same_thread_reentrancy_v1",
        "tls_private_stack_v1",
        "transactional_boundary_writeback_v1",
    }
    implemented_ingress_features = sorted(
        set(plan.ingress_runtime_features) & implemented_feature_set
    )
    native_ingress_blockers = [
        dict(blocker) for blocker in plan.object_authority_blockers
    ]
    declared = set(plan.ingress_runtime_features)
    for feature in sorted(required_base_features - declared):
        native_ingress_blockers.append({
            "category": "native_ingress_required_runtime_feature_missing",
            "feature": feature,
        })
    for feature in sorted(declared - implemented_feature_set):
        native_ingress_blockers.append({
            "category": "native_ingress_runtime_feature_unimplemented",
            "feature": feature,
        })
    result = {
        "format": SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
        "status": "ready" if not native_ingress_blockers else "incomplete",
        "acceptance_authority": False,
        "inputs": plan.payload(),
        "sources": [
            {
                "role": "shared_module_runtime_header",
                "path": header_path.name,
                "sha256": sha256_file(header_path),
            },
            {
                "role": "shared_module_runtime_source",
                "path": source_path.name,
                "sha256": sha256_file(source_path),
            },
            {
                "role": "shared_module_runtime_bindings_source",
                "path": bindings_path.name,
                "sha256": sha256_file(bindings_path),
            },
            {
                "role": "native_ingress_runtime_header",
                "path": ingress_header_path.name,
                "sha256": sha256_file(ingress_header_path),
            },
            {
                "role": "machine_object_authority",
                "path": authority_path.name,
                "sha256": plan.object_authority_sha256,
            },
        ] + canonical_source_rows + (
            [] if profile_source is None else [profile_source]
        ) + profile_dependencies,
        "counts": {
            "transfers": len(plan.transfer_rvas),
            "guest_dispatch_domains": len(plan.guest_dispatch_domains),
            "guest_dispatch_sites": len(plan.guest_dispatch_sites),
            "guest_dispatch_domain_targets": sum(
                len(domain.target_rvas)
                for domain in plan.guest_dispatch_domains
            ),
            "implementation_dispatches": len(plan.implementation_dispatches),
            "nonlocal_transitions": len(plan.nonlocal_transitions),
            "authorized_external_sites": len(
                plan.authorized_external_site_rvas
            ),
            "blocked_external_sites": len(plan.blocked_external_sites),
            "object_authority_rules": len(plan.object_authority_rules),
        },
        "blockers": native_ingress_blockers,
        "policy": {
            "architecture": "i686-pe32",
            "execution_scope": "module-execution-closure-v2",
            "freestanding": True,
            "structural_execution_receipt_required": False,
            "implementation_dispatch": (
                "exact-linked-class-per-executable-transfer-v1"
            ),
            "flat_memory": "exact-little-endian-widths-1-2-4",
            "read_domains": (
                "checked-image-headers-and-sections; captured-stack; "
                "read-only-4KiB-teb-window-at-captured-fs-base; "
                "bounded-profile-derived-external-ranges"
            ),
            "undefined_values": (
                "hash-bound-zero-only-after-semantic-noninterference; "
                "synchronized-slots-use-a-checked-instruction-local-input-expression; "
                "unknown-or-unsupported-slots-latch-unimplemented"
            ),
            "code_targets": (
                "absolute-image-va-in-exact-site-scoped-closure-target-set; "
                "native-capabilities-only-for-canonical-external-sites"
            ),
            "threads": "pe-tls-ingress-and-outgoing-frame-state; host-thread-concurrent",
            "native_ingress": {
                "features": implemented_ingress_features,
                "private_stack_bytes": int(
                    plan.ingress_tls_layout["private_stack_bytes"]
                ),
                "qualification": "complete PE-TLS generic ingress runtime",
            },
            "object_references": (
                "exact-machine-object-authority-v2; image-rva, module-tls, and "
                "loader-written-data-IAT, captured-stack, and checked-external-"
                "allocation/resource realization; unsupported-locators-fail-closed"
            ),
            "private_stack": "checked-PE-TLS-private-stack-disjoint-from-modeled-program-stack",
            "executable_writes": (
                "only-checked-nonexecuting-image-sections, captured-stack, or "
                "bounded-profile-derived-external-ranges"
            ),
            "external_ranges": (
                "machine-call-profile-bound-result-and-release-rules; "
                "8192-live-range-limit; bounded-profile-declared-pointee-shapes; "
                "overflow-and-missing-arguments-fail-closed"
            ),
            "terminal_control": (
                "record-status-and-modeled-environment-termination"
                if plan.has_modeled_termination
                else "record-status-and-unsupported-native-halt"
            ),
        },
        "authority": "candidate generation only; candidate assurance remains required",
    }
    write_json(out_path / NATIVE_RUNTIME_MANIFEST_FILENAME, result)
    return result


def write_shared_module_runtime_package_from_linked_module(
    *,
    linked_semantic_module: Path | str,
    behavioral_c_package: Path | str,
    pinned_layout_authorities: tuple[Mapping[str, Any], ...] = (),
    recovered_executable_data: Path | str | None = None,
    external_profile: Path | str | None = None,
    out: Path | str,
) -> dict[str, Any]:
    """Render one runtime from the linked module's checked package members.

    The linked semantic module is the sole semantic input. Transfer-v2, the
    resolved environment, and object authority are opened only through its
    validated package view. Runtime reachability and effects come directly
    from its linked symbols and effect tables; the compatibility closure
    sidecar is not read.
    """

    linked_path = Path(linked_semantic_module)
    if linked_path.is_dir():
        linked_path = linked_path / "linked-semantic-module.json"
    try:
        raw = _read_json_object(linked_path, "linked semantic module")
        if raw.get("format") != LINKED_SEMANTIC_MODULE_V2_FORMAT:
            raise CandidateRuntimeError(
                "linked semantic module has an unsupported format"
            )
        linked = LinkedSemanticModuleV2.load(linked_path)
        semantic = linked.semantic_object
        if semantic is None:
            raise CandidateRuntimeError(
                "shared runtime requires the packaged V2 semantic object"
            )
        transfer_plan = semantic.transfer_plan_path
        resolved_environment = semantic.resolved_external_environment_path
        object_authority = semantic.machine_object_authority_path
        execution_semantics = linked_execution_view_v2(linked)
    except LinkedSemanticModuleError as exc:
        raise CandidateRuntimeError(str(exc)) from exc
    out_path = Path(out)
    from .native_ingress_plan import (
        _write_native_ingress_plan_from_loaded_module,
    )
    ingress = _write_native_ingress_plan_from_loaded_module(
        linked=linked,
        pinned_layout_authorities=pinned_layout_authorities,
        out=out_path,
    )
    if ingress.get("status") != "complete":
        ingress_path = out_path / "native-ingress-plan.json"
        raw_blockers = ingress.get("blockers")
        blockers = (
            [dict(row) for row in raw_blockers]
            if isinstance(raw_blockers, list)
            and all(isinstance(row, Mapping) for row in raw_blockers)
            else [{"category": "native_ingress_plan_incomplete"}]
        )
        result = {
            "format": SHARED_MODULE_RUNTIME_PACKAGE_FORMAT,
            "status": "incomplete",
            "acceptance_authority": False,
            "inputs": {
                "linked_semantic_module": {
                    "semantic_module_sha256": linked.identity,
                },
                "native_ingress_plan": {
                    "path": ingress_path.name,
                    "sha256": sha256_file(ingress_path),
                    "plan_sha256": ingress.get("plan_sha256"),
                },
            },
            "sources": [{
                "role": "native_ingress_plan",
                "path": ingress_path.name,
                "sha256": sha256_file(ingress_path),
            }],
            "counts": {"blockers": len(blockers)},
            "blockers": blockers,
            "policy": {
                "realization": "fail_closed_before_source_generation",
                "native_ingress": "internal_lowering_member",
            },
            "authority": (
                "candidate generation only; candidate assurance remains required"
            ),
        }
        write_json(out_path / NATIVE_RUNTIME_MANIFEST_FILENAME, result)
        return result
    return write_shared_module_runtime_package(
        behavioral_c_package=behavioral_c_package,
        transfer_plan=transfer_plan,
        execution_closure=execution_semantics,
        resolved_external_environment=resolved_environment,
        native_ingress_plan=out_path / "native-ingress-plan.json",
        object_authority=object_authority,
        recovered_executable_data=recovered_executable_data,
        external_profile=external_profile,
        out=out,
    )


__all__ = [
    "DEFINEDNESS_USE_FORMAT",
    "NATIVE_RUNTIME_BINDINGS_FILENAME",
    "NATIVE_RUNTIME_HEADER_FILENAME",
    "NATIVE_RUNTIME_MANIFEST_FILENAME",
    "SHARED_MODULE_RUNTIME_PACKAGE_FORMAT",
    "NATIVE_RUNTIME_SOURCE_FILENAME",
    "SharedModuleRuntimePlan",
    "NativeUndefinedPolicy",
    "CandidateRuntimeError",
    "plan_shared_module_runtime",
    "write_shared_module_runtime_package",
    "write_shared_module_runtime_package_from_linked_module",
]
