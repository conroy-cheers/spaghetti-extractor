# ruff: noqa: F401
"""Deterministic execution closure over canonical transfer-v2 semantics."""

from __future__ import annotations

from dataclasses import dataclass, field, replace
import heapq
import json
from pathlib import Path
import resource
import time
from typing import Any, Iterable, Mapping, MutableMapping

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary import BoundarySchemaV1, TargetDataLayoutV1
from ..calls.frame import PhysicalCallFrameV3
from ..semantic_objects.object_authority import MachineObjectAuthorityV2
from ..external.formats import RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
from ..external.resolved import ResolvedExternalEnvironmentV1
from ..pe32.behavioral_roots import load_behavioral_roots
from ..pe32.module_interface import Pe32ModuleInterfaceV2
from ..util import sha256_file, write_json
from .formats import MODULE_EXECUTION_CLOSURE_FORMAT
from .exception_semantics import (
    CheckedExceptionTransitionV1,
    derive_checked_exception_transitions_v1,
)
from .model import TransferPlanError, _Call, _REGISTERS, _Transfer
from .plan import _transfer_from_payload, load_executable_transfer_plan
from .provenance import (
    BOUNDED_SCALAR_ALTERNATIVE_LIMIT_V1,
    BOTTOM_REFERENCE_V1,
    CONFLICT_REFERENCE_V1,
    ExternalCallbackRuleV1,
    ExternalCallRuleV1,
    ExternalMemoryWriteV1,
    ExternalMemoryCopyV1,
    ExternalOutPointerV1,
    ObjectRangeV1,
    ReferenceAtomV1,
    UNKNOWN_SCALAR_REFERENCE_V1,
    ReferenceCatalogV1,
    ReferenceStateV1,
    ReferenceValueV1,
    STACK_REFERENCE_ALTERNATIVE_LIMIT_V1,
    adjust_reference_by_constant_v1,
    apply_reference_effects_v1,
    call_parameter_owner_v1,
    captured_stack_owner_v1,
    call_argument_values_v1,
    finite_reference_value_v1,
    is_call_parameter_object_v1,
    instantiate_call_parameter_identity_v1,
    join_reference_values_v1,
    refine_reference_state_for_branch_v1,
)


_OBSERVATIONAL_CLOSURE_METRICS_V1 = frozenset({
    "elapsed_milliseconds", "peak_rss_kib", "worklist_steps",
})

# This is a qualification bound rather than a semantic promise. Reachable
# checked state beyond it produces an explicit fail-closed blocker below.
OUTGOING_STACK_PROJECTION_BYTE_LIMIT_V1 = 4096


from .closure_model import (
    ExecutionClosureContextV1,
    ExecutionFunctionContextV1,
    execution_closure_context_with_roots_v1,
    _reference_state_kernel_payload_v1,
    _execution_closure_kernel_context_payload_v1,
    _boundary_reference_state_v1,
    _effect_summary_state_v1,
    _state_object_identities_v1,
    _implicit_memory_value_v1,
    _normalize_reference_memory_v1,
    _reference_states_equal_v1,
    join_reference_states_v1,
)
from .closure_calls import (
    _direct_successors,
    _reference_targets,
    _external_reference_targets,
    _reference_target_resolution_v1,
    _external_tail_return_state_v1,
    _call_targets,
    _external_call_targets,
    _call_target_resolution,
    _call_argument_values,
    _callback_targets,
    _callback_root_state,
    _stack_frame_identity_v1,
    _expire_stack_frame_value_v1,
    _call_parameter_identity_v1,
    _parameterizable_call_value_v1,
    _explicit_outgoing_stack_cells_v1,
    _outgoing_stack_projection_exceeds_limit_v1,
    _raw_outgoing_stack_projection_v1,
    _parameterized_call_inputs_v1,
    _instantiate_parameter_value_v1,
    _instantiate_parameter_key_v1,
    _instantiate_parameter_range_v1,
    _return_state_for_caller_v1,
    _callee_state,
    _transfer_rpo_priorities_v1,
)
from .closure_fixed_point import (
    build_module_execution_closure_v1,
)


def _json_object(path: Path, context: str) -> dict[str, Any]:
    try:
        value = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise TransferPlanError(
            f"cannot read {context}: {exc}",
            code="malformed_module_execution_closure_input",
        ) from exc
    if not isinstance(value, dict):
        raise TransferPlanError(
            f"{context} must be an object",
            code="malformed_module_execution_closure_input",
        )
    return value


def _canonical_external_transport_v1(
    row: Mapping[str, Any],
) -> tuple[frozenset[int], int, int, str]:
    """Read physical call semantics only from the resolved canonical boundary."""

    boundary = row.get("boundary")
    if not isinstance(boundary, Mapping):
        raise ValueError("missing canonical boundary")
    schema = BoundarySchemaV1.parse(boundary.get("schema"))
    layout = TargetDataLayoutV1.parse(
        boundary.get("target_data_layout"), schema=schema
    )
    frame = PhysicalCallFrameV3.parse(
        boundary.get("physical_call_frame_v3"),
        schema=schema,
        layout=layout,
    )
    transport = frame.transport
    if any(register not in _REGISTERS for register in transport.preserved_state):
        raise ValueError("unsupported preserved physical state")
    outcome_set = set(transport.outcomes)
    if outcome_set == {"normal"}:
        disposition = "returns"
    elif outcome_set == {"no_return"}:
        disposition = "terminates"
    else:
        raise ValueError(
            f"unsupported checked outcomes {list(transport.outcomes)!r}"
        )
    return (
        frozenset(
            _REGISTERS.index(str(register))
            for register in transport.preserved_state
        ),
        len(transport.arguments),
        int(transport.stack.cleanup_bytes),
        disposition,
    )


def _external_write_authority_selector_v1(
    value: object,
    *,
    authority_rule_ids: frozenset[str],
    contract_index: int,
    blockers: list[dict[str, Any]],
) -> tuple[str | None, bool]:
    """Check that a boundary write names one exact canonical object rule."""

    if value is None:
        return None, True
    if not isinstance(value, str) or not value:
        return None, False
    if value not in authority_rule_ids:
        blockers.append({
            "code": "external_memory_write_authority_selector_unknown",
            "contract_index": contract_index,
            "authority_selector": value,
        })
        return None, False
    return value, True


def derive_execution_closure_context_v1(
    *,
    transfer_payload: Mapping[str, Any],
    behavioral_roots: Path,
    original_pe: Path,
    module_interface: Path,
    object_authority: Path,
    resolved_external_environment: Path,
    checked_exception_transitions: tuple[
        CheckedExceptionTransitionV1, ...
    ] | None = None,
    maximum_worklist_steps: int = 1_000_000,
) -> ExecutionClosureContextV1:
    """Derive closure inputs only from existing checked module contracts."""

    interface_path = Path(module_interface)
    interface = Pe32ModuleInterfaceV2.load(interface_path)
    interface_payload = interface.payload
    roots_path = Path(behavioral_roots)
    authority_path = Path(object_authority)
    environment_path = Path(resolved_external_environment)
    original_path = Path(original_pe)
    roots = load_behavioral_roots(roots_path, original_pe=original_path)
    root_rows = roots.get("roots")
    if roots.get("status") != "complete" or not isinstance(root_rows, list):
        raise TransferPlanError(
            "execution closure behavioral roots are incomplete",
            code="incomplete_module_execution_closure_input",
        )
    pe = roots.get("pe")
    identity = interface_payload.get("identity")
    if (
        not isinstance(pe, Mapping)
        or not isinstance(identity, Mapping)
        or pe.get("sha256") != identity.get("pe_sha256")
    ):
        raise TransferPlanError(
            "execution closure roots and module interface disagree",
            code="stale_module_execution_closure_input",
        )
    transfer_bindings = transfer_payload.get("bindings")
    if (
        not isinstance(transfer_bindings, Mapping)
        or transfer_bindings.get("pe_sha256") != sha256_file(original_path)
    ):
        raise TransferPlanError(
            "execution closure original PE contradicts the transfer plan",
            code="stale_module_execution_closure_input",
        )
    authority = MachineObjectAuthorityV2.parse(
        _json_object(authority_path, "machine object authority")
    )
    if authority.bindings.get("module_interface_sha256") != sha256_file(
        interface_path
    ):
        raise TransferPlanError(
            "execution closure object authority has a stale module binding",
            code="stale_module_execution_closure_input",
        )
    environment = _json_object(
        environment_path, "resolved external environment"
    )
    resolved_environment = ResolvedExternalEnvironmentV1.parse(
        environment, module_interface=interface_payload
    )
    environment_core = {
        key: value for key, value in environment.items()
        if key != "resolved_environment_sha256"
    }
    if (
        environment.get("format") != RESOLVED_EXTERNAL_ENVIRONMENT_FORMAT
        or environment.get("resolved_environment_sha256")
        != canonical_sha256_v3(environment_core)
    ):
        raise TransferPlanError(
            "execution closure resolved environment is malformed or stale",
            code="stale_module_execution_closure_input",
        )
    environment_bindings = environment.get("bindings")
    if (
        not isinstance(environment_bindings, Mapping)
        or environment_bindings.get("module_interface_sha256")
        != interface_payload.get("interface_sha256")
    ):
        raise TransferPlanError(
            "execution closure environment has a stale module binding",
            code="stale_module_execution_closure_input",
        )
    loader = interface_payload.get("loader")
    if not isinstance(loader, Mapping) or not isinstance(
        loader.get("preferred_base"), int
    ):
        raise TransferPlanError(
            "execution closure module loader geometry is malformed",
            code="malformed_module_execution_closure_input",
        )
    image_base = int(loader["preferred_base"])
    objects = tuple(
        ObjectRangeV1(
            rule.identity,
            image_base + rule.locator.offset,
            rule.extent,
            writable=bool(rule.permissions & 2),
        )
        for rule in authority.rules
        if rule.locator.kind == "image_rva"
    )
    authority_rule_ids = frozenset(rule.identity for rule in authority.rules)
    entry_targets = transfer_payload.get("entry_targets")
    providers = transfer_payload.get("runtime_provider_requirements")
    finite_control_routes = transfer_payload.get("finite_control_routes")
    if (
        not isinstance(entry_targets, list)
        or not isinstance(providers, list)
        or not isinstance(finite_control_routes, list)
    ):
        raise TransferPlanError(
            "execution closure transfer inventory is malformed",
            code="malformed_module_execution_closure_input",
        )
    finite_control_targets: dict[int, tuple[int, ...]] = {}
    for inventory in finite_control_routes:
        if not isinstance(inventory, Mapping):
            raise TransferPlanError(
                "execution closure finite-control inventory is malformed",
                code="malformed_module_execution_closure_input",
            )
        source_rva = inventory.get("source_rva")
        routes = inventory.get("routes")
        if (
            not isinstance(source_rva, int)
            or isinstance(source_rva, bool)
            or source_rva < 0
            or source_rva in finite_control_targets
            or not isinstance(routes, list)
            or not routes
            or any(
                not isinstance(route, Mapping)
                or not isinstance(route.get("target_rva"), int)
                or isinstance(route.get("target_rva"), bool)
                or route["target_rva"] < 0
                for route in routes
            )
        ):
            raise TransferPlanError(
                "execution closure finite-control inventory is malformed",
                code="malformed_module_execution_closure_input",
            )
        targets = tuple(sorted({int(route["target_rva"]) for route in routes}))
        finite_control_targets[source_rva] = targets
    environment_blockers = environment.get("blockers")
    if not isinstance(environment_blockers, list):
        raise TransferPlanError(
            "execution closure environment blockers are malformed",
            code="malformed_module_execution_closure_input",
        )
    external_calls: dict[tuple[str, str], ExternalCallRuleV1] = {}
    external_function_contracts: dict[str, tuple[str, str]] = {}
    external_function_iat_slots: dict[int, str] = {}
    contract_blockers: list[dict[str, Any]] = []
    interface_import_rows = interface_payload.get("imports")
    if not isinstance(interface_import_rows, list):
        raise TransferPlanError(
            "execution closure module imports are malformed",
            code="malformed_module_execution_closure_input",
        )
    interface_imports: dict[int, Mapping[str, Any]] = {}
    for import_index, import_row in enumerate(interface_import_rows):
        if not isinstance(import_row, Mapping) or not isinstance(
            import_row.get("iat_rva"), int
        ):
            raise TransferPlanError(
                f"execution closure import {import_index} is malformed",
                code="malformed_module_execution_closure_input",
            )
        iat_rva = int(import_row["iat_rva"])
        if iat_rva in interface_imports:
            raise TransferPlanError(
                f"execution closure import IAT RVA 0x{iat_rva:08x} is duplicate",
                code="malformed_module_execution_closure_input",
            )
        interface_imports[iat_rva] = import_row
    contracts = environment.get("machine_import_contracts")
    if not isinstance(contracts, list):
        raise TransferPlanError(
            "execution closure machine-import contracts are malformed",
            code="malformed_module_execution_closure_input",
        )
    loader_rows = environment.get("loader_service_contracts")
    if not isinstance(loader_rows, list):
        raise TransferPlanError(
            "execution closure loader-service contracts are malformed",
            code="malformed_module_execution_closure_input",
        )
    loader_services: dict[tuple[str, str], Mapping[str, Any]] = {}
    dynamic_export_results: dict[tuple[str, str], str] = {}
    dynamic_external_declarations: dict[
        tuple[str, str], tuple[str, str | None]
    ] = {}
    for loader_index, loader_row in enumerate(loader_rows):
        if not isinstance(loader_row, Mapping):
            contract_blockers.append({
                "code": "malformed_loader_service_contract",
                "loader_index": loader_index,
            })
            continue
        identity = loader_row.get("identity")
        contract = loader_row.get("contract")
        payload = contract.get("payload") if isinstance(contract, Mapping) else None
        loader_service = (
            payload.get("loader_service")
            if isinstance(payload, Mapping) else None
        )
        symbol = identity.get("symbol") if isinstance(identity, Mapping) else None
        dll = identity.get("dll") if isinstance(identity, Mapping) else None
        if (
            not isinstance(dll, str)
            or not isinstance(symbol, str)
            or not isinstance(loader_service, Mapping)
        ):
            contract_blockers.append({
                "code": "malformed_loader_service_contract",
                "loader_index": loader_index,
            })
            continue
        key = (dll.lower(), symbol)
        if key in loader_services:
            contract_blockers.append({
                "code": "duplicate_loader_service_contract",
                "dll": key[0],
                "identity": key[1],
            })
            continue
        loader_services[key] = loader_row
        if loader_service.get("kind") != "dynamic_export_resolution":
            continue
        resolution_catalog = loader_row.get("resolution_catalog")
        if not isinstance(resolution_catalog, list):
            contract_blockers.append({
                "code": "malformed_dynamic_export_resolution_catalog",
                "dll": key[0],
                "identity": key[1],
            })
            continue
        for resolution_index, resolved_row in enumerate(resolution_catalog):
            if not isinstance(resolved_row, Mapping):
                contract_blockers.append({
                    "code": "malformed_dynamic_export_contract",
                    "resolution_index": resolution_index,
                })
                continue
            resolved_identity = resolved_row.get("identity")
            resolved_dll = (
                resolved_identity.get("dll")
                if isinstance(resolved_identity, Mapping) else None
            )
            resolved_symbol = (
                resolved_identity.get("symbol")
                if isinstance(resolved_identity, Mapping) else None
            )
            resolved_ordinal = (
                resolved_identity.get("ordinal")
                if isinstance(resolved_identity, Mapping) else None
            )
            resolved_external_id = (
                resolved_symbol if isinstance(resolved_symbol, str)
                else (
                    f"ordinal:{resolved_ordinal}"
                    if isinstance(resolved_ordinal, int) else None
                )
            )
            if (
                resolved_row.get("dynamic_export_kind") != "code"
                or not isinstance(resolved_dll, str)
                or resolved_external_id is None
            ):
                continue
            try:
                (
                    dynamic_preserved,
                    dynamic_arguments,
                    dynamic_cleanup,
                    dynamic_disposition,
                ) = _canonical_external_transport_v1(resolved_row)
            except (TypeError, ValueError) as exc:
                contract_blockers.append({
                    "code": "malformed_dynamic_export_canonical_boundary",
                    "dll": resolved_dll.lower(),
                    "identity": resolved_external_id,
                    "detail": str(exc),
                })
                continue
            boundary = resolved_row.get("boundary")
            raw_views = (
                boundary.get("memory_views")
                if isinstance(boundary, Mapping) else None
            )
            if not isinstance(raw_views, list) or any(
                isinstance(view, Mapping)
                and view.get("access") in {"write", "read_write"}
                for view in raw_views
            ):
                contract_blockers.append({
                    "code": "unsupported_dynamic_export_memory_effect",
                    "dll": resolved_dll.lower(),
                    "identity": resolved_external_id,
                })
                continue
            resolved_key = (resolved_dll.lower(), resolved_external_id)
            dynamic_rule = ExternalCallRuleV1(
                contract_sha256=canonical_sha256_v3(dict(resolved_row)),
                preserved_registers=dynamic_preserved,
                argument_words=dynamic_arguments,
                stack_cleanup_bytes=dynamic_cleanup,
                disposition=dynamic_disposition,
            )
            previous_rule = external_calls.get(resolved_key)
            if previous_rule is not None and previous_rule != dynamic_rule:
                contract_blockers.append({
                    "code": "conflicting_dynamic_export_contract",
                    "dll": resolved_key[0],
                    "identity": resolved_key[1],
                })
                continue
            target_id = (
                f"dynamic-export:{resolved_key[0]}!{resolved_key[1]}"
            )
            previous_target = dynamic_export_results.get(resolved_key)
            if previous_target is not None and previous_target != target_id:
                contract_blockers.append({
                    "code": "conflicting_dynamic_export_identity",
                    "dll": resolved_key[0],
                    "identity": resolved_key[1],
                })
                continue
            external_calls[resolved_key] = dynamic_rule
            external_function_contracts[target_id] = resolved_key
            dynamic_export_results[resolved_key] = target_id
            declaration = (
                canonical_sha256_v3(dict(resolved_row)),
                canonical_sha256_v3(dict(loader_row)),
            )
            previous_declaration = dynamic_external_declarations.get(
                resolved_key
            )
            if (
                previous_declaration is not None
                and previous_declaration != declaration
            ):
                contract_blockers.append({
                    "code": "conflicting_dynamic_export_declaration",
                    "dll": resolved_key[0],
                    "identity": resolved_key[1],
                })
                continue
            dynamic_external_declarations[resolved_key] = declaration
    external_declaration_contracts: dict[
        tuple[str, str], tuple[str, str | None]
    ] = dict(dynamic_external_declarations)
    for declaration_index, row in enumerate(contracts):
        if not isinstance(row, Mapping):
            continue
        identity = row.get("identity")
        boundary = row.get("boundary")
        dll = identity.get("dll") if isinstance(identity, Mapping) else None
        symbol = (
            identity.get("symbol") if isinstance(identity, Mapping) else None
        )
        ordinal = (
            identity.get("ordinal") if isinstance(identity, Mapping) else None
        )
        external_id = (
            symbol if isinstance(symbol, str)
            else f"ordinal:{ordinal}" if isinstance(ordinal, int) else None
        )
        if (
            not isinstance(dll, str)
            or external_id is None
            or not isinstance(boundary, Mapping)
        ):
            continue
        key = (dll.lower(), external_id)
        loader_row = loader_services.get(key)
        loader_sha256 = None
        if loader_row is not None:
            if (
                loader_row.get("identity") == row.get("identity")
                and loader_row.get("contract") == row.get("contract")
                and loader_row.get("boundary") == row.get("boundary")
            ):
                loader_sha256 = canonical_sha256_v3(dict(loader_row))
            else:
                continue
        declaration = (
            canonical_sha256_v3(dict(row)), loader_sha256,
        )
        previous = external_declaration_contracts.get(key)
        if previous is not None and previous != declaration:
            contract_blockers.append({
                "code": "conflicting_external_declaration_contract",
                "contract_index": declaration_index,
                "dll": key[0],
                "identity": key[1],
            })
            continue
        external_declaration_contracts[key] = declaration

    for row in contracts:
        if not isinstance(row, Mapping):
            contract_blockers.append({
                "code": "malformed_external_call_contract",
            })
            continue
        contract = row.get("contract")
        boundary = row.get("boundary")
        if contract is None and boundary is None:
            # A resolved environment is allowed to remain incomplete and
            # records the exact unresolved import blocker itself.  Such a row
            # is an absent contract, not a malformed contract; it contributes
            # no execution rule and cannot authorize the call.
            continue
        contract_payload = (
            contract.get("payload") if isinstance(contract, Mapping) else None
        )
        if not isinstance(contract_payload, Mapping):
            contract_blockers.append({
                "code": "malformed_external_call_contract",
            })
            continue
        relations = (
            contract_payload.get("result_register_relations")
            if isinstance(contract_payload, Mapping) else None
        )
        if not isinstance(relations, list):
            relations = []
        allocation_relations = [
            relation for relation in relations
            if (
                isinstance(relation, Mapping)
                and relation.get("register") == "eax"
                and relation.get("relation") == "dynamic_range_base"
            )
        ]
        if len(allocation_relations) > 1:
            contract_blockers.append({
                "code": "conflicting_external_allocation_result_relations",
                "contract_index": len(external_calls),
            })
            continue
        try:
            (
                preserved_registers,
                argument_words,
                cleanup_bytes,
                disposition,
            ) = _canonical_external_transport_v1(row)
            if not isinstance(boundary, Mapping):
                raise ValueError("missing canonical boundary")
        except (TypeError, ValueError) as exc:
            contract_blockers.append({
                "code": "malformed_external_call_canonical_boundary",
                "detail": str(exc),
            })
            continue
        allocation_relation = (
            allocation_relations[0] if allocation_relations else None
        )
        if allocation_relation is not None and not isinstance(
            allocation_relation.get("nullable"), bool
        ):
            contract_blockers.append({
                "code": "malformed_external_allocation_result_relation",
                "contract_index": len(external_calls),
            })
            continue
        raw_footprints = boundary.get("memory_views", [])
        if not isinstance(raw_footprints, list):
            contract_blockers.append({
                "code": "malformed_external_boundary_memory_views",
            })
            continue
        write_footprints: list[ExternalMemoryWriteV1] = []
        memory_copies: list[ExternalMemoryCopyV1] = []
        out_pointers: list[ExternalOutPointerV1] = []
        unknown_guest_memory_write = False
        for footprint in raw_footprints:
            if not isinstance(footprint, Mapping):
                unknown_guest_memory_write = True
                continue
            if footprint.get("access") not in {"write", "read_write"}:
                continue
            base_parameter_id = footprint.get("base_parameter_id")
            base_argument = (
                int(base_parameter_id.removeprefix("argument-"))
                if isinstance(base_parameter_id, str)
                and base_parameter_id.removeprefix("argument-").isdigit()
                else None
            )
            offset = footprint.get("offset")
            size = footprint.get("size")
            authority_selector, selector_valid = (
                _external_write_authority_selector_v1(
                    footprint.get("authority_selector"),
                    authority_rule_ids=authority_rule_ids,
                    contract_index=len(external_calls),
                    blockers=contract_blockers,
                )
            )
            if (
                not isinstance(base_argument, int)
                or base_argument < 0
                or footprint.get("origin_policy")
                != "resolve_unique_machine_object"
                or not selector_valid
                or not isinstance(offset, int)
                or not isinstance(size, Mapping)
            ):
                unknown_guest_memory_write = True
                continue
            if size.get("kind") == "fixed" and isinstance(
                size.get("bytes"), int
            ):
                write_footprints.append(ExternalMemoryWriteV1(
                    base_argument=base_argument,
                    offset=offset,
                    fixed_bytes=int(size["bytes"]),
                    authority_selector=authority_selector,
                ))
            elif (
                size.get("kind") == "argument"
                and isinstance(size.get("argument"), int)
                and isinstance(size.get("scale"), int)
            ):
                write_footprints.append(ExternalMemoryWriteV1(
                    base_argument=base_argument,
                    offset=offset,
                    size_argument=int(size["argument"]),
                    scale=int(size["scale"]),
                    authority_selector=authority_selector,
                ))
            elif (
                size.get("kind") == "bounded_terminated"
                and isinstance(size.get("unit_bytes"), int)
                and isinstance(size.get("max_units"), int)
                and int(size["unit_bytes"]) > 0
                and int(size["max_units"]) >= 0
            ):
                # The precise terminator position is irrelevant to reference
                # invalidation.  The checked maximum is a sound object-local
                # over-approximation and avoids clobbering unrelated objects.
                write_footprints.append(ExternalMemoryWriteV1(
                    base_argument=base_argument,
                    offset=offset,
                    fixed_bytes=(
                        int(size["unit_bytes"]) * int(size["max_units"])
                    ),
                    authority_selector=authority_selector,
                ))
            elif (
                size.get("kind") == "argument_or_bounded_terminated"
                and isinstance(size.get("unit_bytes"), int)
                and isinstance(size.get("max_units"), int)
                and int(size["unit_bytes"]) > 0
                and int(size["max_units"]) >= 0
            ):
                write_footprints.append(ExternalMemoryWriteV1(
                    base_argument=base_argument,
                    offset=offset,
                    fixed_bytes=(
                        int(size["unit_bytes"]) * int(size["max_units"])
                    ),
                    authority_selector=authority_selector,
                ))
            else:
                unknown_guest_memory_write = True
        raw_memory_relations = boundary.get("memory_relations", [])
        if not isinstance(raw_memory_relations, list):
            contract_blockers.append({
                "code": "malformed_external_boundary_memory_relations",
            })
            continue
        malformed_memory_relation = False
        for raw_relation in raw_memory_relations:
            try:
                if (
                    not isinstance(raw_relation, Mapping)
                    or raw_relation.get("kind") != "byte_copy"
                ):
                    raise ValueError("unsupported memory relation")
                memory_copies.append(ExternalMemoryCopyV1(
                    destination_argument=int(
                        raw_relation["destination_argument"]
                    ),
                    source_argument=int(raw_relation["source_argument"]),
                    size_argument=int(raw_relation["size_argument"]),
                    scale=int(raw_relation["scale"]),
                ))
            except (KeyError, TypeError, ValueError):
                malformed_memory_relation = True
                break
        if malformed_memory_relation:
            contract_blockers.append({
                "code": "malformed_external_boundary_memory_relation",
            })
            continue
        raw_out_pointers = boundary.get("out_pointer_relations", [])
        if not isinstance(raw_out_pointers, list):
            contract_blockers.append({
                "code": "malformed_external_boundary_out_pointer_relations",
            })
            continue
        malformed_out_pointer = False
        for raw_relation in raw_out_pointers:
            shape = (
                raw_relation.get("pointee_shape")
                if isinstance(raw_relation, Mapping) else None
            )
            element = (
                shape.get("element") if isinstance(shape, Mapping) else None
            )
            sentinel = (
                element.get("sentinel")
                if isinstance(element, Mapping) else None
            )
            argument = (
                raw_relation.get("argument")
                if isinstance(raw_relation, Mapping) else None
            )
            offset = (
                raw_relation.get("offset", 0)
                if isinstance(raw_relation, Mapping) else None
            )
            max_elements = (
                shape.get("max_elements")
                if isinstance(shape, Mapping) else None
            )
            unit_bytes = (
                element.get("unit_bytes")
                if isinstance(element, Mapping) else None
            )
            max_units = (
                element.get("max_units")
                if isinstance(element, Mapping) else None
            )
            if (
                not isinstance(raw_relation, Mapping)
                or raw_relation.get("relation")
                != "nullable_dynamic_pointer"
                or not isinstance(argument, int)
                or isinstance(argument, bool)
                or not 0 <= argument < argument_words
                or not isinstance(offset, int)
                or isinstance(offset, bool)
                or offset < 0
                or not isinstance(shape, Mapping)
                or shape.get("kind") != "null_terminated_pointer_vector"
                or not isinstance(max_elements, int)
                or isinstance(max_elements, bool)
                or not 0 < max_elements <= 65_536
                or not isinstance(element, Mapping)
                or element.get("kind") != "bounded_terminated"
                or unit_bytes not in {1, 2, 4}
                or sentinel != [0] * int(unit_bytes or 0)
                or not isinstance(max_units, int)
                or isinstance(max_units, bool)
                or not 0 < max_units <= 1_048_576
            ):
                malformed_out_pointer = True
                break
            out_pointers.append(ExternalOutPointerV1(
                argument=argument,
                offset=offset,
                nullable=True,
                max_elements=max_elements,
                element_unit_bytes=unit_bytes,
                element_max_units=max_units,
            ))
        if malformed_out_pointer:
            contract_blockers.append({
                "code": "malformed_external_boundary_out_pointer_relation",
            })
            continue
        callback_rule: ExternalCallbackRuleV1 | None = None
        callback_effect = contract_payload.get("callback_effect")
        if callback_effect == "explicit":
            callback_protocol = boundary.get("callback_protocol")
            source = (
                callback_protocol.get("source")
                if isinstance(callback_protocol, Mapping) else None
            )
            source_kind = (
                source.get("kind") if isinstance(source, Mapping) else None
            )
            source_offset = (
                source.get("offset", 0)
                if isinstance(source, Mapping) else None
            )
            lifetime = (
                callback_protocol.get("lifetime")
                if isinstance(callback_protocol, Mapping) else None
            )
            delivery = (
                callback_protocol.get("delivery")
                if isinstance(callback_protocol, Mapping) else None
            )
            instance = (
                callback_protocol.get("instance")
                if isinstance(callback_protocol, Mapping) else None
            )
            previous_result = (
                callback_protocol.get("previous_result")
                if isinstance(callback_protocol, Mapping) else None
            )
            sentinels = source.get("sentinels") if isinstance(source, Mapping) else None
            if (
                not isinstance(callback_protocol, Mapping)
                or not isinstance(callback_protocol.get("id"), str)
                or not isinstance(callback_protocol.get("action"), str)
                or not isinstance(source, Mapping)
                or source_kind not in {"argument_word", "argument_pointee"}
                or not isinstance(source.get("argument"), int)
                or isinstance(source.get("argument"), bool)
                or not 0 <= int(source.get("argument")) < argument_words
                or not isinstance(source_offset, int)
                or isinstance(source_offset, bool)
                or source_offset < 0
                or (source_kind == "argument_word" and source_offset != 0)
                or not isinstance(sentinels, list)
                or not all(
                    isinstance(item, Mapping) and isinstance(item.get("word"), int)
                    for item in sentinels
                )
                or not isinstance(lifetime, Mapping)
                or not isinstance(lifetime.get("kind"), str)
                or not isinstance(delivery, Mapping)
                or not isinstance(delivery.get("thread"), str)
                or not isinstance(delivery.get("timing"), str)
                or not isinstance(instance, Mapping)
                or instance.get("kind") not in {
                    "singleton", "registration_sequence", "argument",
                    "provider_resource",
                }
                or (
                    instance.get("kind") in {"argument", "provider_resource"}
                    and (
                        not isinstance(instance.get("argument"), int)
                        or isinstance(instance.get("argument"), bool)
                        or not 0 <= int(instance.get("argument")) < argument_words
                    )
                )
                or (
                    previous_result is not None
                    and (
                        not isinstance(previous_result, Mapping)
                        or previous_result.get("register") not in _REGISTERS
                        or not isinstance(previous_result.get("sentinels"), list)
                        or not all(
                            isinstance(item, Mapping)
                            and isinstance(item.get("word"), int)
                            for item in previous_result.get("sentinels", [])
                        )
                    )
                )
            ):
                contract_blockers.append({
                    "code": "malformed_external_callback_protocol",
                })
                continue
            callback_rule = ExternalCallbackRuleV1(
                protocol_id=str(callback_protocol.get("id")),
                source_argument=int(source["argument"]),
                source_kind=str(source_kind),
                source_offset=int(source_offset),
                sentinels=frozenset(int(item["word"]) for item in sentinels),
                action=str(callback_protocol.get("action")),
                lifetime=str(lifetime["kind"]),
                delivery_thread=str(delivery["thread"]),
                delivery_timing=str(delivery["timing"]),
                instance_kind=str(instance["kind"]),
                instance_argument=(
                    int(instance["argument"])
                    if instance.get("kind") in {
                        "argument", "provider_resource",
                    } else None
                ),
                previous_result_register=(
                    _REGISTERS.index(str(previous_result["register"]))
                    if isinstance(previous_result, Mapping) else None
                ),
                previous_sentinels=frozenset(
                    int(item["word"])
                    for item in previous_result.get("sentinels", [])
                ) if isinstance(previous_result, Mapping) else frozenset(),
            )
        elif callback_effect not in {None, "none"}:
            contract_blockers.append({
                "code": "unsupported_external_callback_effect",
                "callback_effect": callback_effect,
            })
            continue
        import_identity = row.get("identity")
        if not isinstance(import_identity, Mapping):
            continue
        symbol = import_identity.get("symbol")
        ordinal = import_identity.get("ordinal")
        external_id = (
            symbol if isinstance(symbol, str)
            else f"ordinal:{ordinal}" if isinstance(ordinal, int) else None
        )
        dll = import_identity.get("dll")
        if isinstance(dll, str) and external_id is not None:
            key = (dll.lower(), external_id)
            loader_row = loader_services.get(key)
            loader_service: Mapping[str, Any] | None = None
            if loader_row is not None:
                if (
                    loader_row.get("identity") != row.get("identity")
                    or loader_row.get("contract") != row.get("contract")
                    or loader_row.get("boundary") != row.get("boundary")
                ):
                    contract_blockers.append({
                        "code": "loader_service_contract_binding_mismatch",
                        "dll": key[0],
                        "identity": key[1],
                    })
                    continue
                loader_contract = loader_row.get("contract")
                loader_payload = (
                    loader_contract.get("payload")
                    if isinstance(loader_contract, Mapping) else None
                )
                candidate_service = (
                    loader_payload.get("loader_service")
                    if isinstance(loader_payload, Mapping) else None
                )
                if not isinstance(candidate_service, Mapping):
                    contract_blockers.append({
                        "code": "malformed_loader_service_contract",
                        "dll": key[0],
                        "identity": key[1],
                    })
                    continue
                loader_service = candidate_service
            rule = ExternalCallRuleV1(
                contract_sha256=canonical_sha256_v3(dict(row)),
                loader_service_contract_sha256=(
                    None if loader_row is None
                    else canonical_sha256_v3(dict(loader_row))
                ),
                preserved_registers=preserved_registers,
                argument_words=argument_words,
                stack_cleanup_bytes=int(cleanup_bytes),
                disposition=disposition,
                allocation_result_register=(
                    0 if allocation_relation is not None else None
                ),
                allocation_nullable=(
                    bool(allocation_relation["nullable"])
                    if allocation_relation is not None else False
                ),
                write_footprints=tuple(write_footprints),
                memory_copies=tuple(memory_copies),
                out_pointers=tuple(out_pointers),
                unknown_guest_memory_write=unknown_guest_memory_write,
                callback=callback_rule,
                module_handle_name_argument=(
                    int(loader_service["module_name_argument"])
                    if loader_service is not None
                    and loader_service.get("kind") == "module_handle"
                    and isinstance(loader_service.get("module_name_argument"), int)
                    else None
                ),
                module_handle_nullable_name=(
                    bool(loader_service.get("nullable_module_name"))
                    if loader_service is not None
                    and loader_service.get("kind") == "module_handle"
                    else False
                ),
                module_handle_wide_name=(
                    key[1] == "GetModuleHandleW"
                    if loader_service is not None
                    and loader_service.get("kind") == "module_handle"
                    else False
                ),
                dynamic_export_handle_argument=(
                    int(loader_service["module_handle_argument"])
                    if loader_service is not None
                    and loader_service.get("kind")
                    == "dynamic_export_resolution"
                    and isinstance(
                        loader_service.get("module_handle_argument"), int
                    )
                    else None
                ),
                dynamic_export_name_argument=(
                    int(loader_service["export_name_argument"])
                    if loader_service is not None
                    and loader_service.get("kind")
                    == "dynamic_export_resolution"
                    and isinstance(
                        loader_service.get("export_name_argument"), int
                    )
                    else None
                ),
                dynamic_export_results=(
                    dynamic_export_results
                    if loader_service is not None
                    and loader_service.get("kind")
                    == "dynamic_export_resolution"
                    else {}
                ),
            )
            previous = external_calls.get(key)
            if previous is not None and previous != rule:
                contract_blockers.append({
                    "code": "conflicting_external_call_provenance_contract",
                    "dll": key[0],
                    "identity": key[1],
                })
            external_calls[key] = rule
            iat_rva_value = row.get("iat_rva")
            import_row = (
                interface_imports.get(iat_rva_value)
                if isinstance(iat_rva_value, int) else None
            )
            if import_row is None:
                contract_blockers.append({
                    "code": "external_call_contract_missing_iat_slot",
                    "dll": key[0],
                    "identity": key[1],
                })
                continue
            import_external_id = (
                import_row.get("symbol")
                if isinstance(import_row.get("symbol"), str)
                else (
                    f"ordinal:{import_row.get('ordinal')}"
                    if isinstance(import_row.get("ordinal"), int) else None
                )
            )
            slot_id = import_row.get("slot_id")
            if (
                not isinstance(slot_id, str)
                or import_row.get("dll", "").lower() != key[0]
                or import_external_id != key[1]
            ):
                contract_blockers.append({
                    "code": "external_call_contract_iat_identity_mismatch",
                    "dll": key[0],
                    "identity": key[1],
                    "iat_rva": iat_rva_value,
                })
                continue
            external_function_contracts[slot_id] = key
            external_function_iat_slots[iat_rva_value] = slot_id
    catalog = ReferenceCatalogV1(
        guest_code_rvas=frozenset(int(value) for value in entry_targets),
        guest_image_base=image_base,
        objects=objects,
        external_calls=external_calls,
        external_function_contracts=external_function_contracts,
    )
    initial_memory, object_bytes = _initial_image_storage_v1(
        original_path=original_path,
        image_objects=objects,
        image_base=image_base,
        catalog=catalog,
    )
    initial_memory.update(_external_function_iat_memory_v1(
        iat_slots=external_function_iat_slots,
        image_objects=objects,
        image_base=image_base,
        alternative_limit=catalog.alternative_limit,
        blockers=contract_blockers,
    ))
    catalog = replace(
        catalog,
        initial_memory=initial_memory,
        object_bytes=object_bytes,
    )
    root_rvas = tuple(sorted({int(row["rva"]) for row in root_rows}))
    initial_states = {
        root: _root_reference_state_v1(root) for root in root_rvas
    }
    if checked_exception_transitions is None:
        checked_exception_transitions = derive_checked_exception_transitions_v1(
            transfers=tuple(
                _transfer_from_payload(row)
                for row in transfer_payload["transfers"]
            ),
            environment=resolved_environment,
        )
    else:
        checked_exception_transitions = tuple(sorted(checked_exception_transitions))
    exception_semantics_sha256 = canonical_sha256_v3([
        row.payload() for row in checked_exception_transitions
    ])
    return ExecutionClosureContextV1(
        roots=root_rvas,
        catalog=catalog,
        authority_bindings={
            "behavioral_roots_sha256": sha256_file(roots_path),
            "machine_object_authority_sha256": sha256_file(authority_path),
            "module_interface_sha256": sha256_file(interface_path),
            "original_pe_sha256": sha256_file(original_path),
            "resolved_external_environment_sha256": sha256_file(environment_path),
            "exception_semantics_sha256": exception_semantics_sha256,
        },
        runtime_provider_requirements=tuple(providers),
        initial_states=initial_states,
        preexisting_blockers=tuple({
            "code": "resolved_external_environment_incomplete",
            "environment_blocker": row,
        } for row in environment_blockers) + tuple(contract_blockers),
        maximum_worklist_steps=maximum_worklist_steps,
        checked_exception_transitions=checked_exception_transitions,
        finite_control_targets=finite_control_targets,
        external_declaration_contracts=external_declaration_contracts,
    )


def _root_reference_state_v1(root_rva: int) -> ReferenceStateV1:
    registers = list(ReferenceStateV1().registers)
    registers[7] = finite_reference_value_v1(references=(
        ReferenceAtomV1(
            "object", f"captured_stack:root:{root_rva:08x}", 0
        ),
    ))
    return ReferenceStateV1(registers=tuple(registers))


def _initial_image_storage_v1(
    *,
    original_path: Path,
    image_objects: tuple[ObjectRangeV1, ...],
    image_base: int,
    catalog: ReferenceCatalogV1,
) -> tuple[
    dict[tuple[str, str, int, int], ReferenceValueV1],
    dict[str, bytes],
]:
    import pefile

    pe = pefile.PE(str(original_path), fast_load=True)
    image = pe.get_memory_mapped_image()
    memory: dict[tuple[str, str, int, int], ReferenceValueV1] = {}
    object_bytes: dict[str, bytes] = {}
    for object_range in image_objects:
        rva = object_range.address - image_base
        data = image[rva:rva + object_range.extent]
        if len(data) < object_range.extent:
            data += b"\0" * (object_range.extent - len(data))
        object_bytes[object_range.identity] = bytes(data)
        for offset in range(0, object_range.extent - 3, 4):
            value = int.from_bytes(data[offset:offset + 4], "little")
            memory[("object", object_range.identity, offset, 4)] = (
                catalog.classify_scalar(value)
            )
    return memory, object_bytes


def _external_function_iat_memory_v1(
    *,
    iat_slots: Mapping[int, str],
    image_objects: tuple[ObjectRangeV1, ...],
    image_base: int,
    alternative_limit: int,
    blockers: list[dict[str, Any]],
) -> dict[tuple[str, str, int, int], ReferenceValueV1]:
    """Materialize loader-written IAT code values as checked references."""

    memory: dict[tuple[str, str, int, int], ReferenceValueV1] = {}
    for iat_rva, slot_id in sorted(iat_slots.items()):
        address = image_base + iat_rva
        owners = [row for row in image_objects if row.contains(address)]
        if len(owners) != 1:
            blockers.append({
                "code": "external_function_iat_object_authority_not_unique",
                "iat_rva": iat_rva,
                "slot_id": slot_id,
                "owner_count": len(owners),
            })
            continue
        owner = owners[0]
        offset = address - owner.address
        if offset + 4 > owner.extent:
            blockers.append({
                "code": "external_function_iat_outside_object_extent",
                "iat_rva": iat_rva,
                "slot_id": slot_id,
            })
            continue
        memory[("object", owner.identity, offset, 4)] = (
            finite_reference_value_v1(
                references=(
                    ReferenceAtomV1("external_function", slot_id, 0),
                ),
                alternative_limit=alternative_limit,
            )
        )
    return memory
