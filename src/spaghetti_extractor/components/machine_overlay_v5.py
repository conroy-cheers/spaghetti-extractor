"""Direct V5 operation-to-machine-state overlays for portable C."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from ..boundary._canonical import BoundaryModelError, array, object_
from ..external.resolved import (
    ExternalEnvironmentError,
    ResolvedExternalEnvironmentV1,
    resolved_interface_method_index_v1,
)
from ..transfer.model import _Transfer
from ..transfer.values import _c_string
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_external_v5 import (
    _checked_service_argument_transducers,
    _external_service_runtime_helpers,
    _external_service_thunk,
    _service_provider_declaration,
)
from .machine_overlay_boundaries_v5 import (
    authority_selector_expression as _authority_selector_expression,
    callback_projection_lines as _callback_projection_lines,
    callback_type_ids as _callback_type_ids,
    checked_opaque_resource_projection as _checked_opaque_resource_projection,
    state_export_lines as _state_export_lines,
    state_import_lines as _state_import_lines,
    state_projection_index as _state_projection_index,
)
from .normalized_component import (
    NormalizedComponentContract,
    NormalizedMachineBinding,
)

from .machine_overlay_services_v5 import (
    _c_identifier,
    _raw_service_provider_kind,
    _logical_operation_symbol,
    _operation_service_bindings,
    _resolved_external_contract_index,
    _resolved_interface_method_index,
    _service_setup_lines,
    _signature_abi_sha256,
    _uint,
)

@dataclass(frozen=True)
class ComponentMachineOverlayV1:
    source: str
    entries: tuple[Mapping[str, object], ...]


def _binding_authority_selectors(
    *,
    machine_binding: NormalizedMachineBinding | None,
    contract: NormalizedComponentContract,
    object_authority_rule_ids: Sequence[str] | None,
) -> dict[str, dict[str, str]]:
    operation_ids = {item.operation_id for item in contract.machine_semantics}
    if machine_binding is None:
        return {operation_id: {} for operation_id in operation_ids}
    if (
        machine_binding.component_id != contract.component_id
        or machine_binding.contract_sha256 != contract.contract_sha256
    ):
        raise BoundaryModelError("component overlay machine binding is stale")
    available_rules = (
        None if object_authority_rule_ids is None else set(object_authority_rule_ids)
    )
    if available_rules is not None and len(available_rules) != len(
        object_authority_rule_ids
    ):
        raise BoundaryModelError(
            "component overlay object-rule inventory is duplicated"
        )
    result: dict[str, dict[str, str]] = {}
    semantic_index = {item.operation_id: item for item in contract.machine_semantics}
    for operation in machine_binding.operations:
        operation_id = str(operation["id"])
        if operation_id not in operation_ids or operation_id in result:
            raise BoundaryModelError(
                "component overlay authority operation inventory is stale"
            )
        selectors: dict[str, str] = {}
        for raw in operation["object_authority_selectors"]:
            row = object_(raw, "component overlay object authority selector")
            authority_id = str(row["authority_id"])
            rule_id = str(row["rule_id"])
            if authority_id in selectors:
                raise BoundaryModelError(
                    "component overlay object authority selector is duplicated"
                )
            if available_rules is None:
                raise BoundaryModelError(
                    "component overlay object authority registry is unavailable"
                )
            if rule_id not in available_rules:
                raise BoundaryModelError(
                    "component overlay object authority selector is unresolved"
                )
            selectors[authority_id] = rule_id
        referenced = _projection_authority_ids(
            semantic_index[operation_id].machine_projection
        )
        if not set(selectors) <= referenced:
            raise BoundaryModelError(
                "component overlay object authority selector is unused"
            )
        result[operation_id] = selectors
    if set(result) != operation_ids:
        raise BoundaryModelError(
            "component overlay authority operation inventory is not total"
        )
    return result


def _projection_authority_ids(value: object) -> set[str]:
    result: set[str] = set()
    if isinstance(value, Mapping):
        authority = value.get("authority")
        if isinstance(authority, Mapping) and isinstance(authority.get("id"), str):
            result.add(str(authority["id"]))
        for item in value.values():
            result.update(_projection_authority_ids(item))
    elif isinstance(value, list):
        for item in value:
            result.update(_projection_authority_ids(item))
    return result


def render_component_dispatch_registry_v1(
    *,
    entries: Sequence[Mapping[str, object]],
    portable_unit_rvas: Mapping[str, int],
) -> str:
    """Render the one strong module-wide dispatcher for selected V5 overlays."""

    if not entries or not portable_unit_rvas:
        raise BoundaryModelError(
            "portable dispatch registry requires overlays and owned units"
        )
    normalized: list[tuple[int, str, str, str]] = []
    providers: dict[tuple[str, str], Mapping[str, object]] = {}
    covered: set[str] = set()
    seen_rvas: set[int] = set()
    seen_symbols: set[str] = set()
    seen_logical_symbols: set[str] = set()
    for index, raw in enumerate(entries):
        row = object_(raw, f"portable dispatch overlay {index}")
        component_id = str(row.get("component_id", ""))
        operation_id = str(row.get("operation_id", ""))
        entry_unit_id = str(row.get("entry_unit_id", ""))
        symbol = str(row.get("symbol", ""))
        logical_symbol = str(row.get("logical_symbol", ""))
        logical_abi = str(row.get("logical_abi_sha256", ""))
        entry_rva = _uint(row.get("entry_rva"), "portable dispatch entry RVA")
        owned = _strings(row.get("owned_unit_ids"), "portable dispatch owned units")
        if (
            not component_id
            or not operation_id
            or not entry_unit_id
            or _c_identifier(symbol) != symbol
            or _c_identifier(logical_symbol) != logical_symbol
            or len(logical_abi) != 64
            or any(character not in "0123456789abcdef" for character in logical_abi)
            or entry_unit_id not in owned
            or portable_unit_rvas.get(entry_unit_id) != entry_rva
        ):
            raise BoundaryModelError("portable dispatch overlay identity is stale")
        if (
            entry_rva in seen_rvas
            or symbol in seen_symbols
            or logical_symbol in seen_logical_symbols
            or covered & set(owned)
        ):
            raise BoundaryModelError("portable dispatch overlays overlap")
        if any(unit_id not in portable_unit_rvas for unit_id in owned):
            raise BoundaryModelError("portable dispatch overlay owns an inactive unit")
        seen_rvas.add(entry_rva)
        seen_symbols.add(symbol)
        seen_logical_symbols.add(logical_symbol)
        covered.update(owned)
        normalized.append((entry_rva, symbol, component_id, operation_id))
        provider_key = (component_id, operation_id)
        if provider_key in providers:
            raise BoundaryModelError("portable logical provider is duplicated")
        providers[provider_key] = row
    if covered != set(portable_unit_rvas):
        raise BoundaryModelError("portable dispatch overlays are not ownership-total")
    for row in providers.values():
        for index, raw_service in enumerate(
            row.get("service_bindings", [])
            if isinstance(row.get("service_bindings", []), list)
            else ()
        ):
            service = object_(raw_service, f"portable service binding {index}")
            if service.get("provider_kind") in {"external_call", "interface_method"}:
                if _c_identifier(str(service.get("symbol", ""))) != service.get(
                    "symbol"
                ) or not isinstance(service.get("argument_offsets"), list):
                    raise BoundaryModelError(
                        "portable external service binding is malformed"
                    )
                continue
            if service.get("provider_kind") != "component_operation":
                raise BoundaryModelError(
                    "portable service provider kind is unsupported"
                )
            key = (
                str(service.get("provider_component_id", "")),
                str(service.get("provider_operation_id", "")),
            )
            provider = providers.get(key)
            if (
                provider is None
                or service.get("symbol") != provider.get("logical_symbol")
                or service.get("abi_sha256") != provider.get("logical_abi_sha256")
            ):
                raise BoundaryModelError(
                    "portable component service provider is absent or ABI-incompatible"
                )
    normalized.sort()
    declarations = [
        f"extern spx_step_result {symbol}(spx_runtime *, spx_machine_state *);"
        for _rva, symbol, _component, _operation in normalized
    ]
    table = [
        "  { UINT32_C(%d), %s, UINT32_C(0), %s, %s },"
        % (
            rva,
            symbol,
            _c_string(f"{component}:{operation}"),
            _c_string(f"component:{component}"),
        )
        for rva, symbol, component, operation in normalized
    ]
    return "\n".join(
        [
            '#include "behavioral-c.h"',
            "#include <stdint.h>",
            "",
            *declarations,
            "",
            "const spx_region_override spx_region_overrides[] = {",
            *table,
            "};",
            "const uint32_t spx_region_override_count =",
            "    (uint32_t)(sizeof(spx_region_overrides) / sizeof(spx_region_overrides[0]));",
            "",
            "const spx_region_override *spx_region_override_lookup(uint32_t entry_rva) {",
            "  uint32_t low = 0U;",
            "  uint32_t high = spx_region_override_count;",
            "  while (low < high) {",
            "    uint32_t middle = low + (high - low) / 2U;",
            "    uint32_t observed = spx_region_overrides[middle].entry_rva;",
            "    if (observed < entry_rva) low = middle + 1U;",
            "    else if (observed > entry_rva) high = middle;",
            "    else return &spx_region_overrides[middle];",
            "  }",
            "  return (const spx_region_override *)0;",
            "}",
            "",
        ]
    )


def render_component_machine_overlay_v5(
    *,
    bundle: CompiledComponentInterfaceV5,
    contract: NormalizedComponentContract,
    operation_symbols: Mapping[str, str],
    transfers: Sequence[_Transfer],
    machine_binding: NormalizedMachineBinding | None = None,
    object_authority_rule_ids: Sequence[str] | None = None,
    resolved_external_environment: Mapping[str, object] | None = None,
    code_capabilities: Mapping[str, Mapping[str, object]] | None = None,
    proof_classification: str = "machine_overlay",
) -> ComponentMachineOverlayV1:
    """Render fail-closed adapters directly from the checked V5 contract.

    ``machine_overlay`` imports and transactionally writes back the original
    mapped state on every call. ``encapsulated_owned`` imports once into one
    image-lifetime context and never publishes that private representation
    back to the retired mapped cells. The latter is safe only after the direct
    provider has emitted an ownership/alias admission receipt.
    """

    interface = bundle.interface
    if proof_classification not in {"machine_overlay", "encapsulated_owned"}:
        raise BoundaryModelError("component overlay proof classification is invalid")
    if proof_classification == "encapsulated_owned" and not interface.state:
        raise BoundaryModelError("encapsulated-owned overlay requires persistent state")
    transfer_index = {item.identity: item for item in transfers}
    if len(transfer_index) != len(transfers):
        raise BoundaryModelError("component overlay transfer inventory is duplicated")
    operation_index = {item.identity: item for item in interface.operations}
    semantic_index = {item.operation_id: item for item in contract.machine_semantics}
    authority_selectors_by_operation = _binding_authority_selectors(
        machine_binding=machine_binding,
        contract=contract,
        object_authority_rule_ids=object_authority_rule_ids,
    )
    external_contract_index = _resolved_external_contract_index(
        resolved_external_environment
    )
    interface_method_index = _resolved_interface_method_index(
        resolved_external_environment
    )
    code_capabilities = {} if code_capabilities is None else dict(code_capabilities)
    if set(operation_symbols) != set(operation_index) or set(semantic_index) != set(
        operation_index
    ):
        raise BoundaryModelError("component overlay operation inventory is not total")
    view_parameters = [
        value
        for operation in interface.operations
        for value in bundle.intent.schema.signature_index[
            operation.signature_id
        ].parameters
        if value.interpretation == "view"
    ]
    has_views = any(
        projection.get("kind") in {"view", "bytes_view"}
        for semantics in contract.machine_semantics
        for projection in _projection_index(
            object_(
                semantics.machine_projection.get("operation"), "overlay operation"
            ).get("parameters"),
            "overlay parameters",
        ).values()
    )
    has_atomics = any(
        projection.get("kind") == "atomic_object"
        for semantics in contract.machine_semantics
        for projection in _projection_index(
            object_(
                semantics.machine_projection.get("operation"), "overlay operation"
            ).get("parameters"),
            "overlay parameters",
        ).values()
    )
    has_external_services = any(
        _raw_service_provider_kind(raw) in {"external_call", "interface_method"}
        for semantics in contract.machine_semantics
        for raw in (
            semantics.machine_projection.get("service_bindings", [])
            if isinstance(
                semantics.machine_projection.get("service_bindings", []), list
            )
            else []
        )
    )
    callback_type_ids = _callback_type_ids(bundle)
    component = _c_identifier(interface.identity)
    context_type = f"spx_{component}_context_v5"
    initial_protocol_state = interface.protocol_states.index(
        interface.initial_protocol_state
    )
    lines = [
        '#include "state-machine-runtime.h"',
        '#include "portable-component-implementation.h"',
        "#include <stdint.h>",
        "",
        "typedef struct spx_component_service_context_v1 {",
        "  spx_runtime *runtime;",
        "  spx_machine_state *state;",
        "  uint32_t *fault;",
        "  struct { uint32_t physical_word; uint32_t target_rva; } callback_result;",
        "} spx_component_service_context_v1;",
        "",
        *(
            (
                "extern uint32_t spx_native_code_bridge_address(",
                "    uint32_t target_rva);",
                "",
            )
            if code_capabilities
            else ()
        ),
        "static uint32_t spx_component_read(",
        "    spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {",
        "  if (rt == 0 || rt->read == 0) { *fault = 1U; return 0U; }",
        "  return rt->read(rt->context, address, width, fault);",
        "}",
        "",
    ]
    if has_views:
        lines.extend(
            _view_runtime_helpers(
                need_read=any(
                    value.access in {"read", "read_write"} for value in view_parameters
                ),
                need_write=any(
                    value.access in {"write", "read_write"} for value in view_parameters
                ),
            )
        )
    if has_atomics:
        lines.extend(_atomic_runtime_helpers())
    if has_external_services or interface.state:
        lines.extend(_external_service_runtime_helpers())
    if proof_classification == "encapsulated_owned":
        lines.extend(
            [
                f"static {context_type} spx_{component}_owned_context = {{0}};",
                f"static uint32_t spx_{component}_owned_initialized = 0U;",
                "",
            ]
        )
    entries: list[Mapping[str, object]] = []
    for operation_id in sorted(operation_index):
        operation = operation_index[operation_id]
        semantics = semantic_index[operation_id]
        projection = object_(
            semantics.machine_projection.get("operation"),
            f"component overlay operation {operation_id}",
        )
        entry_units = _strings(
            projection.get("entry_unit_ids"), "component overlay entry units"
        )
        exit_units = _strings(
            projection.get("exit_unit_ids"), "component overlay exit units"
        )
        if len(entry_units) != 1 or not exit_units:
            raise BoundaryModelError(
                "component overlay requires one entry and at least one faithful exit"
            )
        owned_units = tuple(semantics.unit_ids)
        if entry_units[0] not in owned_units:
            raise BoundaryModelError(
                "component overlay ownership must contain its entry unit"
            )
        entry = transfer_index.get(entry_units[0])
        exit_transfers = tuple(transfer_index.get(item) for item in exit_units)
        if entry is None or any(item is None for item in exit_transfers):
            raise BoundaryModelError("component overlay unit binding is stale")
        checked_exits = tuple(item for item in exit_transfers if item is not None)
        if len(checked_exits) > 1 and any(
            not item.actions or item.actions[-1].op != "outcome_return"
            for item in checked_exits
        ):
            raise BoundaryModelError(
                "component overlay multiple exits lack terminal-return equivalence"
            )
        exit_transfer = min(checked_exits, key=lambda item: item.rva_start)
        if tuple(semantics.entry_rvas) != (entry.rva_start,):
            raise BoundaryModelError("component overlay entry RVA is stale")
        signature = bundle.intent.schema.signature_index[operation.signature_id]
        types = bundle.intent.schema.type_index
        service_bindings = _operation_service_bindings(
            bundle=bundle,
            operation=operation,
            machine_projection=semantics.machine_projection,
            transfer_index=transfer_index,
            external_contract_index=external_contract_index,
            interface_method_index=interface_method_index,
        )
        for service in service_bindings:
            lines.append(_service_provider_declaration(bundle, service))
        if service_bindings:
            lines.append("")
        for service in service_bindings:
            if service["provider_kind"] in {"external_call", "interface_method"}:
                lines.extend(
                    _external_service_thunk(
                        bundle,
                        service,
                        authority_selectors_by_operation[operation_id],
                    )
                )
        parameters = _projection_index(
            projection.get("parameters"), "component overlay parameters"
        )
        results = _projection_index(
            projection.get("results"), "component overlay results"
        )
        state_projections = _state_projection_index(
            projection.get("state"), "component overlay state"
        )
        expected_parameters = tuple(item.identity for item in signature.parameters)
        expected_results = tuple(item.identity for item in signature.results)
        if tuple(sorted(parameters)) != tuple(sorted(expected_parameters)):
            raise BoundaryModelError(
                "component overlay parameter projection is not total"
            )
        if tuple(sorted(results)) != tuple(sorted(expected_results)):
            raise BoundaryModelError("component overlay result projection is not total")
        if set(state_projections) != {item.value.identity for item in interface.state}:
            raise BoundaryModelError("component overlay state projection is not total")
        symbol = f"spx_component_{component}_{entry.rva_start:08x}"
        context_expression = (
            f"spx_{component}_owned_context"
            if proof_classification == "encapsulated_owned"
            else "logical_context"
        )
        context_pointer = f"&{context_expression}"
        lines.extend(
            [
                f"spx_step_result {symbol}(spx_runtime *rt, spx_machine_state *state) {{",
                "  uint32_t memory_fault = 0U;",
                "  uint32_t service_fault = 0U;",
                *(
                    [f"  {context_type} logical_context = {{0}};"]
                    if proof_classification == "machine_overlay"
                    else []
                ),
                "  (void)rt;",
                "  (void)spx_component_read;",
                "  if (state == 0)",
                "    return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            ]
        )
        lines.extend(
            _service_setup_lines(
                bundle=bundle,
                component=component,
                service_bindings=service_bindings,
                context_expression=context_pointer,
                runtime_expression="rt",
                state_expression="state",
                fault_expression="&service_fault",
            )
        )
        state_import = _state_import_lines(
            bundle=bundle,
            state_projections=state_projections,
            authority_selectors=authority_selectors_by_operation[operation_id],
            context_expression=context_expression,
            runtime_expression="rt",
        )
        if proof_classification == "encapsulated_owned":
            lines.append(f"  if (spx_{component}_owned_initialized == 0U) {{")
            lines.extend(state_import)
            lines.extend(
                [
                    f"    {context_expression}.protocol_state = "
                    f"UINT32_C({initial_protocol_state});",
                    f"    spx_{component}_owned_initialized = 1U;",
                    "  }",
                ]
            )
        else:
            lines.extend(state_import)
            lines.append(
                f"  {context_expression}.protocol_state = "
                f"UINT32_C({initial_protocol_state});"
            )
        arguments_by_id: dict[str, str] = {}
        for value in signature.parameters:
            name = f"argument_{_c_identifier(value.identity)}"
            parameter_projection = parameters[value.identity]
            if parameter_projection.get("kind") in {
                "view",
                "bytes_view",
                "atomic_object",
                "callback_handle",
                "resource",
            }:
                continue
            c_type = _scalar_type(types[value.type_id], types)
            expression = _projection_read(parameter_projection)
            lines.append(f"  {c_type} {name} = ({c_type})({expression});")
            arguments_by_id[value.identity] = name
        for value in signature.parameters:
            name = f"argument_{_c_identifier(value.identity)}"
            parameter_projection = parameters[value.identity]
            if parameter_projection.get("kind") == "callback_handle":
                lines.extend(
                    _callback_projection_lines(
                        value=value,
                        projection=parameter_projection,
                        name=name,
                        code_capabilities=code_capabilities,
                    )
                )
                arguments_by_id[value.identity] = f"&{name}"
                continue
            if parameter_projection.get("kind") == "resource":
                resource_lines, resource_name = _resource_parameter_lines(
                    value=value,
                    projection=parameter_projection,
                    name=name,
                )
                lines.extend(resource_lines)
                arguments_by_id[value.identity] = resource_name
                continue
            if parameter_projection.get("kind") not in {"view", "bytes_view"}:
                if parameter_projection.get("kind") == "atomic_object":
                    lines.extend(
                        _atomic_projection_lines(
                            projection=parameter_projection, name=name
                        )
                    )
                    arguments_by_id[value.identity] = f"&{name}"
                continue
            lines.extend(
                _view_projection_lines(
                    value=value,
                    projection=parameter_projection,
                    name=name,
                    scalar_arguments=arguments_by_id,
                    authority_selectors=authority_selectors_by_operation[operation_id],
                )
            )
            arguments_by_id[value.identity] = f"&{name}_view"
        lines.append(
            "  if (memory_fault != 0U) return "
            "(spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"
        )
        call = (
            f"{operation_symbols[operation_id]}("
            f"{context_pointer}"
            f"{''.join(', ' + arguments_by_id[value.identity] for value in signature.parameters)})"
        )
        if signature.results:
            if len(signature.results) != 1:
                raise BoundaryModelError(
                    "component overlay currently requires at most one scalar result"
                )
            result_value = signature.results[0]
            result_type = _result_type(types, signature)
            lines.append(f"  {result_type} logical_result = {call};")
            lines.append(
                "  if (service_fault != 0U) return "
                "(spx_step_result){ SPX_EXTERNAL_FAULT, 0U, 0U };"
            )
            if proof_classification == "machine_overlay":
                lines.extend(
                    _state_export_lines(
                        bundle=bundle,
                        state_projections=state_projections,
                        context_expression=context_expression,
                        runtime_expression="rt",
                    )
                )
            lines.extend(
                _projection_result(
                    results[result_value.identity],
                    exit_transfer=exit_transfer,
                    exit_rva=exit_transfer.rva_start,
                )
            )
        else:
            lines.append(f"  {call};")
            lines.append(
                "  if (service_fault != 0U) return "
                "(spx_step_result){ SPX_EXTERNAL_FAULT, 0U, 0U };"
            )
            if proof_classification == "machine_overlay":
                lines.extend(
                    _state_export_lines(
                        bundle=bundle,
                        state_projections=state_projections,
                        context_expression=context_expression,
                        runtime_expression="rt",
                    )
                )
        result_projection_kinds = {value.get("kind") for value in results.values()}
        if not result_projection_kinds & {"control_condition", "finite_control_target"}:
            lines.append(
                "  return (spx_step_result){ SPX_FALLTHROUGH, "
                f"0x{exit_transfer.rva_start:08x}U, 0U }};"
            )
        lines.extend(["}", ""])
        logical_symbol = _logical_operation_symbol(interface.identity, operation_id)
        lines.extend(
            _logical_operation_thunk(
                bundle=bundle,
                component=component,
                operation=operation,
                source_symbol=operation_symbols[operation_id],
                logical_symbol=logical_symbol,
                service_bindings=service_bindings,
            )
        )
        entries.append(
            {
                "component_id": interface.identity,
                "operation_id": operation_id,
                "entry_unit_id": entry.identity,
                "entry_rva": entry.rva_start,
                "exit_unit_id": exit_transfer.identity,
                "exit_rva": exit_transfer.rva_start,
                "symbol": symbol,
                "logical_symbol": logical_symbol,
                "logical_abi_sha256": _signature_abi_sha256(bundle, signature),
                "service_bindings": [
                    {
                        key: value
                        for key, value in item.items()
                        if not key.startswith("_")
                    }
                    for item in service_bindings
                ],
                "owned_unit_ids": list(semantics.unit_ids),
                "proof_classification": proof_classification,
            }
        )
    return ComponentMachineOverlayV1("\n".join(lines).rstrip() + "\n", tuple(entries))




















def _logical_operation_thunk(
    *,
    bundle: CompiledComponentInterfaceV5,
    component: str,
    operation: object,
    source_symbol: str,
    logical_symbol: str,
    service_bindings: Sequence[Mapping[str, object]],
) -> list[str]:
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    result_type = _result_type(types, signature)
    parameters = ["void *opaque"] + [
        f"{_parameter_type(types, item)} logical_{_c_identifier(item.identity)}"
        for item in signature.parameters
    ]
    arguments = ", ".join(
        f"logical_{_c_identifier(item.identity)}" for item in signature.parameters
    )
    call = f"{source_symbol}(&logical_context{', ' if arguments else ''}{arguments})"
    zero = _zero_result_expression(result_type)
    lines = [
        f"{result_type} {logical_symbol}({', '.join(parameters)}) {{",
        "  spx_component_service_context_v1 *caller =",
        "      (spx_component_service_context_v1 *)opaque;",
        f"  spx_{component}_context_v5 logical_context = {{0}};",
        f"  if (caller == 0 || caller->runtime == 0 || caller->state == 0) {zero}",
    ]
    if bundle.interface.state:
        lines.extend(
            [
                "  (void)logical_context;",
                *(
                    f"  (void)logical_{_c_identifier(item.identity)};"
                    for item in signature.parameters
                ),
                "  if (caller->fault != 0) *caller->fault = UINT32_C(1);",
                f"  {zero}",
                "}",
                "",
            ]
        )
        return lines
    lines.extend(
        _service_setup_lines(
            bundle=bundle,
            component=component,
            service_bindings=service_bindings,
            context_expression="&logical_context",
            runtime_expression="caller->runtime",
            state_expression="caller->state",
            fault_expression="caller->fault",
        )
    )
    lines.append(f"  {'return ' if result_type != 'void' else ''}{call};")
    lines.extend(["}", ""])
    return lines


def _zero_result_expression(result_type: str) -> str:
    if result_type == "void":
        return "return;"
    if result_type.startswith("spx_ref_"):
        return f"return ({result_type}){{0}};"
    return f"return ({result_type})0;"






def _projection_index(value: object, context: str) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        raise BoundaryModelError(f"{context} must be an array")
    result: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(value):
        row = object_(item, f"{context} {index}")
        identity = str(row.get("id", ""))
        projection = object_(row.get("projection"), f"{context} projection {index}")
        if not identity or identity in result:
            raise BoundaryModelError(f"{context} identities are invalid or duplicated")
        result[identity] = projection
    return result


def _projection_read(value: Mapping[str, object]) -> str:
    kind = value.get("kind")
    if kind == "register":
        return f"state->{_register(value.get('register'))}"
    if kind == "stack":
        width = _width(value.get("width"))
        offset = _uint(value.get("offset"), "component overlay stack offset")
        return (
            f"spx_component_read(rt, state->esp + UINT32_C({offset}), "
            f"UINT32_C({width // 8}), &memory_fault)"
        )
    if kind == "static_slot":
        width = _width(value.get("width"))
        rva = _uint(value.get("rva"), "component overlay static-slot RVA")
        return (
            f"spx_component_read(rt, UINT32_C({rva}), "
            f"UINT32_C({width // 8}), &memory_fault)"
        )
    if kind == "constant":
        return f"UINT32_C({_uint(value.get('value'), 'component overlay constant')})"
    raise BoundaryModelError(f"component overlay projection {kind!r} is unsupported")


def _resource_parameter_lines(
    *, value: object, projection: Mapping[str, object], name: str
) -> tuple[list[str], str]:
    source, type_tag = _checked_opaque_resource_projection(
        value=value,
        projection=projection,
        context=f"component parameter {getattr(value, 'identity', name)}",
    )
    if source.get("kind") != "constant" and source.get("at") != "entry":
        raise BoundaryModelError(
            "component resource parameter must be observed at entry"
        )
    physical_word = f"{name}_physical_word"
    return (
        [
            f"  uint32_t {physical_word} = {_projection_read(source)};",
            f"  if (memory_fault != 0U || ({physical_word} == 0U && "
            f"UINT32_C({1 if getattr(value, 'nullable', False) else 0}) == 0U))",
            "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            f"  spx_resource_v2 {name} = {physical_word} == 0U",
            "      ? (spx_resource_v2){0}",
            f"      : (spx_resource_v2){{ UINT32_C({type_tag}), "
            f"UINT32_C(1), (uint64_t){physical_word} }};",
        ],
        name,
    )


def _view_projection_lines(
    *,
    value: object,
    projection: Mapping[str, object],
    name: str,
    scalar_arguments: Mapping[str, str],
    authority_selectors: Mapping[str, str],
) -> list[str]:
    base = object_(projection.get("base"), "component overlay view base")
    address = _projection_read(base)
    extent_id = projection.get("extent_id")
    raw_requested = projection.get("requested_extent")
    raw_extent = projection.get("extent")
    if isinstance(extent_id, str):
        if extent_id not in scalar_arguments:
            raise BoundaryModelError(
                "component overlay view extent value is unavailable"
            )
        requested = scalar_arguments[extent_id]
        extent = requested
    elif isinstance(raw_requested, Mapping):
        requested = _projection_read(raw_requested)
        if (
            isinstance(raw_extent, Mapping)
            and raw_extent.get("kind") != "origin_remainder"
        ):
            extent = _projection_read(raw_extent)
        else:
            extent = f"({name}_machine.extent - {name}_machine.offset)"
    elif projection.get("kind") == "bytes_view":
        requested = "UINT32_C(1)"
        extent = f"({name}_machine.extent - {name}_machine.offset)"
    else:
        raise BoundaryModelError("component overlay view has no checked extent")
    access = getattr(value, "access", None)
    permissions = {
        "read": 1,
        "write": 2,
        "read_write": 3,
    }.get(access)
    if permissions is None:
        raise BoundaryModelError("component overlay view access is unsupported")
    reader = "spx_component_view_read" if permissions & 1 else "0"
    writer = "spx_component_view_write" if permissions & 2 else "0"
    selector = _authority_selector_expression(projection, authority_selectors)
    return [
        f"  uint32_t {name}_address = (uint32_t)({address});",
        f"  spx_machine_reference_v1 {name}_machine = {{0}};",
        "  if (rt == 0 || rt->resolve_reference == 0 ||",
        f"      rt->resolve_reference(rt->context, {name}_address, (uint32_t)({requested}),",
        f"          UINT32_C({permissions}), {selector}, UINT32_C(0), UINT32_C(0), &{name}_machine) != SPX_BOUNDARY_OK ||",
        f"      {name}_machine.offset > {name}_machine.extent)",
        "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
        f"  uint64_t {name}_extent = (uint64_t)({extent});",
        f"  if ({name}_extent > {name}_machine.extent - {name}_machine.offset)",
        "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
        f"  spx_component_view_context {name}_context = {{",
        f"    rt, {name}_address, {name}_extent, UINT32_C({permissions})",
        "  };",
        f"  spx_view_v5 {name}_view = {{",
        f"    .context = &{name}_context,",
        f"    .read_u8 = {reader}, .write_u8 = {writer},",
        "    .base = {",
        f"      {name}_machine.domain, {name}_machine.object,",
        f"      {name}_machine.generation, {name}_machine.offset,",
        f"      {name}_machine.extent, {name}_machine.permissions",
        "    },",
        f"    .extent = {name}_extent, .element_width = UINT32_C(1),",
        f"    .access_context = &{name}_context,",
        f"    .read = {'spx_component_view_read_span' if permissions & 1 else '0'},",
        f"    .write = {'spx_component_view_write_span' if permissions & 2 else '0'}",
        "  };",
    ]


def _view_runtime_helpers(*, need_read: bool, need_write: bool) -> list[str]:
    lines = [
        "typedef struct spx_component_view_context {",
        "  spx_runtime *runtime;",
        "  uint32_t address;",
        "  uint64_t extent;",
        "  uint32_t permissions;",
        "} spx_component_view_context;",
        "",
    ]
    if need_read:
        lines.extend(
            [
                "static uint32_t spx_component_view_read(",
                "    void *opaque, uint32_t offset, uint8_t *result) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  if (view == 0 || result == 0 || view->runtime == 0 ||",
                "      view->runtime->read == 0 || (view->permissions & UINT32_C(1)) == 0U ||",
                "      (uint64_t)offset >= view->extent || offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  *result = (uint8_t)view->runtime->read(",
                "      view->runtime->context, view->address + (uint32_t)offset, UINT32_C(1), &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
                "static uint32_t spx_component_view_read_span(",
                "    void *opaque, spx_ref_v1 base, uint64_t offset, uint32_t width,",
                "    uint64_t *result) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  (void)base;",
                "  if (view == 0 || result == 0 || view->runtime == 0 ||",
                "      view->runtime->read == 0 || (view->permissions & UINT32_C(1)) == 0U ||",
                "      width == UINT32_C(0) || width > UINT32_C(4) ||",
                "      offset > view->extent || (uint64_t)width > view->extent - offset ||",
                "      offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  *result = (uint64_t)view->runtime->read(",
                "      view->runtime->context, view->address + (uint32_t)offset, width, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
            ]
        )
    if need_write:
        lines.extend(
            [
                "static uint32_t spx_component_view_write(",
                "    void *opaque, uint32_t offset, uint8_t value) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  if (view == 0 || view->runtime == 0 || view->runtime->write == 0 ||",
                "      (view->permissions & UINT32_C(2)) == 0U ||",
                "      (uint64_t)offset >= view->extent || offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  view->runtime->write(view->runtime->context,",
                "      view->address + (uint32_t)offset, UINT32_C(1), value, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
                "static uint32_t spx_component_view_write_span(",
                "    void *opaque, spx_ref_v1 base, uint64_t offset, uint32_t width,",
                "    uint64_t value) {",
                "  spx_component_view_context *view = (spx_component_view_context *)opaque;",
                "  uint32_t fault = 0U;",
                "  (void)base;",
                "  if (view == 0 || view->runtime == 0 || view->runtime->write == 0 ||",
                "      (view->permissions & UINT32_C(2)) == 0U ||",
                "      width == UINT32_C(0) || width > UINT32_C(4) ||",
                "      offset > view->extent || (uint64_t)width > view->extent - offset ||",
                "      offset > UINT32_MAX - view->address)",
                "    return UINT32_C(1);",
                "  view->runtime->write(",
                "      view->runtime->context, view->address + (uint32_t)offset, width,",
                "      (uint32_t)value, &fault);",
                "  return fault == 0U ? UINT32_C(0) : UINT32_C(1);",
                "}",
                "",
            ]
        )
    return lines


def _atomic_projection_lines(
    *, projection: Mapping[str, object], name: str
) -> list[str]:
    source = object_(projection.get("source"), "component atomic object source")
    width = _uint(projection.get("width"), "component atomic object width")
    if width != 4:
        raise BoundaryModelError("component overlay currently requires u32 atomics")
    return [
        f"  spx_atomic_object {name} = {{",
        f"    rt, (uint32_t)({_projection_read(source)}), UINT32_C({width})",
        "  };",
    ]


def _atomic_runtime_helpers() -> list[str]:
    return [
        "struct spx_atomic_object {",
        "  spx_runtime *runtime;",
        "  uint32_t address;",
        "  uint32_t width;",
        "};",
        "",
        "spx_atomic_status spx_atomic_compare_exchange(",
        "    spx_atomic_object *object, uint32_t expected, uint32_t desired,",
        "    spx_atomic_observation *observation) {",
        "  uint32_t fault = 0U;",
        "  if (object == 0 || object->runtime == 0 || observation == 0)",
        "    return SPX_ATOMIC_UNSUPPORTED;",
        "  spx_runtime_atomic_compare_exchange(object->runtime, object->address,",
        "      object->width, expected, desired, &observation->observed,",
        "      &observation->exchanged, &fault);",
        "  observation->written = observation->exchanged != 0U",
        "      ? desired : observation->observed;",
        "  return fault == 0U ? SPX_ATOMIC_OK : SPX_ATOMIC_FAULT;",
        "}",
        "",
        "spx_atomic_status spx_atomic_exchange(",
        "    spx_atomic_object *object, uint32_t desired,",
        "    spx_atomic_observation *observation) {",
        "  uint32_t fault = 0U;",
        "  if (object == 0 || object->runtime == 0 || observation == 0)",
        "    return SPX_ATOMIC_UNSUPPORTED;",
        "  spx_runtime_atomic_exchange(object->runtime, object->address, object->width,",
        "      desired, &observation->observed, &fault);",
        "  observation->written = desired;",
        "  observation->exchanged = fault == 0U;",
        "  return fault == 0U ? SPX_ATOMIC_OK : SPX_ATOMIC_FAULT;",
        "}",
        "",
    ]


def _projection_result(
    value: Mapping[str, object], *, exit_transfer: _Transfer, exit_rva: int
) -> list[str]:
    kind = value.get("kind")
    if kind == "register":
        register = _register(value.get("register"))
        width = _width(value.get("width"))
        mask = 0xFFFFFFFF if width == 32 else (1 << width) - 1
        return [f"  state->{register} = ((uint32_t)logical_result) & UINT32_C({mask});"]
    if kind == "callback_handle":
        source = object_(value.get("source"), "component callback result source")
        if (
            source.get("kind") != "register"
            or source.get("register") != "eax"
            or source.get("width") != 32
        ):
            raise BoundaryModelError("component callback result is not an EAX handle")
        return [
            "  state->eax = logical_result == 0",
            "      ? UINT32_C(0) : logical_result->physical_word;",
        ]
    if kind == "control_condition":
        outcomes = [
            action for action in exit_transfer.actions if action.op == "outcome_branch"
        ]
        if len(outcomes) != 1 or len(outcomes[0].args) != 3:
            raise BoundaryModelError(
                "control-condition result requires one exact branch outcome"
            )
        true_rva, false_rva = outcomes[0].args[1:]
        return [
            "  return (spx_step_result){ SPX_BRANCH,",
            f"      logical_result != 0U ? UINT32_C({true_rva}) : UINT32_C({false_rva}), 0U }};",
        ]
    if kind == "finite_control_target":
        raw_targets = value.get("targets")
        if not isinstance(raw_targets, list) or not raw_targets:
            raise BoundaryModelError(
                "finite-control result requires a nonempty target catalog"
            )
        targets: list[tuple[int, int]] = []
        for index, raw in enumerate(raw_targets):
            row = object_(raw, f"finite-control target {index}")
            logical = _uint(row.get("logical_value"), "finite-control logical value")
            target = _uint(row.get("target_rva"), "finite-control target RVA")
            targets.append((logical, target))
        if targets != sorted(set(targets)) or len({row[0] for row in targets}) != len(
            targets
        ):
            raise BoundaryModelError("finite-control target catalog is duplicated")
        return [
            "  switch ((uint32_t)logical_result) {",
            *(
                f"    case UINT32_C({logical}): return (spx_step_result)"
                f"{{ SPX_JUMP, UINT32_C({target}), 0U }};"
                for logical, target in targets
            ),
            "    default: return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            "  }",
        ]
    raise BoundaryModelError("component overlay result projection is unsupported")


def _scalar_type(value: object, types: Mapping[str, object]) -> str:
    kind = getattr(value, "kind", None)
    body = getattr(value, "body", {})
    if kind == "enum" and isinstance(body, Mapping):
        underlying = body.get("underlying_type_id")
        if not isinstance(underlying, str) or underlying not in types:
            raise BoundaryModelError("component overlay enum has no underlying type")
        return _scalar_type(types[underlying], types)
    width = body.get("width_bits") if isinstance(body, Mapping) else None
    signed = body.get("signed") if isinstance(body, Mapping) else None
    if kind != "integer" or width not in {8, 16, 32} or not isinstance(signed, bool):
        raise BoundaryModelError(
            "component overlay requires an IA-32 scalar integer type"
        )
    return f"{'int' if signed else 'uint'}{width}_t"


def _strings(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise BoundaryModelError(f"{context} must be a nonempty-text array")
    result = tuple(value)
    if result != tuple(sorted(set(result))):
        raise BoundaryModelError(f"{context} must be sorted and unique")
    return result


def _register(value: object) -> str:
    if value not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
        raise BoundaryModelError("component overlay register is unsupported")
    return str(value)


def _width(value: object) -> int:
    result = _uint(value, "component overlay width")
    if result not in {8, 16, 32}:
        raise BoundaryModelError("component overlay width is unsupported")
    return result






__all__ = [
    "ComponentMachineOverlayV1",
    "render_component_dispatch_registry_v1",
    "render_component_machine_overlay_v5",
]
