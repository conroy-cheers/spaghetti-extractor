"""Direct V5 operation-to-machine-state overlays for portable C."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
from typing import Callable, Mapping, Sequence

from ..boundary._canonical import BoundaryModelError, object_
from ..transfer.model import _Transfer
from ..transfer.behavioral_c_render import behavioral_c_dispatch_abi_declarations
from ..transfer.values import _c_string
from .component_c_v5 import _parameter_type, _result_type
from .machine_overlay_result_views import result_view_runtime_helpers, nullable_input_view_lines
from .machine_overlay_state_views import state_view_result_lines
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_storage import register_relative_address
from .machine_overlay_logical_views_v5 import bounded_view_argument_lines
from .machine_overlay_external_v5 import (
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
    checked_result_fault_outcomes,
    result_fault_outcome_lines,
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


from .machine_overlay_runtime_helpers import _view_runtime_helpers, _atomic_runtime_helpers

def _common_owned_boundary_exit(exits, *, owned_units, transfer_index):
    """Find one observable outgoing edge, excluding owned internal branches.

    This only chooses an adapter outcome. Contextual checking still proves the
    C body reaches it with equivalent state, effects and progress.
    """
    owned = [transfer_index.get(identity) for identity in owned_units]
    if any(item is None for item in owned):
        return None
    owned_rvas = {item.rva_start for item in owned}
    if len(owned_rvas) != len(owned):
        return None
    outcomes = set()
    for item in exits:
        if item.identity not in owned_units or not item.actions:
            return None
        terminal = item.actions[-1]
        if terminal.op == 'outcome_branch' and len(terminal.args) == 3:
            targets, kind = terminal.args[1:], 'SPX_BRANCH'
        elif terminal.op in {'outcome_jump', 'outcome_fallthrough'} and len(terminal.args) == 1:
            targets = terminal.args
            kind = 'SPX_JUMP' if terminal.op == 'outcome_jump' else 'SPX_FALLTHROUGH'
        else:
            return None
        if any(type(target) is not int or not 0 <= target <= 0xffffffff for target in targets):
            return None
        outgoing = {target for target in targets if target not in owned_rvas}
        if len(outgoing) != 1:
            return None
        outcomes.add((kind, next(iter(outgoing))))
    return next(iter(outcomes)) if len(outcomes) == 1 else None


ExternalServiceThunkRendererV1 = Callable[
    [
        CompiledComponentInterfaceV5,
        Mapping[str, object],
        Mapping[str, str],
    ],
    Sequence[str],
]


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
    retired_function_symbols: Sequence[str] = (),
) -> str:
    """Render the one strong module-wide dispatcher for selected V5 overlays."""

    if not entries or not portable_unit_rvas:
        raise BoundaryModelError(
            "portable dispatch registry requires overlays and owned units"
        )
    if len(set(portable_unit_rvas.values())) != len(portable_unit_rvas):
        raise BoundaryModelError("portable dispatch unit RVAs overlap")
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
    declarations = [
        f"extern spx_step_result {symbol}(spx_runtime *, spx_machine_state *);"
        for _rva, symbol, _component, _operation in normalized
    ]
    # Ownership covers the interior too. It must never silently fall through to
    # generated code merely because no proved adapter admits this entry.
    rejected_symbol = "spx_portable_interior_rejected"
    for row in providers.values():
        for unit_id in row["owned_unit_ids"]:
            rva = portable_unit_rvas[unit_id]
            if rva != row["entry_rva"]:
                normalized.append((rva, rejected_symbol,
                                   str(row["component_id"]), str(row["operation_id"])))
    if len({rva for rva, *_ in normalized}) != len(normalized):
        raise BoundaryModelError("portable dispatch unit RVAs overlap")
    normalized.sort()
    retired = sorted(set(retired_function_symbols))
    reserved = seen_symbols | seen_logical_symbols | {rejected_symbol,
        "spx_region_overrides", "spx_region_override_count", "spx_region_override_lookup"}
    if any(not symbol or _c_identifier(symbol) != symbol or symbol in reserved
           for symbol in retired):
        raise BoundaryModelError("retired generated function symbol is invalid")
    # The retained, qualified dispatcher still references omitted routine
    # objects. These ABI-compatible guards supply no original implementation;
    # only the proved overlay entry above can execute a selected replacement.
    retired_guards = [
        f"spx_step_result {symbol}(spx_runtime *rt, spx_machine_state *state, uint32_t rva) {{\n"
        "  (void)rt; (void)state;\n"
        "  return (spx_step_result){ SPX_UNIMPLEMENTED, rva, 0U };\n}"
        for symbol in retired
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
            '#include "state-machine-runtime.h"',
            "#include <stdint.h>",
            "",
            *behavioral_c_dispatch_abi_declarations(),
            "",
            *declarations,
            "",
            f"static spx_step_result {rejected_symbol}(spx_runtime *rt, spx_machine_state *state) {{",
            "  (void)rt; (void)state;",
            "  return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            "}",
            *retired_guards,
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
    external_service_thunk_renderer: ExternalServiceThunkRendererV1 | None = None,
    emit_proof_local_view_codec: bool = True,
) -> ComponentMachineOverlayV1:
    """Render fail-closed adapters directly from the checked V5 contract.

    ``machine_overlay`` imports and transactionally writes back the original
    mapped state on every call. ``encapsulated_owned`` imports once into one
    image-lifetime context and never publishes that private representation
    back to the retired mapped cells. The latter is safe only after the direct
    provider has emitted an ownership/alias admission receipt.
    """

    interface = bundle.interface
    if type(emit_proof_local_view_codec) is not bool:
        raise BoundaryModelError("proof local-view codec selection must be boolean")
    render_external_service_thunk = (
        _external_service_thunk
        if external_service_thunk_renderer is None
        else external_service_thunk_renderer
    )
    if proof_classification not in {"machine_overlay", "encapsulated_owned"}:
        raise BoundaryModelError("component overlay proof classification is invalid")
    if proof_classification == "encapsulated_owned" and not interface.state:
        raise BoundaryModelError("encapsulated-owned overlay requires persistent state")
    shared_state_views = any(item.value.interpretation == "view" for item in interface.state)
    if proof_classification == "encapsulated_owned" and shared_state_views:
        raise BoundaryModelError("shared state views cannot persist a borrowed operation runtime")
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
    legacy_view_parameters = [value for value in view_parameters if not value.nullable]
    for value in view_parameters:
        if value.nullable:
            pointer = bundle.intent.schema.type_index[value.type_id]
            element = bundle.intent.schema.type_index.get(pointer.body.get("pointee_type_id"))
            if (pointer.kind != "pointer" or element is None or element.kind != "integer"
                    or element.body.get("width_bits") != 8):
                raise BoundaryModelError("nullable input views require byte elements")
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
        "  uint32_t *memory_fault;",
        "  uint32_t *service_fault;",
        "  struct { uint32_t physical_word; uint32_t target_rva; } callback_result;",
        *([f"  struct {{ uint32_t value, fault; }} entry_targets[{max(1, len(interface.services))}];"]
          if any(raw.get("provider", {}).get("target_sampling") == "operation_entry"
                 for semantics in contract.machine_semantics
                 for raw in semantics.machine_projection.get("service_bindings", [])) else []),
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
    if has_views and legacy_view_parameters:
        lines.extend(
            _view_runtime_helpers(
                need_read=any(
                    value.access in {"read", "read_write"} for value in legacy_view_parameters
                ),
                need_write=any(
                    value.access in {"write", "read_write"} for value in legacy_view_parameters
                ),
            )
        )
    if has_atomics:
        lines.extend(_atomic_runtime_helpers())
    if has_external_services or any(item.value.interpretation != "view" for item in interface.state):
        lines.extend(_external_service_runtime_helpers())
    nullable_view_inputs = any(value.nullable for value in view_parameters)
    input_reference_outputs = any('exit_projection' in row
        for semantics in semantic_index.values()
        for row in semantics.machine_projection.get('operation', {}).get('parameters', []))
    if nullable_view_inputs or shared_state_views or any(value.interpretation == 'view' for service in interface.services
           for value in bundle.intent.schema.signature_index[service.signature_id].results):
        lines.extend(result_view_runtime_helpers(proof_codec_symbol=
            f"__CPROVER_spx_{component}_local_view_codec"
            if external_service_thunk_renderer is not None and emit_proof_local_view_codec else None,
            input_view_decoder=nullable_view_inputs, input_reference_encoder=input_reference_outputs))
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
        common_exit = _common_owned_boundary_exit(checked_exits,
            owned_units=owned_units, transfer_index=transfer_index)
        if len(checked_exits) > 1 and any(
            not item.actions or item.actions[-1].op != "outcome_return"
            for item in checked_exits
        ) and common_exit is None:
            raise BoundaryModelError(
                "component overlay multiple exits lack terminal-return or common-boundary equivalence"
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
                rendered_thunk = tuple(
                    render_external_service_thunk(
                        bundle,
                        service,
                        authority_selectors_by_operation[operation_id],
                    )
                )
                if not rendered_thunk or any(
                    not isinstance(line, str) for line in rendered_thunk
                ):
                    raise BoundaryModelError(
                        "component external-service renderer returned malformed C"
                    )
                lines.extend(rendered_thunk)
        parameters = _projection_index(
            projection.get("parameters"), "component overlay parameters"
        )
        result_bindings = _value_binding_index(
            projection.get("results"), "component overlay results"
        )
        results = {
            identity: object_(
                binding.get("projection"),
                f"component overlay result {identity} projection",
            )
            for identity, binding in result_bindings.items()
        }
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
        fault_outcomes = checked_result_fault_outcomes(signature, result_bindings, types)
        from .machine_overlay_result_views import (checked_parameter_exit_transports,
            parameter_exit_snapshots, parameter_exit_encoding, parameter_exit_stores)
        parameter_exits = checked_parameter_exit_transports(bundle, signature, projection)
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
                # Keep the unused-helper reference unevaluated; it must not
                # introduce another target for runtime read function pointers.
                "  (void)sizeof(&spx_component_read);",
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
                memory_fault_expression="&memory_fault",
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
                "record_view",
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
            if parameter_projection.get("kind") == "record_view":
                record_lines, record_name = _record_parameter_lines(
                    types=types,
                    value=value,
                    projection=parameter_projection,
                    name=name,
                )
                lines.extend(record_lines)
                arguments_by_id[value.identity] = record_name
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
        lines.extend(parameter_exit_snapshots(parameter_exits))
        if signature.results:
            if len(signature.results) != 1:
                raise BoundaryModelError(
                    "component overlay currently requires at most one result"
                )
            result_value = signature.results[0]
            result_type = _result_type(types, signature)
            lines.append(f"  {result_type} logical_result = {call};")
            lines.append(
                "  if (memory_fault != 0U) return "
                "(spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"
            )
            lines.append(
                "  if (service_fault != 0U) return "
                "(spx_step_result){ SPX_EXTERNAL_FAULT, 0U, 0U };"
            )
            lines.extend(result_fault_outcome_lines(fault_outcomes))
            lines.extend(parameter_exit_encoding(parameter_exits))
            if proof_classification == "machine_overlay":
                lines.extend(
                    _state_export_lines(
                        bundle=bundle,
                        state_projections=state_projections,
                        context_expression=context_expression,
                        runtime_expression="rt",
                    )
                )
            result_projection = results[result_value.identity]
            if result_projection.get("kind") == "view":
                if any(result_bindings[result_value.identity].get(field) is not None for field in ("encoding", "decoding")):
                    raise BoundaryModelError("shared state result view cannot use scalar codecs")
                lines.extend(state_view_result_lines(
                    bundle=bundle, value=result_value, projection=result_projection,
                    state_projections=state_projections, runtime="rt",
                ))
                result_projection = result_projection["base"]
            elif result_projection.get("kind") in {"register", "stack"}:
                lines.extend(
                    _logical_result_word_lines(
                        logical_type=types[result_value.type_id],
                        types=types,
                    )
                )
            lines.extend(
                _projection_result(
                    result_projection,
                    encoding=result_bindings[result_value.identity].get("encoding"),
                    decoding=result_bindings[result_value.identity].get("decoding"),
                    parameter_kinds={
                        value.identity: parameters[value.identity].get("kind")
                        for value in signature.parameters
                    },
                    exit_transfer=exit_transfer,
                    exit_rva=exit_transfer.rva_start,
                )
            )
        else:
            lines.append(f"  {call};")
            lines.append(
                "  if (memory_fault != 0U) return "
                "(spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };"
            )
            lines.append(
                "  if (service_fault != 0U) return "
                "(spx_step_result){ SPX_EXTERNAL_FAULT, 0U, 0U };"
            )
            lines.extend(parameter_exit_encoding(parameter_exits))
            if proof_classification == "machine_overlay":
                lines.extend(
                    _state_export_lines(
                        bundle=bundle,
                        state_projections=state_projections,
                        context_expression=context_expression,
                        runtime_expression="rt",
                    )
                )
        lines.extend(parameter_exit_stores(parameter_exits))
        result_projection_kinds = {value.get("kind") for value in results.values()}
        if len(checked_exits) > 1 and result_projection_kinds & {"control_condition", "finite_control_target"}:
            raise BoundaryModelError("component overlay multiple control-result exits require an explicit outcome relation")
        if not result_projection_kinds & {"control_condition", "finite_control_target"}:
            if all(
                item.actions and item.actions[-1].op == "outcome_return"
                for item in checked_exits
            ):
                # Logical C has already computed the operation's postcondition.
                # Consume the compiler-generated cdecl return epilogue here so
                # the adapter exposes the same terminal state.  Falling into
                # that exact epilogue after publishing a logical result can
                # clobber it (for example, a trailing cmov in ascii-to-lower).
                lines.extend(
                    [
                        "  if (rt == 0 || rt->read == 0 ||",
                        "      state->esp > UINT32_MAX - UINT32_C(4))",
                        "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                        "  uint32_t return_address = rt->read(",
                        "      rt->context, state->esp, UINT32_C(4), &memory_fault);",
                        "  if (memory_fault != UINT32_C(0))",
                        "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
                        "  state->esp += UINT32_C(4);",
                        f"  state->original_rva = UINT32_C({exit_transfer.rva_start});",
                        "  return (spx_step_result){ SPX_RETURN, 0U, return_address };",
                    ]
                )
            elif common_exit is not None and (len(checked_exits) > 1 or common_exit[0] == 'SPX_BRANCH'):
                kind, target = common_exit
                lines.append(f"  return (spx_step_result){{ {kind}, UINT32_C({target}), 0U }};")
            else:
                terminal = exit_transfer.actions[-1] if exit_transfer.actions else None
                if terminal is not None and terminal.op in {
                    "outcome_fallthrough",
                    "outcome_jump",
                }:
                    if len(terminal.args) != 1 or not isinstance(terminal.args[0], int):
                        raise BoundaryModelError(
                            "component overlay unconditional exit is malformed"
                        )
                    kind = (
                        "SPX_FALLTHROUGH"
                        if terminal.op == "outcome_fallthrough"
                        else "SPX_JUMP"
                    )
                    lines.append(
                        f"  return (spx_step_result){{ {kind}, "
                        f"UINT32_C({terminal.args[0]}), 0U }};"
                    )
                else:
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
                parameter_projections=parameters,
                authority_selectors=authority_selectors_by_operation[operation_id],
                state_projections=state_projections if proof_classification == "machine_overlay" else None,
                result_projections=results,
                fault_outcomes=fault_outcomes,
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
                "object_authority_selectors": dict(authority_selectors_by_operation[operation_id]),
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


def render_bound_proof_overlay(*, expected_sha256, requires_local_view_codec, **arguments):
    """Reconstruct a retained overlay using only known, exactly bound variants.

    Older overlays included an unused cut codec. Both variants may be imported
    when the checked plan has no local-view cuts; a plan that needs the codec
    has only one admissible variant. No bytes or evidence hashes are normalized.
    """
    if type(requires_local_view_codec) is not bool:
        raise BoundaryModelError("proof local-view codec requirement must be boolean")
    for enabled in ((True,) if requires_local_view_codec else (False, True)):
        overlay = render_component_machine_overlay_v5(
            **arguments, emit_proof_local_view_codec=enabled)
        if hashlib.sha256(overlay.source.encode("ascii")).hexdigest() == expected_sha256:
            return overlay
    raise BoundaryModelError("proof overlay differs from the checked bytes")


def _logical_operation_thunk(
    *,
    bundle: CompiledComponentInterfaceV5,
    component: str,
    operation: object,
    source_symbol: str,
    logical_symbol: str,
    service_bindings: Sequence[Mapping[str, object]],
    parameter_projections: Mapping[str, Mapping[str, object]] | None = None,
    authority_selectors: Mapping[str, str] | None = None,
    state_projections: Mapping[str, Mapping[str, object]] | None = None,
    result_projections: Mapping[str, Mapping[str, object]] | None = None,
    fault_outcomes: Sequence[Mapping[str, object]] = (),
) -> list[str]:
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    result_type = _result_type(types, signature)
    parameters = ["void *opaque"] + [
        f"{_parameter_type(types, item)} logical_{_c_identifier(item.identity)}"
        for item in signature.parameters
    ]
    argument_lines: list[str] = []
    argument_expressions: list[str] = []
    for item in signature.parameters:
        name = f"logical_{_c_identifier(item.identity)}"
        extent = getattr(item, "extent")
        if getattr(item, "interpretation") != "view" or extent.get("kind") not in {
            "fixed",
            "value",
        }:
            argument_expressions.append(name)
            continue
        bounded_pointer = f"{name}_argument"
        extent_expression = (
            f"UINT64_C({int(extent['bytes'])})"
            if extent["kind"] == "fixed"
            else f"(uint64_t)logical_{_c_identifier(str(extent['value_id']))}"
        )
        argument_lines.extend(
            bounded_view_argument_lines(
                name=name, extent=extent_expression, access=item.access,
                selector=_authority_selector_expression(
                    (parameter_projections or {}).get(item.identity, {}),
                    authority_selectors or {},
                ),
                zero_result=_zero_result_expression(result_type),
            )
        )
        argument_expressions.append(bounded_pointer)
    arguments = ", ".join(argument_expressions)
    call = f"{source_symbol}(&logical_context{', ' if arguments else ''}{arguments})"
    zero = _zero_result_expression(result_type)
    lines = [
        f"{result_type} {logical_symbol}({', '.join(parameters)}) {{",
        "  spx_component_service_context_v1 *caller =",
        "      (spx_component_service_context_v1 *)opaque;",
        f"  spx_{component}_context_v5 logical_context = {{0}};",
        f"  if (caller == 0 || caller->runtime == 0 || caller->state == 0) {zero}",
    ]
    shared = bool(bundle.interface.state) and state_projections is not None and len(bundle.intent.protocol_states) == 1 and all(
        item.initial is None and item.value.interpretation == "view" for item in bundle.interface.state)
    if bundle.interface.state and not shared:
        lines.extend(
            [
                "  (void)logical_context;",
                *(
                    f"  (void)logical_{_c_identifier(item.identity)};"
                    for item in signature.parameters
                ),
                "  if (caller->service_fault != 0) *caller->service_fault = UINT32_C(1);",
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
            memory_fault_expression="caller->memory_fault",
            fault_expression="caller->service_fault",
        )
    )
    lines.extend(argument_lines)
    if shared:
        from .machine_overlay_state_views import state_view_import_lines, state_view_export_lines
        failure = "{ if (caller->memory_fault != 0) *caller->memory_fault = UINT32_C(1); " + zero + " }"
        for item in bundle.interface.state:
            row = state_projections[item.value.identity]
            lines.extend(state_view_import_lines(bundle=bundle, item=item, row=row,
                selector=_authority_selector_expression(row["entry"], authority_selectors or {}),
                context="logical_context", runtime="caller->runtime", failure=failure))
        lines.append(f"  {result_type + ' logical_result = ' if result_type != 'void' else ''}{call};")
        lines.extend(result_fault_outcome_lines(fault_outcomes, caller="caller"))
        lines.extend(state_view_export_lines(bundle=bundle, state_projections=state_projections,
            context="logical_context", runtime="caller->runtime", failure=failure))
        if signature.results and signature.results[0].interpretation == "view":
            lines.extend(state_view_result_lines(bundle=bundle, value=signature.results[0],
                projection=(result_projections or {})[signature.results[0].identity],
                state_projections=state_projections, runtime="caller->runtime", failure=failure))
        lines.append("  return logical_result;" if result_type != "void" else "  return;")
    elif fault_outcomes:
        lines.append(f"  {result_type} logical_result = {call};")
        lines.extend(result_fault_outcome_lines(fault_outcomes, caller="caller"))
        lines.append("  return logical_result;")
    else:
        lines.append(f"  {'return ' if result_type != 'void' else ''}{call};")
    lines.extend(["}", ""])
    return lines


def _zero_result_expression(result_type: str) -> str:
    if result_type == "void":
        return "return;"
    if result_type.startswith("spx_") and "*" not in result_type:
        return f"return ({result_type}){{0}};"
    return f"return ({result_type})0;"


def _record_parameter_lines(
    *,
    types: Mapping[str, object],
    value: object,
    projection: Mapping[str, object],
    name: str,
) -> tuple[list[str], str]:
    logical_type = types[getattr(value, "type_id")]
    if getattr(value, "interpretation") != "value" or logical_type.kind != "record":
        raise BoundaryModelError(
            "component record-view projection requires a logical record value"
        )
    raw_fields = projection.get("fields")
    if not isinstance(raw_fields, list):
        raise BoundaryModelError("component record-view fields are malformed")
    projection_by_id = {
        str(object_(item, "component record-view field").get("id")): object_(
            object_(item, "component record-view field").get("projection"),
            "component record-view field projection",
        )
        for item in raw_fields
    }
    schema_fields = tuple(logical_type.body["fields"])
    schema_ids = tuple(str(item["id"]) for item in schema_fields)
    if set(projection_by_id) != set(schema_ids) or len(projection_by_id) != len(
        raw_fields
    ):
        raise BoundaryModelError(
            "component record-view projection is not total over logical fields"
        )
    lines = [f"  spx_{_c_identifier(logical_type.identity)}_v2 {name} = {{"]
    for field in schema_fields:
        field_id = str(field["id"])
        field_type = types[str(field["type_id"])]
        if field_type.kind not in {"bool", "integer", "enum", "pointer"}:
            raise BoundaryModelError(
                "component record-view fields must be scalar machine words"
            )
        field_projection = projection_by_id[field_id]
        if (
            field_projection.get("kind")
            not in {"register", "stack", "static_slot", "constant"}
            or field_projection.get("width") != 32
        ):
            raise BoundaryModelError(
                "component record-view field projection must be one machine word"
            )
        field_c_type = _scalar_type(field_type, types)
        lines.append(
            f"    .{_c_identifier(field_id)} = ({field_c_type})({_projection_read(field_projection)}),"
        )
    lines.append("  };")
    return lines, name


def _projection_index(value: object, context: str) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        raise BoundaryModelError(f"{context} must be an array")
    result: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(value):
        row = object_(item, f"{context} {index}")
        if "fault_outcomes" in row:
            raise BoundaryModelError("fault outcomes are only supported on results")
        identity = str(row.get("id", ""))
        projection = object_(row.get("projection"), f"{context} projection {index}")
        if not identity or identity in result:
            raise BoundaryModelError(f"{context} identities are invalid or duplicated")
        result[identity] = projection
    return result


def _value_binding_index(
    value: object, context: str
) -> dict[str, Mapping[str, object]]:
    if not isinstance(value, list):
        raise BoundaryModelError(f"{context} must be an array")
    result: dict[str, Mapping[str, object]] = {}
    for index, item in enumerate(value):
        row = object_(item, f"{context} {index}")
        identity = str(row.get("id", ""))
        object_(row.get("projection"), f"{context} projection {index}")
        if not identity or identity in result:
            raise BoundaryModelError(f"{context} identities are invalid or duplicated")
        if set(row) - {"id", "projection", "decoding", "encoding", "fault_outcomes"}:
            raise BoundaryModelError(f"{context} {identity} has unsupported fields")
        if row.get("decoding") is not None and row.get("encoding") is None:
            raise BoundaryModelError(
                f"{context} {identity} has a decoding but no inverse encoding"
            )
        result[identity] = row
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
            f"spx_component_read(rt, rt->image_base + UINT32_C({rva}), "
            f"UINT32_C({width // 8}), &memory_fault)"
        )
    if kind == "offset":
        return register_relative_address(value, state="(*state)", phase="entry")
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
    if getattr(value, "nullable", False):
        return nullable_input_view_lines(value=value, projection=projection, name=name,
            address=address, selector=_authority_selector_expression(projection, authority_selectors))
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




def _projection_result(
    value: Mapping[str, object],
    *,
    encoding: object,
    decoding: object,
    parameter_kinds: Mapping[str, object],
    exit_transfer: _Transfer,
    exit_rva: int,
) -> list[str]:
    kind = value.get("kind")
    encoded_result = _result_encoding_expression(
        encoding,
        parameter_kinds=parameter_kinds,
        projected_value="logical_result_word",
    )
    if decoding is not None and encoding is None:
        raise BoundaryModelError(
            "component overlay result decoding has no inverse encoding"
        )
    if kind == "register":
        register = _register(value.get("register"))
        width = _width(value.get("width"))
        mask = 0xFFFFFFFF if width == 32 else (1 << width) - 1
        cast_result = f"({encoded_result})"
        return [f"  state->{register} = ((uint32_t){cast_result}) & UINT32_C({mask});"]
    if kind == "stack":
        if value.get("at") != "exit":
            raise BoundaryModelError("component stack result requires an exit projection")
        width = _width(value.get("width"))
        address = register_relative_address({"kind": "offset", "at": "exit",
            "base": {"kind": "register", "register": "esp", "width": 32, "at": "exit"},
            "offset_bytes": value["offset"]}, state="(*state)", phase="exit")
        return [
            "  if (rt == 0 || rt->write == 0)",
            "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
            f"  rt->write(rt->context, (uint32_t)({address}), UINT32_C({width // 8}),",
            f"      (uint32_t)({encoded_result}), &memory_fault);",
            "  if (memory_fault != 0U)",
            "    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };",
        ]
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
                f"{{ SPX_INDIRECT_JUMP, 0U, "
                f"rt->image_base + UINT32_C({target}) }};"
                for logical, target in targets
            ),
            "    default: return (spx_step_result){ SPX_UNIMPLEMENTED, 0U, 0U };",
            "  }",
        ]
    raise BoundaryModelError("component overlay result projection is unsupported")


def _result_encoding_expression(
    value: object,
    *,
    parameter_kinds: Mapping[str, object],
    projected_value: str = "logical_result",
) -> str:
    """Render the declared logical-result to machine-word codec.

    ``projected_value`` denotes the Portable-C result on the encoding side.
    Result codecs may depend on operation parameters, but never on hidden
    component state.  Byte reads are intentionally unsupported here: an
    adapter result representation must be a pure value transformation.
    """

    if value is None:
        return projected_value
    row = object_(value, "component overlay result encoding")
    op = row.get("op")
    if op == "projected_value":
        return projected_value
    if op == "const":
        raw = _uint(row.get("value"), "component overlay encoding constant")
        return f"UINT32_C({raw & 0xFFFFFFFF})"
    if op == "parameter":
        identity = str(row.get("name", ""))
        name = _c_identifier(identity)
        if identity not in parameter_kinds or parameter_kinds[identity] in {
            "view",
            "bytes_view",
            "resource",
            "callback_handle",
            "atomic_object",
        }:
            raise BoundaryModelError(
                "component overlay result encoding references a non-scalar parameter"
            )
        return f"argument_{name}"
    if op in {"bytes_address", "byte_extent"}:
        identity = str(row.get("name", ""))
        name = _c_identifier(identity)
        if parameter_kinds.get(identity) not in {"view", "bytes_view"}:
            raise BoundaryModelError(
                "component overlay result encoding references a non-view parameter"
            )
        field = "base.object" if op == "bytes_address" else "extent"
        return f"((uint32_t)(argument_{name}_view.{field}))"
    if op in {"state_input", "byte_read"}:
        raise BoundaryModelError(
            "component overlay result encoding is not a pure parameter transformation"
        )
    args = row.get("args")
    if not isinstance(args, list):
        raise BoundaryModelError("component overlay result encoding has no arguments")
    rendered = [
        _result_encoding_expression(
            item,
            parameter_kinds=parameter_kinds,
            projected_value=projected_value,
        )
        for item in args
    ]
    binary = {
        "add32": "+",
        "sub32": "-",
        "and32": "&",
        "or32": "|",
        "xor32": "^",
        "eq": "==",
        "ult32": "<",
        "ule32": "<=",
        "and": "&&",
        "or": "||",
    }
    if op in binary and len(rendered) == 2:
        return f"(({rendered[0]}) {binary[op]} ({rendered[1]}))"
    if op == "not" and len(rendered) == 1:
        return f"(!({rendered[0]}))"
    if op == "ite" and len(rendered) == 3:
        return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
    raise BoundaryModelError("component overlay result encoding is unsupported")


def _logical_result_word_lines(
    *,
    value_name: str = "logical_result",
    logical_type: object,
    types: Mapping[str, object],
) -> list[str]:
    """Render a defined, conversion-checkable IA-32 result bit pattern."""

    value = logical_type
    while getattr(value, "kind", None) == "enum":
        body = getattr(value, "body", {})
        underlying = (
            body.get("underlying_type_id") if isinstance(body, Mapping) else None
        )
        if not isinstance(underlying, str) or underlying not in types:
            raise BoundaryModelError(
                "component overlay enum result has no underlying type"
            )
        value = types[underlying]
    body = getattr(value, "body", {})
    width = body.get("width_bits") if isinstance(body, Mapping) else None
    signed = body.get("signed") if isinstance(body, Mapping) else None
    if getattr(value, "kind", None) not in {"integer", "bool"}:
        raise BoundaryModelError("component overlay register result is not scalar")
    if getattr(value, "kind", None) == "bool":
        width, signed = 8, False
    if width not in {8, 16, 32} or not isinstance(signed, bool):
        raise BoundaryModelError(
            "component overlay register result width is unsupported"
        )
    if not signed:
        return [f"  uint32_t logical_result_word = (uint32_t){value_name};"]
    # Avoid a direct negative signed-to-unsigned cast: CBMC's conversion check
    # quite reasonably asks us to make the intended two's-complement encoding
    # explicit.  +(1) before negation keeps INT_MIN defined.
    return [
        "  uint32_t logical_result_word;",
        f"  if ({value_name} < 0)",
        "    logical_result_word = UINT32_C(0) -",
        f"        ((uint32_t)(-({value_name} + 1)) + UINT32_C(1));",
        "  else",
        f"    logical_result_word = (uint32_t){value_name};",
    ]


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
    "ExternalServiceThunkRendererV1",
    "render_component_dispatch_registry_v1",
    "render_component_machine_overlay_v5",
]
