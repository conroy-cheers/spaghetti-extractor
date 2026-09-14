"""Proof-only wrappers for separately qualified connected Portable-C providers.

The replay strategy executes a connected provider once; the checked scalar
strategy omits its body and couples an arbitrary result. Both require a separately
qualified exact/source dependency and related logical inputs and memory before
the source side can consume the shared result and public effect transcript.
The experimental read-only renderer exercises conditional composition only;
it has no provider qualification or receipt-authority path.
"""

from __future__ import annotations

import re
import hashlib
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_readonly_evidence import checked_connected_source_contract
from .source import component_operation_symbols, load_component_source_package
from .bisimulation_readable_composition import STRATEGY as IMAGE_READABLE_STRATEGY, image_readable_entry_checks
from .bisimulation_call_entry import checked_call_entry_contract, call_entry_checks, POLICY as READABLE_ENTRY_POLICY, MUTABLE_POLICY as MUTABLE_ENTRY_POLICY
from .bisimulation_support import BisimulationRefinementError, mapping as _mapping, rows as _rows
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_services_v5 import _c_identifier
from .bisimulation_summary_contracts import readonly_summary_operations, scalar_summary_operations, memory_summary_operations
from .bisimulation_postconditions import render_scalar_postcondition
from .bisimulation_shared_summary import SHARED_STRATEGY
from .bisimulation_shared_composition import STRATEGY as CHECKED_SHARED_STRATEGY, FRAMED_STRATEGY, shared_entry_checks
from .bisimulation_reference_transport import (
    CONNECTED_REFERENCE_DECLARATION, CONNECTED_READABLE_TRANSPORT_POLICY, CONNECTED_MUTABLE_TRANSPORT_POLICY,
    connected_reference_transport_source, machine_reference_expression,
)


def connected_hidden_symbol(summary_id: int, symbol: str) -> str:
    """Return the private implementation symbol used by a summary wrapper."""

    return f"spx_proof_connected_impl_{summary_id:04d}_{_c_identifier(symbol)}"


def connected_source_prefix(
    operation_symbols: Mapping[str, str],
    summary_ids: Mapping[str, int],
) -> str:
    """Rename connected operation definitions before compiling their source."""

    if set(operation_symbols) != set(summary_ids):
        raise BisimulationRefinementError(
            "connected proof-summary operation inventory is not total"
        )
    return "\n".join(
        f"#define {_c_identifier(operation_symbols[operation_id])} "
        f"{connected_hidden_symbol(summary_ids[operation_id], operation_symbols[operation_id])}"
        for operation_id in sorted(operation_symbols)
    )


def _ref_equal(left: str, right: str) -> str:
    return f"spx_proof_connected_ref_equal(&({left}), &({right}))"


def _resource_equal(left: str, right: str) -> str:
    return f"spx_proof_connected_resource_equal(&({left}), &({right}))"


def _supported_plain_kind(bundle: CompiledComponentInterfaceV5, type_id: str) -> bool:
    logical_type = bundle.intent.schema.type_index[type_id]
    if logical_type.kind == "enum":
        return _supported_plain_kind(
            bundle, str(logical_type.body["underlying_type_id"])
        )
    return logical_type.kind in {"bool", "integer", "pointer"}


def _observe_memory(value: object, expression: str, prefix: str, *,
                    address_slot: str, replay: bool = False) -> list[str]:
    """Expose pointed-to input storage, including borrowed private stack bytes."""

    interpretation = str(getattr(value, "interpretation"))
    permissions = {"none": 0, "read": 1, "write": 2, "read_write": 3}.get(getattr(value, "access", None))
    if interpretation in {"view", "reference"} and permissions is None:
        raise BisimulationRefinementError("connected reference has unsupported access")

    def address(reference: str, extent: str) -> str:
        return ("spx_proof_connected_reference_address(context->services->context, "
                f"{machine_reference_expression(reference)}, {extent}, UINT32_C({permissions}), "
                f"UINT32_C({int(bool(getattr(value, 'nullable', False)))}), UINT32_C(0))")

    def observe(reference: str, extent: str) -> list[str]:
        realized = address(reference, extent)
        if replay:
            equal = f"{address_slot}[position] == {realized}"
            return [f'      __CPROVER_assert({equal}, "spx-bisimulation-connected-summary-reference-address-match");',
                    f"      __CPROVER_assume({equal});"]
        return [f"      {address_slot}[position] = {realized};",
                f"      {prefix}_observe_range(position, {address_slot}[position], {extent});"]

    if interpretation == "view":
        return [
            f"    if ({expression} != 0) {{",
            *observe(f"{expression}->base", f"{expression}->extent"),
            "    }",
        ]
    if interpretation == "reference":
        valid = f"{expression}.offset <= {expression}.extent"
        return [
            f"    __CPROVER_assert({valid},",
            '        "spx-bisimulation-connected-summary-reference-extent");',
            f"    __CPROVER_assume({valid});",
            *observe(expression, f"{expression}.extent - {expression}.offset"),
        ]
    return []


def _value_equal(
    bundle: CompiledComponentInterfaceV5,
    value: object,
    left: str,
    right: str,
) -> str:
    interpretation = str(getattr(value, "interpretation"))
    if interpretation == "value" and _supported_plain_kind(
        bundle, str(getattr(value, "type_id"))
    ):
        return f"({left}) == ({right})"
    if interpretation == "reference":
        return _ref_equal(left, right)
    if interpretation == "view":
        return f"spx_proof_connected_view_equal(&({left}), &({right}))"
    if (
        interpretation == "resource"
        and getattr(value, "resource_kind") != "atomic_object"
    ):
        return _resource_equal(left, right)
    raise BisimulationRefinementError(
        "connected proof summaries currently require scalar, reference, view, "
        "or non-atomic resource values"
    )


def _parameter_storage_and_relation(
    *,
    bundle: CompiledComponentInterfaceV5,
    value: object,
    name: str,
    prefix: str,
) -> tuple[list[str], list[str], str]:
    interpretation = str(getattr(value, "interpretation"))
    parameter_type = _parameter_type(bundle.intent.schema.type_index, value)  # type: ignore[arg-type]
    if interpretation == "view":
        declarations = [
            f"static uint32_t {prefix}_{name}_valid[SPX_PROOF_CONNECTED_CAPACITY];",
            f"static spx_view_v5 {prefix}_{name}[SPX_PROOF_CONNECTED_CAPACITY];",
        ]
        captures = [
            f"    {prefix}_{name}_valid[position] = {name} != 0;",
            f"    if ({name} != 0) {prefix}_{name}[position] = *{name};",
        ]
        relation = (
            f"{prefix}_{name}_valid[position] == ({name} != 0) && "
            f"({prefix}_{name}_valid[position] == UINT32_C(0) || "
            f"spx_proof_connected_view_equal(&{prefix}_{name}[position], {name}))"
        )
        return declarations, captures, relation
    if interpretation == "resource" and (
        getattr(value, "resource_kind") == "atomic_object"
        or getattr(value, "access") in {"write", "read_write"}
    ):
        raise BisimulationRefinementError(
            "connected proof summaries do not yet replay pointer-valued resources"
        )
    declarations = [
        f"static {parameter_type} {prefix}_{name}[SPX_PROOF_CONNECTED_CAPACITY];"
    ]
    captures = [f"    {prefix}_{name}[position] = {name};"]
    relation = _value_equal(bundle, value, f"{prefix}_{name}[position]", name)
    return declarations, captures, relation


def render_connected_summary_wrapper(
    *,
    bundle: CompiledComponentInterfaceV5,
    operation_symbols: Mapping[str, str],
    summary_ids: Mapping[str, int],
    body_free_scalar: bool = False,
    body_free_readonly: bool = False,
    body_free_mutable: bool = False,
    checked_readable_transport: bool = False,
    checked_mutable_transport: bool = False,
    scalar_postconditions: Sequence[Mapping[str, object]] = (),
    shared_contract: Mapping[str, object] | None = None,
) -> str:
    """Render paired calls; rendering alone never qualifies a callee.

    Mutable body omission is a conditional post-memory composition probe.
    Selection still requires a checked rule in the producer and both readers.
    """

    operations = {row.identity: row for row in bundle.interface.operations}
    shared = shared_contract is not None
    shared_aliases = {}
    if shared:
        from .bisimulation_shared_summary import shared_summary_operation, shared_summary_choices
        if (body_free_scalar or body_free_readonly or body_free_mutable or checked_readable_transport
                or not checked_mutable_transport or scalar_postconditions):
            raise BisimulationRefinementError("shared summary requires its own checked mutable transport")
        shared_aliases = {op: shared_summary_operation(bundle, op, shared_contract)[0] for op in operations}
    elif any(state.value.interpretation == "view" for state in bundle.interface.state):
        raise BisimulationRefinementError("shared view states require a checked shared summary rule")
    if body_free_scalar and scalar_summary_operations(bundle) is None:
        raise BisimulationRefinementError("body-free scalar summary has an unsupported interface")
    readable_transport = body_free_readonly or checked_readable_transport
    if readable_transport and readonly_summary_operations(bundle) is None:
        raise BisimulationRefinementError("body-free read-only summary has an unsupported interface")
    if body_free_readonly and (body_free_scalar or scalar_postconditions):
        raise BisimulationRefinementError("read-only summary cannot consume scalar-only certificates")
    if body_free_mutable:
        from .bisimulation_readonly_model import fixed_mutable_summary_operations

        if (body_free_scalar or body_free_readonly or scalar_postconditions
                or not checked_mutable_transport or fixed_mutable_summary_operations(bundle) is None):
            raise BisimulationRefinementError("body-free mutable summary lacks fixed views and checked transport")
    if checked_mutable_transport and (readable_transport or body_free_scalar
            or not shared and memory_summary_operations(bundle, mutable=True) is None):
        raise BisimulationRefinementError("mutable transport has an unsupported interface or summary strategy")
    memory_transport = readable_transport or checked_mutable_transport
    transport_flavor = "mutable" if checked_mutable_transport else "readable"
    body_free = body_free_scalar or body_free_readonly or body_free_mutable or shared
    if set(operation_symbols) != set(operations) or set(summary_ids) != set(operations):
        raise BisimulationRefinementError(
            "connected proof-summary interface and symbol inventories disagree"
        )
    component = _c_identifier(bundle.interface.identity)
    transport_function = f"__CPROVER_spx_connected_mutable_transport_{component}" if checked_mutable_transport else "__CPROVER_spx_connected_readable_transport"
    lines = [
        '#include "connected-proof-summary.h"',
        '#include "state-machine-runtime.h"',
        '#include "portable-component-implementation.h"',
        "",
        "static uint32_t spx_proof_connected_ref_equal(",
        "    const spx_ref_v5 *left, const spx_ref_v5 *right) {",
        "  return left != 0 && right != 0 &&",
        "      left->domain == right->domain && left->object == right->object &&",
        "      left->generation == right->generation &&",
        "      left->offset == right->offset && left->extent == right->extent &&",
        "      left->permissions == right->permissions;",
        "}",
        "static uint32_t spx_proof_connected_view_equal(",
        "    const spx_view_v5 *left, const spx_view_v5 *right) {",
        "  return left != 0 && right != 0 &&",
        "      spx_proof_connected_ref_equal(&left->base, &right->base) &&",
        "      left->extent == right->extent &&",
        "      left->element_width == right->element_width &&",
        "      left->base.permissions == right->base.permissions;",
        "}",
        "static uint32_t spx_proof_connected_resource_equal(",
        "    const spx_resource_v5 *left, const spx_resource_v5 *right) {",
        "  return left != 0 && right != 0 && left->type_tag == right->type_tag &&",
        "      left->generation == right->generation &&",
        "      left->identity == right->identity;",
        "}",
        "",
        "extern uint32_t spx_proof_connected_is_replay(void *opaque);",
        f"extern {CONNECTED_REFERENCE_DECLARATION};",
        *(["extern uint32_t __CPROVER_spx_connected_readable_transport(void *, const spx_view_v5 *);"]
          if readable_transport else []),
        *([f"extern uint32_t {transport_function}(void *, const spx_view_v5 *, uint32_t);"]
          if checked_mutable_transport else []),
        *(["extern spx_runtime *__CPROVER_spx_connected_mutable_runtime(void *);"] if body_free_mutable else []),
        *(["extern void __CPROVER_spx_connected_summary_range(void *, uint32_t, uint32_t);"] if shared else []),
    ]
    for operation_id in sorted(operations):
        operation = operations[operation_id]
        signature = bundle.intent.schema.signature_index[operation.signature_id]
        symbol = _c_identifier(operation_symbols[operation_id])
        summary_id = summary_ids[operation_id]
        hidden = connected_hidden_symbol(summary_id, symbol)
        prefix = f"spx_proof_connected_{summary_id:04d}"
        context_type = f"spx_{component}_context_v5"
        parameters = [f"{context_type} *context"] + [
            f"{_parameter_type(bundle.intent.schema.type_index, value)} "
            f"{_c_identifier(value.identity)}"
            for value in signature.parameters
        ]
        arguments = ["context"] + [
            _c_identifier(value.identity) for value in signature.parameters
        ]
        result_type = _result_type(bundle.intent.schema.type_index, signature)
        returned = f"context->state.{_c_identifier(shared_aliases[operation_id])}" if shared else f"{prefix}_result[position]"
        declarations = [
            f"static uint32_t {prefix}_input_protocol[SPX_PROOF_CONNECTED_CAPACITY];",
        ] if body_free else [
            f"static {context_type} {prefix}_input_context[SPX_PROOF_CONNECTED_CAPACITY];",
            f"static {context_type} {prefix}_output_context[SPX_PROOF_CONNECTED_CAPACITY];",
        ]
        captures: list[str] = []
        memory_observations: list[str] = []
        memory_replay_checks: list[str] = []

        def capture_memory(value, expression, slot):
            if value.interpretation not in {"view", "reference"}:
                return
            declarations.append(f"static uint32_t {slot}[SPX_PROOF_CONNECTED_CAPACITY];")
            memory_observations.extend(_observe_memory(value, expression, prefix, address_slot=slot))
            memory_replay_checks.extend(_observe_memory(value, expression, prefix, address_slot=slot, replay=True))

        relations = [
            f"{prefix}_input_protocol[position] == context->protocol_state"
            if body_free else
            f"{prefix}_input_context[position].protocol_state == context->protocol_state"
        ]
        readonly_preconditions: list[str] = []
        if memory_transport:
            transport_identity = (f"{bundle.interface.identity}:{operation_id}"
                                  if checked_readable_transport or checked_mutable_transport else str(summary_id))
            view_values = [(value, _c_identifier(value.identity), _c_identifier(value.identity))
                           for value in signature.parameters if value.interpretation == "view"]
            if shared:
                view_values += [(state.value, 'state_' + _c_identifier(state.value.identity),
                                 f"(&context->state.{_c_identifier(state.value.identity)})")
                                for state in bundle.interface.state]
            views = [expression for _, _, expression in view_values]
            present_conditions, domain_conditions, transport_variables, transport_calls = [], [], [], []
            for value, slot, name in view_values:
                permissions = f", {3 if value.access == 'read_write' else 1}U" if checked_mutable_transport else ""
                readonly_preconditions.extend([
                    f'  __CPROVER_assert({name} != 0, "spx-bisimulation-connected-summary-{transport_flavor}-view:{transport_identity}");',
                    f"  __CPROVER_assume({name} != 0);",
                ])
                condition = f"{name}->element_width == 1U"
                if value.extent["kind"] == "fixed":
                    condition += f" && {name}->extent == UINT64_C({value.extent['bytes']})"
                present_conditions.append(f'{name} != 0')
                domain_conditions.append(condition)
                transport_variables.append(f'{prefix}_transport_{slot}')
                transport_calls.append(f"  uint32_t {prefix}_transport_{slot} = {transport_function}(context->services->context, {name}{permissions});")
                readonly_preconditions.extend([
                    f'  __CPROVER_assert({condition}, "spx-bisimulation-connected-summary-{transport_flavor}-domain:{transport_identity}");',
                    f"  __CPROVER_assume({condition});",
                    f"  uint32_t {prefix}_transport_{slot} = {transport_function}(context->services->context, {name}{permissions});",
                    f'  __CPROVER_assert({prefix}_transport_{slot}, "spx-bisimulation-connected-summary-{transport_flavor}-transport:{transport_identity}");',
                    f"  __CPROVER_assume({prefix}_transport_{slot});",
                ])
            if len(view_values) > 1:
                # One semantic inventory obligation per category, retaining
                # every view's conditions. Single-view output stays identical.
                readonly_preconditions = []
                for kind, predicates in (('view', present_conditions), ('domain', domain_conditions),
                                         ('transport', transport_variables)):
                    if kind == 'transport':
                        readonly_preconditions.extend(transport_calls)
                    condition = ' && '.join(f'({predicate})' for predicate in predicates)
                    readonly_preconditions += [
                        f'  __CPROVER_assert({condition}, "spx-bisimulation-connected-summary-{transport_flavor}-{kind}:{transport_identity}");',
                        f'  __CPROVER_assume({condition});']
            # Native pointer equality of the view descriptors is observable C,
            # independently of overlap between their realized memory ranges.
            for index, left in enumerate(views):
                for right_index, right in enumerate(views[index + 1:], start=index + 1):
                    slot = f"{prefix}_descriptor_alias_{index}_{right_index}"
                    declarations.append(f"static uint32_t {slot}[SPX_PROOF_CONNECTED_CAPACITY];")
                    captures.append(f"    {slot}[position] = {left} == {right};")
                    relations.append(f"{slot}[position] == ({left} == {right})")
        for state in bundle.interface.state:
            state_name = _c_identifier(state.value.identity)
            stored = f"{prefix}_input_context[position].state.{state_name}"
            if shared:
                stored = f"{prefix}_input_state_{state_name}[position]"
                declarations.append(f"static spx_view_v5 {prefix}_input_state_{state_name}[SPX_PROOF_CONNECTED_CAPACITY];")
                captures.append(f"    {stored} = context->state.{state_name};")
            relations.append(
                _value_equal(
                    bundle,
                    state.value,
                    stored,
                    f"context->state.{state_name}",
                )
            )
            capture_memory(state.value, f"(&context->state.{state_name})" if state.value.interpretation == "view" else
                           f"context->state.{state_name}", f"{prefix}_state_address_{state_name}")
        for value in signature.parameters:
            name = _c_identifier(value.identity)
            storage, capture, relation = _parameter_storage_and_relation(
                bundle=bundle,
                value=value,
                name=name,
                prefix=prefix,
            )
            declarations.extend(storage)
            captures.extend(capture)
            relations.append(relation)
            capture_memory(value, name, f"{prefix}_parameter_address_{name}")
        if result_type != "void" and not shared:
            declarations.append(
                f"static {result_type} {prefix}_result[SPX_PROOF_CONNECTED_CAPACITY];"
            )
        lines.extend(
            [
                *declarations,
                f"extern uint32_t {prefix}_begin(void *opaque);",
                f"extern void {prefix}_finish(uint32_t position);",
                f"extern void {prefix}_replay(uint32_t position);",
                f"extern void {prefix}_observe_range(",
                "    uint32_t position, uint64_t address, uint64_t extent);",
                *( [f"extern {result_type} {hidden}({', '.join(parameters)});"]
                   if not body_free else [] ),
                "",
                f"{result_type} {symbol}({', '.join(parameters)}) {{",
                *([] if body_free else [f"  const spx_{component}_services_v5 *saved_services;"]),
                "  uint32_t replay;",
                "  uint32_t position;",
                "  __CPROVER_assert(context != 0 && context->services != 0,",
                f'      "spx-bisimulation-connected-summary-context:{summary_id}");',
                "  __CPROVER_assume(context != 0 && context->services != 0);",
                *readonly_preconditions,
                "  replay = spx_proof_connected_is_replay(context->services->context);",
                f"  position = {prefix}_begin(context->services->context);",
                "  __CPROVER_assert(position < SPX_PROOF_CONNECTED_CAPACITY,",
                f'      "spx-bisimulation-connected-summary-wrapper-capacity:{summary_id}");',
                "  __CPROVER_assume(position < SPX_PROOF_CONNECTED_CAPACITY);",
                "  if (replay == UINT32_C(0)) {",
                f"    {prefix}_input_protocol[position] = context->protocol_state;"
                if body_free else f"    {prefix}_input_context[position] = *context;",
                *captures,
                *memory_observations,
            ]
        )
        if body_free:
            if shared:
                lines.extend(shared_summary_choices(bundle=bundle, operation_id=operation_id, contract=shared_contract,
                                                    prefix=prefix))
            if body_free_mutable:
                # Write the fixed writable union through the existing world.
                # Overlapping views may write the same address again; the last
                # event defines one shared byte, and replay uses those events.
                # No body, descriptor copy, or allocation initializer is used.
                lines.append("    spx_runtime *post_runtime = __CPROVER_spx_connected_mutable_runtime(context->services->context);")
                for value in signature.parameters:
                    if value.interpretation != "view" or value.access != "read_write":
                        continue
                    name = _c_identifier(value.identity)
                    lines += [f"    for (uint64_t post_offset_{name} = 0; post_offset_{name} < UINT64_C({value.extent['bytes']}); ++post_offset_{name}) {{",
                        "      uint8_t post_byte; uint32_t post_fault = 0U;",
                        "      __CPROVER_havoc_object(&post_byte);",
                        f"      post_runtime->write(post_runtime->context, (uint32_t)((uint64_t){prefix}_parameter_address_{name}[position] + post_offset_{name}), 1U, post_byte, &post_fault);",
                        f'      __CPROVER_assert(post_fault == 0U, "spx-bisimulation-connected-summary-mutable-post-memory:{bundle.interface.identity}:{operation_id}");',
                        "      __CPROVER_assume(post_fault == 0U);", "    }"]
            if result_type != "void" and not shared:
                lines.extend([
                    f"    {result_type} abstract_result;",
                    "    __CPROVER_havoc_object(&abstract_result);",
                ])
                for fact in scalar_postconditions:
                    if fact["operation_id"] == operation_id:
                        predicate = render_scalar_postcondition(fact["expression"], bundle=bundle,
                            operation_id=operation_id, result_expression="abstract_result")
                        lines.append(f"    __CPROVER_assume({predicate});")
                lines.append(f"    {prefix}_result[position] = abstract_result;")
        elif result_type == "void":
            lines.append(f"    {hidden}({', '.join(arguments)});")
        else:
            lines.append(
                f"    {prefix}_result[position] = {hidden}({', '.join(arguments)});"
            )
        lines.extend(
            [
                *([] if body_free else [f"    {prefix}_output_context[position] = *context;"]),
                f"    {prefix}_finish(position);",
            ]
        )
        if result_type == "void":
            lines.extend(["    return;", "  }"])
        else:
            lines.extend([f"    return {returned};", "  }"])
        relation = " &&\n      ".join(relations) or "UINT32_C(1)"
        lines.extend(
            [
                f"  uint32_t inputs_match = {relation};",
                "  __CPROVER_assert(inputs_match != UINT32_C(0),",
                f'      "spx-bisimulation-connected-summary-input:{summary_id}");',
                "  __CPROVER_assume(inputs_match != UINT32_C(0));",
                *memory_replay_checks,
                f"  {prefix}_replay(position);",
            ]
        )
        # An empty frame forbids writes through either context.
        # Preserve each caller's storage, including transport/reserved fields;
        # copying the other side's context would violate that empty frame.
        if not body_free:
            lines.extend([
                "  saved_services = context->services;",
                f"  *context = {prefix}_output_context[position];",
                "  context->services = saved_services;",
            ])
        if result_type == "void":
            lines.append("  return;")
        else:
            lines.append(f"  return {returned};")
        lines.extend(["}", ""])
    return "\n".join(lines)


def _connected_summary_source(
    summaries: Sequence[Mapping[str, object]],
) -> list[str]:
    """Render exact-call adapters backed by separately qualified providers."""

    if not summaries:
        return []
    from .bisimulation_clobber_frame import call_havoc
    normalized: list[tuple[int, int, str, str]] = []
    entry_checks = {}
    clobber_havoc = {}
    entry_rvas: set[int] = set()
    for row in summaries:
        component_id = str(row.get("component_id", ""))
        symbol = str(row.get("symbol", ""))
        entry_rva = int(row.get("entry_rva", -1))
        exit_rva = int(row.get("exit_rva", -1))
        if (
            not component_id
            or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None
            or entry_rva <= 0
            or exit_rva <= 0
            or entry_rva in entry_rvas
        ):
            raise BisimulationRefinementError(
                "connected provider summary entry is malformed or ambiguous"
            )
        entry_rvas.add(entry_rva)
        from . import bisimulation_private_frame as private_frame
        entry_checks[entry_rva] = call_entry_checks(row) + image_readable_entry_checks(row) + shared_entry_checks(row) + private_frame.call_preparation(row)
        clobber_havoc[entry_rva] = call_havoc(row) + private_frame.call_havoc(row)
        normalized.append((entry_rva, exit_rva, symbol, component_id))
    normalized.sort()
    lines = [
        *connected_reference_transport_source().splitlines(),
        "extern spx_call_status spx_proof_exact_invoke_call_fallback(",
        "    spx_runtime *, const spx_call_event *,",
        "    const spx_machine_state *, spx_machine_state *);",
        *(
            f"extern spx_step_result {symbol}(spx_runtime *, spx_machine_state *);"
            for _entry, _exit, symbol, _component in normalized
        ),
        "",
        "spx_call_status spx_invoke_call(",
        "    spx_runtime *rt, const spx_call_event *event,",
        "    const spx_machine_state *input, spx_machine_state *output) {",
        "  if (event != 0 && input != 0 && output != 0 &&",
        "      event->kind == SPX_CALL_INTERNAL_DIRECT) {",
    ]
    for entry_rva, exit_rva, symbol, component_id in normalized:
        lines.extend(
            [
                f"    if (event->target_rva == UINT32_C({entry_rva})) {{",
                "      uint32_t fault = UINT32_C(0);",
                "      spx_machine_state call_state = *input;",
                "      spx_step_result summary;",
                "      if (rt == 0 || rt->write == 0 || input->esp < UINT32_C(4) ||",
                "          event->return_rva == UINT32_C(0) ||",
                "          rt->image_base > UINT32_MAX - event->return_rva) {",
                "        *output = *input;",
                "        return SPX_CALL_UNIMPLEMENTED;",
                "      }",
                "      call_state.esp -= UINT32_C(4);",
                "      rt->write(rt->context, call_state.esp, UINT32_C(4),",
                "          rt->image_base + event->return_rva, &fault);",
                "      if (fault != UINT32_C(0)) {",
                "        *output = call_state;",
                "        return SPX_CALL_MEMORY_FAULT;",
                "      }",
                *entry_checks[entry_rva],
                f"      summary = {symbol}(rt, &call_state);",
                *clobber_havoc[entry_rva],
                "      if (summary.kind == SPX_RETURN &&",
                "          summary.value == rt->image_base + event->return_rva) {",
                "        *output = call_state;",
                "        return SPX_CALL_OK;",
                "      }",
                "      if (summary.kind <= SPX_BRANCH &&",
                f"          summary.target_rva == UINT32_C({exit_rva}))",
                "        return spx_behavioral_run(",
                "            rt, summary.target_rva, &call_state, output);",
                "      *output = call_state;",
                "      if (summary.kind == SPX_MEMORY_FAULT)",
                "        return SPX_CALL_MEMORY_FAULT;",
                "      if (summary.kind == SPX_EXTERNAL_FAULT)",
                "        return SPX_CALL_EXTERNAL_FAULT;",
                "      if (summary.kind == SPX_DIVIDE_ERROR)",
                "        return SPX_CALL_DIVIDE_ERROR;",
                f"      /* Invalidates the bound {component_id} proof summary. */",
                "      return SPX_CALL_UNIMPLEMENTED;",
                "    }",
            ]
        )
    lines.extend(
        [
            "  }",
            "  return spx_proof_exact_invoke_call_fallback(",
            "      rt, event, input, output);",
            "}",
            "",
        ]
    )
    return lines



def _connected_replay_source(
    summaries: Sequence[Mapping[str, object]],
    *,
    max_writes: int,
    max_calls: int,
    max_atomics: int,
    call_range_writes_per_call: int = 0,
    runtime_assurance: Mapping[str, object] | None = None,
) -> list[str]:
    """Render connected hooks, including the non-authorizing read-only probe."""

    if not summaries:
        return []
    from .bisimulation_assurance import runtime_contract_selected
    native_access = runtime_contract_selected(runtime_assurance, 'native-memory-admission')
    if type(call_range_writes_per_call) is not int or call_range_writes_per_call < 0:
        raise BisimulationRefinementError("connected call-range write capacity is invalid")
    # The same service-footprint budget extends the world. Its late events must
    # also be replayed, even when the original instruction store bound is small.
    max_writes += max_calls * call_range_writes_per_call
    normalized: list[tuple[int, int, bool]] = []
    summary_ids: set[int] = set()
    capacities: set[int] = set()
    for row in summaries:
        summary_id = int(row.get("summary_id", -1))
        capacity = int(row.get("summary_capacity", 0))
        strategy = row.get("summary_strategy", "connected-replay-v1")
        if strategy not in {"connected-replay-v1", "scalar-body-free-v1", "readonly-body-free-experiment-v1", "mutable-body-free-experiment-v1", "image-mutable-body-free-v1", IMAGE_READABLE_STRATEGY, SHARED_STRATEGY, CHECKED_SHARED_STRATEGY, FRAMED_STRATEGY}:
            raise BisimulationRefinementError("connected proof replay strategy is unsupported")
        if summary_id < 0 or summary_id in summary_ids or capacity <= 0:
            raise BisimulationRefinementError(
                "connected proof replay identity or capacity is malformed"
            )
        summary_ids.add(summary_id)
        capacities.add(capacity)
        normalized.append((summary_id, capacity, strategy not in {"connected-replay-v1", "mutable-body-free-experiment-v1", "image-mutable-body-free-v1", SHARED_STRATEGY, CHECKED_SHARED_STRATEGY, FRAMED_STRATEGY}))
    if len(capacities) != 1:
        raise BisimulationRefinementError(
            "connected proof replay capacities are inconsistent"
        )
    normalized.sort()
    shared_ranges = any(row.get('summary_strategy') in {SHARED_STRATEGY, CHECKED_SHARED_STRATEGY, FRAMED_STRATEGY} for row in summaries)
    lines = [
        "typedef struct spx_proof_connected_service_prefix {",
        "  spx_runtime *runtime;",
        "} spx_proof_connected_service_prefix;",
        "",
        "static spx_proof_world *spx_proof_connected_world(void *opaque) {",
        *(['  __CPROVER_assert(0, "spx-bisimulation-native-admission-summary-context-unqualified");']
          if native_access else []),
        "  spx_proof_connected_service_prefix *service =",
        "      (spx_proof_connected_service_prefix *)opaque;",
        "  __CPROVER_assert(service != 0 && service->runtime != 0,",
        '      "spx-bisimulation-connected-summary-runtime");',
        "  __CPROVER_assume(service != 0 && service->runtime != 0);",
        "  if (service->runtime->context == &spx_exact_world)",
        "    return &spx_exact_world;",
        "  __CPROVER_assert(service->runtime->context == &spx_source_world,",
        '      "spx-bisimulation-connected-summary-world");',
        "  __CPROVER_assume(service->runtime->context == &spx_source_world);",
        "  return &spx_source_world;",
        "}",
        "",
        "uint32_t spx_proof_connected_is_replay(void *opaque) {",
        "  return spx_proof_connected_world(opaque)->replay;",
        "}",
        "",
    ]
    if any(row.get("readable_transport_policy") == CONNECTED_READABLE_TRANSPORT_POLICY or
           row.get("summary_strategy") == "readonly-body-free-experiment-v1" for row in summaries):
        lines.extend([
            "spx_runtime *__CPROVER_spx_connected_read_runtime(void *opaque) {",
            "  spx_proof_world *world = spx_proof_connected_world(opaque);",
            "  spx_runtime *runtime = ((spx_proof_connected_service_prefix *)opaque)->runtime;",
            "  spx_runtime canonical = spx_proof_runtime(world);",
            *(["  __CPROVER_assert(world->allocation_count == 0U,",
               '      "spx-bisimulation-connected-summary-readable-empty-allocation-world");',
               "  __CPROVER_assume(world->allocation_count == 0U);"]
              if any(row.get("summary_strategy") == IMAGE_READABLE_STRATEGY for row in summaries) else []),
            "  uint32_t valid = runtime->read == canonical.read &&",
            "      runtime->realize_reference == canonical.realize_reference &&",
            "      runtime->resolve_reference == canonical.resolve_reference;",
            '  __CPROVER_assert(valid, "spx-bisimulation-connected-summary-readable-runtime");',
            "  __CPROVER_assume(valid);",
            "  return runtime;",
            "}",
        ])
    if any(row.get("mutable_transport_policy") == CONNECTED_MUTABLE_TRANSPORT_POLICY for row in summaries):
        lines.extend([
            "spx_runtime *__CPROVER_spx_connected_mutable_runtime(void *opaque) {",
            "  spx_proof_world *world = spx_proof_connected_world(opaque);",
            "  spx_runtime *runtime = ((spx_proof_connected_service_prefix *)opaque)->runtime;",
            "  spx_runtime canonical = spx_proof_runtime(world);",
            *(["  __CPROVER_assert(world->allocation_count == 0U,",
               '      "spx-bisimulation-connected-summary-mutable-empty-allocation-world");',
               "  __CPROVER_assume(world->allocation_count == 0U);"]
              if any(row.get("summary_strategy") in {"image-mutable-body-free-v1", SHARED_STRATEGY, CHECKED_SHARED_STRATEGY} for row in summaries) else []),
            "  uint32_t valid = runtime->read == canonical.read && runtime->write == canonical.write &&",
            "      runtime->realize_reference == canonical.realize_reference &&",
            "      runtime->resolve_reference == canonical.resolve_reference;",
            '  __CPROVER_assert(valid, "spx-bisimulation-connected-summary-mutable-runtime");',
            "  __CPROVER_assume(valid);",
            "  return runtime;",
            "}",
        ])
    if any(row.get('summary_strategy') == FRAMED_STRATEGY for row in summaries):
        lines += [
            'spx_runtime *__CPROVER_spx_connected_framed_runtime(void *opaque) {',
            '  spx_proof_world *world = spx_proof_connected_world(opaque);',
            '  spx_runtime *runtime = ((spx_proof_connected_service_prefix *)opaque)->runtime;',
            '  spx_runtime canonical = spx_proof_runtime(world);',
            '  uint32_t valid = runtime->read == canonical.read && runtime->write == canonical.write &&',
            '      runtime->realize_reference == canonical.realize_reference && runtime->resolve_reference == canonical.resolve_reference;',
            '  __CPROVER_assert(valid, "spx-bisimulation-connected-summary-framed-runtime");',
            '  __CPROVER_assume(valid);', '  return runtime;', '}']
    if shared_ranges:
        lines += ["#ifndef SPX_PROOF_SUMMARY_RANGES", '#error "shared summaries require summary-range memory semantics"', "#endif",
            "void __CPROVER_spx_connected_summary_range(void *opaque, uint32_t base, uint32_t extent) {",
            "  spx_proof_world *world = spx_proof_connected_world(opaque);",
            '  __CPROVER_assert(world == &spx_exact_world, "spx-bisimulation-summary-range-original-world");',
            "  __CPROVER_assume(world == &spx_exact_world);",
            "  spx_proof_append_summary_range(world, base, extent, world->write_count);", "}"]
    for summary_id, capacity, effect_free in normalized:
        prefix = f"spx_proof_connected_{summary_id:04d}"
        lines.extend(
            [
                f"static uint32_t {prefix}_exact_count;",
                f"static uint32_t {prefix}_source_count;",
                f"static uint32_t {prefix}_finished[{capacity}];",
                f"static uint32_t {prefix}_write_begin[{capacity}];",
                f"static uint32_t {prefix}_write_end[{capacity}];",
                f"static uint32_t {prefix}_call_begin[{capacity}];",
                f"static uint32_t {prefix}_call_end[{capacity}];",
                f"static uint32_t {prefix}_atomic_begin[{capacity}];",
                f"static uint32_t {prefix}_atomic_end[{capacity}];",
                f"static uint32_t {prefix}_memory_address[{capacity}];",
                f"static uint8_t {prefix}_memory_value[{capacity}];",
                f"static uint32_t {prefix}_memory_observed[{capacity}];",
                "",
                f"uint32_t {prefix}_begin(void *opaque) {{",
                "  spx_proof_world *world = spx_proof_connected_world(opaque);",
                "  uint32_t position;",
                "  if (world == &spx_exact_world) {",
                f"    position = {prefix}_exact_count++;",
                f"    __CPROVER_assert(position < UINT32_C({capacity}),",
                f'        "spx-bisimulation-connected-summary-exact-capacity:{summary_id}");',
                f"    __CPROVER_assume(position < UINT32_C({capacity}));",
                f"    {prefix}_finished[position] = UINT32_C(0);",
                f"    {prefix}_write_begin[position] = world->write_count;",
                f"    {prefix}_call_begin[position] = world->call_count;",
                f"    {prefix}_atomic_begin[position] = world->atomic_count;",
                # A fresh arbitrary address makes the separately inventoried
                # assertion universal over the input memory. Capture BEFORE
                # the connected call: exact execution may have advanced past
                # all of its effects by the time source execution reaches it.
                f"    {prefix}_memory_address[position] = spx_nondet_u32();",
                f"    {prefix}_memory_value[position] = spx_proof_exact_byte(",
                f"        {prefix}_memory_address[position]);",
                f"    {prefix}_memory_observed[position] =",
                "        spx_proof_is_private(&spx_exact_world,",
                f"            {prefix}_memory_address[position]) == UINT32_C(0) &&",
                "        spx_proof_is_private(&spx_source_world,",
                f"            {prefix}_memory_address[position]) == UINT32_C(0);",
                "    return position;",
                "  }",
                f"  position = {prefix}_source_count++;",
                f"  __CPROVER_assert(position < UINT32_C({capacity}) &&",
                f"      position < {prefix}_exact_count &&",
                f"      {prefix}_finished[position] != UINT32_C(0),",
                f'      "spx-bisimulation-connected-summary-source-ready:{summary_id}");',
                f"  __CPROVER_assume(position < UINT32_C({capacity}) &&",
                f"      position < {prefix}_exact_count &&",
                f"      {prefix}_finished[position] != UINT32_C(0));",
                "  return position;",
                "}",
                "",
                f"void {prefix}_observe_range(",
                "    uint32_t position, uint64_t address, uint64_t extent) {",
                f"  __CPROVER_assert(position < UINT32_C({capacity}) &&",
                "      address <= UINT64_C(4294967295) &&",
                "      extent <= UINT64_C(4294967296) - address,",
                f'      "spx-bisimulation-connected-summary-range:{summary_id}");',
                f"  __CPROVER_assume(position < UINT32_C({capacity}) &&",
                "      address <= UINT64_C(4294967295) &&",
                "      extent <= UINT64_C(4294967296) - address);",
                f"  if ((uint64_t){prefix}_memory_address[position] >= address &&",
                f"      (uint64_t){prefix}_memory_address[position] - address < extent)",
                f"    {prefix}_memory_observed[position] = UINT32_C(1);",
                "}",
                "",
                f"void {prefix}_finish(uint32_t position) {{",
                f"  __CPROVER_assert(position < {prefix}_exact_count &&",
                f"      position < UINT32_C({capacity}) &&",
                "      spx_exact_world.write_count <= SPX_PROOF_MAX_WRITES &&",
                "      spx_exact_world.call_count <= SPX_PROOF_MAX_CALLS &&",
                "      spx_exact_world.atomic_count <= SPX_PROOF_MAX_ATOMICS,",
                f'      "spx-bisimulation-connected-summary-finish:{summary_id}");',
                f"  __CPROVER_assume(position < {prefix}_exact_count &&",
                f"      position < UINT32_C({capacity}) &&",
                "      spx_exact_world.write_count <= SPX_PROOF_MAX_WRITES &&",
                "      spx_exact_world.call_count <= SPX_PROOF_MAX_CALLS &&",
                "      spx_exact_world.atomic_count <= SPX_PROOF_MAX_ATOMICS);",
                f"  {prefix}_write_end[position] = spx_exact_world.write_count;",
                f"  {prefix}_call_end[position] = spx_exact_world.call_count;",
                f"  {prefix}_atomic_end[position] = spx_exact_world.atomic_count;",
                f"  {prefix}_finished[position] = UINT32_C(1);",
                "}",
                "",
                f"void {prefix}_replay(uint32_t position) {{",
                f"  __CPROVER_assert(position < UINT32_C({capacity}) &&",
                f"      {prefix}_finished[position] != UINT32_C(0) &&",
                f"      spx_source_world.call_count == {prefix}_call_begin[position] &&",
                f"      spx_source_world.atomic_count == {prefix}_atomic_begin[position],",
                f'      "spx-bisimulation-connected-summary-prefix:{summary_id}");',
                f"  __CPROVER_assume(position < UINT32_C({capacity}) &&",
                f"      {prefix}_finished[position] != UINT32_C(0) &&",
                f"      spx_source_world.call_count == {prefix}_call_begin[position] &&",
                f"      spx_source_world.atomic_count == {prefix}_atomic_begin[position]);",
                f"  uint32_t memory_matches = !{prefix}_memory_observed[position] ||",
                f"      {prefix}_memory_value[position] == spx_proof_source_byte(",
                f"          {prefix}_memory_address[position]);",
                "  __CPROVER_assert(memory_matches,",
                f'      "spx-bisimulation-connected-summary-memory:{summary_id}");',
                "  __CPROVER_assume(memory_matches);",
            ]
        )
        # The scalar strategy has a checked empty frame and no services/effects.
        # Its generated wrapper changes only proof bookkeeping and its result;
        # emitting impossible effect branches adds costly, redundant queries.
        for event_index in range(0 if effect_free else max_writes):
            lines.extend(
                [
                    f"  if ({prefix}_write_begin[position] <= UINT32_C({event_index}) &&",
                    f"      UINT32_C({event_index}) < {prefix}_write_end[position]) {{",
                    "    uint32_t replay_fault = UINT32_C(0);",
                    f"    spx_proof_write_event event = spx_exact_world.writes[{event_index}];",
                    *([
                        "    if (event.call_range == UINT32_C(2)) {",
                        f'      __CPROVER_assert(event.value == UINT32_C({event_index}), "spx-bisimulation-summary-range-token");',
                        f"      __CPROVER_assume(event.value == UINT32_C({event_index}));",
                        "      spx_proof_append_summary_range(&spx_source_world, event.address, event.width, event.value);",
                        "    } else {",
                    ] if shared_ranges else []),
                    *([
                        "    if (event.call_range) {",
                        f"      uint32_t admitted = event.value >= {prefix}_call_begin[position] &&",
                        f"          event.value < {prefix}_call_end[position] &&",
                        "          spx_proof_call_range_admitted(&spx_source_world, event.address, event.width, 2U);",
                        '      __CPROVER_assert(admitted, "spx-bisimulation-connected-summary-range-replay-authority");',
                        "      __CPROVER_assume(admitted);",
                        "      spx_proof_append_call_range(&spx_source_world, event.address, event.width, event.value);",
                        "    } else {",
                    ] if call_range_writes_per_call else []),
                    "    spx_proof_source_write(0, event.address, event.width, event.value, &replay_fault);",
                    *(["    }"] if call_range_writes_per_call else []),
                    *(["    }"] if shared_ranges else []),
                    "    __CPROVER_assert(replay_fault == UINT32_C(0),",
                    f'        "spx-bisimulation-connected-summary-write-valid:{summary_id}");',
                    "    __CPROVER_assume(replay_fault == UINT32_C(0));",
                    "  }",
                ]
            )
        for event_index in range(0 if effect_free else max_calls):
            lines.extend(
                [
                    f"  if ({prefix}_call_begin[position] <= UINT32_C({event_index}) &&",
                    f"      UINT32_C({event_index}) < {prefix}_call_end[position]) {{",
                    "    uint32_t target = spx_source_world.call_count++;",
                    "    __CPROVER_assert(target < SPX_PROOF_MAX_CALLS,",
                    f'        "spx-bisimulation-connected-summary-call-capacity:{summary_id}");',
                    "    __CPROVER_assume(target < SPX_PROOF_MAX_CALLS);",
                    f"    spx_source_world.calls[target] = spx_exact_world.calls[{event_index}];",
                    "  }",
                ]
            )
        for event_index in range(0 if effect_free else max_atomics):
            lines.extend(
                [
                    f"  if ({prefix}_atomic_begin[position] <= UINT32_C({event_index}) &&",
                    f"      UINT32_C({event_index}) < {prefix}_atomic_end[position]) {{",
                    "    uint32_t target = spx_source_world.atomic_count++;",
                    "    __CPROVER_assert(target < SPX_PROOF_MAX_ATOMICS,",
                    f'        "spx-bisimulation-connected-summary-atomic-capacity:{summary_id}");',
                    "    __CPROVER_assume(target < SPX_PROOF_MAX_ATOMICS);",
                    f"    spx_source_world.atomics[target] = spx_exact_world.atomics[{event_index}];",
                    "  }",
                ]
            )
        lines.extend(["}", ""])
    lines.extend(
        [
            "static void spx_proof_reset_connected_summaries(void) {",
            *(
                f"  spx_proof_connected_{summary_id:04d}_exact_count = "
                f"spx_proof_connected_{summary_id:04d}_source_count = UINT32_C(0);"
                for summary_id in sorted(summary_ids)
            ),
            "}",
            "",
            "static uint32_t spx_proof_connected_summaries_equal(void) {",
            "  return "
            + " &&\n      ".join(
                f"spx_proof_connected_{summary_id:04d}_exact_count == "
                f"spx_proof_connected_{summary_id:04d}_source_count"
                for summary_id in sorted(summary_ids)
            )
            + ";",
            "}",
            "",
        ]
    )
    return lines


def prepare_connected_models(connected_components, component_id, *, runtime_assurance=None):
    """Validate the connected provider model inputs before generating wrappers."""
    from .bisimulation_source_dependencies import validate_current_qualified_closure
    try:
        validate_current_qualified_closure(connected_components)
    except (ValueError, TypeError, KeyError, AttributeError) as error:
        raise BisimulationRefinementError(str(error)) from error
    connected_models: list[dict[str, object]] = []
    connected_ids: set[str] = set()
    for index, raw in enumerate(connected_components):
        row = _mapping(raw, f"connected component {index}")
        connected_id = str(row.get("component_id", ""))
        if (
            not connected_id
            or connected_id == component_id
            or connected_id in connected_ids
        ):
            raise BisimulationRefinementError(
                "connected component identity is malformed or duplicated"
            )
        connected_ids.add(connected_id)
        connected_root = Path(str(row.get("source_package", "")))
        connected_source = load_component_source_package(connected_root)
        connected_bundle = row.get("compiled_interface")
        connected_symbols = row.get("operation_symbols")
        if connected_source.get("lift_unit_id") != connected_id:
            raise BisimulationRefinementError(
                "connected component source package names another component"
            )
        if (
            not isinstance(connected_bundle, CompiledComponentInterfaceV5)
            or connected_bundle.interface.identity != connected_id
            or not isinstance(connected_symbols, Mapping)
            or dict(connected_symbols) != component_operation_symbols(connected_source)
        ):
            raise BisimulationRefinementError(
                "connected component proof-summary interface is incomplete or stale"
            )
        connected_profile = _mapping(
            row.get("source_profile"), "connected component source profile"
        )
        connected_profile_core = dict(connected_profile)
        connected_profile_digest = connected_profile_core.pop("receipt_sha256", None)
        if (
            connected_profile.get("status") != "satisfied"
            or _mapping(
                connected_profile.get("bindings"),
                "connected source profile bindings",
            ).get("implementation_sha256")
            != connected_source.get("implementation_sha256")
            or connected_profile_digest != canonical_sha256_v3(connected_profile_core)
        ):
            raise BisimulationRefinementError(
                "connected component source profile is incomplete or stale"
            )
        production_overlay_source = str(row.get("machine_overlay_source", ""))
        if not production_overlay_source:
            raise BisimulationRefinementError(
                "connected component machine overlay is empty"
            )
        raw_proof_overlay_source = row.get("trusted_proof_overlay_source")
        proof_overlay_source = (
            production_overlay_source
            if raw_proof_overlay_source is None
            else str(raw_proof_overlay_source)
        )
        if not proof_overlay_source:
            raise BisimulationRefinementError(
                "connected component proof overlay is empty"
            )
        connected_lowering = row.get("trusted_adapter_lowering")
        if (proof_overlay_source == production_overlay_source) is not (
            connected_lowering is None
        ):
            raise BisimulationRefinementError(
                "connected component proof overlay and lowering disagree"
            )
        if connected_lowering is not None:
            lowering = _mapping(
                connected_lowering, "connected trusted adapter lowering"
            )
            lowering_core = dict(lowering)
            lowering_digest = lowering_core.pop("receipt_sha256", None)
            if (
                lowering.get("status") != "complete"
                or lowering_digest != canonical_sha256_v3(lowering_core)
                or lowering.get("production_overlay_sha256")
                != hashlib.sha256(production_overlay_source.encode("ascii")).hexdigest()
                or lowering.get("proof_overlay_sha256")
                != hashlib.sha256(proof_overlay_source.encode("ascii")).hexdigest()
            ):
                raise BisimulationRefinementError(
                    "connected trusted adapter lowering is stale"
                )
        headers = _mapping(row.get("c_headers"), "connected component C headers")
        if any(
            not isinstance(name, str)
            or not name
            or Path(name).name != name
            or not isinstance(content, str)
            for name, content in headers.items()
        ):
            raise BisimulationRefinementError(
                "connected component C headers are malformed"
            )
        binding_digest = str(row.get("binding_intent_sha256", ""))
        from .bisimulation_assurance import admitted_supplier_assurance, validate_runtime_assurance_binding
        supplier_assurance = admitted_supplier_assurance(row.get('proof_system', {}).get('proof', {}), runtime_assurance)
        validate_runtime_assurance_binding(row, supplier_assurance)
        if supplier_assurance is not None and row.get("qualification_sha256") is not None:
            raise BisimulationRefinementError("conditional supplier cannot supply native qualification")
        qualification_digest = None if supplier_assurance is not None else str(row.get("qualification_sha256", ""))
        contextual_digest = str(row.get("contextual_refinement_sha256", ""))
        proof_digest = str(row.get("proof_receipt_sha256", ""))
        if any(
            re.fullmatch(r"[0-9a-f]{64}", digest) is None
            for digest in (
                binding_digest,
                *(() if supplier_assurance is not None else (qualification_digest,)),
                contextual_digest,
                proof_digest,
            )
        ):
            raise BisimulationRefinementError(
                "connected component proof-summary digest is malformed"
            )
        raw_summary = row.get("source_summary_contracts")
        try:
            summary_certificate = checked_connected_source_contract(
                bound=None if raw_summary is None else _mapping(raw_summary, "connected source summary"),
                bundle=connected_bundle, source=connected_source,
                source_profile_sha256=str(connected_profile_digest),
                operation_symbols=dict(connected_symbols), headers=dict(headers),
                readonly_artifacts=row.get("source_summary_artifacts"),
                qualified_models=row.get('proof_system', {}).get('proof', {}).get('models'),
            )
            entry_contract = checked_call_entry_contract(row, connected={
                "component_id": connected_id, "binding_intent_sha256": binding_digest,
                "proof_receipt_sha256": proof_digest, "implementation_sha256": connected_source["implementation_sha256"],
                "source_profile_sha256": connected_profile_digest,
                "machine_overlay_sha256": hashlib.sha256(production_overlay_source.encode("ascii")).hexdigest(),
                "proof_overlay_sha256": hashlib.sha256(proof_overlay_source.encode("ascii")).hexdigest()},
                runtime_assurance=supplier_assurance)
        except (ValueError, TypeError, KeyError) as error:
            raise BisimulationRefinementError(str(error)) from error
        if summary_certificate is None and entry_contract is None:
            raise BisimulationRefinementError(
                f"connected replay for {connected_id} lacks checked callee entry and machine-state premises")
        connected_models.append(
            {
                "component_id": connected_id,
                **({"assurance": supplier_assurance, "authorizing": False} if supplier_assurance is not None else {}),
                "source_root": connected_root,
                "source": connected_source,
                "compiled_interface": connected_bundle,
                "operation_symbols": dict(connected_symbols),
                "source_profile_sha256": connected_profile_digest,
                "production_overlay_source": production_overlay_source,
                "proof_overlay_source": proof_overlay_source,
                "trusted_adapter_lowering": connected_lowering,
                "overlay_entries": list(
                    _rows(
                        row.get("machine_overlay_entries"),
                        "connected machine-overlay entries",
                    )
                ),
                "headers": dict(headers),
                "binding_intent_sha256": binding_digest,
                "qualification_sha256": qualification_digest,
                "contextual_refinement_sha256": contextual_digest,
                "proof_receipt_sha256": proof_digest,
                "summary_strategy": "scalar-body-free-v1" if summary_certificate is not None else "connected-replay-v1",
                "source_summary_certificate": summary_certificate,
                "entry_contract": entry_contract,
                "readable_transport_policy": CONNECTED_READABLE_TRANSPORT_POLICY
                    if entry_contract is not None and entry_contract["policy"] == READABLE_ENTRY_POLICY else None,
                **({"mutable_transport_policy": CONNECTED_MUTABLE_TRANSPORT_POLICY}
                    if entry_contract is not None and entry_contract["policy"] == MUTABLE_ENTRY_POLICY else {}),
            }
        )
    if [str(row["component_id"]) for row in connected_models] != sorted(connected_ids):
        raise BisimulationRefinementError(
            "connected component closure must be canonically ordered"
        )
    return connected_models
