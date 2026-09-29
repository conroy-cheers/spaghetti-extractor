"""Typed service proof adapters and their checked call model."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_support import BisimulationRefinementError, mapping as _mapping, rows as _rows
from .bisimulation_service_preconditions import borrowed_input_checks
from .bisimulation_lifetime_admission import admitted_call_specs, lifetime_implementation_paths, uses_lifetime_services
from .bisimulation_call_ranges import call_range_implementation_paths, uses_call_ranges
from .bisimulation_terminated_reads import (terminated_read_implementation_paths,
    borrowed_memory_implementation_paths, uses_terminated_results)
from .bisimulation_service_targets import external_target_implementation_paths, uses_external_target_slots, typed_external_target_lines
from .bisimulation_service_effects import (
    checked_proof_external_effect_contract, checked_proof_external_contract_identity, require_typed_external_target_support,
)
from .component_c_v5 import _parameter_type, _result_type
from .finite_word_transducers import FiniteWordMapError, parse_finite_word_map
from .formats import (
    INTERACTION_CONTRACT_RECEIPT_V1_FORMAT,
    TRUSTED_ADAPTER_LOWERING_V1_FORMAT,
)
from .interface_ir import ProofKernelComponentInterface
from .interface_package_v5 import CompiledComponentInterfaceV5
from .local_cell_transducers import LocalCellTransducerError, checked_initial_words, checked_local_cell_selection
from .logical_value_types import logical_value_type_identity
from .machine_overlay_services_v5 import _c_identifier
from .machine_overlay_result_views import result_view_lines
from .machine_overlay_boundaries_v5 import authority_selector_expression
from .machine_overlay_v5 import ExternalServiceThunkRendererV1


def _opaque_resource_type_tag(parameter: object, *, context: str) -> int:
    provider_domain = getattr(parameter, "provider_domain", None)
    resource_kind = getattr(parameter, "resource_kind", None)
    if not isinstance(provider_domain, str) or not isinstance(resource_kind, str):
        raise BisimulationRefinementError(f"{context} resource codec is stale")
    return int(
        canonical_sha256_v3(
            {
                "provider_domain": provider_domain,
                "resource_kind": resource_kind,
            }
        )[:8],
        16,
    ) | 0x80000000


def _checked_reference_result_origins(
    *,
    interface: ProofKernelComponentInterface,
    relation_evidence: Sequence[Mapping[str, object]],
) -> dict[str, dict[str, object]]:
    """Validate normalized reviewed borrowed-interior service relations."""

    operations = interface.operation_index()
    services = {item.identity: item for item in interface.services}
    types = interface.type_index()
    result: dict[str, dict[str, object]] = {}
    for index, raw in enumerate(relation_evidence):
        row = _mapping(raw, f"typed proof relation evidence {index}")
        operation_id = str(row.get("operation_id", ""))
        service_id = str(row.get("service_id", ""))
        input_index = row.get("input_argument_index")
        operation = operations.get(operation_id)
        service = services.get(service_id)
        origin_type = (
            None
            if service is None
            or not isinstance(input_index, int)
            or isinstance(input_index, bool)
            or not 0 <= input_index < len(service.parameter_type_ids)
            else types[service.parameter_type_ids[input_index]]
        )
        result_type = (
            None
            if service is None or service.result_type_id is None
            else types[service.result_type_id]
        )
        origin_policy = row.get("origin_type")
        result_policy = row.get("result_policy")
        remaining = row.get("nonnull_min_remaining")
        receipt = row.get("contract_receipt")
        receipt_core = dict(receipt) if isinstance(receipt, Mapping) else {}
        receipt_digest = receipt_core.pop("receipt_sha256", None)
        expected_fields = {
            "operation_id",
            "requirement_id",
            "service_id",
            "input_argument_index",
            "relation",
            "origin_type",
            "result_policy",
            "nonnull_min_remaining",
            "contract_id",
            "contract_sha256",
            "contract_catalog_sha256",
            "contract_receipt",
            "contract_receipt_sha256",
        }
        expected_permissions = (
            None
            if result_type is None
            else {"read": 1, "write": 2, "read_write": 3}.get(
                result_type.access,
                0,
            )
        )
        remaining_valid = remaining is None or (
            isinstance(remaining, Mapping)
            and set(remaining) == {"nonzero_argument_index", "minimum"}
            and isinstance(remaining.get("nonzero_argument_index"), int)
            and not isinstance(remaining.get("nonzero_argument_index"), bool)
            and service is not None
            and 0
            <= int(remaining["nonzero_argument_index"])
            < len(service.parameter_type_ids)
            and types[
                service.parameter_type_ids[
                    int(remaining["nonzero_argument_index"])
                ]
            ].kind
            in {"scalar", "enum"}
            and isinstance(remaining.get("minimum"), int)
            and not isinstance(remaining.get("minimum"), bool)
            and 0 < int(remaining["minimum"]) <= 0xFFFFFFFF
        )
        if (
            set(row) != expected_fields
            or operation is None
            or service is None
            or service_id not in operation.allowed_service_ids
            or not isinstance(input_index, int)
            or isinstance(input_index, bool)
            or not 0 <= input_index < len(service.parameter_type_ids)
            or result_type is None
            or result_type.kind != "reference"
            or origin_type is None
            or origin_type.kind not in {"reference", "view"}
            or row.get("relation") != "borrowed_interior_or_null"
            or not isinstance(row.get("requirement_id"), str)
            or not row.get("requirement_id")
            or not isinstance(origin_policy, Mapping)
            or set(origin_policy) != {"kind", "nul_terminated"}
            or origin_policy.get("kind") != origin_type.kind
            or origin_policy.get("nul_terminated")
            is not bool(origin_type.nul_terminated)
            or not isinstance(result_policy, Mapping)
            or set(result_policy)
            != {"nullable", "allow_one_past", "permissions"}
            or result_policy.get("nullable") is not bool(result_type.nullable)
            or result_policy.get("allow_one_past")
            is not bool(result_type.allow_one_past)
            or result_policy.get("permissions") != expected_permissions
            or not remaining_valid
            or not isinstance(row.get("contract_id"), str)
            or not row.get("contract_id")
            or re.fullmatch(r"[0-9a-f]{64}", str(row.get("contract_sha256", "")))
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(row.get("contract_receipt_sha256", "")),
            )
            is None
            or re.fullmatch(
                r"[0-9a-f]{64}",
                str(row.get("contract_catalog_sha256", "")),
            )
            is None
            or set(receipt_core)
            != {
                "format",
                "contract_id",
                "contract_sha256",
                "status",
                "code",
            }
            or receipt_core.get("format") != INTERACTION_CONTRACT_RECEIPT_V1_FORMAT
            or receipt_core.get("contract_id") != row.get("contract_id")
            or receipt_core.get("contract_sha256") != row.get("contract_sha256")
            or receipt_core.get("status") != "checked"
            or receipt_core.get("code") != "reviewed_reusable_contract"
            or receipt_digest != canonical_sha256_v3(receipt_core)
            or receipt_digest != row.get("contract_receipt_sha256")
            or service_id in result
        ):
            raise BisimulationRefinementError(
                "typed proof reference-origin evidence is malformed or ambiguous"
            )
        result[service_id] = dict(row)
    return result


def build_typed_proof_service_thunk_renderer(
    *,
    interface: ProofKernelComponentInterface,
    service_bindings: Sequence[Mapping[str, object]],
    relation_evidence: Sequence[Mapping[str, object]] = (),
    reference_authority: Mapping[str, object] | None = None,
    allocation_requirements: list[Mapping[str, object]] | None = None,
) -> ExternalServiceThunkRendererV1:
    """Build a structural proof renderer for checked external-service thunks.

    The callback consumes the same normalized binding that would otherwise be
    passed to the production thunk renderer.  It therefore selects a proof
    implementation before the overlay C is assembled, rather than finding and
    replacing a function in rendered C text.
    """

    service_index = {item.identity: item for item in interface.services}
    type_index = interface.type_index()
    reference_result_origins = _checked_reference_result_origins(
        interface=interface,
        relation_evidence=relation_evidence,
    )
    call_specs = admitted_call_specs(service_bindings, reference_authority=reference_authority,
                                    allocation_requirements=allocation_requirements)
    specs_by_service: dict[str, list[Mapping[str, object]]] = {}
    for spec in call_specs:
        specs_by_service.setdefault(str(spec["service_id"]), []).append(spec)
    normalized_bindings: dict[str, dict[str, object]] = {}
    for raw_binding in service_bindings:
        binding = {
            key: value
            for key, value in _mapping(
                raw_binding, "proof service renderer binding"
            ).items()
            if not str(key).startswith("_")
        }
        # Connected Portable-C providers are already proved and linked through
        # their logical operation symbol.  They do not need an external-call
        # record/replay thunk, but can coexist with external services in the
        # same operation inventory.
        if binding.get("provider_kind") == "component_operation":
            continue
        require_typed_external_target_support(binding)
        symbol = str(binding.get("symbol", ""))
        service_id = str(binding.get("service_id", ""))
        previous = normalized_bindings.get(symbol)
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None
            or service_id not in service_index
            or (previous is not None and previous != binding)
        ):
            raise BisimulationRefinementError(
                "proof service adapter inventory is malformed or ambiguous"
            )
        normalized_bindings[symbol] = binding

    selected_specs: dict[str, Mapping[str, object]] = {}
    for symbol, binding in normalized_bindings.items():
        service_id = str(binding["service_id"])
        specs = specs_by_service.get(service_id, [])
        spec_ids = {int(item["spec_id"]) for item in specs}
        shapes = {
            canonical_sha256_v3(
                {
                    key: item[key]
                    for key in (
                        "offsets",
                        "raw_indices",
                        "outputs",
                        "compare_target",
                        "callee_cleanup",
                    )
                }
            )
            for item in specs
        }
        if not specs or len(spec_ids) != 1 or len(shapes) != 1:
            matching_symbols = sorted(
                str(item.get("symbol", ""))
                for item in service_bindings
                if item.get("service_id") == service_id
            )
            raise BisimulationRefinementError(
                f"proof service {service_id!r} has no unique typed call shape: "
                f"spec_ids={sorted(spec_ids)!r}; shapes={sorted(shapes)!r}; "
                f"symbols={matching_symbols!r}"
            )
        selected_specs[symbol] = specs[0]

    def render(
        bundle: CompiledComponentInterfaceV5,
        raw_binding: Mapping[str, object],
        authority_selectors: Mapping[str, str],
    ) -> Sequence[str]:
        binding = {
            key: value
            for key, value in _mapping(
                raw_binding, "proof service renderer input"
            ).items()
            if not str(key).startswith("_")
        }
        symbol = str(binding.get("symbol", ""))
        expected = normalized_bindings.get(symbol)
        if expected is None or binding != expected:
            raise BisimulationRefinementError(
                "proof service renderer received an unbound service thunk"
            )
        service_id = str(binding["service_id"])
        return _render_typed_proof_service_thunk(
            bundle=bundle,
            symbol=symbol,
            service=service_index[service_id],
            type_index=type_index,
            binding=binding,
            spec=selected_specs[symbol],
            authority_selectors=authority_selectors,
            reference_result_relation=reference_result_origins.get(service_id),
        )

    return render


def _render_typed_proof_service_thunk(
    *,
    bundle: CompiledComponentInterfaceV5,
    symbol: str,
    service: object,
    type_index: Mapping[str, object],
    binding: Mapping[str, object],
    spec: Mapping[str, object],
    authority_selectors: Mapping[str, str],
    reference_result_relation: Mapping[str, object] | None,
) -> Sequence[str]:
    matching_services = [
        item for item in bundle.interface.services if item.identity == binding["service_id"]
    ]
    if len(matching_services) != 1:
        raise BisimulationRefinementError(
            f"generated proof service {symbol!r} is absent or duplicated"
        )
    compiled_service = matching_services[0]
    signature = bundle.intent.schema.signature_index[compiled_service.signature_id]
    types = bundle.intent.schema.type_index
    result_c_type = _result_type(types, signature)
    parameter_declarations = ["void *opaque"] + [
        f"{_parameter_type(types, item)} logical_{_c_identifier(item.identity)}"
        for item in signature.parameters
    ]
    parameter_names = ["opaque"] + [
        f"logical_{_c_identifier(item.identity)}" for item in signature.parameters
    ]
    parameter_type_ids = tuple(getattr(service, "parameter_type_ids", ()))
    escaped_callbacks = {entry.path.value_id for lifecycle in bundle.lifecycles.values()
                         for entry in lifecycle.bindings if entry.transition == "escape_callback"}

    def matches(item, proof_type_id):
        return (item.type_id == proof_type_id
            or (types[item.type_id].kind in {"pointer", "opaque"}
                and proof_type_id == logical_value_type_identity(
                    item, callback_retained=item.identity in escaped_callbacks))
            or (
            item.interpretation == "resource"
            and item.access != "none"
            and getattr(type_index.get(proof_type_id), "kind", None)
            == "resource_cell"
            and getattr(type_index.get(proof_type_id), "resource_kind", None)
            == item.resource_kind
        ))

    parameters_match = len(signature.parameters) == len(parameter_type_ids) and all(
        matches(item, proof_type_id) for item, proof_type_id in zip(signature.parameters, parameter_type_ids))
    proof_result_type_id = getattr(service, "result_type_id", None)
    result_matches = (proof_result_type_id is None if not signature.results
                      else len(signature.results) == 1 and matches(signature.results[0], proof_result_type_id))
    if (
        not parameters_match
        or not result_matches
        or len(signature.results) > 1
    ):
        raise BisimulationRefinementError(
            f"generated proof service {symbol!r} signature is stale"
        )
    transducers = binding.get("argument_transducers")
    if transducers is None:
        normalized_transducers: list[Mapping[str, object]] = [
            {"kind": "logical_argument", "parameter_index": index}
            for index in range(len(parameter_type_ids))
        ]
    else:
        normalized_transducers = [
            _mapping(item, "typed proof service transducer")
            for item in _rows(transducers, "typed proof service transducers")
        ]
    raw_indices = [int(item) for item in spec["raw_indices"]]
    zero_result = (
        "return;"
        if result_c_type == "void"
        else (
            f"return ({result_c_type}){{0}};"
            if result_c_type.startswith("spx_") and "*" not in result_c_type
            else f"return ({result_c_type})0;"
        )
    )
    lines = [
        f"static {result_c_type} {symbol}({', '.join(parameter_declarations)}) {{",
        "  extern void spx_proof_typed_service_begin(void *context, uint32_t spec);",
        "  extern void spx_proof_typed_service_target(uint32_t value);",
        "  extern void spx_proof_typed_service_argument(uint32_t index, uint32_t value);",
        "  extern void spx_proof_typed_service_cell_input(uint32_t index, uint32_t value);",
        "  extern uint32_t spx_proof_typed_service_result(void);",
        "  extern uint32_t spx_proof_typed_service_output_active(uint32_t index);",
        "  extern uint32_t spx_proof_typed_service_output(uint32_t index);",
        "  extern void spx_proof_typed_service_finish(void);",
        "  extern uint32_t spx_proof_typed_service_public_range(",
        "      uint32_t address, uint32_t width);",
        "  spx_component_service_context_v1 *spx_typed_service =",
        "      (spx_component_service_context_v1 *)opaque;",
        "  uint32_t spx_typed_fault = UINT32_C(0);",
        "  if (spx_typed_service == 0 || spx_typed_service->runtime == 0 ||",
        "      spx_typed_service->state == 0 ||",
        "      spx_typed_service->memory_fault == 0 ||",
        "      spx_typed_service->service_fault == 0)",
        f"    {zero_result}",
        "  if (*spx_typed_service->memory_fault != UINT32_C(0) ||",
        "      *spx_typed_service->service_fault != UINT32_C(0))",
        f"    {zero_result}",
    ]
    input_interface_parameters = {
        int(_mapping(item, "typed proof input interface").get("parameter_index", -1))
        for item in _rows(
            binding.get("input_interfaces", []), "typed proof input interfaces"
        )
    }
    validated_parameters: set[int] = set()
    for transducer in normalized_transducers:
        if transducer.get("kind") != "logical_argument":
            continue
        parameter_index = int(transducer.get("parameter_index", -1))
        if (
            parameter_index in validated_parameters
            or not 0 <= parameter_index < len(parameter_type_ids)
        ):
            continue
        validated_parameters.add(parameter_index)
        logical_type = type_index.get(parameter_type_ids[parameter_index])
        logical_kind = getattr(logical_type, "kind", None)
        logical = parameter_names[1:][parameter_index]
        parameter = signature.parameters[parameter_index]
        nullable = 1 if getattr(parameter, "nullable", False) else 0
        if logical_kind in {"view", "bytes", "reference"}:
            lines.extend(borrowed_input_checks(
                logical=logical, logical_type=logical_type, parameter=parameter,
                type_index=type_index, symbol=symbol, parameter_index=parameter_index,
                zero_result=zero_result,
            ))
        elif logical_kind == "resource":
            if parameter_index in input_interface_parameters:
                invalid = (
                    f"({logical}.identity == UINT64_C(0) && "
                    f"UINT32_C({nullable}) == UINT32_C(0)) || "
                    f"{logical}.identity > UINT32_MAX"
                )
            else:
                type_tag = _opaque_resource_type_tag(
                    parameter,
                    context=f"proof service {symbol!r}",
                )
                invalid = (
                    f"({logical}.identity == UINT64_C(0) && "
                    f"(UINT32_C({nullable}) == UINT32_C(0) || "
                    f"{logical}.type_tag != UINT32_C(0) || "
                    f"{logical}.generation != UINT32_C(0))) || "
                    f"({logical}.identity != UINT64_C(0) && "
                    f"({logical}.type_tag != UINT32_C({type_tag}) || "
                    f"{logical}.generation != UINT32_C(1) || "
                    f"{logical}.identity > UINT32_MAX))"
                )
            lines.extend(
                [
                    f"  if ({invalid}) {{",
                    "    *spx_typed_service->service_fault = UINT32_C(1);",
                    f"    {zero_result}",
                    "  }",
                ]
            )
        elif logical_kind == "callback":
            lines.extend(
                [
                    f"  if ({logical} == 0 || {logical}->physical_word == UINT32_C(0)) {{",
                    "    *spx_typed_service->service_fault = UINT32_C(1);",
                    f"    {zero_result}",
                    "  }",
                ]
            )
    typed_target_expression: str | None = None
    if binding.get("provider_kind") == "interface_method":
        receiver = binding.get("receiver_argument")
        slot = binding.get("slot")
        if (
            not isinstance(receiver, int)
            or isinstance(receiver, bool)
            or not 0 <= receiver < len(normalized_transducers)
            or not isinstance(slot, int)
            or isinstance(slot, bool)
            or not 0 <= slot <= 0x3FFFFFFF
            or spec.get("compare_target") is not True
        ):
            raise BisimulationRefinementError(
                f"proof service {symbol!r} interface target recipe is stale"
            )
        receiver_expression = _typed_service_word_expression(
            transducer=normalized_transducers[receiver],
            parameter_names=parameter_names[1:],
            parameter_type_ids=parameter_type_ids,
            type_index=type_index,
        )
        slot_offset = slot * 4
        lines.extend(
            [
                f"  uint32_t spx_typed_receiver = {receiver_expression};",
                "  if (spx_proof_typed_service_public_range(",
                "      spx_typed_receiver, UINT32_C(4)) == UINT32_C(0)) {",
                "    *spx_typed_service->memory_fault = UINT32_C(1);",
                f"    {zero_result}",
                "  }",
                "  uint32_t spx_typed_vtable = spx_component_read(",
                "      spx_typed_service->runtime, spx_typed_receiver,",
                "      UINT32_C(4), &spx_typed_fault);",
                "  if (spx_typed_fault != UINT32_C(0)) {",
                "    *spx_typed_service->memory_fault = UINT32_C(1);",
                f"    {zero_result}",
                "  }",
                "  if (spx_proof_typed_service_public_range(",
                f"      spx_typed_vtable + UINT32_C({slot_offset}),",
                "      UINT32_C(4)) == UINT32_C(0)) {",
                "    *spx_typed_service->memory_fault = UINT32_C(1);",
                f"    {zero_result}",
                "  }",
                "  uint32_t spx_typed_target = spx_component_read(",
                "      spx_typed_service->runtime,",
                f"      spx_typed_vtable + UINT32_C({slot_offset}),",
                "      UINT32_C(4), &spx_typed_fault);",
                "  if (spx_typed_fault != UINT32_C(0)) {",
                "    *spx_typed_service->memory_fault = UINT32_C(1);",
                f"    {zero_result}",
                "  }",
                "  if (spx_typed_target == UINT32_C(0)) {",
                "    *spx_typed_service->service_fault = UINT32_C(1);",
                f"    {zero_result}",
                "  }",
            ]
        )
        typed_target_expression = "spx_typed_target"
    else:
        target_lines, typed_target_expression = typed_external_target_lines(binding, zero_result=zero_result,
            entry_index=next(i for i, item in enumerate(bundle.interface.services) if item == compiled_service))
        lines.extend(target_lines)
    lines.append(
        "  spx_proof_typed_service_begin(spx_typed_service->runtime->context, "
        f"UINT32_C({int(spec['spec_id'])}));"
    )
    if typed_target_expression is not None:
        lines.append(
            f"  spx_proof_typed_service_target({typed_target_expression});"
        )
    for logical_position, physical_index in enumerate(raw_indices):
        if not 0 <= physical_index < len(normalized_transducers):
            raise BisimulationRefinementError(
                f"proof service {symbol!r} raw argument is outside its codec"
            )
        expression = _typed_service_word_expression(
            transducer=normalized_transducers[physical_index],
            parameter_names=parameter_names[1:],
            parameter_type_ids=parameter_type_ids,
            type_index=type_index,
        )
        if normalized_transducers[physical_index].get("kind") == "finite_word_map":
            parameter_index, cases = _checked_typed_finite_word_map(
                normalized_transducers[physical_index],
                parameter_names=parameter_names[1:],
                parameter_type_ids=parameter_type_ids,
                type_index=type_index,
            )
            logical = parameter_names[1:][parameter_index]
            domain = " || ".join(
                f"(uint32_t){logical} == UINT32_C({item.logical_value})"
                for item in cases
            )
            lines.append(
                f"  __CPROVER_assert({domain}, "
                '"spx-bisimulation-typed-finite-word-domain");'
            )
        lines.append(
            "  spx_proof_typed_service_argument("
            f"UINT32_C({logical_position}), {expression});"
        )
    cell_inputs = [
        _mapping(item, "typed proof service cell input")
        for item in spec["cell_inputs"]
    ]
    needs_private_cell_read = False
    cell_lines: list[str] = []
    for position, item in enumerate(cell_inputs):
        physical_index = int(item["physical_index"])
        word_index = int(item["word_index"])
        if not 0 <= physical_index < len(normalized_transducers):
            raise BisimulationRefinementError(
                f"proof service {symbol!r} local-cell argument is outside its codec"
            )
        transducer = normalized_transducers[physical_index]
        if transducer.get("kind") != "local_cell":
            raise BisimulationRefinementError(
                f"proof service {symbol!r} local-cell input is stale"
            )
        initial_words = checked_initial_words(
            transducer.get("initial_words"), context="typed proof local cell"
        )
        if not 0 <= word_index < len(initial_words):
            raise BisimulationRefinementError(
                f"proof service {symbol!r} local-cell word is outside its recipe"
            )
        expression, reads_private_cell = _typed_local_cell_word_expression(
            initial_words[word_index]
        )
        needs_private_cell_read |= reads_private_cell
        cell_lines.append(
            "  spx_proof_typed_service_cell_input("
            f"UINT32_C({position}), {expression});"
        )
    lines.extend(cell_lines)
    if needs_private_cell_read:
        lines.append(
            "  __CPROVER_assert(spx_typed_fault == UINT32_C(0), "
            '"spx-bisimulation-typed-local-cell-read");'
        )
    result_type_id = getattr(service, "result_type_id", None)
    result_projection = binding.get("result_projection")
    outputs = [
        _mapping(item, "typed proof service output")
        for item in spec["outputs"]
    ]
    output_positions = {
        (int(item["physical_index"]), int(item["word_index"])): index
        for index, item in enumerate(outputs)
    }
    out_interfaces = [
        _mapping(item, "typed proof out interface")
        for item in _rows(binding.get("out_interfaces", []), "typed proof out interfaces")
    ]
    if out_interfaces:
        if result_type_id is None:
            raise BisimulationRefinementError(
                f"proof service {symbol!r} has outputs but no status result"
            )
        lines.append("  uint32_t spx_typed_result = spx_proof_typed_service_result();")
        lines.append("  if ((int32_t)spx_typed_result >= INT32_C(0)) {")
        for out_index, item in enumerate(out_interfaces):
            parameter_index = int(item.get("parameter_index", -1))
            physical_index = int(item.get("physical_index", -1))
            key = (physical_index, 0)
            if (
                not 0 <= parameter_index < len(parameter_names) - 1
                or key not in output_positions
                or type_index.get(parameter_type_ids[parameter_index]) is None
                or getattr(type_index[parameter_type_ids[parameter_index]], "kind", None)
                not in {"resource", "resource_cell"}
            ):
                raise BisimulationRefinementError(
                    f"proof service {symbol!r} out-interface codec is stale"
                )
            logical = parameter_names[1:][parameter_index]
            type_tag = _opaque_resource_type_tag(
                signature.parameters[parameter_index],
                context=f"proof service {symbol!r} out-interface",
            )
            output_position = output_positions[key]
            lines.extend(
                [
                    "    __CPROVER_assert(spx_proof_typed_service_output_active("
                    f"        UINT32_C({output_position})) != UINT32_C(0),",
                    '        "spx-bisimulation-typed-out-interface-active");',
                    f"    uint32_t spx_typed_output_{out_index} =",
                    "        spx_proof_typed_service_output("
                    f"            UINT32_C({output_position}));",
                    f"    {logical}->type_tag = spx_typed_output_{out_index} == UINT32_C(0)",
                    f"        ? UINT32_C(0) : UINT32_C({type_tag});",
                    f"    {logical}->generation = spx_typed_output_{out_index} == UINT32_C(0)",
                    "        ? UINT32_C(0) : UINT32_C(1);",
                    f"    {logical}->identity = (uint64_t)spx_typed_output_{out_index};",
                ]
            )
        lines.extend(
            [
                "  }",
                "  spx_proof_typed_service_finish();",
                f"  return ({result_c_type})spx_typed_result;",
            ]
        )
    elif result_type_id is None:
        lines.extend(["  spx_proof_typed_service_finish();", "  return;"])
    elif getattr(type_index.get(str(result_type_id)), 'kind', None) == 'view':
        lines.append('  uint32_t result = spx_proof_typed_service_result();')
        lines.extend(result_view_lines(signature=signature, types=types,
            projection=result_projection, authority_selectors=authority_selectors,
            runtime='spx_typed_service->runtime', result_word='result',
            failure=['    *spx_typed_service->service_fault = UINT32_C(1);',
                     '    spx_proof_typed_service_finish();', f'    {zero_result}'],
            finish=['    spx_proof_typed_service_finish();']))
    elif getattr(type_index.get(str(result_type_id)), "kind", None) == "reference":
        projection = _mapping(
            result_projection, "typed proof reference result projection"
        )
        source = _mapping(
            projection.get("source"), "typed proof reference result source"
        )
        requested = _mapping(
            projection.get("requested_extent"),
            "typed proof reference result requested extent",
        )
        extent = int(requested.get("value", -1))
        if (
            projection.get("kind") != "reference"
            or source.get("kind") != "register"
            or source.get("register") != "eax"
            or source.get("width") != 32
            or requested.get("kind") != "constant"
            or not 0 <= extent <= 0xFFFFFFFF
        ):
            raise BisimulationRefinementError(
                f"proof service {symbol!r} reference result is unsupported"
            )
        result = signature.results[0]
        permissions = {"read": 1, "write": 2, "read_write": 3}.get(
            result.access, 0
        )
        nullable = 1 if result.nullable else 0
        selector = authority_selector_expression(projection, authority_selectors)
        if reference_result_relation is not None:
            reference_result_origin_index = int(
                reference_result_relation["input_argument_index"]
            )
            origin_type = type_index[
                parameter_type_ids[reference_result_origin_index]
            ]
            origin_parameter = parameter_names[1:][
                reference_result_origin_index
            ]
            origin_is_view = getattr(origin_type, "kind", None) == "view"
            origin_expression = (
                f"{origin_parameter}->base" if origin_is_view else origin_parameter
            )
            if reference_result_origin_index not in validated_parameters:
                raise BisimulationRefinementError(
                    f"proof service {symbol!r} reference result origin was not realized")
            origin_word_expression = f"spx_typed_input_{reference_result_origin_index}_address"
            origin_remaining_expression = (
                f"{origin_parameter}->extent"
                if origin_is_view
                else "service_result_origin.extent - service_result_origin.offset"
            )
            minimum_remaining = reference_result_relation.get(
                "nonnull_min_remaining"
            )
            conditional_minimum_lines: list[str] = [
                "  uint64_t service_result_minimum_remaining = UINT64_C(1);"
            ]
            if isinstance(minimum_remaining, Mapping):
                nonzero_index = int(
                    minimum_remaining["nonzero_argument_index"]
                )
                minimum = int(minimum_remaining["minimum"])
                conditional_minimum_lines.extend(
                    [
                        f"  if ((uint64_t){parameter_names[1:][nonzero_index]} != UINT64_C(0))",
                        "    service_result_minimum_remaining = "
                        f"UINT64_C({minimum});",
                    ]
                )
            lines.extend(
                [
                    "  uint32_t result = spx_proof_typed_service_result();",
                    *(
                        [
                            "  if (result == UINT32_C(0)) {",
                            "    spx_proof_typed_service_finish();",
                            f"    return ({result_c_type}){{0}};",
                            "  }",
                        ]
                        if nullable
                        else [
                            "  __CPROVER_assume(result != UINT32_C(0));"
                        ]
                    ),
                    f"  spx_ref_v1 service_result_origin = {origin_expression};",
                    "  uint32_t service_result_origin_word =",
                    f"      {origin_word_expression};",
                    "  uint64_t service_result_origin_remaining =",
                    f"      {origin_remaining_expression};",
                    *conditional_minimum_lines,
                    "  __CPROVER_assume(result >= service_result_origin_word);",
                    "  uint64_t service_result_delta =",
                    "      (uint64_t)result - (uint64_t)service_result_origin_word;",
                    "  __CPROVER_assume(service_result_origin_remaining >=",
                    "      service_result_minimum_remaining);",
                    "  __CPROVER_assume(service_result_delta <=",
                    "      service_result_origin_remaining -",
                    "      service_result_minimum_remaining);",
                    "  service_result_origin.offset += service_result_delta;",
                    "  spx_machine_reference_v1 service_result_origin_machine = {",
                    "    service_result_origin.domain, service_result_origin.object,",
                    "    service_result_origin.generation, service_result_origin.offset,",
                    "    service_result_origin.extent, service_result_origin.permissions",
                    "  };",
                    "  uint32_t service_result_address = UINT32_C(0);",
                    "  if (spx_typed_service->runtime->realize_reference(",
                    "          spx_typed_service->runtime->context, &service_result_origin_machine,",
                    f"          UINT32_C({permissions}), UINT32_C(0), UINT32_C(0),",
                    "          &service_result_address) != SPX_BOUNDARY_OK || service_result_address != result) {",
                    f'    __CPROVER_assert(0, "spx-bisimulation-typed-service-reference-result:{symbol}");',
                    "    *spx_typed_service->service_fault = UINT32_C(1);",
                    "    spx_proof_typed_service_finish();",
                    f"    {zero_result}",
                    "  }",
                    "  spx_proof_typed_service_finish();",
                    f"  return ({result_c_type}){{",
                    "    service_result_origin.domain, service_result_origin.object,",
                    "    service_result_origin.generation, service_result_origin.offset,",
                    "    service_result_origin.extent, service_result_origin.permissions",
                    "  };",
                ]
            )
        else:
            lines.extend(
                [
                    "  uint32_t result = spx_proof_typed_service_result();",
                    "  spx_machine_reference_v1 service_result_reference = {0};",
                    "  if (spx_typed_service->runtime->resolve_reference == 0 ||",
                    "      spx_typed_service->runtime->resolve_reference(",
                    "          spx_typed_service->runtime->context, result,",
                    f"          UINT32_C({extent}), UINT32_C({permissions}),",
                    f"          {selector}, UINT32_C({nullable}), UINT32_C(0),",
                    "          &service_result_reference) != SPX_BOUNDARY_OK) {",
                    "    *spx_typed_service->service_fault = UINT32_C(1);",
                    "    spx_proof_typed_service_finish();",
                    f"    {zero_result}",
                    "  }",
                    "  spx_proof_typed_service_finish();",
                    f"  return ({result_c_type}){{",
                    "    service_result_reference.domain,",
                    "    service_result_reference.object,",
                    "    service_result_reference.generation,",
                    "    service_result_reference.offset, service_result_reference.extent,",
                    "    service_result_reference.permissions",
                    "  };",
                ]
            )
    elif getattr(type_index.get(str(result_type_id)), "kind", None) == "callback":
        nullable_result = bool(signature.results[0].nullable)
        lines.extend(
            [
                "  uint32_t result = spx_proof_typed_service_result();",
                "  if (result == UINT32_C(0)) {",
                *(
                    []
                    if nullable_result
                    else [
                        "    *spx_typed_service->service_fault = UINT32_C(1);"
                    ]
                ),
                "    spx_proof_typed_service_finish();",
                f"    return ({result_c_type})0;",
                "  }",
                "  spx_typed_service->callback_result.physical_word = result;",
                "  spx_typed_service->callback_result.target_rva = UINT32_C(0);",
                "  spx_proof_typed_service_finish();",
                f"  return ({result_c_type})&spx_typed_service->callback_result;",
            ]
        )
    elif (
        isinstance(result_projection, Mapping)
        and result_projection.get("kind") == "local_cell_record"
    ):
        cell_id = str(result_projection.get("cell_id", ""))
        physical_cells = [
            index
            for index, item in enumerate(normalized_transducers)
            if item.get("kind") == "local_cell" and item.get("cell_id") == cell_id
        ]
        fields = result_projection.get("fields")
        if len(physical_cells) != 1 or not isinstance(fields, list) or not fields:
            raise BisimulationRefinementError(
                f"proof service {symbol!r} record result is malformed"
            )
        logical_result_type = type_index.get(str(result_type_id))
        expected_fields = tuple(getattr(logical_result_type, "fields", ()))
        field_index = {
            str(_mapping(item, "typed proof record field").get("id", "")): int(
                _mapping(item, "typed proof record field").get("word_index", -1)
            )
            for item in fields
        }
        if set(field_index) != {str(item.identity) for item in expected_fields}:
            raise BisimulationRefinementError(
                f"proof service {symbol!r} record result is not total"
            )
        result_lines = []
        for field in expected_fields:
            key = (physical_cells[0], field_index[str(field.identity)])
            if key not in output_positions:
                raise BisimulationRefinementError(
                    f"proof service {symbol!r} record output is absent"
                )
            result_lines.append(
                f"    .{field.identity} = spx_proof_typed_service_output("
                f"UINT32_C({output_positions[key]})),"
            )
        lines.extend(
            [
                f"  {result_c_type} result = ({result_c_type}){{",
                *result_lines,
                "  };",
                "  spx_proof_typed_service_finish();",
                "  return result;",
            ]
        )
    elif isinstance(result_projection, Mapping) and result_projection.get(
        "kind"
    ) == "local_cell_word":
        cell_id = str(result_projection.get("cell_id", ""))
        word_index = int(result_projection.get("word_index", -1))
        physical_cells = [
            index
            for index, item in enumerate(normalized_transducers)
            if item.get("kind") == "local_cell" and item.get("cell_id") == cell_id
        ]
        key = (physical_cells[0], word_index) if len(physical_cells) == 1 else None
        if key not in output_positions:
            raise BisimulationRefinementError(
                f"proof service {symbol!r} local-cell result is absent"
            )
        lines.extend(
            [
                "  uint32_t result = spx_proof_typed_service_output("
                f"      UINT32_C({output_positions[key]}));",
                "  spx_proof_typed_service_finish();",
                f"  return ({result_c_type})result;",
            ]
        )
    else:
        lines.extend(
            [
                "  uint32_t result = spx_proof_typed_service_result();",
                "  spx_proof_typed_service_finish();",
                f"  return ({result_c_type})result;",
            ]
        )
    lines.extend(["}", ""])
    return tuple(lines)


def _typed_service_word_expression(
    *,
    transducer: Mapping[str, object],
    parameter_names: Sequence[str],
    parameter_type_ids: Sequence[str],
    type_index: Mapping[str, object],
) -> str:
    kind = str(transducer.get("kind", ""))
    if kind == "constant":
        value = int(transducer.get("value", -1))
        if not 0 <= value <= 0xFFFFFFFF:
            raise BisimulationRefinementError(
                "typed proof service constant is outside one word"
            )
        return f"UINT32_C({value})"
    if kind == "finite_word_map":
        parameter_index, cases = _checked_typed_finite_word_map(
            transducer,
            parameter_names=parameter_names,
            parameter_type_ids=parameter_type_ids,
            type_index=type_index,
        )
        name = parameter_names[parameter_index]
        expression = "UINT32_C(0)"
        for item in reversed(cases):
            expression = (
                f"((uint32_t){name} == UINT32_C({item.logical_value}) "
                f"? UINT32_C({item.physical_value}) : {expression})"
            )
        return expression
    if kind not in {"logical_argument", "record_field"}:
        raise BisimulationRefinementError(
            f"typed proof service transducer {kind!r} is unsupported"
        )
    parameter_index = int(transducer.get("parameter_index", -1))
    if not 0 <= parameter_index < len(parameter_names):
        raise BisimulationRefinementError(
            "typed proof service parameter index is outside its signature"
        )
    name = parameter_names[parameter_index]
    logical_type = type_index.get(parameter_type_ids[parameter_index])
    logical_kind = getattr(logical_type, "kind", None)
    if kind == "record_field":
        field_id = str(transducer.get("field_id", ""))
        if (
            logical_kind != "record"
            or field_id
            not in {str(item.identity) for item in getattr(logical_type, "fields", ())}
        ):
            raise BisimulationRefinementError(
                "typed proof record-field transducer is stale"
            )
        return f"(uint32_t){name}.{field_id}"
    if logical_kind in {"scalar", "enum"}:
        return f"(uint32_t){name}"
    if logical_kind == "resource":
        return f"(uint32_t){name}.identity"
    if logical_kind == "callback":
        return f"(uint32_t){name}->physical_word"
    if logical_kind in {"view", "bytes", "reference"}:
        # The call precondition has already realized this reference. Object IDs
        # name origins; only the runtime supplies their physical addresses.
        return f"spx_typed_input_{parameter_index}_address"
    raise BisimulationRefinementError(
        f"typed proof logical argument kind {logical_kind!r} is unsupported"
    )


def _checked_typed_finite_word_map(
    transducer: Mapping[str, object],
    *,
    parameter_names: Sequence[str],
    parameter_type_ids: Sequence[str],
    type_index: Mapping[str, object],
) -> tuple[int, object]:
    try:
        parameter_index, cases = parse_finite_word_map(
            transducer, context="typed proof finite-word map"
        )
    except FiniteWordMapError as exc:
        raise BisimulationRefinementError(str(exc)) from exc
    if (
        not 0 <= parameter_index < len(parameter_names)
        or parameter_index >= len(parameter_type_ids)
        or getattr(type_index.get(parameter_type_ids[parameter_index]), "kind", None)
        not in {"scalar", "enum"}
    ):
        raise BisimulationRefinementError(
            "typed proof finite-word parameter is outside its scalar signature"
        )
    return parameter_index, cases


def _typed_local_cell_word_expression(word: object) -> tuple[str, bool]:
    if word is None:
        return "UINT32_C(0)", False
    if isinstance(word, int) and not isinstance(word, bool):
        if not 0 <= word <= 0xFFFFFFFF:
            raise BisimulationRefinementError(
                "typed proof local-cell constant is outside one word"
            )
        return f"UINT32_C({word})", False
    row = _mapping(word, "typed proof local-cell initial word")
    if row.get("kind") != "entry_projection" or set(row) != {
        "kind",
        "projection",
    }:
        raise BisimulationRefinementError(
            "typed proof local-cell initial word kind is unsupported"
        )
    projection = _mapping(
        row.get("projection"), "typed proof local-cell entry projection"
    )
    kind = projection.get("kind")
    if kind == "constant":
        value = int(projection.get("value", -1))
        if not 0 <= value <= 0xFFFFFFFF:
            raise BisimulationRefinementError(
                "typed proof local-cell projection is outside one word"
            )
        return f"UINT32_C({value})", False
    if projection.get("at") != "entry" or projection.get("width") != 32:
        raise BisimulationRefinementError(
            "typed proof local-cell projection is not an entry word"
        )
    if kind == "register":
        register = str(projection.get("register", ""))
        if register not in {"eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp"}:
            raise BisimulationRefinementError(
                "typed proof local-cell register is unsupported"
            )
        return f"spx_typed_service->state->{register}", True
    if kind == "stack":
        offset = int(projection.get("offset", -1))
        if not 0 <= offset <= 4092 or offset % 4 != 0:
            raise BisimulationRefinementError(
                "typed proof local-cell stack word is outside its private frame"
            )
        return (
            "spx_component_read(spx_typed_service->runtime, "
            "spx_typed_service->state->esp + "
            f"UINT32_C({offset}), UINT32_C(4), &spx_typed_fault)",
            True,
        )
    raise BisimulationRefinementError(
        "typed proof local-cell projection cannot be rendered"
    )


def _trusted_adapter_lowering_receipt(
    *,
    interface: ProofKernelComponentInterface,
    service_bindings: Sequence[Mapping[str, object]],
    production_overlay_source: str,
    proof_overlay_source: str,
    relation_evidence: Sequence[Mapping[str, object]] = (),
    reference_authority: Mapping[str, object] | None = None,
    allocation_requirements: list[Mapping[str, object]] | None = None,
) -> dict[str, object] | None:
    """Bind a trusted dual lowering of one checked typed-adapter plan.

    The ordinary case executes the byte-identical production overlay and needs
    no extra authority.  A distinct proof overlay is admitted only for checked
    external/interface adapters and records the complete normalized plan used
    by both structural renderers.  It is never a post-render source rewrite.
    """

    production_sha256 = hashlib.sha256(
        production_overlay_source.encode("ascii")
    ).hexdigest()
    proof_sha256 = hashlib.sha256(proof_overlay_source.encode("ascii")).hexdigest()
    if production_sha256 == proof_sha256:
        return None

    service_ids = {item.identity for item in interface.services}
    reference_result_origins = _checked_reference_result_origins(
        interface=interface,
        relation_evidence=relation_evidence,
    )
    origin_evidence = {
        str(row["service_id"]): dict(row) for row in relation_evidence
    }
    adapter_rows: list[dict[str, object]] = []
    observed_symbols: set[str] = set()
    for raw in service_bindings:
        binding = {
            str(key): value
            for key, value in _mapping(
                raw, "trusted adapter lowering binding"
            ).items()
            if not str(key).startswith("_")
        }
        provider_kind = str(binding.get("provider_kind", ""))
        if provider_kind not in {"external_call", "interface_method"}:
            continue
        require_typed_external_target_support(binding)
        symbol = str(binding.get("symbol", ""))
        service_id = str(binding.get("service_id", ""))
        abi_sha256 = str(binding.get("abi_sha256", ""))
        if (
            re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", symbol) is None
            or symbol in observed_symbols
            or service_id not in service_ids
            or re.fullmatch(r"[0-9a-f]{64}", abi_sha256) is None
        ):
            raise BisimulationRefinementError(
                "trusted adapter lowering inventory is malformed or ambiguous"
            )
        observed_symbols.add(symbol)
        specs = admitted_call_specs((binding,), reference_authority=reference_authority,
                                    allocation_requirements=allocation_requirements)
        if not specs:
            raise BisimulationRefinementError(
                f"trusted adapter {service_id!r} has no checked proof-call event"
            )
        adapter_core: dict[str, object] = {
            "service_id": service_id,
            "symbol": symbol,
            "provider_kind": provider_kind,
            "abi_sha256": abi_sha256,
            "checked_binding": binding,
            "checked_binding_sha256": canonical_sha256_v3(binding),
            "proof_call_specs": specs,
            "proof_call_specs_sha256": canonical_sha256_v3(specs),
            "reference_result_origin": (
                origin_evidence[service_id]
                if service_id in reference_result_origins
                else None
            ),
        }
        adapter_rows.append(
            {
                **adapter_core,
                "adapter_sha256": canonical_sha256_v3(adapter_core),
            }
        )
    adapter_rows.sort(key=lambda row: (str(row["service_id"]), str(row["symbol"])))
    if not adapter_rows:
        raise BisimulationRefinementError(
            "a distinct proof overlay has no checked typed adapters"
        )

    implementation_paths = [
        Path(__file__),
        Path(__file__).with_name("bisimulation_service_effects.py"),
        Path(__file__).with_name("bisimulation_service_preconditions.py"),
        Path(__file__).with_name("machine_overlay_external_v5.py"),
        Path(__file__).with_name("machine_overlay_boundaries_v5.py"),
        Path(__file__).with_name("machine_overlay_result_views.py"),
        Path(__file__).with_name("machine_overlay_services_v5.py"),
        Path(__file__).with_name("machine_overlay_state_views.py"),
        Path(__file__).with_name("machine_overlay_v5.py"),
        *(Path(__file__).parents[1] / "external" / name for name in (
            "contracts.py", "resolved_contract.py", "range_allocation.py",
            "range_ownership.py", "range_release.py",
        )),
    ]
    implementation_files = [
        {
            "path": path.name,
            "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
        }
        for path in sorted({*implementation_paths,
                            *(lifetime_implementation_paths() if uses_lifetime_services(service_bindings) else []),
                            *(call_range_implementation_paths() if uses_call_ranges(service_bindings) else []),
                            *borrowed_memory_implementation_paths(),
                            *(terminated_read_implementation_paths() if uses_terminated_results(service_bindings) else []),
                            *(external_target_implementation_paths() if uses_external_target_slots(service_bindings) else [])},
                           key=lambda item: item.name)
    ]
    renderer = {
        "id": "checked-service-adapter-dual-lowering-v5",
        "version": 5,
        "implementation_files": implementation_files,
        "implementation_closure_sha256": canonical_sha256_v3(
            implementation_files
        ),
    }
    core: dict[str, object] = {
        "format": TRUSTED_ADAPTER_LOWERING_V1_FORMAT,
        "status": "complete",
        "trust_basis": "trusted_c_compiler_over_single_checked_adapter_plan",
        "interface_sha256": interface.sha256,
        "adapter_plan": adapter_rows,
        "adapter_plan_sha256": canonical_sha256_v3(adapter_rows),
        "production_overlay_sha256": production_sha256,
        "proof_overlay_sha256": proof_sha256,
        "renderer": renderer,
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _proof_call_specs(
    service_bindings: Sequence[Mapping[str, object]],
    *, allow_lifetime_effects: bool = False,
) -> list[dict[str, object]]:
    """Normalize checked service events into address-independent proof calls."""

    result: list[dict[str, object]] = []
    event_keys: set[tuple[str, int, int, int]] = set()
    for raw_binding in service_bindings:
        binding = _mapping(raw_binding, "proof service binding")
        provider_kind = str(binding.get("provider_kind", ""))
        if provider_kind not in {"external_call", "interface_method"}:
            continue
        external_effect_contract = checked_proof_external_effect_contract(
            binding, allow_lifetime_effects=allow_lifetime_effects)
        external_contract_identity = checked_proof_external_contract_identity(binding)
        raw_offsets = binding.get("argument_offsets")
        if (
            not isinstance(raw_offsets, list)
            or not raw_offsets
            or any(
                not isinstance(item, int)
                or isinstance(item, bool)
                or item < 0
                or item > 124
                or item % 4 != 0
                for item in raw_offsets
            )
        ):
            raise BisimulationRefinementError(
                "proof service argument offsets are malformed"
            )
        offsets = [int(item) for item in raw_offsets]
        if offsets != list(range(0, len(offsets) * 4, 4)):
            raise BisimulationRefinementError(
                "proof service argument frame is not canonical"
            )
        raw_transducers = binding.get("argument_transducers")
        transducers = (
            None
            if raw_transducers is None
            else list(_rows(raw_transducers, "proof service argument transducers"))
        )
        if transducers is not None and len(transducers) != len(offsets):
            raise BisimulationRefinementError(
                "proof service transducer arity differs from its ABI"
            )
        pointer_indices: set[int] = set()
        cell_inputs: set[tuple[int, int]] = set()
        output_conditions: dict[tuple[int, int], set[str]] = {}
        output_nonnull: set[tuple[int, int]] = set()
        for raw_out in _rows(binding.get("out_interfaces", []), "proof out interfaces"):
            out = _mapping(raw_out, "proof out interface")
            physical_index = int(out.get("physical_index", -1))
            if not 0 <= physical_index < len(offsets):
                raise BisimulationRefinementError(
                    "proof out-interface argument is outside its ABI"
                )
            pointer_indices.add(physical_index)
            key = (physical_index, 0)
            output_conditions.setdefault(key, set()).add("success")
            if not bool(out.get("nullable")):
                output_nonnull.add(key)
        relation_index = {
            canonical_sha256_v3(dict(item)): _mapping(
                item, "proof local-cell relation"
            )
            for item in _rows(binding.get("local_cells", []), "proof local-cell relations")
        }
        for physical_index, raw_transducer in enumerate(transducers or []):
            transducer = _mapping(raw_transducer, "proof service transducer")
            if transducer.get("kind") != "local_cell":
                continue
            pointer_indices.add(physical_index)
            relation_sha256 = transducer.get("local_cell_relation_sha256")
            if relation_sha256 is None:
                continue
            relation = relation_index.get(str(relation_sha256))
            if relation is None:
                raise BisimulationRefinementError(
                    "proof local-cell transducer names an absent relation"
                )
            try:
                initial_words = checked_initial_words(
                    transducer.get("initial_words"), context="proof local cell"
                )
                selection = checked_local_cell_selection(
                    relation,
                    physical_index=physical_index,
                    initial_words=initial_words,
                    memory={
                        "role": "caller_memory",
                        "access": "read_write",
                        "extent": "enclosing_object",
                        "retention": "during_call",
                    },
                    context="proof local cell",
                )
            except LocalCellTransducerError as exc:
                raise BisimulationRefinementError(str(exc)) from exc
            cell_inputs.update(
                (physical_index, word_index)
                for word_index in (
                    selection.input_word_indices
                    | selection.failure_preserved_word_indices
                    | selection.failure_observed_word_indices
                )
            )
            condition = (
                "always"
                if selection.output_condition == "always"
                else "success"
            )
            for word_index in selection.output_word_indices:
                output_conditions.setdefault(
                    (physical_index, word_index), set()
                ).add(condition)
            for word_index in selection.failure_observed_word_indices:
                output_conditions.setdefault(
                    (physical_index, word_index), set()
                ).add("failure")
        outputs = []
        for key, conditions in sorted(output_conditions.items()):
            condition = (
                "always"
                if "always" in conditions or conditions == {"success", "failure"}
                else next(iter(conditions))
            )
            outputs.append(
                {
                    "physical_index": key[0],
                    "word_index": key[1],
                    "condition": condition,
                    "nonnull": key in output_nonnull,
                }
            )
        raw_indices = [
            index for index in range(len(offsets)) if index not in pointer_indices
        ]
        if provider_kind == "interface_method":
            event_kind = "SPX_CALL_INDIRECT"
            callee_cleanup = len(offsets) * 4
            compare_target = True
        else:
            compare_target = binding.get("captured_target_projection") is not None
            event_kind = (
                "SPX_CALL_INDIRECT"
                if compare_target
                else "SPX_CALL_EXTERNAL_IMPORT"
            )
            abi_template = str(binding.get("abi_template", ""))
            callee_cleanup = len(offsets) * 4 if "stdcall" in abi_template else 0
        behavior_core = {
            "external_effect_contract": external_effect_contract,
            "external_contract_identity_sha256": external_contract_identity,
            # A connected proof overlay is rendered before its parent closure
            # is known.  Derive the transcript identity from the checked
            # address-independent behavior rather than a renderer-local
            # ordinal, so separately rendered overlays compose without an ID
            # remapping layer.
            "service_id": str(binding.get("service_id", "")),
            "provider_kind": provider_kind,
            "abi_sha256": str(binding.get("abi_sha256", "")),
            "event_kind": event_kind,
            "offsets": offsets,
            "raw_indices": raw_indices,
            "cell_inputs": [
                {"physical_index": item[0], "word_index": item[1]}
                for item in sorted(cell_inputs)
            ],
            "outputs": outputs,
            "compare_target": compare_target,
            "callee_cleanup": callee_cleanup,
        }
        behavior_sha256 = canonical_sha256_v3(behavior_core)
        spec_id = int(behavior_sha256[:8], 16)
        if spec_id == 0:
            raise BisimulationRefinementError(
                "proof service behavior has the reserved zero identity"
            )
        colliding = {
            str(item["behavior_sha256"])
            for item in result
            if int(item["spec_id"]) == spec_id
        }
        if colliding and colliding != {behavior_sha256}:
            raise BisimulationRefinementError(
                "proof service behavior identity collision"
            )
        for raw_event in _rows(binding.get("events"), "proof service events"):
            event = _mapping(raw_event, "proof service event")
            key = (
                event_kind,
                int(event.get("instruction_rva", -1)),
                int(event.get("event_index", -1)),
                int(event.get("return_rva", -1)),
            )
            if min(key[1:]) < 0 or key in event_keys:
                raise BisimulationRefinementError(
                    "proof service event identity is malformed or duplicated"
                )
            event_keys.add(key)
            result.append(
                {
                    # Every exact call site for one logical service shares a
                    # typed behavior.  Portable-C deliberately has no source
                    # address at which to distinguish those sites.
                    "spec_id": spec_id,
                    "behavior_sha256": behavior_sha256,
                    "external_effect_contract": external_effect_contract,
                    "external_contract_identity_sha256": external_contract_identity,
                    "service_id": str(binding.get("service_id", "")),
                    "event_kind": event_kind,
                    "instruction_rva": key[1],
                    "event_index": key[2],
                    "return_rva": key[3],
                    **({'checked_external_contract': event['checked_external_contract']}
                       if 'checked_external_contract' in event else {}),
                    "offsets": offsets,
                    "raw_indices": raw_indices,
                    "cell_inputs": [
                        {"physical_index": item[0], "word_index": item[1]}
                        for item in sorted(cell_inputs)
                    ],
                    "outputs": outputs,
                    "compare_target": compare_target,
                    "callee_cleanup": callee_cleanup,
                }
            )
    return result


def _canonical_proof_service_bindings(
    *inventories: Sequence[Mapping[str, object]],
    reference_authority: Mapping[str, object] | None = None,
    allocation_requirements: list[Mapping[str, object]] | None = None,
) -> list[dict[str, object]]:
    """Return one deterministic, duplicate-free connected service plan."""

    by_digest: dict[str, dict[str, object]] = {}
    for inventory in inventories:
        for raw in inventory:
            binding = dict(_mapping(raw, "connected proof service binding"))
            digest = canonical_sha256_v3(binding)
            previous = by_digest.get(digest)
            if previous is not None and previous != binding:
                raise BisimulationRefinementError(
                    "connected proof service binding digest collision"
                )
            by_digest[digest] = binding
    result = [by_digest[digest] for digest in sorted(by_digest)]
    # Validate event uniqueness and stable behavior-ID collision freedom at
    # closure construction time rather than relying on generated C case order.
    admitted_call_specs(result, reference_authority=reference_authority, allocation_requirements=allocation_requirements)
    return result


def _proof_private_ranges(
    operation_projection: Mapping[str, object],
    *,
    image_base: int,
) -> list[tuple[int, int]]:
    """Return image-VA ranges whose final values are checked as component state."""

    ranges: set[tuple[int, int]] = set()
    for raw in _rows(operation_projection.get("state"), "proof state projections"):
        row = _mapping(raw, "proof state projection")
        for phase in ("entry", "exit"):
            projection = _mapping(row.get(phase), "proof state phase projection")
            if projection.get("kind") != "static_slot":
                continue
            width = int(projection.get("width", 0))
            rva = int(projection.get("rva", -1))
            if width not in {8, 16, 32} or rva < 0:
                raise BisimulationRefinementError(
                    "proof state static-slot projection is malformed"
                )
            ranges.add((image_base + rva, width // 8))
    return sorted(ranges)
