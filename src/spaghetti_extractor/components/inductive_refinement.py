"""Universal CBMC refinement of portable init/step/finish operations."""

from __future__ import annotations

import copy
import hashlib
import json
import tempfile
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .cbmc_backend import CbmcBackendError, cbmc_version, run_cbmc_properties
from .inductive_contract import (
    InductiveOperationCertificateV1,
    check_inductive_operation_certificate,
)
from .inductive_receipts import (
    INDUCTIVE_SOURCE_RECEIPT_V1,
    CheckedInductiveMachineReceiptV1,
)
from .inductive_relation import InductiveCutpointRelationV1
from .inductive_source import InductiveSourcePlanV1
from .inductive_world import (
    InductiveServiceWorld,
    InductiveWorldError,
    render_inductive_service_world,
)
from .interface_ir import PortableComponentInterfaceV2
from .semantic_path_errors import SemanticPathError
from .semantic_paths import build_inductive_segment_models, build_operation_path_model
from .semantic_contract import ComponentSemanticContractV1
from .source import component_operation_symbols, load_component_source_package


class InductiveRefinementError(ValueError):
    """Inductive refinement inputs or checker execution are invalid."""


def check_inductive_source_refinement_artifacts(
    *,
    semantic_contract: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object],
    source_package: Path | str,
    source_profile: Path | str | Mapping[str, object],
    source_plan: Path | str | Mapping[str, object],
    machine_receipt: Path | str | Mapping[str, object],
    cutpoint_relation: Path | str | Mapping[str, object],
    certificate: Path | str | Mapping[str, object],
    cbmc: Path | str,
    timeout_seconds: int = 300,
    component_service_contracts: Mapping[str, object] | None = None,
) -> dict[str, object]:
    """Load and cross-bind the immutable artifacts used by the Nix phase."""

    semantic = ComponentSemanticContractV1.parse(
        _load_artifact(semantic_contract, "component semantic contract")
    )
    if semantic.status != "satisfied":
        raise InductiveRefinementError(
            "inductive refinement requires a satisfied semantic contract"
        )
    portable = PortableComponentInterfaceV2.parse(
        _load_artifact(interface, "portable component interface")
    )
    plan = InductiveSourcePlanV1.parse(
        _load_artifact(source_plan, "inductive source plan")
    )
    semantic_payload = semantic.to_payload()
    operations = [
        item
        for item in _rows(semantic_payload.get("operations"), "semantic operations")
        if item.get("operation_id") == plan.operation_id
    ]
    if len(operations) != 1:
        raise InductiveRefinementError(
            "inductive semantic operation is missing or ambiguous"
        )
    machine = CheckedInductiveMachineReceiptV1.parse(
        _load_artifact(machine_receipt, "inductive machine receipt"),
        exact_operation=operations[0],
    )
    relation = InductiveCutpointRelationV1.parse(
        _load_artifact(cutpoint_relation, "inductive cutpoint relation")
    )
    checked_certificate = InductiveOperationCertificateV1.parse(
        _load_artifact(certificate, "inductive operation certificate")
    )
    provider_contracts = _load_provider_contracts(
        component_service_contracts or {},
        semantic_payload=semantic.to_payload(),
        interface=portable,
        operation_id=plan.operation_id,
    )
    return check_inductive_source_refinement(
        operation=operations[0],
        service_bindings=semantic_payload.get("services", []),
        interface=portable,
        source_package=source_package,
        source_profile=_load_artifact(source_profile, "source-profile receipt"),
        source_plan=plan,
        machine_receipt=machine,
        relation=relation,
        certificate=checked_certificate,
        cbmc=cbmc,
        timeout_seconds=timeout_seconds,
        provider_contracts=provider_contracts,
    )


def check_inductive_source_refinement(
    *,
    operation: Mapping[str, object],
    service_bindings: object,
    interface: PortableComponentInterfaceV2,
    source_package: Path | str,
    source_profile: Mapping[str, object],
    source_plan: InductiveSourcePlanV1,
    machine_receipt: CheckedInductiveMachineReceiptV1,
    relation: InductiveCutpointRelationV1,
    certificate: InductiveOperationCertificateV1,
    cbmc: Path | str,
    timeout_seconds: int = 300,
    provider_contracts: Mapping[str, Mapping[str, object]] | None = None,
) -> dict[str, object]:
    """Prove initialization and one arbitrary step at every exact cutpoint."""

    source_root = Path(source_package)
    source = load_component_source_package(source_root)
    symbols = component_operation_symbols(source)
    source_plan.validate_for(interface, symbols)
    relation.validate_for(interface, source_plan, machine_receipt)
    bindings = certificate.bindings
    if (
        bindings.interface_sha256 != interface.sha256
        or bindings.operation_id != source_plan.operation_id
        or bindings.machine_semantic_contract_sha256
        != machine_receipt.semantic_contract_sha256
        or bindings.source_plan_sha256 != source_plan.plan_sha256
        or bindings.cutpoint_relation_sha256 != relation.relation_sha256
        or bindings.implementation_sha256 != source.get("implementation_sha256")
    ):
        raise InductiveRefinementError(
            "inductive certificate bindings differ from refinement inputs"
        )
    machine_reference = next(
        (item for item in certificate.receipts if item.kind == "machine_semantics"),
        None,
    )
    if (
        machine_reference is None
        or machine_reference.receipt_sha256 != machine_receipt.receipt_sha256
    ):
        raise InductiveRefinementError(
            "inductive certificate does not reference the exact machine receipt"
        )
    inventory_check = check_inductive_operation_certificate(
        certificate,
        receipt_payloads={
            machine_reference.receipt_id: machine_receipt.to_payload()
        },
    )
    if inventory_check.status == "violated":
        raise InductiveRefinementError(
            "inductive certificate contradicts the exact machine inventory"
        )
    if source_profile.get("status") != "satisfied" or _mapping(
        source_profile.get("bindings"), "source-profile bindings"
    ).get("implementation_sha256") != source.get("implementation_sha256"):
        raise InductiveRefinementError(
            "restricted source profile is incomplete or stale"
        )
    source_profile_core = dict(source_profile)
    source_profile_sha256 = source_profile_core.pop("receipt_sha256", None)
    if (
        not isinstance(source_profile_sha256, str)
        or canonical_sha256_v3(source_profile_core) != source_profile_sha256
    ):
        raise InductiveRefinementError("restricted source-profile receipt is stale")
    if interface.state:
        raise InductiveRefinementError(
            "inductive refinement of persistent component state is not implemented"
        )
    logical_operation = interface.operation_index()[source_plan.operation_id]
    if logical_operation.effect_ids or operation.get("callback_operation_ids"):
        raise InductiveRefinementError(
            "inductive effects and callbacks require a checked world model"
        )
    if any(item.kind not in {"scalar", "enum", "resource", "bytes"} for item in (
        interface.type_index()[value.type_id]
        for value in logical_operation.parameters
    )):
        raise InductiveRefinementError("inductive parameter type is unsupported")
    if any(
        interface.type_index()[value.type_id].kind
        not in {"scalar", "enum", "resource"}
        for value in logical_operation.results
    ):
        raise InductiveRefinementError("inductive result type is unsupported")

    model = build_inductive_segment_models(
        operation,
        interface,
        source_plan,
        machine_receipt,
        relation,
        service_bindings,
    )
    cbmc_path = Path(cbmc)
    try:
        version = cbmc_version(cbmc_path)
    except CbmcBackendError as exc:
        raise InductiveRefinementError(str(exc)) from exc
    checker_sha256 = hashlib.sha256(cbmc_path.read_bytes()).hexdigest()
    package_root = source_root if source_root.is_dir() else source_root.parent
    translation_units = [
        package_root / "sources" / str(row["path"])
        for row in source["files"]
        if isinstance(row, Mapping) and str(row.get("path", "")).endswith(".c")
    ]
    with tempfile.TemporaryDirectory(prefix="inductive-refinement-") as temporary:
        root = Path(temporary)
        _write_cbmc_stdint(root / "stdint.h")
        (root / "portable-component.h").write_text(
            interface.render_public_header(), encoding="ascii"
        )
        (root / "portable-component-implementation.h").write_text(
            interface.render_implementation_header(symbols), encoding="ascii"
        )
        plan_header = root / "portable-component-inductive.h"
        plan_header.write_text(
            source_plan.render_header(interface, symbols), encoding="ascii"
        )
        harness = root / "inductive-refinement-harness.c"
        harness.write_text(
            _render_harness(
                interface=interface,
                source_plan=source_plan,
                relation=relation,
                certificate=certificate,
                model=model,
                provider_contracts=provider_contracts or {},
            ),
            encoding="ascii",
        )
        wrapped_translation_units: list[Path] = []
        for index, translation_unit in enumerate(translation_units):
            wrapper = root / f"source-unit-{index:04d}.c"
            wrapper.write_text(
                f'#include "{plan_header.name}"\n'
                f'#include "{_c_include_path(translation_unit)}"\n',
                encoding="ascii",
            )
            wrapped_translation_units.append(wrapper)
        command = [
            str(cbmc_path),
            "--i386-win32",
            "--json-ui",
            "--trace",
            "--function",
            "spx_inductive_refinement_harness",
            "--bounds-check",
            "--pointer-check",
            "--memory-leak-check",
            "--div-by-zero-check",
            "--signed-overflow-check",
            "--conversion-check",
            "--undefined-shift-check",
            "--unwinding-assertions",
            "-I",
            str(root),
            "-I",
            str(package_root / "sources"),
            *(str(path) for path in wrapped_translation_units),
            str(harness),
        ]
        result = run_cbmc_properties(
            command=command, timeout_seconds=timeout_seconds
        )

    status = str(result["status"])
    issues = [] if status == "satisfied" else [{
        "status": status,
        "code": result["code"],
        "source": result.get("source"),
        "counterexample": result.get("counterexample"),
        "detail": result.get("detail"),
    }]
    obligations = (
        _obligation_rows(certificate, model, source_plan, result)
        if status == "satisfied"
        else []
    )
    core: dict[str, object] = {
        "format": INDUCTIVE_SOURCE_RECEIPT_V1,
        "status": status,
        "component_id": source["lift_unit_id"],
        "operation_id": source_plan.operation_id,
        "bindings": {
            "interface_sha256": interface.sha256,
            "semantic_contract_sha256": machine_receipt.semantic_contract_sha256,
            "source_profile_sha256": source_profile_sha256,
            "source_plan_sha256": source_plan.plan_sha256,
            "relation_sha256": relation.relation_sha256,
            "implementation_sha256": source["implementation_sha256"],
            "machine_receipt_sha256": machine_receipt.receipt_sha256,
            "component_service_contracts": [
                {
                    "service_id": service_id,
                    "interface_sha256": contract["interface_sha256"],
                    "semantic_contract_sha256": contract[
                        "semantic_contract_sha256"
                    ],
                    "operation_sha256": contract["operation_sha256"],
                    "model_sha256": contract["model_sha256"],
                }
                for service_id, contract in sorted(
                    (provider_contracts or {}).items()
                )
            ],
        },
        "checker": {
            "id": "cbmc",
            "version": version,
            "executable_sha256": checker_sha256,
            "output_sha256": result["output_sha256"],
        },
        "obligations": obligations,
        "issues": issues,
        "model": {
            "sha256": model["model_sha256"],
            "segment_count": len(model["segments"]),
            "cutpoint_count": len(relation.cutpoints),
        },
        "policy": {
            "original_binary_executed": False,
            "behavior_examples_used": False,
            "bounded_unwinding_used": False,
            "all_properties_satisfied": status == "satisfied",
        },
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _render_harness(
    *,
    interface: PortableComponentInterfaceV2,
    source_plan: InductiveSourcePlanV1,
    relation: InductiveCutpointRelationV1,
    certificate: InductiveOperationCertificateV1,
    model: Mapping[str, object],
    provider_contracts: Mapping[str, Mapping[str, object]],
) -> str:
    operation = interface.operation_index()[source_plan.operation_id]
    types = interface.type_index()
    byte_tokens = {
        parameter.identity: index + 1
        for index, parameter in enumerate(
            parameter
            for parameter in operation.parameters
            if types[parameter.type_id].kind == "bytes"
        )
    }
    prefix = f"SPX_{_macro(interface.identity)}_{_macro(operation.identity)}"
    state_type = f"spx_{_fragment(interface.identity)}_{_fragment(operation.identity)}_state_v1"
    control_type = f"spx_{_fragment(interface.identity)}_{_fragment(operation.identity)}_control_v1"
    c_types = {
        interface.logical_c_value_type(field.type_id)
        for field in source_plan.state
    } | {
        interface.logical_c_value_type(value.type_id)
        for value in operation.parameters
        if types[value.type_id].kind != "bytes"
    }
    if any(
        types[value.type_id].kind == "bytes"
        and types[value.type_id].nul_terminated
        for value in operation.parameters
    ):
        c_types.add("uint32_t")
    c_types.update(
        interface.logical_c_type(service.result_type_id)
        for service in interface.services
        if service.identity in operation.allowed_service_ids
        and service.result_type_id is not None
    )
    nondet = {
        c_type: f"spx_nondet_{index}" for index, c_type in enumerate(sorted(c_types))
    }
    lines = [
        '#include "portable-component-inductive.h"',
        "#include <stdint.h>",
        "",
        *(
            f"static {c_type} {symbol}(void) {{ {c_type} value; return value; }}"
            for c_type, symbol in nondet.items()
        ),
        "",
        "static uint32_t spx_i32_bits(int32_t value) {",
        "  if (value >= 0) return (uint32_t)value;",
        "  return UINT32_MAX - (uint32_t)(-(value + 1));",
        "}",
        "",
    ]
    try:
        world = render_inductive_service_world(
            interface=interface,
            operation_id=operation.identity,
            model=model,
            nondeterministic_functions=nondet,
            provider_contracts=provider_contracts,
        )
    except InductiveWorldError as exc:
        raise InductiveRefinementError(str(exc)) from exc
    lines.extend(world.prelude)
    byte_parameters = [
        value
        for value in operation.parameters
        if types[value.type_id].kind == "bytes"
    ]
    for parameter in byte_parameters:
        logical_type = types[parameter.type_id]
        extent_id = logical_type.extent_parameter_id
        if extent_id is None and not logical_type.nul_terminated:
            raise InductiveRefinementError(
                f"byte parameter {parameter.identity!r} needs a finite extent"
            )
        lines.extend(
            [
                f"uint8_t __CPROVER_uninterpreted_spx_byte_{parameter.identity}(uint32_t index);",
                f"static uint32_t spx_read_{parameter.identity}(void *opaque, uint32_t index, uint8_t *result) {{",
                "  spx_bytes_view_v2 *view = (spx_bytes_view_v2 *)opaque;",
                "  if (result == 0 || index >= view->extent) return UINT32_C(1);",
                f"  *result = __CPROVER_uninterpreted_spx_byte_{parameter.identity}(index);",
                "  return UINT32_C(0);",
                "}",
                "",
            ]
        )

    segments = [
        row for row in model["segments"] if isinstance(row, Mapping)
    ]
    entry_segments = [
        row for row in segments if _mapping(row["source"], "source")["kind"] == "operation_entry"
    ]
    lines.extend(
        _render_check_function(
            name="spx_check_initialize",
            mode="initialize",
            segments=entry_segments,
            interface=interface,
            source_plan=source_plan,
            relation=relation,
            certificate=certificate,
            nondet=nondet,
            prefix=prefix,
            state_type=state_type,
            control_type=control_type,
            world=world,
            byte_tokens=byte_tokens,
        )
    )
    check_names = ["spx_check_initialize"]
    for index, cutpoint in enumerate(relation.cutpoints):
        name = f"spx_check_step_{index}"
        check_names.append(name)
        cutpoint_segments = [
            row
            for row in segments
            if _mapping(row["source"], "source").get("kind") == "cutpoint"
            and _mapping(row["source"], "source").get("id") == cutpoint.unit_id
        ]
        lines.extend(
            _render_check_function(
                name=name,
                mode="step",
                segments=cutpoint_segments,
                interface=interface,
                source_plan=source_plan,
                relation=relation,
                certificate=certificate,
                nondet=nondet,
                prefix=prefix,
                state_type=state_type,
                control_type=control_type,
                world=world,
                byte_tokens=byte_tokens,
                cutpoint_unit_id=cutpoint.unit_id,
            )
        )
    lines.extend(
        [
            "void spx_inductive_refinement_harness(void) {",
            *(f"  {name}();" for name in check_names),
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _render_check_function(
    *,
    name: str,
    mode: str,
    segments: Sequence[Mapping[str, object]],
    interface: PortableComponentInterfaceV2,
    source_plan: InductiveSourcePlanV1,
    relation: InductiveCutpointRelationV1,
    certificate: InductiveOperationCertificateV1,
    nondet: Mapping[str, str],
    prefix: str,
    state_type: str,
    control_type: str,
    world: InductiveServiceWorld,
    byte_tokens: Mapping[str, int],
    cutpoint_unit_id: str | None = None,
) -> list[str]:
    if not segments:
        raise InductiveRefinementError(f"{mode} has no exact machine segments")
    operation = interface.operation_index()[source_plan.operation_id]
    types = interface.type_index()
    lines = [
        f"static void {name}(void) {{",
        f"  spx_{interface.identity}_context_v2 context = {{0}};",
        f"  {state_type} state = {{0}};",
        *world.setup,
    ]
    for field in source_plan.state:
        c_type = interface.logical_c_value_type(field.type_id)
        if mode == "step":
            lines.extend(
                [
                    f"  {c_type} spx_initial_state_{field.identity} = {nondet[c_type]}();",
                    f"  state.{field.identity} = spx_initial_state_{field.identity};",
                ]
            )
    argument_by_id: dict[str, str] = {}
    for parameter in operation.parameters:
        logical_type = types[parameter.type_id]
        if logical_type.kind != "bytes":
            c_type = interface.logical_c_value_type(parameter.type_id)
            lines.append(
                f"  {c_type} {parameter.identity} = {nondet[c_type]}();"
            )
            argument_by_id[parameter.identity] = parameter.identity
    for parameter in operation.parameters:
        logical_type = types[parameter.type_id]
        if logical_type.kind != "bytes":
            continue
        extent_id = logical_type.extent_parameter_id
        if extent_id is not None and extent_id not in argument_by_id:
            raise InductiveRefinementError(
                f"byte parameter {parameter.identity!r} has no scalar extent"
            )
        if extent_id is None and not logical_type.nul_terminated:
            raise InductiveRefinementError(
                f"byte parameter {parameter.identity!r} has no finite domain"
            )
        extent_expression = (
            extent_id
            if extent_id is not None
            else f"{nondet['uint32_t']}()"
        )
        lines.extend(
            [
                f"  spx_bytes_view_v2 {parameter.identity} = {{0}};",
                f"  {parameter.identity}.context = &{parameter.identity};",
                f"  {parameter.identity}.extent = {extent_expression};",
                f"  {parameter.identity}.read_u8 = spx_read_{parameter.identity};",
            ]
        )
        if logical_type.nul_terminated:
            lines.extend(
                [
                    f"  __CPROVER_assume({parameter.identity}.extent > UINT32_C(0));",
                    f"  __CPROVER_assume(__CPROVER_uninterpreted_spx_byte_{parameter.identity}({parameter.identity}.extent - UINT32_C(1)) == UINT8_C(0));",
                ]
            )
        argument_by_id[parameter.identity] = f"&{parameter.identity}"
    arguments = [
        "&context",
        *(argument_by_id[item.identity] for item in operation.parameters),
    ]
    if mode == "initialize":
        call = f"{source_plan.symbols.initialize}(&state, {', '.join(arguments)})"
    else:
        assert cutpoint_unit_id is not None
        cutpoint = next(
            item for item in relation.cutpoints if item.unit_id == cutpoint_unit_id
        )
        phase_number = source_plan.phase_ids.index(cutpoint.phase_id)
        invariants = _cutpoint_invariants(certificate, cutpoint_unit_id)
        signed_state_ids = {
            field.identity
            for field in source_plan.state
            if interface.logical_c_value_type(field.type_id) == "int32_t"
        }
        for invariant in invariants:
            lines.append(
                f"  __CPROVER_assume({_render_expression(invariant.expression.to_payload(), byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)});"
            )
        call = (
            f"{source_plan.symbols.step}(&state, UINT32_C({phase_number}), "
            f"{', '.join(arguments)})"
        )
    lines.append(f"  {control_type} control = {call};")
    result_type = interface.operation_c_result(operation)
    finish_arguments = ", ".join(
        ["&state", "control.completion_id", *arguments]
    )
    if result_type == "void":
        lines.extend(
            [
                f"  if (control.kind == {prefix}_CONTROL_COMPLETE) {{",
                f"    {source_plan.symbols.finish}({finish_arguments});",
                "  }",
            ]
        )
    else:
        lines.extend(
            [
                f"  {result_type} observed_result = {{0}};"
                if result_type.startswith("spx_")
                else f"  {result_type} observed_result = 0;",
                f"  if (control.kind == {prefix}_CONTROL_COMPLETE) {{",
                f"    observed_result = {source_plan.symbols.finish}({finish_arguments});",
                "  }",
            ]
        )
    clauses = [
        _segment_clause(
            segment,
            interface=interface,
            source_plan=source_plan,
            certificate=certificate,
            prefix=prefix,
            service_numbers=world.service_numbers,
            byte_tokens=byte_tokens,
        )
        for segment in segments
    ]
    assertion = " ||\n      ".join(f"({item})" for item in clauses)
    lines.extend(
        [
            f'  __CPROVER_assert(({assertion}), "spx-inductive:{source_plan.operation_id}:{name}");',
            "}",
            "",
        ]
    )
    return lines


def _segment_clause(
    segment: Mapping[str, object],
    *,
    interface: PortableComponentInterfaceV2,
    source_plan: InductiveSourcePlanV1,
    certificate: InductiveOperationCertificateV1,
    prefix: str,
    service_numbers: Mapping[str, int],
    byte_tokens: Mapping[str, int],
) -> str:
    signed_state_ids = {
        field.identity
        for field in source_plan.state
        if interface.logical_c_value_type(field.type_id) == "int32_t"
    }
    conditions = [
        f"({_render_expression(item, byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)})"
        for item in _rows(segment.get("guards"), "segment guards")
    ]
    conditions.extend(
        f"({_render_expression(item, byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)})"
        for item in _rows(
            segment.get("relation_checks", []), "segment relation checks"
        )
    )
    trace = _rows(segment.get("trace"), "segment service trace")
    conditions.extend(
        [
            "spx_oracle.overflow == UINT32_C(0)",
            f"spx_oracle.count == UINT32_C({len(trace)})",
        ]
    )
    for event_index, event in enumerate(trace):
        service_id = _text(event.get("service_id"), "segment service id")
        service_number = service_numbers.get(service_id)
        arguments = event.get("arguments")
        if service_number is None or not isinstance(arguments, list) or any(
            not isinstance(argument, Mapping) for argument in arguments
        ):
            raise InductiveRefinementError("segment service trace is malformed")
        conditions.extend(
            [
                f"spx_oracle.ids[{event_index}] == UINT32_C({service_number})",
                f"spx_oracle.argument_counts[{event_index}] == UINT32_C({len(arguments)})",
                *(
                    f"spx_oracle.arguments[{event_index}][{argument_index}] == "
                    f"(uint64_t)({_render_expression(expression, byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)})"
                    for argument_index, expression in enumerate(arguments)
                ),
            ]
        )
    target = _mapping(segment.get("target"), "segment target")
    if target.get("kind") == "cutpoint":
        phase_id = str(target["phase_id"])
        conditions.extend(
            [
                f"control.kind == {prefix}_CONTROL_RUNNING",
                f"control.phase_id == UINT32_C({source_plan.phase_ids.index(phase_id)})",
            ]
        )
        values = _mapping(segment.get("target_values"), "segment target values")
        state_types = {
            field.identity: interface.logical_c_value_type(field.type_id)
            for field in source_plan.state
        }
        for key, expression in values.items():
            kind, identity = str(key).split(":", 1)
            observed = (
                f"UINT32_C({byte_tokens[identity]})"
                if kind == "parameter" and identity in byte_tokens
                else identity
                if kind == "parameter"
                else f"state.{identity}"
            )
            if kind == "source_state" and state_types.get(identity) == "int32_t":
                observed = f"spx_i32_bits({observed})"
            conditions.append(
                f"({observed}) == ({_render_expression(expression, byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)})"
            )
        target_updates = {
            str(key).split(":", 1)[1]: expression
            for key, expression in values.items()
            if str(key).startswith("source_state:")
        }
        for invariant in _cutpoint_invariants(
            certificate, str(target["id"])
        ):
            target_invariant = _substitute_target_state(
                invariant.expression.to_payload(), target_updates
            )
            conditions.append(
                _render_expression(
                    target_invariant,
                    byte_tokens=byte_tokens,
                    signed_state_ids=signed_state_ids,
                )
            )
        segment_id = str(segment["segment_id"])
        decreases = [
            item for item in certificate.decreases if item.transition_id == segment_id
        ]
        for decrease in decreases:
            conditions.append(
                f"(uint32_t)({_render_expression(decrease.after.to_payload(), byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)}) "
                f"< (uint32_t)({_render_expression(decrease.before.to_payload(), byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)})"
            )
    else:
        completion_id = str(target["completion_id"])
        conditions.extend(
            [
                f"control.kind == {prefix}_CONTROL_COMPLETE",
                f"control.completion_id == UINT32_C({source_plan.completion_ids.index(completion_id)})",
            ]
        )
        results = _mapping(segment.get("results"), "segment results")
        operation = interface.operation_index()[source_plan.operation_id]
        for result in operation.results:
            observed = (
                "observed_result"
                if len(operation.results) == 1
                else f"observed_result.{result.identity}"
            )
            if interface.logical_c_value_type(result.type_id) == "int32_t":
                observed = f"spx_i32_bits({observed})"
            conditions.append(
                f"({observed}) == ({_render_expression(results[result.identity], byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)})"
            )
    return " && ".join(f"({item})" for item in conditions)


def _substitute_target_state(
    value: object, updates: Mapping[str, object]
) -> dict[str, object]:
    row = _mapping(value, "target invariant expression")
    op = row.get("op")
    if op in {"loop_variable", "state_input"}:
        name = _text(row.get("name"), "target invariant state name")
        replacement = updates.get(name)
        if replacement is not None:
            return copy.deepcopy(dict(_mapping(replacement, "target state value")))
    result: dict[str, object] = {}
    for key, item in row.items():
        if isinstance(item, Mapping):
            result[str(key)] = _substitute_target_state(item, updates)
        elif isinstance(item, list):
            result[str(key)] = [
                _substitute_target_state(child, updates)
                if isinstance(child, Mapping)
                else copy.deepcopy(child)
                for child in item
            ]
        else:
            result[str(key)] = copy.deepcopy(item)
    return result


def _cutpoint_invariants(
    certificate: InductiveOperationCertificateV1, cutpoint_id: str
) -> tuple[object, ...]:
    owning = [
        scc
        for scc in certificate.sccs
        if cutpoint_id in scc.cutpoint_ids
    ]
    if len(owning) != 1:
        raise InductiveRefinementError(
            f"cutpoint {cutpoint_id!r} has no unique invariant owner"
        )
    predicates = tuple(
        item
        for item in certificate.predicates
        if item.scc_id == owning[0].identity and item.kind == "invariant"
    )
    if not predicates:
        raise InductiveRefinementError(
            f"cutpoint {cutpoint_id!r} has no inductive invariant"
        )
    return predicates


def _render_expression(
    value: object,
    *,
    byte_tokens: Mapping[str, int] | None = None,
    signed_state_ids: set[str] | None = None,
) -> str:
    row = _mapping(value, "inductive logical expression")
    op = row.get("op")
    if op == "parameter":
        return _text(row.get("name"), "parameter expression")
    if op == "bytes_address":
        name = _text(row.get("name"), "byte-view address expression")
        if byte_tokens is None or name not in byte_tokens:
            raise InductiveRefinementError(
                f"byte-view address {name!r} has no operation parameter"
            )
        return f"UINT32_C({byte_tokens[name]})"
    if op in {"state_input", "loop_variable"}:
        name = _text(row.get("name"), "state expression")
        rendered = "spx_initial_state_" + name
        return (
            f"spx_i32_bits({rendered})"
            if name in (signed_state_ids or set())
            else rendered
        )
    if op == "service_result":
        index = row.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise InductiveRefinementError("service-result index is invalid")
        return f"spx_oracle.results[{index}]"
    if op == "byte_extent":
        return _text(row.get("name"), "byte extent") + ".extent"
    if op == "byte_read":
        name = _text(row.get("name"), "byte view")
        return (
            f"__CPROVER_uninterpreted_spx_byte_{name}"
            f"((uint32_t)({_render_expression(row.get('index'), byte_tokens=byte_tokens, signed_state_ids=signed_state_ids)}))"
        )
    if op == "const":
        return f"UINT32_C({int(row.get('value', 0)) & 0xFFFFFFFF})"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    args = row.get("args")
    if not isinstance(args, list):
        raise InductiveRefinementError(f"expression {op!r} has no arguments")
    rendered = [
        _render_expression(
            item,
            byte_tokens=byte_tokens,
            signed_state_ids=signed_state_ids,
        )
        if isinstance(item, Mapping)
        else str(item)
        for item in args
    ]
    word_binary = {
        "add32": "+",
        "sub32": "-",
        "and32": "&",
        "or32": "|",
        "xor32": "^",
        "mul32": "*",
        "ult32": "<",
        "ule32": "<=",
    }
    logical_binary = {
        "eq": "==",
        "and": "&&",
        "and_bool": "&&",
        "or": "||",
        "or_bool": "||",
    }
    if op in word_binary and len(rendered) == 2:
        return (
            f"(((uint32_t)({rendered[0]})) {word_binary[op]} "
            f"((uint32_t)({rendered[1]})))"
        )
    if op in logical_binary and len(rendered) == 2:
        return f"(({rendered[0]}) {logical_binary[op]} ({rendered[1]}))"
    if op == "not" and len(rendered) == 1:
        return f"(!({rendered[0]}))"
    if op == "ite" and len(rendered) == 3:
        return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
    if op == "sign_extend" and len(rendered) == 2:
        width = args[0]
        if width == 32:
            return f"((uint32_t)({rendered[1]}))"
        if width in {8, 16}:
            mask = (1 << width) - 1
            sign = 1 << (width - 1)
            narrowed = f"(((uint32_t)({rendered[1]})) & UINT32_C({mask}))"
            return f"((({narrowed}) ^ UINT32_C({sign})) - UINT32_C({sign}))"
        raise InductiveRefinementError("sign extension width is unsupported")
    raise InductiveRefinementError(f"expression operation {op!r} is unsupported")


def _obligation_rows(
    certificate: InductiveOperationCertificateV1,
    model: Mapping[str, object],
    source_plan: InductiveSourcePlanV1,
    result: Mapping[str, object],
) -> list[dict[str, object]]:
    property_ids = sorted(str(item) for item in result["property_ids"])
    segment_ids = sorted(
        str(item["segment_id"])
        for item in model["segments"]
        if isinstance(item, Mapping)
    )
    rows: list[dict[str, object]] = []
    families = (
        ("initialization", certificate.initialization, source_plan.symbols.initialize),
        ("preservation", certificate.preservation, source_plan.symbols.step),
        ("bridge", certificate.bridges, source_plan.symbols.step),
        ("decrease", certificate.decreases, source_plan.symbols.step),
        ("exit", certificate.exits, source_plan.symbols.step),
        ("completion", certificate.completions, source_plan.symbols.finish),
    )
    for kind, evidence, symbol in families:
        for item in evidence:
            selected = (
                [item.transition_id]
                if hasattr(item, "transition_id")
                else segment_ids
            )
            rows.append(
                {
                    "obligation_id": item.identity,
                    "kind": kind,
                    "status": "satisfied",
                    "segment_ids": sorted(set(selected) & set(segment_ids)),
                    "source_symbol": symbol,
                    "property_ids": property_ids,
                }
            )
    rows.sort(key=lambda item: str(item["obligation_id"]))
    return rows


def _write_cbmc_stdint(path: Path) -> None:
    path.write_text(
        "#ifndef SPX_CBMC_STDINT_H\n#define SPX_CBMC_STDINT_H\n"
        "typedef unsigned char uint8_t; typedef signed char int8_t;\n"
        "typedef unsigned short uint16_t; typedef signed short int16_t;\n"
        "typedef unsigned int uint32_t; typedef signed int int32_t;\n"
        "typedef unsigned long long uint64_t; typedef signed long long int64_t;\n"
        "#define UINT8_C(x) x##U\n#define UINT16_C(x) x##U\n"
        "#define UINT32_C(x) x##U\n#define UINT64_C(x) x##ULL\n"
        "#define UINT32_MAX UINT32_C(4294967295)\n#endif\n",
        encoding="ascii",
    )


def _mapping(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise InductiveRefinementError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(item, Mapping) for item in value):
        raise InductiveRefinementError(f"{context} must be an array of objects")
    return list(value)


def _load_artifact(
    value: Path | str | Mapping[str, object], context: str
) -> dict[str, object]:
    if isinstance(value, Mapping):
        return copy.deepcopy(dict(value))
    try:
        loaded = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise InductiveRefinementError(f"cannot read {context}: {exc}") from exc
    if not isinstance(loaded, Mapping):
        raise InductiveRefinementError(f"{context} must be an object")
    return dict(loaded)


def _load_provider_contracts(
    declarations: Mapping[str, object],
    *,
    semantic_payload: Mapping[str, object],
    interface: PortableComponentInterfaceV2,
    operation_id: str,
) -> dict[str, dict[str, object]]:
    operation = interface.operation_index()[operation_id]
    allowed = set(operation.allowed_service_ids)
    services = {item.identity: item for item in interface.services}
    semantic_services = {
        str(item["service_id"]): item
        for item in _rows(semantic_payload.get("services"), "semantic services")
    }
    if set(declarations) - allowed:
        raise InductiveRefinementError(
            "component service contract inventory contains an unused service"
        )
    result: dict[str, dict[str, object]] = {}
    for service_id, raw in sorted(declarations.items()):
        declaration = _mapping(raw, f"component service contract {service_id}")
        if set(declaration) != {
            "component_id",
            "operation_id",
            "semantic_contract",
            "interface",
        }:
            raise InductiveRefinementError(
                f"component service contract {service_id!r} has unknown fields"
            )
        semantic_service = semantic_services.get(service_id)
        provider = (
            _mapping(semantic_service.get("provider"), "semantic service provider")
            if semantic_service is not None
            else {}
        )
        component_id = _text(
            declaration.get("component_id"), "provider component id"
        )
        provider_operation_id = _text(
            declaration.get("operation_id"), "provider operation id"
        )
        if (
            provider.get("kind") != "component_operation"
            or provider.get("component_id") != component_id
            or provider.get("operation_id") != provider_operation_id
        ):
            raise InductiveRefinementError(
                f"component service contract {service_id!r} differs from exact resolution"
            )
        provider_semantic = ComponentSemanticContractV1.parse(
            _load_artifact(
                _text(
                    declaration.get("semantic_contract"),
                    "provider semantic contract path",
                ),
                "provider semantic contract",
            )
        )
        provider_interface = PortableComponentInterfaceV2.parse(
            _load_artifact(
                _text(declaration.get("interface"), "provider interface path"),
                "provider interface",
            )
        )
        if provider_semantic.status != "satisfied":
            raise InductiveRefinementError(
                f"component service provider {component_id!r} is not semantically satisfied"
            )
        provider_operations = [
            item
            for item in _rows(
                provider_semantic.to_payload().get("operations"),
                "provider semantic operations",
            )
            if item.get("operation_id") == provider_operation_id
        ]
        if len(provider_operations) != 1:
            raise InductiveRefinementError(
                f"component service provider operation {provider_operation_id!r} is ambiguous"
            )
        provider_operation = provider_interface.operation_index().get(
            provider_operation_id
        )
        if provider_operation is None:
            raise InductiveRefinementError(
                f"component service provider operation {provider_operation_id!r} is absent"
            )
        consumer_service = services[service_id]
        if (
            len(provider_operation.parameters)
            != len(consumer_service.parameter_type_ids)
            or len(provider_operation.results) != 1
            or consumer_service.result_type_id is None
        ):
            raise InductiveRefinementError(
                f"component service provider {service_id!r} is not a scalar function"
            )
        consumer_types = [
            interface.logical_c_value_type(type_id)
            for type_id in consumer_service.parameter_type_ids
        ]
        provider_types = [
            provider_interface.logical_c_value_type(item.type_id)
            for item in provider_operation.parameters
        ]
        if consumer_types != provider_types or interface.logical_c_value_type(
            consumer_service.result_type_id
        ) != provider_interface.logical_c_value_type(
            provider_operation.results[0].type_id
        ):
            raise InductiveRefinementError(
                f"component service provider {service_id!r} has incompatible value types"
            )
        try:
            model = build_operation_path_model(
                provider_operations[0],
                provider_interface,
                provider_semantic.to_payload().get("services", []),
            )
        except SemanticPathError as exc:
            raise InductiveRefinementError(
                f"component service provider {service_id!r} has no finite contract: {exc}"
            ) from exc
        if model.get("service_ids") or model.get("state_ids"):
            raise InductiveRefinementError(
                f"component service provider {service_id!r} is not a closed scalar function"
            )
        paths = _rows(model.get("paths"), "provider finite paths")
        if any(_rows(path.get("trace"), "provider path trace") for path in paths):
            raise InductiveRefinementError(
                f"component service provider {service_id!r} invokes another service"
            )
        result_id = provider_operation.results[0].identity
        result[service_id] = {
            "component_id": component_id,
            "operation_id": provider_operation_id,
            "parameter_ids": [item.identity for item in provider_operation.parameters],
            "result_id": result_id,
            "paths": [
                {
                    "guards": copy.deepcopy(path["guards"]),
                    "results": copy.deepcopy(path["results"]),
                }
                for path in paths
            ],
            "interface_sha256": provider_interface.sha256,
            "semantic_contract_sha256": provider_semantic.contract_sha256,
            "operation_sha256": canonical_sha256_v3(provider_operations[0]),
            "model_sha256": canonical_sha256_v3(model),
        }
    return result


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise InductiveRefinementError(f"{context} must be a nonempty string")
    return value


def _fragment(value: str) -> str:
    return "".join(character if character.isalnum() or character == "_" else "_" for character in value)


def _macro(value: str) -> str:
    return _fragment(value).upper()


def _c_include_path(path: Path) -> str:
    return str(path).replace("\\", "\\\\").replace('"', '\\"')


__all__ = [
    "InductiveRefinementError",
    "check_inductive_source_refinement",
    "check_inductive_source_refinement_artifacts",
]
