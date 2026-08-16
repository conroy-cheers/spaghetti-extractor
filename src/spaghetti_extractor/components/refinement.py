"""CBMC-backed static refinement for restricted portable C components."""

from __future__ import annotations

import json
import hashlib
import tempfile
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .cbmc_backend import CbmcBackendError, cbmc_version, run_cbmc_properties
from .formats import COMPONENT_REFINEMENT_RECEIPT_V1_FORMAT
from .interface_ir import LogicalTypeV1, PortableComponentInterfaceV2
from .semantic_contract import ComponentSemanticContractV1
from .semantic_paths import (
    SemanticPathError,
    SemanticPathViolation,
    build_operation_path_model,
)
from .source import component_operation_symbols, load_component_source_package


class ComponentRefinementError(ValueError):
    """A refinement input or checker invocation is invalid."""


class _UnsupportedRefinement(ValueError):
    pass


def check_component_refinement(
    *,
    semantic_contract: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object],
    source_package: Path | str,
    source_profile: Path | str | Mapping[str, object],
    cbmc: Path | str,
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Check every operation for all modeled inputs without runtime examples."""

    contract = ComponentSemanticContractV1.parse(
        _load(semantic_contract, "component semantic contract")
    )
    portable = PortableComponentInterfaceV2.parse(
        _load(interface, "portable component interface")
    )
    source = load_component_source_package(source_package)
    profile = _load(source_profile, "component source profile")
    issues: list[dict[str, object]] = []
    checks: list[dict[str, object]] = []
    cbmc_path = Path(cbmc)

    def issue(status: str, code: str, **fields: object) -> None:
        issues.append({"status": status, "code": code, **fields})

    if contract.status != "satisfied":
        issue("incomplete", "semantic_contract_not_satisfied", observed=contract.status)
    component_id = contract.payload.get("component_id")
    if not isinstance(component_id, str) or not component_id:
        issue("violated", "semantic_contract_component_identity_invalid")
    if source.get("lift_unit_id") != component_id:
        issue("violated", "source_component_identity_mismatch")
    if profile.get("status") != "satisfied":
        issue("incomplete", "restricted_c_profile_not_satisfied")
    if profile.get("bindings", {}).get("implementation_sha256") != source.get(
        "implementation_sha256"
    ):
        issue("violated", "restricted_c_profile_binding_stale")
    contract_bindings = _object(contract.payload.get("bindings"), "semantic bindings")
    if contract_bindings.get("interface_sha256") != portable.sha256:
        issue("violated", "semantic_contract_interface_digest_mismatch")

    try:
        version = cbmc_version(cbmc_path)
    except CbmcBackendError as exc:
        raise ComponentRefinementError(str(exc)) from exc
    checker_sha256 = hashlib.sha256(cbmc_path.read_bytes()).hexdigest()
    if not issues:
        operation_symbols = component_operation_symbols(source)
        operation_index = portable.operation_index()
        contract_operations = _rows(
            contract.payload.get("operations"), "semantic operations"
        )
        contract_operation_ids = tuple(
            _text(row.get("operation_id"), "semantic operation id")
            for row in contract_operations
        )
        expected_operation_ids = tuple(sorted(operation_index))
        if (
            tuple(sorted(contract_operation_ids)) != expected_operation_ids
            or tuple(sorted(operation_symbols)) != expected_operation_ids
            or len(contract_operation_ids) != len(set(contract_operation_ids))
        ):
            issue(
                "violated",
                "operation_inventory_mismatch",
                expected=list(expected_operation_ids),
                contract=list(contract_operation_ids),
                source=sorted(operation_symbols),
            )
        for raw_operation in (() if issues else contract_operations):
            operation = _object(raw_operation, "semantic operation")
            operation_id = _text(operation.get("operation_id"), "semantic operation id")
            logical = operation_index.get(operation_id)
            if logical is None or operation_id not in operation_symbols:
                issue("violated", "operation_inventory_mismatch", operation_id=operation_id)
                continue
            try:
                model = build_operation_path_model(
                    operation,
                    portable,
                    contract.payload["services"],
                )
                result = _run_cbmc_operation(
                    cbmc=cbmc_path,
                    timeout_seconds=timeout_seconds,
                    package=Path(source_package),
                    source=source,
                    interface=portable,
                    operation_id=operation_id,
                    operation_symbol=operation_symbols[operation_id],
                    model=model,
                )
                result["model"] = _model_summary(model)
            except SemanticPathViolation as exc:
                issue(
                    "violated",
                    "semantic_binding_contradicts_machine_path",
                    operation_id=operation_id,
                    detail=str(exc),
                )
                continue
            except (SemanticPathError, _UnsupportedRefinement) as exc:
                issue(
                    "incomplete", "semantic_refinement_form_unsupported",
                    operation_id=operation_id, detail=str(exc),
                )
                continue
            checks.append(result)
            if result["status"] != "satisfied":
                issue(
                    str(result["status"]), str(result["code"]),
                    operation_id=operation_id,
                    source=result.get("source"),
                    counterexample=result.get("counterexample"),
                    detail=result.get("detail"),
                )

    status = (
        "violated" if any(row["status"] == "violated" for row in issues)
        else "incomplete" if issues
        else "satisfied"
    )
    core: dict[str, object] = {
        "format": COMPONENT_REFINEMENT_RECEIPT_V1_FORMAT,
        "status": status,
        "activation_authorized": status == "satisfied",
        "component_id": component_id,
        "bindings": {
            "semantic_contract_sha256": contract.contract_sha256,
            "interface_sha256": portable.sha256,
            "implementation_sha256": source["implementation_sha256"],
            "source_profile_sha256": profile.get("receipt_sha256"),
        },
        "checker": {
            "id": "cbmc",
            "version": version,
            "sha256": checker_sha256,
            "architecture": "i386-win32",
            "timeout_seconds": timeout_seconds,
        },
        "checks": checks,
        "issues": sorted(
            issues,
            key=lambda row: (
                str(row["status"]), str(row["code"]), str(row.get("operation_id", ""))
            ),
        ),
        "policy": {
            "original_binary_executed": False,
            "operator_behavior_examples_used": False,
            "cbmc_is_pinned_trusted_checker": True,
            "finite_unwinding_cannot_authorize_loops": True,
            "unsupported_semantics_fail_closed": True,
        },
    }
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _model_summary(model: Mapping[str, object]) -> dict[str, object]:
    paths = _rows(model.get("paths"), "semantic paths")
    return {
        "kind": "finite-machine-paths-v1",
        "path_count": len(paths),
        "max_service_events": int(model.get("max_events", 0)),
        "service_ids": list(
            _string_rows(model.get("service_ids"), "semantic service ids")
        ),
        "state_ids": list(
            _string_rows(model.get("state_ids"), "semantic state ids")
        ),
    }


def _run_cbmc_operation(
    *, cbmc: Path, timeout_seconds: int, package: Path,
    source: Mapping[str, object], interface: PortableComponentInterfaceV2,
    operation_id: str, operation_symbol: str, model: Mapping[str, object],
) -> dict[str, object]:
    operation = interface.operation_index()[operation_id]
    types = interface.type_index()
    scalar_nondeterministic_types = {
        _logical_c_type(types[parameter.type_id])
        for parameter in operation.parameters
        if types[parameter.type_id].kind in {"scalar", "enum", "resource"}
    }
    nondeterministic_types = sorted({
        "uint32_t",
        "uint64_t",
        *scalar_nondeterministic_types,
        *(
            _logical_c_type(types[field.type_id])
            for field in interface.state
        ),
        *(
            _logical_c_type(types[service.result_type_id])
            for service in interface.services
            if service.result_type_id is not None
        ),
    })
    nondeterministic_functions = {
        c_type: f"spx_nondet_value_{index}"
        for index, c_type in enumerate(nondeterministic_types)
    }
    package_root = package if package.is_dir() else package.parent
    translation_units = [
        package_root / "sources" / str(row["path"])
        for row in source["files"]
        if isinstance(row, Mapping) and str(row.get("path", "")).endswith(".c")
    ]
    with tempfile.TemporaryDirectory(prefix="component-refinement-") as temporary:
        root = Path(temporary)
        # CBMC's i386-win32 frontend otherwise asks the host glibc for 32-bit
        # multilib headers.  Components use this reviewed freestanding subset,
        # so provide the exact fixed-width definitions directly.
        (root / "stdint.h").write_text(
            "#ifndef SPX_CBMC_STDINT_H\n"
            "#define SPX_CBMC_STDINT_H\n"
            "typedef unsigned char uint8_t; typedef signed char int8_t;\n"
            "typedef unsigned short uint16_t; typedef signed short int16_t;\n"
            "typedef unsigned int uint32_t; typedef signed int int32_t;\n"
            "typedef unsigned long long uint64_t; typedef signed long long int64_t;\n"
            "#define UINT8_C(x) x##U\n#define UINT16_C(x) x##U\n"
            "#define UINT32_C(x) x##U\n#define UINT64_C(x) x##ULL\n"
            "#define UINT32_MAX UINT32_C(4294967295)\n"
            "#endif\n",
            encoding="ascii",
        )
        (root / "portable-component.h").write_text(
            interface.render_public_header(), encoding="ascii"
        )
        symbols = component_operation_symbols(source)
        (root / "portable-component-implementation.h").write_text(
            interface.render_implementation_header(symbols), encoding="ascii"
        )
        argument_by_id: dict[str, str] = {}
        declarations = []
        for parameter in operation.parameters:
            logical_type = types[parameter.type_id]
            if logical_type.kind == "bytes":
                continue
            c_type = _logical_c_type(logical_type)
            declarations.append(
                f"  {c_type} {parameter.identity} = "
                f"{nondeterministic_functions[c_type]}();"
            )
            argument_by_id[parameter.identity] = parameter.identity
        for parameter in operation.parameters:
            logical_type = types[parameter.type_id]
            if logical_type.kind != "bytes":
                continue
            if logical_type.nul_terminated:
                raise _UnsupportedRefinement(
                    "NUL-terminated byte parameters require an inductive extent contract"
                )
            extent_id = logical_type.extent_parameter_id
            if extent_id is None or extent_id not in argument_by_id:
                raise _UnsupportedRefinement(
                    f"byte parameter {parameter.identity!r} has no scalar extent argument"
                )
            declarations.extend(
                [
                    f"  spx_refinement_bytes_context_v1 spx_bytes_{parameter.identity}_context = "
                    f"{{{extent_id}}};",
                    f"  spx_bytes_view_v2 spx_bytes_{parameter.identity}_view = "
                    f"{{&spx_bytes_{parameter.identity}_context, {extent_id}, "
                    f"spx_refinement_read_u8_{parameter.identity}, 0}};",
                ]
            )
            argument_by_id[parameter.identity] = (
                f"&spx_bytes_{parameter.identity}_view"
            )
        arguments = [argument_by_id[row.identity] for row in operation.parameters]
        result_type = interface.operation_c_result(operation)
        call_arguments = ", ".join(["&context", *arguments])
        common = [
            '#include "portable-component-implementation.h"',
            "#include <stdint.h>",
            *(
                f"static {c_type} {function}(void) "
                f"{{ {c_type} value; return value; }}"
                for c_type, function in nondeterministic_functions.items()
            ),
        ]
        if any(
            types[parameter.type_id].kind == "bytes"
            for parameter in operation.parameters
        ):
            common.extend(
                [
                    "typedef struct { uint32_t extent; } "
                    "spx_refinement_bytes_context_v1;",
                ]
            )
            for parameter in operation.parameters:
                if types[parameter.type_id].kind != "bytes":
                    continue
                name = parameter.identity
                common.extend(
                    [
                        f"uint8_t __CPROVER_uninterpreted_spx_byte_{name}("
                        "uint32_t index);",
                        f"static uint32_t spx_refinement_read_u8_{name}("
                        "void *opaque, uint32_t index, uint8_t *result) {",
                        "  spx_refinement_bytes_context_v1 *view = "
                        "(spx_refinement_bytes_context_v1 *)opaque;",
                        "  if (result == 0 || index >= view->extent) "
                        "return UINT32_C(1);",
                        f"  *result = __CPROVER_uninterpreted_spx_byte_{name}(index);",
                        "  return UINT32_C(0);",
                        "}",
                    ]
                )
        harness = _render_service_path_harness(
            interface=interface,
            operation_id=operation_id,
            operation_symbol=operation_symbol,
            result_type=str(result_type),
            declarations=declarations,
            arguments=call_arguments,
            model=model,
            common=common,
            nondeterministic_functions=nondeterministic_functions,
        )
        harness_path = root / "refinement-harness.c"
        harness_path.write_text(harness, encoding="ascii")
        command = [
            str(cbmc), "--i386-win32", "--json-ui", "--trace",
            "--function", "spx_refinement_harness",
            "--bounds-check", "--pointer-check", "--memory-leak-check",
            "--div-by-zero-check", "--signed-overflow-check",
            "--conversion-check",
            "--undefined-shift-check", "--unwinding-assertions",
            "-I", str(root), "-I", str(package_root / "sources"),
            *(str(path) for path in translation_units), str(harness_path),
        ]
        return {
            "operation_id": operation_id,
            **run_cbmc_properties(
                command=command, timeout_seconds=timeout_seconds
            ),
        }


def _render_expression(
    value: object, *, byte_tokens: Mapping[str, int] | None = None
) -> str:
    row = _object(value, "normalized expression")
    op = row.get("op")
    if op == "parameter":
        return _text(row.get("name"), "parameter expression")
    if op == "state_input":
        return "spx_initial_state_" + _text(
            row.get("name"), "state-input expression"
        )
    if op == "service_result":
        index = row.get("index")
        if not isinstance(index, int) or isinstance(index, bool) or index < 0:
            raise _UnsupportedRefinement("service-result index is invalid")
        return f"spx_oracle.results[{index}]"
    if op == "byte_read":
        name = _text(row.get("name"), "byte-read view")
        index = row.get("index")
        if not isinstance(index, Mapping):
            raise _UnsupportedRefinement("byte-read index is malformed")
        return (
            f"__CPROVER_uninterpreted_spx_byte_{name}("
            f"(uint32_t)({_render_expression(index, byte_tokens=byte_tokens)}))"
        )
    if op == "bytes_address":
        name = _text(row.get("name"), "byte-view address")
        if byte_tokens is None or name not in byte_tokens:
            raise _UnsupportedRefinement(
                f"byte-view address {name!r} has no operation parameter"
            )
        return f"UINT64_C({byte_tokens[name]})"
    if op == "const":
        return f"UINT32_C({int(row.get('value', 0)) & 0xffffffff})"
    if op in {"true", "false"}:
        return "UINT32_C(1)" if op == "true" else "UINT32_C(0)"
    args = row.get("args")
    if not isinstance(args, list):
        raise _UnsupportedRefinement(f"expression {op!r} has no arguments")
    rendered = [
        _render_expression(item, byte_tokens=byte_tokens)
        if isinstance(item, Mapping)
        else str(item)
        for item in args
    ]
    binary = {
        "add32": "+", "sub32": "-", "and32": "&", "or32": "|",
        "xor32": "^", "eq": "==", "ult32": "<", "shl32": "<<",
        "lshr32": ">>",
    }
    if op in binary and len(rendered) == 2:
        return f"((uint32_t)({rendered[0]}) {binary[op]} (uint32_t)({rendered[1]}))"
    if op == "ite" and len(rendered) == 3:
        return f"(({rendered[0]}) ? ({rendered[1]}) : ({rendered[2]}))"
    if op == "not" and len(rendered) == 1:
        return f"(!({rendered[0]}))"
    if op == "msb" and len(rendered) == 2:
        return f"(((uint32_t)({rendered[1]}) >> ({rendered[0]} - 1U)) & 1U)"
    if op == "parity" and len(rendered) == 2:
        return f"spx_even_parity_u8((uint8_t)({rendered[1]}))"
    if op == "add_overflow" and len(rendered) == 4:
        return (
            "spx_add_overflow_u32((uint32_t)(%s), (uint32_t)(%s), "
            "(uint32_t)(%s), (uint32_t)(%s))"
            % tuple(rendered)
        )
    if op == "sub_overflow" and len(rendered) == 4:
        return (
            "spx_sub_overflow_u32((uint32_t)(%s), (uint32_t)(%s), "
            "(uint32_t)(%s), (uint32_t)(%s))"
            % tuple(rendered)
        )
    raise _UnsupportedRefinement(f"expression operation {op!r} is unsupported")


def _render_service_path_harness(
    *,
    interface: PortableComponentInterfaceV2,
    operation_id: str,
    operation_symbol: str,
    result_type: str,
    declarations: list[str],
    arguments: str,
    model: Mapping[str, object],
    common: list[str],
    nondeterministic_functions: Mapping[str, str],
) -> str:
    paths = _rows(model.get("paths"), "semantic paths")
    if not paths:
        raise _UnsupportedRefinement("service path model has no paths")
    enabled = set(_string_rows(model.get("service_ids"), "semantic service ids"))
    services = [row for row in interface.services if row.identity in enabled]
    if {row.identity for row in services} != enabled:
        raise _UnsupportedRefinement("semantic path model has unknown services")
    service_numbers = {
        service.identity: index + 1
        for index, service in enumerate(interface.services)
    }
    max_events = max(1, int(model.get("max_events", 0)))
    max_arguments = max(
        1,
        max((len(service.parameter_type_ids) for service in services), default=0),
    )
    operation = interface.operation_index()[operation_id]
    type_index = interface.type_index()
    byte_parameters = [
        parameter
        for parameter in operation.parameters
        if type_index[parameter.type_id].kind == "bytes"
    ]
    byte_tokens = {
        parameter.identity: index + 1
        for index, parameter in enumerate(byte_parameters)
    }
    lines = [
        *common,
        "static uint32_t spx_even_parity_u8(uint8_t value) {",
        "  value ^= (uint8_t)(value >> 4); value &= UINT8_C(15);",
        "  return (UINT16_C(0x9669) >> value) & UINT32_C(1);",
        "}",
        "static uint32_t spx_add_overflow_u32(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {",
        "  uint32_t mask = width == UINT32_C(32) ? UINT32_MAX : ((UINT32_C(1) << width) - UINT32_C(1));",
        "  uint32_t sign = UINT32_C(1) << (width - UINT32_C(1));",
        "  return ((~(left ^ right) & (left ^ result) & sign & mask) != UINT32_C(0));",
        "}",
        "static uint32_t spx_sub_overflow_u32(uint32_t width, uint32_t left, uint32_t right, uint32_t result) {",
        "  uint32_t mask = width == UINT32_C(32) ? UINT32_MAX : ((UINT32_C(1) << width) - UINT32_C(1));",
        "  uint32_t sign = UINT32_C(1) << (width - UINT32_C(1));",
        "  return (((left ^ right) & (left ^ result) & sign & mask) != UINT32_C(0));",
        "}",
        "typedef struct {",
        "  uint32_t count;",
        "  uint32_t overflow;",
        f"  uint32_t ids[{max_events}];",
        f"  uint32_t argument_counts[{max_events}];",
        f"  uint64_t arguments[{max_events}][{max_arguments}];",
        f"  uint64_t results[{max_events}];",
        f"  const spx_bytes_view_v2 *byte_views[{max(1, len(byte_parameters))}];",
        "} spx_refinement_oracle_v1;",
        "static spx_refinement_oracle_v1 spx_oracle;",
        "static uint64_t spx_refinement_bytes_token(",
        "    const spx_refinement_oracle_v1 *oracle,",
        "    const spx_bytes_view_v2 *view) {",
        *(
            f"  if (view == oracle->byte_views[{index}]) return UINT64_C({index + 1});"
            for index in range(len(byte_parameters))
        ),
        "  return UINT64_C(0);",
        "}",
    ]
    for service in services:
        result = (
            "void"
            if service.result_type_id is None
            else _logical_c_type(type_index[service.result_type_id])
        )
        parameters = ["void *opaque"] + [
            f"{_logical_c_type(type_index[type_id])} argument_{index}"
            for index, type_id in enumerate(service.parameter_type_ids)
        ]
        lines.extend(
            [
                f"static {result} spx_refinement_service_{service.identity}({', '.join(parameters)}) {{",
                "  spx_refinement_oracle_v1 *oracle = (spx_refinement_oracle_v1 *)opaque;",
                "  uint32_t index = oracle->count++;",
                f"  if (index >= UINT32_C({max_events})) {{ oracle->overflow = UINT32_C(1); index = UINT32_C(0); }}",
                f"  oracle->ids[index] = UINT32_C({service_numbers[service.identity]});",
                f"  oracle->argument_counts[index] = UINT32_C({len(service.parameter_type_ids)});",
            ]
        )
        for position, type_id in enumerate(service.parameter_type_ids):
            if type_index[type_id].kind == "bytes":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"spx_refinement_bytes_token(oracle, argument_{position});"
                )
            else:
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"(uint64_t)argument_{position};"
                )
        if result != "void":
            lines.extend(
                [
                    f"  {result} logical_result = "
                    f"{nondeterministic_functions[result]}();",
                    "  oracle->results[index] = (uint64_t)logical_result;",
                    "  return logical_result;",
                ]
            )
        lines.extend(["}", ""])

    service_type = f"spx_{interface.identity}_services_v2"
    lines.extend(
        [
            "void spx_refinement_harness(void) {",
            f"  {service_type} services = {{0}};",
            "  services.context = &spx_oracle;",
        ]
    )
    lines.extend(
        f"  services.{service.identity} = spx_refinement_service_{service.identity};"
        for service in services
    )
    lines.extend(
        [
            f"  spx_{interface.identity}_context_v2 context = {{0}};",
            "  context.services = &services;",
        ]
    )
    protocol_type = f"spx_{interface.identity}_protocol_state_v2"
    lines.append(
        "  uint32_t spx_initial_protocol_state = "
        f"{nondeterministic_functions['uint32_t']}();"
    )
    pre_states = [
        f"spx_initial_protocol_state == UINT32_C({interface.protocol_states.index(state)})"
        for state in operation.pre_states
    ]
    lines.append(f"  __CPROVER_assume({' || '.join(pre_states)});")
    lines.append(
        f"  context.protocol_state = ({protocol_type})spx_initial_protocol_state;"
    )
    for field in interface.state:
        c_type = _logical_c_type(type_index[field.type_id])
        lines.extend(
            [
                f"  {c_type} spx_initial_state_{field.identity} = "
                f"{nondeterministic_functions[c_type]}();",
                f"  context.state.{field.identity} = "
                f"spx_initial_state_{field.identity};",
            ]
        )
    lines.extend(declarations)
    lines.extend(
        f"  spx_oracle.byte_views[{index}] = &spx_bytes_{parameter.identity}_view;"
        for index, parameter in enumerate(byte_parameters)
    )
    if operation.results:
        lines.append(f"  {result_type} observed = {operation_symbol}({arguments});")
    else:
        lines.append(f"  {operation_symbol}({arguments});")
    clauses: list[str] = []
    for path in paths:
        trace = _rows(path.get("trace"), "semantic path trace")
        guards = path.get("guards")
        if not isinstance(guards, list) or any(
            not isinstance(guard, Mapping) for guard in guards
        ):
            raise _UnsupportedRefinement("semantic path guards are malformed")
        conditions = ["spx_oracle.overflow == UINT32_C(0)"]
        conditions.extend(
            f"({_render_expression(guard, byte_tokens=byte_tokens)})"
            for guard in guards
        )
        conditions.append(f"spx_oracle.count == UINT32_C({len(trace)})")
        path_results = _object(path.get("results"), "semantic path results")
        if set(path_results) != {result.identity for result in operation.results}:
            raise _UnsupportedRefinement("semantic path result inventory differs")
        for result in operation.results:
            observed = (
                "observed"
                if len(operation.results) == 1
                else f"observed.{result.identity}"
            )
            c_type = _logical_c_type(type_index[result.type_id])
            conditions.append(
                f"{observed} == ({c_type})"
                f"({_render_expression(path_results[result.identity], byte_tokens=byte_tokens)})"
            )
        path_state = _object(path.get("state"), "semantic path state")
        if set(path_state) != {field.identity for field in interface.state}:
            raise _UnsupportedRefinement("semantic path state inventory differs")
        conditions.extend(
            f"context.state.{field.identity} == "
            f"({_logical_c_type(type_index[field.type_id])})"
            f"({_render_expression(path_state[field.identity], byte_tokens=byte_tokens)})"
            for field in interface.state
        )
        post_states = [
            f"context.protocol_state == SPX_{interface.identity.upper()}_PROTOCOL_{state.upper()}"
            for state in operation.post_states
        ]
        conditions.append("(" + " || ".join(post_states) + ")")
        for event_index, event in enumerate(trace):
            service_id = _text(event.get("service_id"), "semantic trace service id")
            if service_id not in service_numbers:
                raise _UnsupportedRefinement(
                    "semantic trace references an unknown service"
                )
            event_arguments = event.get("arguments")
            if not isinstance(event_arguments, list) or any(
                not isinstance(expression, Mapping) for expression in event_arguments
            ):
                raise _UnsupportedRefinement("semantic trace arguments are malformed")
            conditions.extend(
                [
                    f"spx_oracle.ids[{event_index}] == UINT32_C({service_numbers[service_id]})",
                    f"spx_oracle.argument_counts[{event_index}] == UINT32_C({len(event_arguments)})",
                ]
            )
            conditions.extend(
                f"spx_oracle.arguments[{event_index}][{argument_index}] == "
                f"(uint64_t)({_render_expression(expression, byte_tokens=byte_tokens)})"
                for argument_index, expression in enumerate(event_arguments)
            )
        clauses.append("(" + " && ".join(f"({item})" for item in conditions) + ")")
    assertion = " ||\n      ".join(clauses)
    lines.extend(
        [
            f'  __CPROVER_assert(({assertion}), "spx-refinement:{operation_id}:results-state-trace");',
            "}",
            "",
        ]
    )
    return "\n".join(lines)


def _logical_c_type(logical_type: LogicalTypeV1) -> str:
    if logical_type.kind in {"scalar", "enum"} and logical_type.c_type is not None:
        return logical_type.c_type
    if logical_type.kind == "resource":
        return "spx_resource_v2"
    if logical_type.kind == "bytes":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_bytes_view_v2 *"
    raise _UnsupportedRefinement(
        f"logical type {logical_type.identity!r} cannot be represented in the scalar path checker"
    )


def _string_rows(value: object, context: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        raise _UnsupportedRefinement(f"{context} must be an array of strings")
    return tuple(value)


def _load(value: Path | str | Mapping[str, object], context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        result = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentRefinementError(f"cannot read {context}: {exc}") from exc
    return dict(_object(result, context))


def _object(value: object, context: str) -> Mapping[str, object]:
    if not isinstance(value, Mapping):
        raise ComponentRefinementError(f"{context} must be an object")
    return value


def _rows(value: object, context: str) -> list[Mapping[str, object]]:
    if not isinstance(value, list) or any(not isinstance(row, Mapping) for row in value):
        raise ComponentRefinementError(f"{context} must be an array of objects")
    return list(value)


def _text(value: object, context: str) -> str:
    if not isinstance(value, str) or not value:
        raise ComponentRefinementError(f"{context} must be a nonempty string")
    return value


__all__ = ["ComponentRefinementError", "check_component_refinement"]
