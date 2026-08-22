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
from .atomics import ATOMIC_OBJECT_RESOURCE_KIND, spx_atomics_header
from .boundary_plan import ComponentBoundaryPlanReceiptV2, ComponentBoundaryPlanV2
from .capabilities import spx_reference_runtime_header, spx_reference_runtime_source
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
    boundary_plan: Path | str | Mapping[str, object] | None = None,
    boundary_plan_receipt: Path | str | Mapping[str, object] | None = None,
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
    plan = None
    plan_receipt = None
    if (boundary_plan is None) != (boundary_plan_receipt is None):
        raise ComponentRefinementError(
            "boundary plan and its receipt must be supplied together"
        )
    if boundary_plan is not None and boundary_plan_receipt is not None:
        plan = ComponentBoundaryPlanV2.parse(
            _load(boundary_plan, "component boundary plan")
        )
        plan_receipt = ComponentBoundaryPlanReceiptV2.parse(
            _load(boundary_plan_receipt, "component boundary plan receipt")
        )
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
    if plan is not None and plan_receipt is not None:
        if (
            plan.component_id != component_id
            or plan.bindings.get("interface_sha256") != portable.sha256
            or plan.bindings.get("semantic_contract_sha256")
            != contract.contract_sha256
            or plan_receipt.component_id != component_id
            or plan_receipt.plan_sha256 != plan.plan_sha256
            or not plan_receipt.authorizing
        ):
            issue("violated", "boundary_plan_binding_stale_or_unauthorized")

    try:
        version = cbmc_version(cbmc_path)
    except CbmcBackendError as exc:
        raise ComponentRefinementError(str(exc)) from exc
    checker_sha256 = hashlib.sha256(cbmc_path.read_bytes()).hexdigest()
    if not issues:
        operation_symbols = component_operation_symbols(source)
        operation_index = portable.operation_index()
        boundary_operations = (
            {} if plan is None else {row.operation_id: row for row in plan.operations}
        )
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
                    boundary_operation=(
                        None
                        if operation_id not in boundary_operations
                        else boundary_operations[operation_id].to_payload()
                    ),
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
            **(
                {}
                if plan is None or plan_receipt is None
                else {
                    "boundary_plan_sha256": plan.plan_sha256,
                    "boundary_plan_receipt_sha256": plan_receipt.receipt_sha256,
                }
            ),
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
        "entry_precondition_count": len(
            _rows(model.get("entry_preconditions", []), "entry preconditions")
        ),
        "max_service_events": int(model.get("max_events", 0)),
        "atomic_actions": len(_rows(model.get("atomic_actions", []), "atomic actions")),
        "callback_parameters": len(
            _rows(model.get("callback_parameters", []), "callback parameters")
        ),
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
        and types[parameter.type_id].resource_kind != ATOMIC_OBJECT_RESOURCE_KIND
    }
    nondeterministic_types = sorted({
        "uint32_t",
        "uint64_t",
        *scalar_nondeterministic_types,
        *(
            _logical_c_type(types[service.result_type_id])
            for service in interface.services
            if service.result_type_id is not None
            and types[service.result_type_id].kind
            not in {"callback", "reference", "view"}
        ),
        *(
            _logical_c_type(types[field.type_id])
            for field in interface.state
            if types[field.type_id].kind not in {"reference", "view"}
        ),
    })
    nondeterministic_functions = {
        c_type: f"spx_nondet_value_{index}"
        for index, c_type in enumerate(nondeterministic_types)
    }
    atomic_models = _rows(model.get("atomic_actions", []), "atomic actions")
    atomic_tokens = {
        _text(row.get("parameter_id"), "atomic parameter id"): index + 1
        for index, row in enumerate(atomic_models)
    }
    callback_parameter_words = {
        _text(row.get("parameter_id"), "callback parameter id"): int(
            row.get("machine_word")
        )
        for row in _rows(
            model.get("callback_parameters", []), "callback parameters"
        )
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
            "#define INT32_C(x) x\n#define INT64_C(x) x##LL\n"
            "#define UINT32_MAX UINT32_C(4294967295)\n"
            "#define UINT64_MAX UINT64_C(18446744073709551615)\n"
            "#define INT64_MAX INT64_C(9223372036854775807)\n"
            "#endif\n",
            encoding="ascii",
        )
        (root / "portable-component.h").write_text(
            interface.render_public_header(), encoding="ascii"
        )
        (root / "spx-atomics.h").write_text(
            spx_atomics_header(), encoding="ascii"
        )
        (root / "spx-reference-runtime.h").write_text(
            spx_reference_runtime_header(), encoding="ascii"
        )
        reference_runtime_tu = root / "spx-reference-runtime.c"
        reference_runtime_tu.write_text(
            spx_reference_runtime_source(), encoding="ascii"
        )
        translation_units.append(reference_runtime_tu)
        symbols = component_operation_symbols(source)
        (root / "portable-component-implementation.h").write_text(
            interface.render_implementation_header(symbols), encoding="ascii"
        )
        argument_by_id: dict[str, str] = {}
        declarations = []
        reference_parameters = [
            parameter
            for parameter in operation.parameters
            if types[parameter.type_id].kind in {"reference", "view"}
        ]
        parameter_machine_words = _object(
            model.get("parameter_machine_words"), "parameter machine words"
        )
        if set(parameter_machine_words) != {
            parameter.identity for parameter in operation.parameters
        }:
            raise _UnsupportedRefinement("parameter machine-word inventory differs")
        for parameter in operation.parameters:
            logical_type = types[parameter.type_id]
            if logical_type.kind == "bytes":
                continue
            if logical_type.kind in {"reference", "view"}:
                machine_word = _object(
                    parameter_machine_words[parameter.identity],
                    f"{parameter.identity} machine word",
                )
                if machine_word.get("op") == "const":
                    machine_initializer = (
                        f"UINT32_C({int(machine_word.get('value', 0)) & 0xFFFFFFFF})"
                    )
                elif (
                    machine_word.get("op") == "parameter"
                    and machine_word.get("name") == parameter.identity
                ):
                    machine_initializer = f"{nondeterministic_functions['uint32_t']}()"
                else:
                    raise _UnsupportedRefinement(
                        f"{parameter.identity} has a non-canonical machine word"
                    )
                context = f"spx_reference_context_{parameter.identity}"
                extent = f"spx_reference_extent_{parameter.identity}"
                machine = f"spx_machine_word_{parameter.identity}"
                origin = f"spx_reference_origin_{parameter.identity}"
                declarations.extend(
                    [
                        f"  uint32_t {machine} = {machine_initializer};",
                        f"  uint32_t {extent} = {nondeterministic_functions['uint32_t']}();",
                        f"  __CPROVER_assume({extent} != UINT32_C(0));",
                        f"  __CPROVER_assume({machine} <= UINT32_MAX - {extent});",
                        f"  spx_ref_v1 {origin} = {{",
                        f"    UINT64_C({len(argument_by_id) + 1}), UINT64_C({len(argument_by_id) + 1}),",
                        f"    UINT64_C(1), UINT64_C(0), (uint64_t){extent}, UINT32_C(1)",
                        "  };",
                        f"  spx_reference_context_{parameter.identity}.machine_base = {machine};",
                        f"  spx_reference_context_{parameter.identity}.origin = {origin};",
                    ]
                )
                if logical_type.kind == "view" and logical_type.nul_terminated:
                    declarations.append(
                        "  __CPROVER_assume(spx_refinement_machine_load("
                        f"{machine} + {extent} - UINT32_C(1), UINT32_C(1)) "
                        "== UINT64_C(0));"
                    )
                if logical_type.kind == "view":
                    declarations.extend(
                        [
                            f"  spx_view_v1 {parameter.identity}_object = {{",
                            f"    {origin}, (uint64_t){extent}, UINT32_C(1),",
                            f"    &{context}, spx_refinement_reference_read, 0",
                            "  };",
                            f"  const spx_view_v1 *{parameter.identity} = &{parameter.identity}_object;",
                        ]
                    )
                else:
                    declarations.append(
                        f"  spx_ref_v1 {parameter.identity} = {origin};"
                    )
                argument_by_id[parameter.identity] = parameter.identity
                continue
            if logical_type.kind == "callback":
                if parameter.identity not in callback_parameter_words:
                    raise _UnsupportedRefinement(
                        f"callback parameter {parameter.identity!r} has no machine word"
                    )
                c_type = _logical_c_type(logical_type)
                declarations.extend(
                    [
                        f"  struct spx_callback_{logical_type.identity}_v2 "
                        f"spx_callback_{parameter.identity}_object = "
                        f"{{UINT32_C({callback_parameter_words[parameter.identity]})}};",
                        f"  {c_type} {parameter.identity} = "
                        f"&spx_callback_{parameter.identity}_object;",
                    ]
                )
                argument_by_id[parameter.identity] = parameter.identity
                continue
            if (
                logical_type.kind == "resource"
                and logical_type.resource_kind == ATOMIC_OBJECT_RESOURCE_KIND
            ):
                declarations.extend(
                    [
                        f"  spx_atomic_object spx_atomic_{parameter.identity}_object = "
                        f"{{UINT32_C({atomic_tokens[parameter.identity]})}};",
                        f"  spx_atomic_object *{parameter.identity} = "
                        f"&spx_atomic_{parameter.identity}_object;",
                    ]
                )
                argument_by_id[parameter.identity] = parameter.identity
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
        if reference_parameters:
            common.extend(
                _render_checked_reference_support(
                    [parameter.identity for parameter in reference_parameters]
                )
            )
        common.extend(_render_callback_refinement_types(interface))
        common.extend(
            _render_atomic_refinement_oracle(
                atomic_models,
                nondeterministic_u32=nondeterministic_functions["uint32_t"],
            )
        )
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
    value: object,
    *,
    byte_tokens: Mapping[str, int] | None = None,
    machine_words: Mapping[str, str] | None = None,
    state_machine_words: Mapping[str, str] | None = None,
) -> str:
    row = _object(value, "normalized expression")
    op = row.get("op")
    if op == "parameter":
        name = _text(row.get("name"), "parameter expression")
        return name if machine_words is None else machine_words.get(name, name)
    if op == "atomic_observed":
        return "spx_atomic_observed_" + _text(
            row.get("name"), "atomic observation"
        )
    if op == "state_input":
        name = _text(row.get("name"), "state-input expression")
        default = "spx_initial_state_" + name
        return (
            default
            if state_machine_words is None
            else state_machine_words.get(name, default)
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
            f"(uint32_t)({_render_expression(index, byte_tokens=byte_tokens, machine_words=machine_words, state_machine_words=state_machine_words)}))"
        )
    if op == "load":
        address = row.get("address")
        width = row.get("width")
        if not isinstance(address, Mapping) or width not in {1, 2, 4, 8}:
            raise _UnsupportedRefinement("logical memory load is malformed")
        return (
            "spx_refinement_machine_load((uint32_t)("
            + _render_expression(
                address,
                byte_tokens=byte_tokens,
                machine_words=machine_words,
                state_machine_words=state_machine_words,
            )
            + f"), UINT32_C({width}))"
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
        _render_expression(
            item,
            byte_tokens=byte_tokens,
            machine_words=machine_words,
            state_machine_words=state_machine_words,
        )
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
    if op == "and_bool" and len(rendered) == 2:
        return f"(({rendered[0]}) && ({rendered[1]}))"
    if op == "or_bool" and len(rendered) == 2:
        return f"(({rendered[0]}) || ({rendered[1]}))"
    if op == "xor_bool" and len(rendered) == 2:
        return f"((!!({rendered[0]})) != (!!({rendered[1]})))"
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


def _render_atomic_refinement_oracle(
    actions: list[Mapping[str, object]], *, nondeterministic_u32: str
) -> list[str]:
    if not actions:
        return []
    lines = ["struct spx_atomic_object { uint32_t token; };", ""]
    for action in actions:
        name = _text(action.get("parameter_id"), "atomic parameter id")
        lines.extend(
            [
                f"static uint32_t spx_atomic_called_{name};",
                f"static uint32_t spx_atomic_expected_{name};",
                f"static uint32_t spx_atomic_desired_{name};",
                f"static uint32_t spx_atomic_observed_{name};",
            ]
        )
    lines.extend(
        [
            "spx_atomic_status spx_atomic_compare_exchange(",
            "    spx_atomic_object *object, uint32_t expected, uint32_t desired,",
            "    spx_atomic_observation *observation) {",
            "  if (object == 0 || observation == 0) return SPX_ATOMIC_UNSUPPORTED;",
        ]
    )
    for index, action in enumerate(actions):
        name = _text(action.get("parameter_id"), "atomic parameter id")
        keyword = "if" if index == 0 else "else if"
        lines.extend(
            [
                f"  {keyword} (object->token == UINT32_C({index + 1})) {{",
                f"    spx_atomic_called_{name}++;",
                f"    spx_atomic_expected_{name} = expected;",
                f"    spx_atomic_desired_{name} = desired;",
                f"    spx_atomic_observed_{name} = {nondeterministic_u32}();",
                f"    observation->observed = spx_atomic_observed_{name};",
                "    observation->exchanged = observation->observed == expected;",
                "    observation->written = observation->exchanged ? desired : observation->observed;",
                "    return SPX_ATOMIC_OK;",
                "  }",
            ]
        )
    lines.extend(["  return SPX_ATOMIC_UNSUPPORTED;", "}", ""])
    lines.extend(
        [
            "spx_atomic_status spx_atomic_exchange(",
            "    spx_atomic_object *object, uint32_t desired,",
            "    spx_atomic_observation *observation) {",
            "  if (object == 0 || observation == 0) return SPX_ATOMIC_UNSUPPORTED;",
        ]
    )
    for index, action in enumerate(actions):
        name = _text(action.get("parameter_id"), "atomic parameter id")
        keyword = "if" if index == 0 else "else if"
        lines.extend(
            [
                f"  {keyword} (object->token == UINT32_C({index + 1})) {{",
                f"    spx_atomic_called_{name}++;",
                f"    spx_atomic_desired_{name} = desired;",
                f"    spx_atomic_observed_{name} = {nondeterministic_u32}();",
                f"    observation->observed = spx_atomic_observed_{name};",
                "    observation->exchanged = UINT32_C(1);",
                "    observation->written = desired;",
                "    return SPX_ATOMIC_OK;",
                "  }",
            ]
        )
    lines.extend(["  return SPX_ATOMIC_UNSUPPORTED;", "}", ""])
    return lines


def _render_callback_refinement_types(
    interface: PortableComponentInterfaceV2,
) -> list[str]:
    lines: list[str] = []
    for logical_type in interface.types:
        if logical_type.kind != "callback":
            continue
        identity = logical_type.identity
        lines.extend(
            [
                f"struct spx_callback_{identity}_v2 {{ uint32_t word; }};",
                f"static uint32_t spx_refinement_callback_{identity}_word(",
                f"    const spx_callback_{identity}_v2 *handle) {{",
                "  return handle == 0 ? UINT32_C(0) : handle->word;",
                "}",
            ]
        )
    if lines:
        lines.append("")
    return lines


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
    reference_constraints: dict[int, dict[str, object]] = {}
    trace_services: dict[int, set[str]] = {}
    for path in paths:
        for trace_index, event in enumerate(
            _rows(path.get("trace"), "semantic path trace")
        ):
            trace_services.setdefault(trace_index, set()).add(
                _text(event.get("service_id"), "semantic trace service id")
            )
        for row in _rows(
            path.get("reference_origins", []), "path reference origins"
        ):
            trace_index = int(row["trace_index"])
            constraint = {
                key: value for key, value in row.items() if key != "trace_index"
            }
            previous = reference_constraints.get(trace_index)
            if previous is not None and previous != constraint:
                raise _UnsupportedRefinement(
                    "interaction reference constraint differs between machine paths"
                )
            reference_constraints[trace_index] = constraint
    byte_parameters = [
        parameter
        for parameter in operation.parameters
        if type_index[parameter.type_id].kind == "bytes"
    ]
    byte_tokens = {
        parameter.identity: index + 1
        for index, parameter in enumerate(byte_parameters)
    }
    machine_words = {
        parameter.identity: (
            f"spx_machine_word_{parameter.identity}"
            if type_index[parameter.type_id].kind in {"reference", "view"}
            else parameter.identity
        )
        for parameter in operation.parameters
    }
    state_machine_words = {
        field.identity: (
            f"spx_refinement_reference_word(spx_initial_state_{field.identity})"
            if type_index[field.type_id].kind == "reference"
            else f"spx_initial_state_{field.identity}"
        )
        for field in interface.state
    }

    def render_expression(value: object) -> str:
        return _render_expression(
            value,
            byte_tokens=byte_tokens,
            machine_words=machine_words,
            state_machine_words=state_machine_words,
        )
    atomic_actions = _rows(model.get("atomic_actions", []), "atomic actions")
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
        if service.result_type_id is None:
            continue
        logical_result = type_index[service.result_type_id]
        if logical_result.kind == "callback":
            lines.append(
                f"static spx_callback_{logical_result.identity}_v2 "
                f"spx_refinement_{service.identity}_results[{max_events}];"
            )
    if any(
        service.result_type_id is not None
        and type_index[service.result_type_id].kind == "callback"
        for service in services
    ):
        lines.append("")
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
            elif type_index[type_id].kind == "callback":
                identity = type_index[type_id].identity
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"(uint64_t)spx_refinement_callback_{identity}_word(argument_{position});"
                )
            elif type_index[type_id].kind == "view":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"spx_refinement_reference_word(argument_{position}->base);"
                )
            elif type_index[type_id].kind == "reference":
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"spx_refinement_reference_word(argument_{position});"
                )
            else:
                lines.append(
                    f"  oracle->arguments[index][{position}] = "
                    f"(uint64_t)argument_{position};"
                )
        if result != "void":
            logical_result_type = type_index[service.result_type_id]
            if logical_result_type.kind == "reference":
                origin_cases = []
                for trace_index, constraint in sorted(reference_constraints.items()):
                    argument_index = int(constraint["input_argument_index"])
                    services_at_index = trace_services.get(trace_index, set())
                    if len(services_at_index) > 1:
                        raise _UnsupportedRefinement(
                            "interaction reference origin has an ambiguous service position"
                        )
                    if services_at_index != {service.identity}:
                        continue
                    if argument_index >= len(service.parameter_type_ids):
                        raise _UnsupportedRefinement(
                            "interaction origin references an unknown service argument"
                        )
                    origin_type = type_index[service.parameter_type_ids[argument_index]]
                    if origin_type.kind == "view":
                        origin_expression = f"argument_{argument_index}->base"
                    elif origin_type.kind == "reference":
                        origin_expression = f"argument_{argument_index}"
                    else:
                        raise _UnsupportedRefinement(
                            "interaction reference output is not tied to a reference or view input"
                        )
                    minimum_remaining = constraint.get("nonnull_min_remaining")
                    nonzero_argument_index = None
                    minimum = None
                    if minimum_remaining is not None:
                        remaining = _object(
                            minimum_remaining,
                            "interaction non-null remaining constraint",
                        )
                        nonzero_argument_index = int(
                            remaining["nonzero_argument_index"]
                        )
                        minimum = int(remaining["minimum"])
                        if (
                            nonzero_argument_index < 0
                            or nonzero_argument_index
                            >= len(service.parameter_type_ids)
                            or type_index[
                                service.parameter_type_ids[nonzero_argument_index]
                            ].kind
                            not in {"scalar", "enum"}
                            or minimum <= 0
                        ):
                            raise _UnsupportedRefinement(
                                "interaction remaining constraint is not scalar-guarded"
                            )
                    origin_cases.extend(
                        _render_reference_service_result_case(
                            trace_index=trace_index,
                            origin_expression=origin_expression,
                            nullable=bool(logical_result_type.nullable),
                            allow_one_past=bool(logical_result_type.allow_one_past),
                            nonzero_argument_index=nonzero_argument_index,
                            minimum_remaining=minimum,
                            nondeterministic_u32=nondeterministic_functions["uint32_t"],
                        )
                    )
                if not origin_cases:
                    raise _UnsupportedRefinement(
                        f"reference service {service.identity!r} has no checked origin contract"
                    )
                lines.extend(
                    [
                        *origin_cases,
                        "  oracle->overflow = UINT32_C(1);",
                        "  return (spx_ref_v1){0};",
                    ]
                )
            elif logical_result_type.kind == "callback":
                identity = logical_result_type.identity
                nullable = logical_result_type.nullable
                lines.extend(
                    [
                        "  uint32_t logical_word = "
                        f"{nondeterministic_functions['uint32_t']}();",
                        "  oracle->results[index] = (uint64_t)logical_word;",
                        *(
                            [
                                "  if (logical_word == UINT32_C(0)) return 0;"
                            ]
                            if nullable
                            else [
                                "  __CPROVER_assume(logical_word != UINT32_C(0));"
                            ]
                        ),
                        f"  spx_refinement_{service.identity}_results[index].word = logical_word;",
                        f"  return &spx_refinement_{service.identity}_results[index];",
                    ]
                )
            else:
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
    lines.extend(declarations)
    for field in interface.state:
        c_type = _logical_c_type(type_index[field.type_id])
        if type_index[field.type_id].kind == "reference":
            lines.extend(
                _render_reference_state_initialization(
                    field_id=field.identity,
                    parameter_ids=[
                        parameter.identity
                        for parameter in operation.parameters
                        if type_index[parameter.type_id].kind in {"reference", "view"}
                    ],
                    nullable=bool(type_index[field.type_id].nullable),
                    allow_one_past=bool(type_index[field.type_id].allow_one_past),
                    nondeterministic_u32=nondeterministic_functions["uint32_t"],
                )
            )
            lines.append(
                f"  context.state.{field.identity} = spx_initial_state_{field.identity};"
            )
        else:
            lines.extend(
                [
                    f"  {c_type} spx_initial_state_{field.identity} = "
                    f"{nondeterministic_functions[c_type]}();",
                    f"  context.state.{field.identity} = "
                    f"spx_initial_state_{field.identity};",
                ]
            )
    entry_preconditions = _rows(
        model.get("entry_preconditions", []), "entry preconditions"
    )
    if entry_preconditions:
        rendered_preconditions = [
            render_expression(item)
            for item in entry_preconditions
        ]
        lines.append(
            "  __CPROVER_assume("
            + " || ".join(f"({item})" for item in rendered_preconditions)
            + ");"
        )
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
        for action in atomic_actions:
            name = _text(action.get("parameter_id"), "atomic parameter id")
            conditions.extend([
                f"spx_atomic_called_{name} == UINT32_C(1)",
                f"spx_atomic_desired_{name} == "
                f"(uint32_t)({render_expression(action.get('desired'))})",
            ])
            if action.get("operation") == "compare_exchange":
                conditions.append(
                    f"spx_atomic_expected_{name} == "
                    f"(uint32_t)({render_expression(action.get('expected'))})"
                )
        conditions.extend(
            f"({render_expression(guard)})"
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
            logical_result_type = type_index[result.type_id]
            expected = render_expression(path_results[result.identity])
            if logical_result_type.kind == "callback":
                conditions.append(
                    f"spx_refinement_callback_{logical_result_type.identity}_word({observed}) "
                    f"== (uint32_t)({expected})"
                )
            elif logical_result_type.kind == "reference":
                conditions.append(
                    f"spx_refinement_reference_word({observed}) == "
                    f"(uint64_t)({expected})"
                )
            else:
                conditions.append(
                    f"{observed} == ({c_type})({expected})"
                )
        path_state = _object(path.get("state"), "semantic path state")
        if set(path_state) != {field.identity for field in interface.state}:
            raise _UnsupportedRefinement("semantic path state inventory differs")
        for field in interface.state:
            expected_state = render_expression(path_state[field.identity])
            if type_index[field.type_id].kind == "reference":
                conditions.append(
                    f"spx_refinement_reference_word(context.state.{field.identity}) == "
                    f"(uint64_t)({expected_state})"
                )
            else:
                conditions.append(
                    f"context.state.{field.identity} == "
                    f"({_logical_c_type(type_index[field.type_id])})"
                    f"({expected_state})"
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
                f"(uint64_t)({render_expression(expression)})"
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
        if logical_type.resource_kind == ATOMIC_OBJECT_RESOURCE_KIND:
            return "spx_atomic_object *"
        return "spx_resource_v2"
    if logical_type.kind == "bytes":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_bytes_view_v2 *"
    if logical_type.kind == "callback":
        return f"spx_callback_{logical_type.identity}_v2 *"
    if logical_type.kind == "reference":
        return "spx_ref_v1"
    if logical_type.kind == "view":
        qualifier = "const " if logical_type.access == "read" else ""
        return f"{qualifier}spx_view_v1 *"
    raise _UnsupportedRefinement(
        f"logical type {logical_type.identity!r} cannot be represented in the scalar path checker"
    )


def _render_checked_reference_support(parameter_ids: list[str]) -> list[str]:
    contexts = [
        f"static spx_refinement_reference_context_v1 spx_reference_context_{name};"
        for name in parameter_ids
    ]
    origin_cases: list[str] = []
    for name in parameter_ids:
        context = f"spx_reference_context_{name}"
        origin_cases.extend(
            [
                f"  if (reference.domain == {context}.origin.domain &&",
                f"      reference.object == {context}.origin.object &&",
                f"      reference.generation == {context}.origin.generation &&",
                f"      reference.extent == {context}.origin.extent &&",
                f"      reference.offset >= {context}.origin.offset &&",
                f"      reference.offset - {context}.origin.offset <= UINT32_MAX &&",
                f"      {context}.machine_base <= UINT32_MAX -",
                f"          (uint32_t)(reference.offset - {context}.origin.offset))",
                f"    return (uint64_t)({context}.machine_base +",
                f"        (uint32_t)(reference.offset - {context}.origin.offset));",
            ]
        )
    return [
        "typedef struct { uint32_t machine_base; spx_ref_v1 origin; }",
        "    spx_refinement_reference_context_v1;",
        *contexts,
        "uint8_t __CPROVER_uninterpreted_spx_memory_u8(uint32_t address);",
        "static uint64_t spx_refinement_machine_load(uint32_t address, uint32_t width) {",
        "  uint64_t value = (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address);",
        "  if (width > UINT32_C(1)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(1)) << 8;",
        "  if (width > UINT32_C(2)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(2)) << 16;",
        "  if (width > UINT32_C(3)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(3)) << 24;",
        "  if (width > UINT32_C(4)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(4)) << 32;",
        "  if (width > UINT32_C(5)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(5)) << 40;",
        "  if (width > UINT32_C(6)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(6)) << 48;",
        "  if (width > UINT32_C(7)) value |= (uint64_t)__CPROVER_uninterpreted_spx_memory_u8(address + UINT32_C(7)) << 56;",
        "  return value;",
        "}",
        "static uint32_t spx_refinement_reference_is_null(spx_ref_v1 value) {",
        "  return value.domain == UINT64_C(0) && value.object == UINT64_C(0) &&",
        "      value.generation == UINT64_C(0) && value.offset == UINT64_C(0) &&",
        "      value.extent == UINT64_C(0) && value.permissions == UINT32_C(0);",
        "}",
        "static uint64_t spx_refinement_reference_word(spx_ref_v1 reference) {",
        "  if (spx_refinement_reference_is_null(reference)) return UINT64_C(0);",
        *origin_cases,
        "  return UINT64_MAX;",
        "}",
        "static uint32_t spx_refinement_reference_read(",
        "    void *opaque, spx_ref_v1 base, uint64_t offset,",
        "    uint32_t width, uint64_t *result) {",
        "  spx_refinement_reference_context_v1 *context =",
        "      (spx_refinement_reference_context_v1 *)opaque;",
        "  uint64_t machine_word;",
        "  if (context == 0 || result == 0 || width == UINT32_C(0) || width > UINT32_C(8) ||",
        "      base.domain != context->origin.domain || base.object != context->origin.object ||",
        "      base.generation != context->origin.generation || base.extent != context->origin.extent ||",
        "      base.offset < context->origin.offset || base.offset > base.extent ||",
        "      offset > base.extent - base.offset) return UINT32_C(1);",
        "  machine_word = spx_refinement_reference_word(base);",
        "  if (machine_word > UINT32_MAX || offset > UINT32_MAX ||",
        "      (uint32_t)machine_word > UINT32_MAX - (uint32_t)offset ||",
        "      width > UINT32_MAX - ((uint32_t)machine_word + (uint32_t)offset))",
        "    return UINT32_C(1);",
        "  *result = spx_refinement_machine_load(",
        "      (uint32_t)machine_word + (uint32_t)offset, width);",
        "  return UINT32_C(0);",
        "}",
    ]


def _render_reference_service_result_case(
    *,
    trace_index: int,
    origin_expression: str,
    nullable: bool,
    allow_one_past: bool,
    nonzero_argument_index: int | None,
    minimum_remaining: int | None,
    nondeterministic_u32: str,
) -> list[str]:
    lines = [
        f"  if (index == UINT32_C({trace_index})) {{",
        f"    spx_ref_v1 logical_origin = {origin_expression};",
    ]
    if nullable:
        lines.extend(
            [
                f"    if (({nondeterministic_u32}() & UINT32_C(1)) == UINT32_C(0)) {{",
                "      oracle->results[index] = UINT64_C(0);",
                "      return (spx_ref_v1){0};",
                "    }",
            ]
        )
    lines.extend(
        [
            f"    uint32_t logical_offset = {nondeterministic_u32}();",
            "    __CPROVER_assume(logical_origin.extent <= UINT32_MAX);",
            "    __CPROVER_assume((uint64_t)logical_offset >= logical_origin.offset);",
            (
                "    __CPROVER_assume((uint64_t)logical_offset <= logical_origin.extent);"
                if allow_one_past
                else "    __CPROVER_assume((uint64_t)logical_offset < logical_origin.extent);"
            ),
            *(
                []
                if nonzero_argument_index is None or minimum_remaining is None
                else [
                    f"    __CPROVER_assume(argument_{nonzero_argument_index} == 0 ||",
                    f"        (logical_origin.extent >= UINT64_C({minimum_remaining}) &&",
                    f"         (uint64_t)logical_offset <= logical_origin.extent - UINT64_C({minimum_remaining})));",
                ]
            ),
            "    spx_ref_v1 logical_result = logical_origin;",
            "    logical_result.offset = (uint64_t)logical_offset;",
            "    oracle->results[index] = spx_refinement_reference_word(logical_result);",
            "    return logical_result;",
            "  }",
        ]
    )
    return lines


def _render_reference_state_initialization(
    *,
    field_id: str,
    parameter_ids: list[str],
    nullable: bool,
    allow_one_past: bool,
    nondeterministic_u32: str,
) -> list[str]:
    name = f"spx_initial_state_{field_id}"
    lines = [f"  spx_ref_v1 {name} = {{0}};"]
    if not parameter_ids:
        if not nullable:
            raise _UnsupportedRefinement(
                f"reference state {field_id!r} has no checked origin"
            )
        return lines
    selector_limit = len(parameter_ids) + (1 if nullable else 0)
    lines.append(
        f"  uint32_t spx_initial_state_selector_{field_id} = "
        f"{nondeterministic_u32}() % UINT32_C({selector_limit});"
    )
    for index, parameter_id in enumerate(parameter_ids):
        selector = index + (1 if nullable else 0)
        prefix = "if" if index == 0 else "else if"
        lines.extend(
            [
                f"  {prefix} (spx_initial_state_selector_{field_id} == UINT32_C({selector})) {{",
                f"    uint32_t spx_initial_state_offset_{field_id} = {nondeterministic_u32}();",
                f"    {name} = spx_reference_context_{parameter_id}.origin;",
                f"    __CPROVER_assume((uint64_t)spx_initial_state_offset_{field_id} "
                f"{('<=' if allow_one_past else '<')} {name}.extent);",
                f"    {name}.offset = (uint64_t)spx_initial_state_offset_{field_id};",
                "  }",
            ]
        )
    return lines


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
