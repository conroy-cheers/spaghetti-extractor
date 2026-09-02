"""CBMC-backed static refinement for restricted portable C components."""

from __future__ import annotations

import json
import hashlib
import tempfile
from pathlib import Path
from typing import Mapping

from ..artifacts.artifact_set import canonical_sha256_v3
from .cbmc_backend import CbmcBackendError, cbmc_version, run_cbmc_properties
from .atomics import ATOMIC_OBJECT_RESOURCE_KIND, spx_atomics_header
from .capabilities import spx_reference_runtime_header, spx_reference_runtime_source
from .interface_ir import ProofKernelLogicalType, ProofKernelComponentInterface
from .semantic_contract import ProofKernelSemanticContract
from .semantic_paths import (
    SemanticPathError,
    SemanticPathViolation,
    build_operation_path_model,
)
from .source import component_operation_symbols, load_component_source_package
from .refinement_harness import (
    _UnsupportedRefinement,
    _logical_c_type,
    _object,
    _render_atomic_refinement_oracle,
    _render_callback_refinement_types,
    _render_checked_reference_support,
    _render_service_path_harness,
    _rows,
    _string_rows,
    _text,
)


class ComponentRefinementError(ValueError):
    """A refinement input or checker invocation is invalid."""


def check_component_refinement(
    *,
    semantic_contract: Path | str | Mapping[str, object],
    interface: Path | str | Mapping[str, object],
    source_package: Path | str,
    source_profile: Path | str | Mapping[str, object],
    cbmc: Path | str,
    boundary_operations: Mapping[str, object] | None = None,
    c_headers: Mapping[str, str] | None = None,
    timeout_seconds: int = 300,
) -> dict[str, object]:
    """Check every operation for all modeled inputs without runtime examples."""

    contract = ProofKernelSemanticContract.parse(
        _load(semantic_contract, "component semantic contract")
    )
    portable = ProofKernelComponentInterface.parse(
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
        checked_boundary_operations = dict(boundary_operations or {})
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
                        if operation_id not in checked_boundary_operations
                        else _boundary_operation_payload(
                            checked_boundary_operations[operation_id]
                        )
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
                    c_headers=c_headers,
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
        "status": status,
        "activation_authorized": status == "satisfied",
        "component_id": component_id,
        "bindings": {
            "semantic_contract_sha256": contract.contract_sha256,
            "interface_sha256": portable.sha256,
            "implementation_sha256": source["implementation_sha256"],
            "source_profile_sha256": profile.get("receipt_sha256"),
            "boundary_operations_sha256": canonical_sha256_v3(
                {
                    operation_id: _boundary_operation_payload(value)
                    for operation_id, value in sorted(
                        (boundary_operations or {}).items()
                    )
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


def _boundary_operation_payload(value: object) -> Mapping[str, object]:
    if isinstance(value, Mapping):
        return dict(value)
    to_payload = getattr(value, "to_payload", None)
    if not callable(to_payload):
        raise ComponentRefinementError(
            "checked boundary operation must be a mapping or model"
        )
    payload = to_payload()
    if not isinstance(payload, Mapping):
        raise ComponentRefinementError(
            "checked boundary operation model emitted a malformed payload"
        )
    return dict(payload)


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
    source: Mapping[str, object], interface: ProofKernelComponentInterface,
    operation_id: str, operation_symbol: str, model: Mapping[str, object],
    c_headers: Mapping[str, str] | None,
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
        (root / "stddef.h").write_text(
            "#ifndef SPX_CBMC_STDDEF_H\n"
            "#define SPX_CBMC_STDDEF_H\n"
            "typedef unsigned int size_t; typedef signed int ptrdiff_t;\n"
            "#define NULL ((void *)0)\n"
            "#endif\n",
            encoding="ascii",
        )
        public_header = (
            interface.render_public_header()
            if c_headers is None
            else c_headers.get("portable-component.h")
        )
        implementation_header = (
            interface.render_implementation_header(
                component_operation_symbols(source)
            )
            if c_headers is None
            else c_headers.get("portable-component-implementation.h")
        )
        if not isinstance(public_header, str) or not isinstance(
            implementation_header, str
        ):
            raise ComponentRefinementError(
                "exact component C ABI headers are incomplete"
            )
        (root / "portable-component.h").write_text(
            public_header, encoding="ascii"
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
        (root / "portable-component-implementation.h").write_text(
            implementation_header, encoding="ascii"
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
                            "    .context = 0, .read_u8 = 0, .write_u8 = 0,",
                            f"    .base = {origin}, .extent = (uint64_t){extent},",
                            "    .element_width = UINT32_C(1),",
                            f"    .access_context = &{context},",
                            "    .read = spx_refinement_reference_read, .write = 0",
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
                        f"  spx_callback_{logical_type.identity}_v2 "
                        f"spx_callback_{parameter.identity}_object = "
                        f"{{UINT32_C({callback_parameter_words[parameter.identity]}), "
                        "UINT32_C(0)};",
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
                    f"  spx_bytes_view_v2 spx_bytes_{parameter.identity}_view = {{"
                    f".context = &spx_bytes_{parameter.identity}_context, "
                    f".extent = {extent_id}, "
                    f".read_u8 = spx_refinement_read_u8_{parameter.identity}, "
                    ".write_u8 = 0};",
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
























def _load(value: Path | str | Mapping[str, object], context: str) -> dict[str, object]:
    if isinstance(value, Mapping):
        return json.loads(json.dumps(value))
    try:
        result = json.loads(Path(value).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ComponentRefinementError(f"cannot read {context}: {exc}") from exc
    return dict(_object(result, context))








__all__ = ["ComponentRefinementError", "check_component_refinement"]
