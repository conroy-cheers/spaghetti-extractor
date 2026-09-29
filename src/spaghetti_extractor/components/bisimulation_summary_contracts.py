"""Checked source obligations needed by scalar relational summaries.

These certificates are supplementary evidence. They cannot replace exact/source
bisimulation, dependency qualification, or the parent call precondition proof.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from ..artifacts.artifact_set import canonical_sha256_v3
from .cbmc_backend import run_cbmc_properties
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import CompiledComponentInterfaceV5
from .inductive_refinement import _write_cbmc_stdint
from .machine_overlay_services_v5 import _c_identifier
from .bisimulation_postconditions import (
    check_scalar_postconditions, validate_scalar_postconditions,
    validate_scalar_postcondition_bindings,
    scalar_postcondition_requests,
)


SCALAR_SUMMARY_STRATEGY = "scalar-result-empty-frame-context-independence-v1"
_CHECKER_OPTIONS = [
    "--json-ui", "--trace", "--bounds-check", "--pointer-check",
    "--signed-overflow-check", "--undefined-shift-check", "--div-by-zero-check",
    "--unwind", "2", "--unwinding-assertions", "--sat-solver", "cadical",
]


def _cyclic_calls(edges: Sequence[tuple[str, str]]) -> bool:
    successors: dict[str, set[str]] = {}
    for caller, callee in edges:
        successors.setdefault(caller, set()).add(callee)
    active: set[str] = set()
    done: set[str] = set()

    def visit(node: str) -> bool:
        if node in active:
            return True
        if node in done:
            return False
        active.add(node)
        if any(visit(child) for child in successors.get(node, ())):
            return True
        active.remove(node)
        done.add(node)
        return False

    return any(visit(node) for node in successors)


def scalar_summary_operations(
    bundle: CompiledComponentInterfaceV5,
) -> tuple[str, ...] | None:
    """Recognize a candidate shape; this does not establish a summary theorem."""
    interface = bundle.interface
    if interface.state or interface.services or interface.effects:
        return None
    if not interface.operations:
        return None
    if len(bundle.intent.protocol_states) != 1:
        return None
    types = bundle.intent.schema.type_index
    for operation in interface.operations:
        if (set(operation.pre_states) != {bundle.intent.initial_protocol_state}
                or set(operation.post_states) != {bundle.intent.initial_protocol_state}):
            return None
        signature = bundle.intent.schema.signature_index[operation.signature_id]
        if len(signature.results) > 1:
            return None
        for value in (*signature.parameters, *signature.results):
            kind = types[value.type_id].kind
            if (value.interpretation != "value" or value.access != "none"
                    or value.nullable or kind not in {"integer", "bool", "enum"}):
                return None
    return tuple(sorted(operation.identity for operation in interface.operations))


def memory_summary_operations(
    bundle: CompiledComponentInterfaceV5, *, mutable: bool = False,
) -> tuple[str, ...] | None:
    """Recognize a candidate memory contract shape, not a summary theorem.

    This shape deliberately grants no provider qualification. Source frame,
    input/output dependence and progress certificates need checked composition
    rules before a provider may omit bodies. A service that happens to compare
    memory is not service-free. Mutable mode requires at least one writer.
    """
    interface = bundle.interface
    if (interface.state or interface.services or interface.effects
            or not interface.operations or len(bundle.intent.protocol_states) != 1):
        return None
    types = bundle.intent.schema.type_index
    has_view = False
    has_writer = False
    for operation in interface.operations:
        if (set(operation.pre_states) != {bundle.intent.initial_protocol_state}
                or set(operation.post_states) != {bundle.intent.initial_protocol_state}):
            return None
        signature = bundle.intent.schema.signature_index[operation.signature_id]
        if mutable and not any(value.interpretation == "view" for value in signature.parameters):
            return None
        if len(signature.results) > 1:
            return None
        for value in signature.results:
            if (value.interpretation != "value" or value.access != "none"
                    or value.nullable or types[value.type_id].kind not in {"integer", "bool", "enum"}):
                return None
        for value in signature.parameters:
            if value.nullable:
                return None
            if value.interpretation == "view" and value.access in ({"read", "read_write"} if mutable else {"read"}):
                has_view = True
                has_writer |= value.access == "read_write"
            elif (value.interpretation != "value" or value.access != "none"
                    or types[value.type_id].kind not in {"integer", "bool", "enum"}):
                return None
    return tuple(sorted(operation.identity for operation in interface.operations)) if has_view and (not mutable or has_writer) else None


def readonly_summary_operations(bundle: CompiledComponentInterfaceV5) -> tuple[str, ...] | None:
    return memory_summary_operations(bundle)


def checked_scalar_summary_certificate(
    *, bound: Mapping[str, object] | None, bundle: CompiledComponentInterfaceV5,
    source: Mapping[str, object], source_profile_sha256: str,
    operation_symbols: Mapping[str, str], headers: Mapping[str, str],
) -> Mapping[str, object] | None:
    """Select a source certificate only after its enclosing provider is qualified."""
    if bound is None:
        return None
    certificate = bound.get("certificate")
    if not isinstance(certificate, Mapping):
        raise ValueError("connected source summary certificate is missing")
    validate_scalar_summary_contracts(certificate)
    if (bound.get("implementation_sha256") != source.get("implementation_sha256")
            or bound.get("source_profile_sha256") != source_profile_sha256
            or certificate["interface_sha256"] != bundle.interface.interface_sha256
            or certificate["operation_symbols"] != dict(operation_symbols)
            or certificate["headers_sha256"] != canonical_sha256_v3(dict(headers))):
        raise ValueError("connected source summary certificate binding is stale")
    source_rows = [row for row in source["files"] if str(row["path"]).endswith(".c")]
    if certificate["inputs"] != [{"path": f"source-{index:04d}.c", "sha256": row["sha256"]}
                                 for index, row in enumerate(source_rows)]:
        raise ValueError("connected source summary certificate source bytes are stale")
    if certificate["status"] != "satisfied":
        return None
    if scalar_summary_operations(bundle) is None:
        raise ValueError("connected scalar summary has an unsupported interface")
    validate_scalar_postcondition_bindings(certificate["postconditions"], bundle=bundle, symbols=operation_symbols)
    return certificate


def consumed_scalar_summary_contract(certificate: Mapping[str, object]) -> dict[str, object]:
    """Extract the checked source guarantees consumed by the scalar wrapper.

    Implementation, compiler and solver evidence identifies the supplier that
    established these guarantees; it is not part of their meaning. Keep the full
    interface and header identities, frame/context policy and exact predicates.
    Equal results are a source-summary compatibility premise, not permission to
    replace a supplier: current machine qualification, entry/adapter contracts,
    unchanged caller inputs and retained caller evidence still need checking.
    """
    validate_scalar_summary_contracts(certificate)
    if certificate["status"] != "satisfied":
        raise ValueError("consumed scalar contract requires satisfied source evidence")
    return {
        "strategy": certificate["strategy"],
        "interface_sha256": certificate["interface_sha256"],
        "headers_sha256": certificate["headers_sha256"],
        "operation_symbols": dict(certificate["operation_symbols"]),
        "postconditions": [{key: fact[key] for key in
                            ("operation_id", "id", "signature", "expression")}
                           for fact in certificate["postconditions"]],
    }


def _contract_source(
    bundle: CompiledComponentInterfaceV5, operation_id: str, symbol: str,
) -> tuple[str, str]:
    operation = next(item for item in bundle.interface.operations if item.identity == operation_id)
    signature = bundle.intent.schema.signature_index[operation.signature_id]
    types = bundle.intent.schema.type_index
    context = f"spx_{_c_identifier(bundle.interface.identity)}_context_v5"
    parameters = [f"{context} *context"] + [
        f"{_parameter_type(types, value)} {_c_identifier(value.identity)}"
        for value in signature.parameters
    ]
    arguments = ", ".join(_c_identifier(value.identity) for value in signature.parameters)
    result_type = _result_type(types, signature)
    declaration = (
        '#include "portable-component-implementation.h"\n'
        "void *malloc(__CPROVER_size_t);\n"
        f"{result_type} {symbol}({', '.join(parameters)})\n"
        "__CPROVER_requires(__CPROVER_is_fresh(context, sizeof(*context)))\n"
        "__CPROVER_assigns();\n"
    )
    pair_symbol = f"spx_summary_context_independence_{_c_identifier(operation_id)}"
    lines = [declaration, f"void {pair_symbol}(void) {{", f"  {context} left, right;"]
    lines.extend(
        f"  {_parameter_type(types, value)} {_c_identifier(value.identity)};"
        for value in signature.parameters
    )
    for side in ("left", "right"):
        call = f"{symbol}(&{side}{', ' if arguments else ''}{arguments})"
        lines.append(f"  {result_type} result_{side} = {call};" if result_type != "void"
                     else f"  {call};")
    condition = "result_left == result_right" if result_type != "void" else "1"
    lines.extend([
        f"  __CPROVER_assert({condition},",
        f'      "spx-summary-context-independence:{operation_id}");', "}",
    ])
    return "\n".join(lines) + "\n", pair_symbol


def check_scalar_summary_contracts(
    *, bundle: CompiledComponentInterfaceV5, operation_symbols: Mapping[str, str],
    source_files: Sequence[Path], headers: Mapping[str, str], output: Path,
    goto_cc: Path, goto_instrument: Path, cbmc: Path, timeout_seconds: int = 60,
    workspace: Path | None = None, postcondition_intent=None,
) -> dict[str, object]:
    """Prove an empty write frame and independence from fresh operation contexts.

    Every helper is compiled from the supplied source. Undefined reachable
    functions are rejected before instrumentation; no absent body becomes an
    assumed effect-free call. All unwinding assertions and language checks remain
    enabled. The certificate is intentionally not deployment authority.
    """
    operation_ids = scalar_summary_operations(bundle)
    requested = (None if postcondition_intent is None else
                 scalar_postcondition_requests(bundle, postcondition_intent))
    if operation_ids is None or set(operation_symbols) != set(operation_ids):
        return {"status": "incomplete", "authorizing": False,
                "code": "scalar_summary_contract_shape_unsupported"}
    if (not source_files or timeout_seconds <= 0
            or any(not name or Path(name).name != name or name in {"stdint.h", "stddef.h"} for name in headers)
            or any(_c_identifier(symbol) != symbol for symbol in operation_symbols.values())):
        raise ValueError("scalar summary contract inputs are malformed")
    artifact_output = output
    if workspace is not None:
        if (workspace.resolve().is_relative_to(output.resolve())
                or output.resolve().is_relative_to(workspace.resolve())):
            raise ValueError("scalar summary workspace and artifact output must be disjoint")
        workspace.mkdir(parents=True, exist_ok=False)
        output = workspace
    output.mkdir(parents=True, exist_ok=True)
    _write_cbmc_stdint(output / "stdint.h")
    (output / "stddef.h").write_text(
        "#ifndef SPX_SUMMARY_STDDEF_H\n#define SPX_SUMMARY_STDDEF_H\n"
        "typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n"
        "#define NULL ((void *)0)\n#endif\n", encoding="ascii",
    )
    for name, source in headers.items():
        (output / name).write_text(source, encoding="ascii")
    inputs = []
    for index, source in enumerate(source_files):
        target = output / f"source-{index:04d}.c"
        content = source.read_bytes()
        target.write_bytes(content)
        inputs.append({"path": target.name, "sha256": hashlib.sha256(content).hexdigest()})
    checks: list[dict[str, object]] = []
    models: list[dict[str, object]] = []
    commands: list[dict[str, object]] = []

    def run(command: list[str], name: str) -> subprocess.CompletedProcess[str] | None:
        try:
            result = subprocess.run(command, text=True, capture_output=True,
                                    timeout=timeout_seconds, check=False)
        except (OSError, subprocess.TimeoutExpired) as error:
            checks.append({"status": "incomplete", "code": "summary_contract_tool_failed",
                           "detail": str(error), "step": name})
            return None
        (output / f"{name}.stdout").write_text(result.stdout)
        (output / f"{name}.stderr").write_text(result.stderr)
        commands.append({"step": name, "command": command, "exit_code": result.returncode,
                         "output_sha256": hashlib.sha256((result.stdout + result.stderr).encode()).hexdigest()})
        if result.returncode:
            checks.append({"status": "incomplete", "code": "summary_contract_tool_failed",
                           "detail": result.stderr[-2000:], "step": name})
            return None
        return result

    for operation_id in operation_ids:
        symbol = operation_symbols[operation_id]
        generated, pair_symbol = _contract_source(bundle, operation_id, symbol)
        contract = output / f"contract-{_c_identifier(operation_id)}.c"
        contract.write_text(generated, encoding="ascii")
        for kind, entry in (("frame", symbol), ("context_independence", pair_symbol)):
            name = f"{_c_identifier(operation_id)}-{kind}"
            raw = output / f"{name}.goto"
            reachable = output / f"{name}-reachable.goto"
            compiled = run([str(goto_cc), "--i386-win32", "-I", str(output),
                            str(contract), *(str(output / row["path"]) for row in inputs),
                            "--function", entry, "-o", str(raw)], name + "-compile")
            if compiled is None:
                continue
            if run([str(goto_instrument), "--drop-unused-functions", str(raw), str(reachable)], name + "-reachable") is None:
                continue
            call_graph = run([str(goto_instrument), "--reachable-call-graph", str(reachable)], name + "-calls")
            loops = run([str(goto_instrument), "--show-loops", "--json-ui", str(reachable)], name + "-loops")
            if call_graph is None or loops is None:
                continue
            edges = [tuple(line.split(" -> ")) for line in call_graph.stdout.splitlines() if " -> " in line]
            nodes = {node for edge in edges for node in edge}
            try:
                loop_records = [row["loops"] for row in json.loads(loops.stdout) if "loops" in row]
                if len(loop_records) != 1 or not isinstance(loop_records[0], list):
                    raise ValueError("loop inventory is malformed")
            except (ValueError, TypeError, KeyError):
                checks.append({"operation_id": operation_id, "kind": kind, "status": "incomplete",
                               "code": "summary_contract_control_inventory_malformed"})
                continue
            if entry not in nodes or any(len(edge) != 2 for edge in edges):
                checks.append({"operation_id": operation_id, "kind": kind, "status": "incomplete",
                               "code": "summary_contract_control_inventory_malformed"})
                continue
            if loop_records[0] or _cyclic_calls(edges):
                checks.append({"operation_id": operation_id, "kind": kind, "status": "incomplete",
                               "code": "summary_contract_requires_acyclic_control"})
                continue
            undefined = run([str(goto_instrument), "--list-undefined-functions", str(reachable)], name + "-undefined")
            if undefined is None:
                continue
            unresolved = [line.strip() for line in undefined.stdout.splitlines()
                          if line.strip() in nodes
                          and not line.startswith("__CPROVER_") and line != f"contract::{symbol}"]
            if unresolved:
                checks.append({"operation_id": operation_id, "kind": kind, "status": "incomplete",
                               "code": "summary_contract_undefined_function", "functions": unresolved})
                continue
            checked = reachable
            if kind == "frame":
                checked = output / f"{name}-checked.goto"
                if run([str(goto_instrument), "--enforce-contract", symbol,
                        str(reachable), str(checked)], name + "-instrument") is None:
                    continue
            checker_command = [str(cbmc), str(checked), "--function", entry, *_CHECKER_OPTIONS]
            result = run_cbmc_properties(command=checker_command,
                timeout_seconds=timeout_seconds)
            commands.append({"step": name + "-check", "command": checker_command,
                             "output_sha256": result["output_sha256"]})
            checks.append({"operation_id": operation_id, "kind": kind, **result})
            models.append({"operation_id": operation_id, "kind": kind,
                           "contract_sha256": hashlib.sha256(generated.encode()).hexdigest(),
                           "goto_sha256": hashlib.sha256(checked.read_bytes()).hexdigest()})
    expected = {(operation_id, kind) for operation_id in operation_ids
                for kind in ("frame", "context_independence")}
    complete = (len(checks) == len(expected)
                and {(row.get("operation_id"), row.get("kind")) for row in checks} == expected
                and all(row["status"] == "satisfied" for row in checks))
    postconditions = check_scalar_postconditions(
        bundle=bundle, operation_symbols=operation_symbols, output=output, inputs=inputs,
        goto_cc=goto_cc, cbmc=cbmc, checker_options=_CHECKER_OPTIONS,
        timeout_seconds=timeout_seconds,
        candidates_by_operation=requested,
    ) if complete else []
    core = {"status": "satisfied" if complete else "incomplete", "authorizing": False,
            "strategy": SCALAR_SUMMARY_STRATEGY,
            "checker_options": _CHECKER_OPTIONS,
            "interface_sha256": bundle.interface.interface_sha256,
            "inputs": inputs,
            "headers_sha256": canonical_sha256_v3(dict(headers)),
            "operation_symbols": dict(operation_symbols),
            "tools": {name: hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
                      for name, path in (("goto_cc", goto_cc), ("goto_instrument", goto_instrument), ("cbmc", cbmc))},
            "checks": checks, "models": models, "postconditions": postconditions,
            "commands": [{**row, "command": [item.replace(str(output), "$MODEL_ROOT")
                                               for item in row["command"]]} for row in commands]}
    result = {**core, "receipt_sha256": canonical_sha256_v3(core)}
    if workspace is not None:
        shutil.copytree(workspace, artifact_output)
    return result


def validate_scalar_summary_contracts(value: Mapping[str, object]) -> None:
    """Validate supplementary evidence; satisfaction still grants no authority."""
    fields = {"status", "authorizing", "strategy", "checker_options", "interface_sha256",
              "inputs", "headers_sha256", "operation_symbols", "tools", "checks", "models",
              "commands", "receipt_sha256", "postconditions"}
    if set(value) != fields or value.get("receipt_sha256") != canonical_sha256_v3(
        {key: item for key, item in value.items() if key != "receipt_sha256"}
    ):
        raise ValueError("source summary contract certificate fields or digest are stale")
    symbols = value.get("operation_symbols")
    tools = value.get("tools")
    checks = value.get("checks")
    models = value.get("models")
    if (value.get("status") not in {"satisfied", "incomplete"}
            or value.get("authorizing") is not False
            or value.get("strategy") != SCALAR_SUMMARY_STRATEGY
            or value.get("checker_options") != _CHECKER_OPTIONS
            or not isinstance(symbols, Mapping) or not symbols
            or not isinstance(tools, Mapping) or set(tools) != {"goto_cc", "goto_instrument", "cbmc"}
            or not isinstance(checks, list) or not isinstance(models, list)
            or not all(isinstance(row, Mapping) for row in [*checks, *models])):
        raise ValueError("source summary contract certificate policy is malformed")
    expected = {(operation_id, kind) for operation_id in symbols
                for kind in ("frame", "context_independence")}
    def digest(item: object) -> bool:
        return isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item) is not None

    inputs = value["inputs"]
    if (not digest(value["interface_sha256"]) or not digest(value["headers_sha256"])
            or not isinstance(inputs, list) or not inputs
            or any(not isinstance(row, Mapping) or set(row) != {"path", "sha256"}
                   or row["path"] != f"source-{index:04d}.c" or not digest(row["sha256"])
                   for index, row in enumerate(inputs))
            or any(not isinstance(key, str) or not key or not isinstance(symbol, str)
                   or not symbol or _c_identifier(symbol) != symbol for key, symbol in symbols.items())
            or any(not digest(item) and item is not None for item in tools.values())
            or not isinstance(value["commands"], list)):
        raise ValueError("source summary contract certificate inputs are malformed")
    validate_scalar_postconditions(value["postconditions"], symbols=symbols,
                                   checker_options=_CHECKER_OPTIONS, inputs=inputs)
    if value["status"] == "satisfied":
        if (len(checks) != len(expected) or len(models) != len(expected)
                or any(not digest(item) for item in tools.values())
                or {(row.get("operation_id"), row.get("kind")) for row in checks} != expected
                or {(row.get("operation_id"), row.get("kind")) for row in models} != expected
                or any(row.get("status") != "satisfied" for row in checks)
                or any(not digest(row.get("output_sha256")) for row in checks)
                or any(set(row) != {"operation_id", "kind", "contract_sha256", "goto_sha256"}
                       or not digest(row["contract_sha256"]) or not digest(row["goto_sha256"])
                       for row in models)
                or any(f"spx_summary_context_independence_{_c_identifier(str(row['operation_id']))}.assertion.1"
                       not in row.get("property_ids", []) for row in checks
                       if row["kind"] == "context_independence")):
            raise ValueError("source summary contract certificate omits a required proof")
        command_rows = value["commands"]
        if any(not isinstance(row, Mapping) or not isinstance(row.get("command"), list)
               or not all(isinstance(item, str) for item in row["command"])
               or not digest(row.get("output_sha256")) for row in command_rows):
            raise ValueError("source summary contract command evidence is malformed")
        for operation_id, symbol in symbols.items():
            prefix = _c_identifier(operation_id)
            instrument = [row for row in command_rows if row.get("step") == f"{prefix}-frame-instrument"]
            if len(instrument) != 1 or instrument[0]["command"][1:3] != ["--enforce-contract", symbol]:
                raise ValueError("source summary contract omits frame instrumentation")
            for kind, entry in (("frame", symbol), ("context_independence", f"spx_summary_context_independence_{prefix}")):
                checker = [row for row in command_rows if row.get("step") == f"{prefix}-{kind}-check"]
                if (len(checker) != 1 or checker[0]["command"][2:]
                        != ["--function", entry, *_CHECKER_OPTIONS]):
                    raise ValueError("source summary contract checker command is weakened")
