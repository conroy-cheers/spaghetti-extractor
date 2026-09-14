"""Checked scalar postrelations expressed in the existing Relation IR."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
from pathlib import Path
from typing import Mapping, Sequence

from .cbmc_backend import run_cbmc_properties
from .component_c_v5 import _parameter_type, _result_type
from .interface_package_v5 import CompiledComponentInterfaceV5
from .machine_overlay_services_v5 import _c_identifier
from .relation_ir import BOOL_SORT, LogicalPathV1, RelationExpressionV1, RelationSortV1


def _width(bundle: CompiledComponentInterfaceV5, type_id: str) -> int:
    value = bundle.intent.schema.type_index[type_id]
    if value.kind == "enum":
        return _width(bundle, str(value.body["underlying_type_id"]))
    width = 1 if value.kind == "bool" else value.body.get("width_bits")
    if value.kind not in {"integer", "bool"} or width not in {1, 8, 16, 32, 64}:
        raise ValueError("scalar postcondition has an unsupported value type")
    return int(width)


def _signature(bundle: CompiledComponentInterfaceV5, operation_id: str):
    operation = next(item for item in bundle.interface.operations if item.identity == operation_id)
    return bundle.intent.schema.signature_index[operation.signature_id]


def scalar_postcondition_candidates(bundle: CompiledComponentInterfaceV5, operation_id: str) -> list[dict[str, object]]:
    """Propose a generic fact; only a successful source proof may consume it."""
    signature = _signature(bundle, operation_id)
    if len(signature.parameters) != 1 or len(signature.results) != 1:
        return []
    terms = []
    for root, value in (("parameter", signature.parameters[0]), ("result", signature.results[0])):
        sort = RelationSortV1("bitvector", _width(bundle, value.type_id))
        atom = RelationExpressionV1("logical", sort, (), {"path": LogicalPathV1(root, value.identity).to_payload()})
        zero = RelationExpressionV1("const", sort, (), {"value": 0})
        terms.append(RelationExpressionV1("eq", BOOL_SORT, (atom, zero), {}))
    predicate = RelationExpressionV1("or", BOOL_SORT, (
        RelationExpressionV1("not", BOOL_SORT, (terms[0],), {}), terms[1]), {})
    return [{"id": "zero-preserving", "expression": predicate.to_payload()}]


def render_scalar_postcondition(
    expression: Mapping[str, object], *, bundle: CompiledComponentInterfaceV5,
    operation_id: str, result_expression: str,
) -> str:
    """Render a typed, pure subset; unsupported observations cannot become facts."""
    signature = _signature(bundle, operation_id)
    bindings = {(root, value.identity, ()): (_width(bundle, value.type_id),
                 _c_identifier(value.identity) if root == "parameter" else result_expression)
                for root, values in (("parameter", signature.parameters), ("result", signature.results))
                for value in values}
    return _render(expression, bindings)


def _render(expression, bindings):
    predicate = RelationExpressionV1.parse(expression)
    if predicate.sort != BOOL_SORT:
        raise ValueError("scalar postcondition must be Boolean")

    def render(term: RelationExpressionV1) -> str:
        if term.sort.kind not in {"bool", "bitvector"} or (
                term.sort.kind == "bitvector" and term.sort.width not in {1, 8, 16, 32, 64}):
            raise ValueError("scalar postcondition sort is unsupported")
        if term.op == "logical":
            key = LogicalPathV1.parse(term.attributes["path"]).key
            if key not in bindings or term.sort != RelationSortV1("bitvector", bindings[key][0]):
                raise ValueError("scalar postcondition names a foreign or mistyped value")
            return f"((uint64_t)({bindings[key][1]}) & UINT64_C({(1 << bindings[key][0]) - 1}))"
        if term.op == "const":
            if term.sort.kind != "bitvector":
                raise ValueError("scalar postcondition constant is not a bitvector")
            return f"UINT64_C({term.attributes['value']})"
        if term.op in {"true", "false"}:
            return "1" if term.op == "true" else "0"
        args = [render(item) for item in term.arguments]
        if term.op == "not":
            return f"(!({args[0]}))"
        operators = {"and": "&&", "or": "||", "eq": "==", "ult": "<", "ule": "<=",
                     "add": "+", "sub": "-", "bit_and": "&", "bit_or": "|", "bit_xor": "^"}
        if term.op not in operators:
            raise ValueError("scalar postcondition operation is unsupported")
        rendered = f"(({args[0]}) {operators[term.op]} ({args[1]}))"
        if term.sort.kind == "bitvector":
            rendered = f"({rendered} & UINT64_C({(1 << int(term.sort.width)) - 1}))"
        return rendered

    return render(predicate)


def _signature_payload(bundle, operation_id):
    signature = _signature(bundle, operation_id)
    return {"context_type": f"spx_{_c_identifier(bundle.interface.identity)}_context_v5",
            "parameters": [{"id": value.identity, "width": _width(bundle, value.type_id),
                            "c_type": _parameter_type(bundle.intent.schema.type_index, value)}
                           for value in signature.parameters],
            "result": {"id": signature.results[0].identity,
                       "width": _width(bundle, signature.results[0].type_id),
                       "c_type": _result_type(bundle.intent.schema.type_index, signature)}}


def _source_from_signature(signature, operation_id, symbol, predicate):
    if (not isinstance(signature, Mapping) or set(signature) != {"context_type", "parameters", "result"}
            or not isinstance(signature["parameters"], list)
            or not isinstance(signature["context_type"], str)
            or re.fullmatch(r"spx_[a-zA-Z0-9_]+_context_v5", signature["context_type"]) is None):
        raise ValueError("scalar postcondition signature is malformed")
    bindings = {}
    for root, values in (("parameter", signature["parameters"]), ("result", [signature["result"]])):
        for value in values:
            if (not isinstance(value, Mapping) or set(value) != {"id", "width", "c_type"}
                    or not isinstance(value["id"], str) or not value["id"]
                    or value["width"] not in {1, 8, 16, 32, 64}
                    or not isinstance(value["c_type"], str)
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", value["c_type"]) is None):
                raise ValueError("scalar postcondition value signature is malformed")
            key = (root, value["id"], ())
            if key in bindings:
                raise ValueError("scalar postcondition value signature is duplicated")
            bindings[key] = (value["width"], _c_identifier(value["id"]) if root == "parameter" else "post_result")
    entry = f"spx_summary_postcondition_{_c_identifier(operation_id)}"
    lines = ['#include "portable-component-implementation.h"', f"void {entry}(void) {{",
             f"  {signature['context_type']} context;"]
    lines.extend(f"  {value['c_type']} {_c_identifier(value['id'])};" for value in signature["parameters"])
    arguments = ", ".join(_c_identifier(value["id"]) for value in signature["parameters"])
    lines.extend([
        f"  {signature['result']['c_type']} post_result = {symbol}(&context{', ' if arguments else ''}{arguments});",
        f"  __CPROVER_assert({_render(predicate, bindings)},",
        f'      "spx-summary-postcondition:{operation_id}");', "}",
    ])
    return "\n".join(lines) + "\n", entry


def _source(bundle, operation_id, symbol, predicate):
    return _source_from_signature(_signature_payload(bundle, operation_id), operation_id, symbol, predicate)


def check_scalar_postconditions(
    *, bundle: CompiledComponentInterfaceV5, operation_symbols: Mapping[str, str],
    output: Path, inputs: Sequence[Mapping[str, object]], goto_cc: Path, cbmc: Path,
    checker_options: Sequence[str], timeout_seconds: int,
) -> list[dict[str, object]]:
    """Check candidates after the same source has passed frame and control checks."""
    facts, attempts = [], []
    for operation_id, symbol in sorted(operation_symbols.items()):
        for candidate in scalar_postcondition_candidates(bundle, operation_id):
            source, entry = _source(bundle, operation_id, symbol, candidate["expression"])
            path = output / f"postcondition-{_c_identifier(operation_id)}-{candidate['id']}.c"
            path.write_text(source, encoding="ascii")
            model = path.with_suffix(".goto")
            command = [str(goto_cc), "--i386-win32", "-I", str(output), str(path),
                       *(str(output / str(row["path"])) for row in inputs), "--function", entry, "-o", str(model)]
            try:
                compiled = subprocess.run(command, capture_output=True, text=True,
                                          timeout=timeout_seconds, check=False)
                if compiled.returncode:
                    raise ValueError(compiled.stderr)
                checker_command = [str(cbmc), str(model), "--function", entry, *checker_options]
                check = run_cbmc_properties(command=checker_command, timeout_seconds=timeout_seconds)
            except (OSError, ValueError, subprocess.TimeoutExpired) as error:
                attempts.append({"operation_id": operation_id, "id": candidate["id"],
                                 "status": "incomplete", "detail": str(error)})
                continue
            attempts.append({"operation_id": operation_id, "id": candidate["id"], **check})
            if check["status"] == "satisfied":
                facts.append({"operation_id": operation_id, **candidate, "check": check,
                              "signature": _signature_payload(bundle, operation_id),
                              "source_sha256": hashlib.sha256(source.encode()).hexdigest(),
                              "goto_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
                              "compile_command": [item.replace(str(output), "$MODEL_ROOT") for item in command],
                              "checker_command": [item.replace(str(output), "$MODEL_ROOT") for item in checker_command]})
    (output / "postcondition-attempts.json").write_text(json.dumps(attempts, indent=2) + "\n")
    return facts


def validate_scalar_postconditions(value: object, *, symbols: Mapping[str, str], checker_options: Sequence[str], inputs) -> None:
    if not isinstance(value, list):
        raise ValueError("scalar postcondition inventory is malformed")
    identities = []
    for row in value:
        if not isinstance(row, Mapping) or set(row) != {"operation_id", "id", "expression", "check",
                "source_sha256", "goto_sha256", "compile_command", "checker_command", "signature"}:
            raise ValueError("scalar postcondition fields are malformed")
        operation_id = row["operation_id"]
        if operation_id not in symbols or not isinstance(row["id"], str) or re.fullmatch(r"[a-z][a-z0-9-]*", row["id"]) is None:
            raise ValueError("scalar postcondition identity is malformed")
        identities.append((operation_id, row["id"]))
        if RelationExpressionV1.parse(row["expression"]).sort != BOOL_SORT:
            raise ValueError("scalar postcondition must be Boolean")
        entry = f"spx_summary_postcondition_{_c_identifier(operation_id)}"
        source, _ = _source_from_signature(row["signature"], operation_id, symbols[operation_id], row["expression"])
        if hashlib.sha256(source.encode()).hexdigest() != row["source_sha256"]:
            raise ValueError("scalar postcondition source binding is stale")
        check = row["check"]
        if (not isinstance(check, Mapping) or check.get("status") != "satisfied"
                or f"{entry}.assertion.1" not in check.get("property_ids", [])
                or not all(isinstance(item, str) and re.fullmatch(r"[0-9a-f]{64}", item)
                           for item in [row["source_sha256"], row["goto_sha256"], check.get("output_sha256")])):
            raise ValueError("scalar postcondition lacks its required source proof")
        stem = f"$MODEL_ROOT/postcondition-{_c_identifier(operation_id)}-{row['id']}"
        if (not isinstance(row["checker_command"], list)
                or row["checker_command"][1:] != [stem + ".goto", "--function", entry, *checker_options]):
            raise ValueError("scalar postcondition checker command is weakened")
        expected_compile = ["--i386-win32", "-I", "$MODEL_ROOT", stem + ".c",
                            *("$MODEL_ROOT/" + item["path"] for item in inputs),
                            "--function", entry, "-o", stem + ".goto"]
        if not isinstance(row["compile_command"], list) or row["compile_command"][1:] != expected_compile:
            raise ValueError("scalar postcondition compilation evidence is missing")
    if identities != sorted(set(identities)):
        raise ValueError("scalar postcondition inventory is duplicated or unordered")


def validate_scalar_postcondition_bindings(facts, *, bundle, symbols) -> None:
    for fact in facts:
        if fact["signature"] != _signature_payload(bundle, fact["operation_id"]):
            raise ValueError("scalar postcondition interface signature is stale")
        source, _ = _source(bundle, fact["operation_id"], symbols[fact["operation_id"]], fact["expression"])
        if hashlib.sha256(source.encode()).hexdigest() != fact["source_sha256"]:
            raise ValueError("scalar postcondition source binding is stale")
