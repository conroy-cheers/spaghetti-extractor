"""Compiler-derived source storage for an independent cut-entry model.

This constructs proof input, not an entry theorem. The initial profile admits
only a BEGIN before stateful source operations and locals overapproximated by
the existing havoc rule. Discarded nonvolatile parameter values may precede it.
Other sources retain the original model. A candidate must also pass a
compiled type-closure check before any query can use its entry source.
"""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import time
from pathlib import Path

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_cut_state import _local_havoc, _symbol, _walk
from .bisimulation_support import BisimulationRefinementError


POLICY = "compiler-derived-first-begin-source-entry-v1"
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class UnsupportedSourceEntry(ValueError):
    """The ordinary source remains valid but needs the original entry model."""


def _require(condition, message):
    if not condition:
        raise UnsupportedSourceEntry(message)


def _semantic_type(value):
    # These two attributes describe compiler locations/bookkeeping. Preserve
    # all other attributes, including qualifiers, widths, calling conventions,
    # field names/order, padding and recursively referenced type definitions.
    # This is a type comparison; compiled program bytes are never normalized.
    if isinstance(value, dict):
        return {key: _semantic_type(child) for key, child in value.items()
                if key not in {"#source_location", "#failed_symbol"}}
    if isinstance(value, list):
        return [_semantic_type(child) for child in value]
    return value


def _type_closure(symbols, selected):
    roots = {name: _semantic_type(symbols[identity]["type"])
             for name, identity in selected.items()}
    tags = {}
    pending = list(roots.values())
    while pending:
        for node in _walk(pending.pop()):
            if node.get("id") not in {"struct_tag", "union_tag", "c_enum_tag"}:
                continue
            tag = node["namedSub"]["identifier"]["id"]
            if tag in tags:
                continue
            _require(tag in symbols and symbols[tag]["isType"], "unresolved boundary type")
            tags[tag] = _semantic_type(symbols[tag]["type"])
            pending.append(tags[tag])
    return {"objects": roots, "tags": tags}


def _erased_prefix(instruction, symbols, function):
    if instruction["instructionId"] in {"SKIP", "LOCATION"}:
        return True
    code = instruction.get("code", {})
    values = code.get("sub", [])
    if (instruction["instructionId"] != "OTHER" or len(values) != 1
            or code.get("namedSub", {}).get("statement", {}).get("id") != "expression"):
        return False
    cast = values[0]
    operands = cast.get("sub", [])
    if (cast.get("id") != "typecast" or len(operands) != 1
            or cast.get("namedSub", {}).get("type", {}).get("id") != "empty"):
        return False
    row = symbols.get(_symbol(operands[0]), {})
    typ = row.get("type", {})
    # A conventional (void)parameter suppresses an unused-argument warning.
    # Do not generalize this to dereferences, volatile reads, arithmetic,
    # initializers or local aliases with earlier state to preserve.
    return (row.get("isParameter") is True and row.get("location", {}).get("function") == function
            and typ.get("id") in {"pointer", "signedbv", "unsignedbv"}
            and "#volatile" not in typ.get("namedSub", {}))


def source_entry_candidate(*, symbols, instructions, function, operation, sync,
                           omitted_parameters=()):
    """Retain the exact entry storage inventory or explain why it is unsupported.

    Call only after ordinary source/marker and parameter-binding validation.
    Skipped initializers are already skipped by BEGIN's jump in the original
    proof; every emitted local is havoced by that same cut rule. In particular,
    stable prefix aliases/constants are rejected rather than reconstructed from
    potentially different cut memory. This does not authorize substitution.
    """
    try:
        source, binding = _render(symbols=symbols, instructions=instructions,
            function=function, operation=operation, sync=sync,
            omitted_parameters=omitted_parameters)
    except UnsupportedSourceEntry as error:
        return {"policy": POLICY, "authorizing": False, "status": "unsupported",
                "detail": str(error)}
    binding = {**binding, "source_sha256": hashlib.sha256(source.encode("ascii")).hexdigest()}
    return {"policy": POLICY, "authorizing": False, "status": "prepared",
            "source": source, "binding": binding,
            "binding_sha256": canonical_sha256_v3(binding)}


def _render(*, symbols, instructions, function, operation, sync, omitted_parameters):
    _require(all(_IDENTIFIER.fullmatch(name) for name in (function, operation, sync.identity)),
             "invalid entry boundary name")
    declarations = {_symbol(row["code"]["sub"][0]): index
                    for index, row in enumerate(instructions) if row["instructionId"] == "DECL"}
    anchors = [identity for identity in declarations if symbols[identity]["baseName"]
               == "__CPROVER_spx_local_sync_" + sync.identity]
    begins = [identity for identity in declarations if symbols[identity]["baseName"]
              == "__CPROVER_spx_local_begin"]
    _require(len(anchors) == len(begins) == 1, "ambiguous entry boundary marker")
    begin = declarations[begins[0]]
    _require(all(_erased_prefix(row, symbols, function) for row in instructions[:begin]),
             "entry source profile does not support code or storage before BEGIN")
    anchor = anchors[0]
    scope = anchor.rsplit("::", 1)[0] + "::"
    locals_ = [identity for identity, index in declarations.items()
               if index < declarations[anchor]
               and scope.startswith(identity.rsplit("::", 1)[0] + "::")
               and not symbols[identity]["baseName"].startswith("__CPROVER_spx_local_")
               and not symbols[identity]["isAuxiliary"]]
    parameters = [row["namedSub"]["#identifier"]["id"] for row in
                  symbols[function]["type"]["namedSub"]["parameters"]["sub"]]
    selected = {}
    for identity in parameters + locals_:
        row = symbols[identity]
        name = row["baseName"]
        _require(_IDENTIFIER.fullmatch(name) and name not in selected,
                 "shadowed or invalid entry boundary name")
        _require(not row["isStaticLifetime"], "static entry boundary storage")
        _require(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_ *]*", row["prettyType"]),
                 "unsupported entry boundary C type spelling")
        _require(not any("#volatile" in node.get("namedSub", {}) for node in _walk(row["type"])),
                 "volatile entry boundary type")
        selected[name] = identity
    havoc = _local_havoc(symbols=symbols, instructions=instructions, function=function,
        sync_ids=[sync.identity], omitted_parameters={sync.identity: omitted_parameters})[sync.identity]
    _require(all(symbols[identity]["baseName"] in havoc for identity in locals_),
             "entry source profile cannot discard stable local state")
    signature = symbols[function]["prettyType"]
    opening = signature.find("(")
    _require(opening > 0 and signature.endswith(")"), "unsupported entry operation signature")
    declaration = signature[:opening] + function + signature[opening:]
    lines = ['#include "portable-component-implementation.h"', declaration + " {",
             f"  SPX_PROOF_BEGIN({operation});"]
    lines.extend(f"  {symbols[identity]['prettyType']} {symbols[identity]['baseName']};"
                 for identity in locals_)
    lines.extend([f"  SPX_PROOF_SYNC({sync.identity}, 1, {', '.join(sync.source_arguments())});",
                  '  __CPROVER_assert(0, "spx-source-entry:escaped-cut");',
                  "  __CPROVER_assume(0);", "}"])
    selected["$signature"] = function
    return "\n".join(lines) + "\n", {
        "function": function, "operation": operation, "cut": sync.identity,
        "sync_sha256": canonical_sha256_v3(sync.to_payload()),
        "locals": [symbols[identity]["baseName"] for identity in locals_],
        "parameters": [symbols[identity]["baseName"] for identity in parameters],
        "havoc": havoc, "source_arguments": list(sync.source_arguments()),
        "types": _type_closure(symbols, selected),
    }


def check_compiled_entry_types(candidate, symbols):
    """Reject stale source bindings or a different compiled boundary layout.

    This gate checks source preparation and types only. Entry safety, relation
    nonvacuity and source-entry conformance are distinct required obligations.
    """
    try:
        binding = candidate["binding"]
        if (candidate.get("policy") != POLICY or candidate.get("authorizing") is not False
                or candidate.get("status") != "prepared"
                or candidate.get("binding_sha256") != canonical_sha256_v3(binding)
                or binding.get("source_sha256") != hashlib.sha256(candidate["source"].encode("ascii")).hexdigest()):
            raise ValueError("entry source preparation binding differs")
        selected = {"$signature": binding["function"]}
        for name in binding["parameters"] + binding["locals"]:
            matches = [identity for identity, row in symbols.items()
                       if row.get("location", {}).get("function") == binding["function"]
                       and row["baseName"] == name and not row["isAuxiliary"]]
            if len(matches) != 1:
                raise ValueError("compiled entry object is missing or ambiguous: " + name)
            selected[name] = matches[0]
        if _type_closure(symbols, selected) != binding["types"]:
            raise ValueError("compiled entry boundary type or layout changed")
    except (KeyError, TypeError, ValueError) as error:
        raise BisimulationRefinementError(str(error)) from error


def preparation_summary(candidate):
    """Expose preparation state without mistaking it for checked entry evidence."""
    return {key: candidate[key] for key in
            ("policy", "authorizing", "status", "binding_sha256", "detail") if key in candidate}


def compile_source_entry(task, *, timeout_seconds):
    """Retain a conditional entry candidate with its actual compiled type gate.

    No property or cover query is redirected to this model. Full source-entry
    conformance and entry obligations must be checked before such substitution.
    Keeping this step separate lets the public diagnostic retain the independent
    model and compilation costs even when the ordinary region is incomplete.
    """
    from .bisimulation_compilation import VIRTUAL_WORKSPACE, workspace_compile_command
    from .bisimulation_diagnostics import ProofQueryTimings

    candidate = task.get("source_entry_candidate")
    if candidate is None:
        return None
    if task.get("assurance") is None:
        raise BisimulationRefinementError("independent entry preparation requires conditional assurance")
    summary = preparation_summary(candidate)
    result = {"preparation": summary, "authorizing": False,
              "source_conformance_checked": False, "entry_obligations_checked": False}
    if candidate["status"] == "unsupported":
        return {**result, "status": "unsupported", "detail": candidate["detail"]}
    directory = Path(task["goto_model"]).parent / "source-entry"
    directory.mkdir()
    source = directory / "source.c"
    source.write_text('#include "../component-bisimulation.h"\n' + candidate["source"], encoding="ascii")
    (directory / "preparation.json").write_text(json.dumps(candidate, indent=2) + "\n")
    model = directory / "model.goto"
    wrappers = {str(path) for path in task["source_entry_wrappers"]}
    original = task["compile_command"]
    if not wrappers or not wrappers <= set(original):
        raise BisimulationRefinementError("entry compilation lacks original source wrappers")
    first_wrapper = str(task["source_entry_wrappers"][0])
    command = [str(source) if argument == first_wrapper
               else argument for argument in original
               if argument not in wrappers or argument == first_wrapper]
    if command.count(str(task["goto_model"])) != 1:
        raise BisimulationRefinementError("entry compilation has an ambiguous original output")
    command = [str(model) if argument == str(task["goto_model"]) else argument for argument in command]
    # Match ordinary compilation. CBMC's explicit --function query selects the
    # relation root and generates startup/initialization for either model.
    timings = ProofQueryTimings(model, {"operation_id": task["operation_id"],
        "obligation_id": task["obligation_id"], "model_scope": "source_entry_preparation"})
    timings.record_compile_inputs(command, proof_root=task["diagnostic_proof_root"],
        compiler_workspace=VIRTUAL_WORKSPACE if task.get("compile_workspace") is not None else None)
    commands = [command, [str(task["goto_instrument"]), "--show-symbol-table", "--json-ui", str(model)]]
    milliseconds = []
    for index, arguments in enumerate(commands):
        (directory / f"{index}.command.json").write_text(json.dumps(arguments, indent=2) + "\n")
        started = time.monotonic_ns()
        try:
            run = subprocess.run(workspace_compile_command(arguments, task["compile_workspace"]),
                                 capture_output=True, text=True, timeout=timeout_seconds)
        except (OSError, subprocess.TimeoutExpired) as error:
            for name in ("stdout", "stderr"):
                data = getattr(error, name, None) or b""
                (directory / f"{index}.{name}").write_bytes(data if isinstance(data, bytes) else data.encode())
            return {**result, "status": "incomplete", "detail": f"entry preparation tool failed: {error}"}
        milliseconds.append((time.monotonic_ns() - started) // 1_000_000)
        (directory / f"{index}.stdout").write_text(run.stdout)
        (directory / f"{index}.stderr").write_text(run.stderr)
        if run.returncode:
            return {**result, "status": "incomplete", "detail": "entry preparation compiler failed: " + run.stderr[-1000:]}
    try:
        tables = [row["symbolTable"] for row in json.loads(run.stdout) if "symbolTable" in row]
        if len(tables) != 1:
            raise ValueError("entry compiler has no unique symbol table")
        check_compiled_entry_types(candidate, tables[0])
    except (ValueError, TypeError, KeyError, BisimulationRefinementError) as error:
        return {**result, "status": "incomplete", "detail": f"entry type conformance failed: {error}"}
    from .bisimulation_entry_conformance import inspect_source_entry_prefix
    prefix = inspect_source_entry_prefix(task, model, directory, timeout_seconds=timeout_seconds)
    return {**result, "status": "compiled", "compiled_types_checked": True,
            "goto_model_sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
            "compile_milliseconds": milliseconds[0], "type_inventory_milliseconds": milliseconds[1],
            "prefix_correspondence": prefix}
