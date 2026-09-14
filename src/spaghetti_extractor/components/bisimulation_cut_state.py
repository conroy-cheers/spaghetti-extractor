"""Compiler-derived local storage to overapproximate when resuming a source cut."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Mapping, Sequence

from .bisimulation import BisimulationOperationV1
from .bisimulation_parameter_bindings import check_parameter_bindings
from .bisimulation_support import BisimulationRefinementError, include_path


@dataclass(frozen=True)
class CutLocalState:
    havoc: dict[str, dict[str, list[str]]]
    unsigned_words: dict[str, dict[str, list[str]]]
    entries: dict[str, dict[str, dict]] = field(default_factory=dict)


def _cut_unsigned_words(*, symbols, instructions, function, sync_ids):
    """Identify plain unsigned C words in the actual lexical marker scope.

    This is an optimization eligibility inventory, not a declaration of types
    by the operator. Ambiguous, shadowed, volatile and non-word objects are
    omitted; their relations continue to be admitted in the source macro.
    """
    declarations = {_symbol(row['code']['sub'][0]): index
                    for index, row in enumerate(instructions) if row.get('instructionId') == 'DECL'}
    result = {}
    for sync_id in sync_ids:
        anchors = [key for key in declarations if symbols.get(key, {}).get('baseName')
                   == '__CPROVER_spx_local_sync_' + sync_id]
        if len(anchors) != 1:
            raise BisimulationRefinementError('source cut word inventory has no unique scope marker')
        anchor = anchors[0]
        scope = anchor.rsplit('::', 1)[0] + '::'
        visible = {}
        for identity, row in symbols.items():
            if (row.get('location', {}).get('function') != function
                    or not scope.startswith(identity.rsplit('::', 1)[0] + '::')
                    or (not row.get('isParameter') and
                        declarations.get(identity, len(instructions)) >= declarations[anchor])):
                continue
            visible.setdefault(row.get('baseName'), []).append(row)
        words = []
        for name, rows in visible.items():
            if len(rows) != 1 or not isinstance(name, str) or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_]*', name):
                continue
            if sum(row.get('baseName') == name and row.get('location', {}).get('function') == function
                   for row in symbols.values()) != 1:
                continue
            row = rows[0]
            typ = row.get('type', {})
            attributes = typ.get('namedSub', {})
            if (not row.get('isStaticLifetime') and not row.get('isAuxiliary')
                    and not name.startswith('__CPROVER_spx_local_')
                    and typ.get('id') == 'unsignedbv'
                    and attributes.get('width', {}).get('id') == '32'
                    and attributes.get('#c_type', {}).get('id') in {'unsigned_int', 'unsigned_long_int'}
                    and '#volatile' not in attributes):
                words.append(name)
        result[sync_id] = sorted(words)
    return result


def _walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            yield from _walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from _walk(child)


def _symbol(value: Mapping) -> str | None:
    if value.get("id") == "symbol":
        return value.get("namedSub", {}).get("identifier", {}).get("id")
    return None


def _written_object(value: Mapping) -> str | None:
    identity = _symbol(value)
    if identity is not None:
        return identity
    if value.get("id") in {"member", "index", "typecast"}:
        return _written_object(value["sub"][0])
    if value.get("id") in {"dereference", "nil", "string_constant"}:
        return None
    raise BisimulationRefinementError("source cut local write shape is unsupported")


def _local_havoc(*, symbols: Mapping, instructions: Sequence[Mapping], function: str,
                 sync_ids: Sequence[str], omitted_parameters: Mapping[str, Sequence[str]] | None = None) -> dict[str, list[str]]:
    declarations: dict[str, int] = {}
    assignments: dict[str, list[int]] = {}
    assigned_values: dict[str, list[Mapping]] = {}
    complete_assignments: set[tuple[str, int]] = set()
    escaped: set[str] = set()
    for index, instruction in enumerate(instructions):
        code = instruction.get("code", {})
        operands = code.get("sub", [])
        kind = instruction.get("instructionId")
        if kind == "DECL":
            identity = _symbol(operands[0])
            if identity is None or identity in declarations:
                raise BisimulationRefinementError("source cut local declarations are ambiguous")
            declarations[identity] = index
        if kind in {"ASSIGN", "FUNCTION_CALL"}:
            identity = _written_object(operands[0])
            if identity is not None:
                assignments.setdefault(identity, []).append(index)
                if _symbol(operands[0]) == identity and kind == "ASSIGN":
                    complete_assignments.add((identity, index))
                assigned_values.setdefault(identity, []).append(
                    operands[1] if kind == "ASSIGN" else {"id": "side_effect"}
                )
        for node in _walk([code, instruction.get("guard", {})]):
            if node.get("id") == "address_of":
                identity = _written_object(node["sub"][0])
                if identity is not None:
                    escaped.add(identity)

    def marker(name: str) -> str:
        matches = [key for key in declarations if symbols.get(key, {}).get("baseName") == name]
        if len(matches) != 1:
            raise BisimulationRefinementError("source cut scope marker is absent or ambiguous")
        return matches[0]

    begin_symbol = marker("__CPROVER_spx_local_begin")
    if re.fullmatch(re.escape(function) + r"::[0-9]+::[0-9]+::__CPROVER_spx_local_begin", begin_symbol) is None:
        raise BisimulationRefinementError(f"source cut {function} BEGIN is not in the function's outer block")
    begin = declarations[begin_symbol]
    locations = {row["locationNumber"]: index for index, row in enumerate(instructions)}
    for instruction in instructions[:begin]:
        kind = instruction.get("instructionId")
        code = instruction.get("code", {})
        safe = kind in {"DECL", "DEAD", "SKIP", "LOCATION"}
        if kind == "ASSIGN":
            safe = (_written_object(code["sub"][0]) in declarations
                    and not any(node.get("id") == "side_effect" for node in _walk(code["sub"][1])))
        if kind == "GOTO":
            targets = instruction.get("targets")
            safe = (isinstance(targets, list) and bool(targets)
                    and all(locations.get(target, begin + 1) <= begin for target in targets))
        if kind == "OTHER":
            safe = (code.get("namedSub", {}).get("statement", {}).get("id") == "expression"
                    and not any(node.get("id") == "side_effect" for node in _walk(code)))
        if not safe:
            raise BisimulationRefinementError(
                f"source cut {function} has nonlocal effects or control before BEGIN"
            )
    result = {}
    for sync_id in sync_ids:
        omitted = set((omitted_parameters or {}).get(sync_id, ()))
        anchor = marker("__CPROVER_spx_local_sync_" + sync_id)
        scope = anchor.rsplit("::", 1)[0] + "::"
        candidates = {}
        for identity, row in symbols.items():
            parameter = row.get("isParameter") is True
            declaration = -1 if parameter else declarations.get(identity)
            name = row.get("baseName", "")
            if (declaration is None or row.get("location", {}).get("function") != function
                    or row.get("isStaticLifetime")
                    or row.get("isAuxiliary") or name.startswith("__CPROVER_spx_local_")
                    or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name) is None):
                continue
            if parameter and identity not in assignments and identity not in escaped and identity not in omitted:
                continue
            parent = identity.rsplit("::", 1)[0] + "::"
            if scope.startswith(parent) and declaration < declarations[anchor]:
                candidates[identity] = name
        if not omitted <= set(candidates):
            raise BisimulationRefinementError(f"source cut {function}:{sync_id} cannot overapproximate an omitted parameter")
        for identity in sorted(omitted):
            name = candidates[identity]
            if any(
                other != identity and symbols[other].get("baseName") == name
                and scope.startswith(other.rsplit("::", 1)[0] + "::")
                and declaration < declarations[anchor] for other, declaration in declarations.items()
            ):
                raise BisimulationRefinementError(
                    f"source cut {function}:{sync_id} has shadowed omitted parameter {name}"
                )
        havoc = []
        for identity, name in candidates.items():
            values = assigned_values.get(identity, [])
            value = values[0] if len(values) == 1 else {"id": "side_effect"}
            closed = not any(node.get("id") in {
                "symbol", "side_effect", "dereference", "address_of",
            } for node in _walk(value))
            while value.get("id") == "typecast":
                value = value["sub"][0]
            alias = (_symbol(value["sub"][0]) if value.get("id") == "address_of" else None)
            local_alias = (alias in declarations and declarations[alias] < begin) or (
                symbols.get(alias, {}).get("isParameter") is True
                and symbols[alias].get("location", {}).get("function") == function
            )
            # Re-evaluating an initializer against the cut's memory is not
            # generally equivalent to its original value. Retain only closed
            # constants or immutable direct aliases of local storage; havoc
            # every other visible object before restoring the checked captures.
            stable = (identity in declarations and declarations[identity] < begin and identity not in escaped
                      and assignments.get(identity) == [declarations[identity] + 1]
                      and (identity, declarations[identity] + 1) in complete_assignments
                      and declarations[identity] + 1 < begin
                      and (closed or local_alias))
            if stable:
                continue
            if list(candidates.values()).count(name) != 1:
                raise BisimulationRefinementError(f"source cut {function}:{sync_id} has shadowed mutable local {name}")
            havoc.append(name)
        result[sync_id] = sorted(havoc)
    return result


def collect_cut_local_state(*, root: Path, source_files: Sequence[Path],
                            include_root: Path,
                            operations: Sequence[BisimulationOperationV1],
                            operation_parameter_ids: Mapping[str, Sequence[str]],
                            operation_symbols: Mapping[str, str], goto_cc: Path,
                            goto_instrument: Path, timeout_seconds: int,
                            prepare_entries: bool = False) -> CutLocalState:
    """Inventory source storage without executing or assuming the original prefix.

    Scope tokens are compiled into the original source's lexical blocks. GOTO
    declarations and writes determine the visible mutable objects at each cut.
    The actual proof havocs those objects and then restores declared captures.
    Unknown or ambiguous inventories fail closed; this inventory grants no authority.
    """
    selected = [operation for operation in operations if operation.syncs]
    if not selected:
        return CutLocalState({}, {})
    directory = root / "source-cut-locals"
    directory.mkdir()
    prefix = (
        '#include "stdint.h"\n'
        '#define SPX_PROOF_BEGIN(operation_id) do { uint32_t __CPROVER_spx_local_begin = 0; } while (0)\n'
        '#define SPX_PROOF_SYNC(sync_id, invariant, ...) SPX_LOCAL_SCOPE(sync_id)\n'
        '#define SPX_LOCAL_SCOPE(sync_id) do { uint32_t __CPROVER_spx_local_sync_##sync_id = 0; } while (0)\n'
    )
    wrappers = []
    for index, source in enumerate(source_files):
        path = directory / f"source-{index:04d}.c"
        path.write_text(prefix + f'#include "{include_path(source)}"\n', encoding="ascii")
        wrappers.append(path)
    model = directory / "inventory.goto"
    commands = [
        [str(goto_cc), "--i386-win32", "-I", str(root), "-I", str(include_root),
         *map(str, wrappers), "-o", str(model)],
        [str(goto_instrument), "--show-symbol-table", "--json-ui", str(model)],
        [str(goto_instrument), "--show-goto-functions", "--json-ui", str(model)],
    ]
    outputs = []
    for index, command in enumerate(commands):
        try:
            run = subprocess.run(command, capture_output=True, text=True, timeout=timeout_seconds)
        except (OSError, subprocess.TimeoutExpired) as error:
            raise BisimulationRefinementError(f"source cut local inventory failed: {error}") from error
        (directory / f"{index}.stdout").write_text(run.stdout)
        (directory / f"{index}.stderr").write_text(run.stderr)
        if run.returncode:
            raise BisimulationRefinementError("source cut local inventory compiler failed: " + run.stderr[-1000:])
        outputs.append(run.stdout)
    try:
        symbol_tables = [row["symbolTable"] for row in json.loads(outputs[1]) if "symbolTable" in row]
        inventories = [row["functions"] for row in json.loads(outputs[2]) if "functions" in row]
        if len(symbol_tables) != 1 or len(inventories) != 1:
            raise ValueError("ambiguous compiler inventory")
        result = {}
        unsigned_words = {}
        parameter_bindings = {}
        entries = {}
        for operation in selected:
            symbol = operation_symbols[operation.operation_id]
            functions = [row for row in inventories[0] if row["name"] == symbol and row["isBodyAvailable"]]
            if len(functions) != 1:
                raise ValueError("source operation has no unique compiled body")
            parameter_bindings[operation.operation_id] = check_parameter_bindings(
                symbols=symbol_tables[0], instructions=functions[0]["instructions"], function=symbol,
                parameter_ids=operation_parameter_ids[operation.operation_id], operation=operation,
            )
            result[operation.operation_id] = _local_havoc(
                symbols=symbol_tables[0], instructions=functions[0]["instructions"], function=symbol,
                sync_ids=[sync.identity for sync in operation.syncs],
                omitted_parameters=parameter_bindings[operation.operation_id]["omitted_scalar_parameters"],
            )
            unsigned_words[operation.operation_id] = _cut_unsigned_words(
                symbols=symbol_tables[0], instructions=functions[0]['instructions'], function=symbol,
                sync_ids=[sync.identity for sync in operation.syncs],
            )
            if prepare_entries:
                from .bisimulation_source_entry import source_entry_candidate
                entries[operation.operation_id] = {
                    sync.identity: source_entry_candidate(symbols=symbol_tables[0],
                        instructions=functions[0]["instructions"], function=symbol,
                        operation=operation.operation_id, sync=sync,
                        omitted_parameters=parameter_bindings[operation.operation_id]["omitted_scalar_parameters"][sync.identity])
                    for sync in operation.syncs
                }
    except (ValueError, KeyError, IndexError, TypeError) as error:
        raise BisimulationRefinementError(f"source cut local inventory is malformed: {error}") from error
    (directory / "local-havoc.json").write_text(json.dumps({
        "authorizing": False, "storage_scope": "automatic_locals_and_mutable_parameters",
        "commands": commands, "operations": result, "unsigned_words": unsigned_words,
    }, indent=2) + "\n")
    (directory / "parameter-bindings.json").write_text(json.dumps({
        "authorizing": False, "operations": parameter_bindings,
    }, indent=2) + "\n")
    if prepare_entries:
        (directory / "entry-candidates.json").write_text(json.dumps({
            "authorizing": False, "operations": entries,
        }, indent=2) + "\n")
    return CutLocalState(result, unsigned_words, entries)
