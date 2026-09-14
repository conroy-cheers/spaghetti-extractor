"""Restricted compiled prefix correspondence, conditional on entry qualification.

This checks a structural relation between two compiled programs. It is not an
entry theorem: the caller must bind both actual model inventories and prove the
entry's false frontier unreachable, all safety obligations and nonvacuity before
using it. No compiled bytes or query cache keys are normalized or rewritten.

The initial rule requires identical symbol identities and helper functions. It
preserves declarations, havoc, assumptions, effects and both unknown branch
arms. Only silent finite control paths and known compiler jump flags are folded.
Removed automatic objects must belong to the replaced function and occur in no
matched prefix or other function. This deliberately rejects more general source
transformations rather than guessing an alias or storage correspondence.
"""

from collections import deque

from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_cut_state import _symbol, _walk
from .bisimulation_support import BisimulationRefinementError


POLICY = "compiled-entry-prefix-correspondence-v1"
_FLAG = "__CPROVER_going_to::"
_LOCATION_METADATA = {"file", "line", "column", "function", "workingDirectory", "propertyId", "hide"}
_KINDS = {"SKIP", "LOCATION", "GOTO", "DECL", "DEAD", "ASSIGN", "ASSUME",
          "ASSERT", "FUNCTION_CALL", "OTHER", "END_FUNCTION", "SET_RETURN_VALUE"}


def _require(condition, message):
    if not condition:
        raise BisimulationRefinementError("entry prefix correspondence: " + message)


def _semantic(value):
    # Failed-pointer object bindings are semantic here, unlike the earlier
    # source spelling/type round trip. Only source locations are discarded.
    if isinstance(value, dict):
        if "#source_location" in value:
            location = value["#source_location"]
            _require(set(location) <= {"id", "namedSub"} and set(location.get("namedSub", {}))
                     <= {"file", "line", "column", "function", "working_directory"},
                     "unsupported type location semantics")
        return {key: _semantic(child) for key, child in value.items() if key != "#source_location"}
    if isinstance(value, list):
        return [_semantic(child) for child in value]
    return value


def _truth(expression, facts):
    kind = expression.get("id")
    named = expression.get("namedSub", {})
    operands = expression.get("sub", [])
    if kind == "symbol":
        return facts.get(named.get("identifier", {}).get("id"))
    if kind == "constant" and named.get("type", {}).get("id") == "bool":
        return {"true": True, "false": False}.get(named["value"]["id"])
    if kind == "constant" and named.get("type", {}).get("id") in {"signedbv", "unsignedbv", "c_bool"}:
        return int(named["value"]["id"], 16) != 0
    if kind == "typecast" and named.get("type", {}).get("id") in {"bool", "c_bool"} and len(operands) == 1:
        return _truth(operands[0], facts)
    if kind == "not" and len(operands) == 1:
        value = _truth(operands[0], facts)
        return None if value is None else not value
    if kind in {"equal", "notequal"} and len(operands) == 2:
        if all(value.get("id") == "constant" and value.get("namedSub", {}).get(
                "type", {}).get("id") in {"signedbv", "unsignedbv", "bool"} for value in operands):
            left, right = [_semantic(value)["namedSub"] for value in operands]
            if left["type"] == right["type"]:
                equal = left["value"] == right["value"]
                return equal if kind == "equal" else not equal
    return None


def _payload(row):
    # Retain property meaning, but not the compiler's sequential property ID.
    # Any query inventory must bind the IDs of its own actual compiled model.
    return {**{key: _semantic(value) for key, value in row.items() if key not in {
                "instruction", "locationNumber", "sourceLocation", "targets", "labels"}},
            "property": {key: value for key, value in row.get("sourceLocation", {}).items()
                         if key not in _LOCATION_METADATA}}


def _function_payload(function):
    rows = function.get("instructions", [])
    locations = {row["locationNumber"]: index for index, row in enumerate(rows)}
    _require(len(locations) == len(rows), "duplicate instruction location")
    return {**{key: value for key, value in function.items() if key != "instructions"},
            "instructions": [{**_payload(row), "targets": [locations[target]
                for target in row.get("targets", [])]} for row in rows]}


def _symbol_payload(row):
    # Automatic initializers are executed by GOTO instructions; their source
    # expression also appears in the symbol table even when BEGIN skips it.
    ignored = {"location", "module", "prettyName", "prettyType", "prettyValue"}
    if not row["isStaticLifetime"] and not row["isType"] and row["type"]["id"] != "code":
        ignored.add("value")
    return {**{key: _semantic(value) for key, value in row.items() if key not in ignored},
            "locationSemantics": {key: value for key, value in row.get("location", {}).items()
                                  if key not in _LOCATION_METADATA}}


def _identifiers(value):
    return {node["namedSub"][key]["id"] for node in _walk(value)
            for key in ("identifier", "#identifier", "#failed_symbol") if key in node.get("namedSub", {})}


def _erased_parameters(rows, symbols, function):
    from .bisimulation_source_entry import _erased_prefix

    erased = set()
    for index, row in enumerate(rows):
        if _erased_prefix(row, symbols, function):
            erased.add(index)
            continue
        operands = row.get('code', {}).get('sub', [])
        identity = _symbol(operands[0]) if operands else None
        symbol = symbols.get(identity, {})
        if (identity and identity.startswith(_FLAG) and symbol.get('isAuxiliary') is True
                and symbol.get('type', {}).get('id') == 'bool'
                and (row['instructionId'] == 'DECL' or (row['instructionId'] == 'ASSIGN'
                     and len(operands) == 2 and _truth(operands[1], {}) is False))):
            continue
        break
    return erased


def _advance(rows, locations, index, facts, erased):
    seen = set()
    while True:
        _require(0 <= index < len(rows), "prefix falls off function")
        _require(index not in seen, "silent control-flow cycle")
        seen.add(index)
        row = rows[index]
        if row["instructionId"] in {"SKIP", "LOCATION"} or index in erased:
            index += 1
            continue
        if row["instructionId"] == "GOTO":
            _require(len(row.get("targets", [])) == 1, "ambiguous branch")
            value = _truth(row["guard"], facts)
            if value is not None:
                index = locations[row["targets"][0]] if value else index + 1
                continue
        return index


def _prefix(original, entry, original_symbols, entry_symbols):
    left, right = [function["instructions"] for function in (original, entry)]
    _require({key: value for key, value in original.items() if key != "instructions"}
             == {key: value for key, value in entry.items() if key != "instructions"},
             "function parameters or attributes differ")
    maps = [{row["locationNumber"]: index for index, row in enumerate(rows)} for rows in (left, right)]
    erased = [_erased_parameters(rows, symbols, original['name'])
              for rows, symbols in zip((left, right), (original_symbols, entry_symbols))]
    for rows, locations in zip((left, right), maps):
        _require(len(rows) == len(locations), "duplicate instruction location")
        for row in rows:
            _require(set(row) <= {"instruction", "instructionId", "locationNumber", "sourceLocation",
                                 "code", "guard", "targets", "labels"}, "unknown instruction field")
            _require(row["instructionId"] in _KINDS, "unsupported instruction kind")
            _require(all(target in locations for target in row.get("targets", [])), "foreign CFG target")
            _require(not row.get("targets") or row["instructionId"] == "GOTO", "unexpected target")
            for node in _walk(row.get("code", {})):
                if node.get("id") == "address_of":
                    _require(not any(identity.startswith(_FLAG) for identity in _identifiers(node)),
                             "compiler jump flag address escapes")
    pending = deque([(0, 0, ())])
    visited, pairs, frontiers, exits = set(), set(), set(), set()
    branches = 0
    while pending:
        i, j, known = pending.popleft()
        facts = dict(known)
        i, j = [_advance(rows, locations, index, facts, ignored)
                for rows, locations, index, ignored in zip((left, right), maps, (i, j), erased)]
        state = (i, j, known)
        if state in visited:
            continue
        visited.add(state)
        before, after = left[i], right[j]
        if after.get("sourceLocation", {}).get("comment") == "spx-source-entry:escaped-cut":
            _require(after["instructionId"] == "ASSERT" and _truth(after.get("guard", {}), {}) is False,
                     "frontier is not a false assertion")
            _require(j + 1 < len(right) and right[j + 1]["instructionId"] == "ASSUME"
                     and _truth(right[j + 1].get("guard", {}), {}) is False,
                     "frontier lacks a false assumption")
            frontiers.add((i, j))
            continue
        _require(_payload(before) == _payload(after), f"instruction differs at original {i}, entry {j}")
        pairs.add((i, j))
        kind = before["instructionId"]
        if kind == "OTHER":
            _require(before.get("code", {}).get("namedSub", {}).get("statement", {}).get("id")
                     == "havoc_object", "unsupported OTHER instruction")
        if kind == "ASSUME" and _truth(before["guard"], facts) is False:
            exits.add((i, j))
            continue
        _require(kind not in {"END_FUNCTION", "SET_RETURN_VALUE"}, "return outside guarded frontier")
        if kind == "GOTO":
            branches += 1
            pending.append((maps[0][before["targets"][0]], maps[1][after["targets"][0]], known))
        if kind == "ASSIGN":
            lhs, rhs = before["code"]["sub"]
            identity = lhs.get("namedSub", {}).get("identifier", {}).get("id") if lhs.get("id") == "symbol" else None
            if identity and identity.startswith(_FLAG):
                value = _truth(rhs, {})
                facts.pop(identity, None)
                if value is not None:
                    facts[identity] = value
            else:
                facts.clear()
        elif kind in {"FUNCTION_CALL", "OTHER"}:
            facts.clear()
        elif kind in {"DECL", "DEAD"}:
            facts.pop(before["code"]["sub"][0].get("namedSub", {}).get("identifier", {}).get("id"), None)
        pending.append((i + 1, j + 1, tuple(sorted(facts.items()))))
    _require(frontiers, "no checked entry frontier")
    return {"instruction_pairs": sorted(pairs), "frontiers": sorted(frontiers),
            "false_assumption_exits": sorted(exits), "unknown_branches": branches}


def check_compiled_entry_prefix(*, original_functions, entry_functions,
                                original_symbols, entry_symbols, function):
    """Check a guarded compiled relation; do not authorize model substitution.

    All other functions, including initialization and the calling harness, must
    match. Missing types/automatic objects may not be referenced by any retained
    symbol payload, helper body or matched prefix. Function-pointer target sets
    and static objects cannot shrink. Exact local identities and DECL/DEAD order
    are preserved; no new pointer or heap relation is inferred from type equality.
    """
    try:
        _require(original_functions.keys() == entry_functions.keys(), "function universe differs")
        _require(entry_symbols.keys() <= original_symbols.keys(), "entry introduces symbols")
        missing = original_symbols.keys() - entry_symbols.keys()
        private = {name for name in missing if not original_symbols[name]["isStaticLifetime"]
                   and not original_symbols[name]["isParameter"] and original_symbols[name]["type"]["id"] != "code"
                   and original_symbols[name].get("location", {}).get("function") == function}
        failed_objects = {node["namedSub"]["#failed_symbol"]["id"] for name in private
                          for node in _walk(original_symbols[name]["type"]) if "#failed_symbol" in node.get("namedSub", {})}
        for identity in missing:
            row = original_symbols[identity]
            _require(row["isType"] or identity in private or (identity in failed_objects
                and not row["isStaticLifetime"] and not row["isParameter"]
                and row["type"].get("namedSub", {}).get("#is_failed_symbol", {}).get("id") == "1"),
                "removed object is not private automatic storage: " + identity)
        for identity, row in entry_symbols.items():
            before, after = _symbol_payload(original_symbols[identity]), _symbol_payload(row)
            _require(before == after, "symbol meaning differs: " + identity)
            _require(not (_identifiers(before) & missing), "retained symbol references removed storage/type")
        for identity in original_functions:
            if identity == function:
                continue
            before, after = [_function_payload(functions[identity])
                             for functions in (original_functions, entry_functions)]
            _require(before == after, "helper or harness differs: " + identity)
            _require(not (_identifiers(before) & missing), "helper references removed storage/type")
        relation = _prefix(original_functions[function], entry_functions[function], original_symbols, entry_symbols)
        for i, _ in relation["instruction_pairs"]:
            _require(not (_identifiers(_payload(original_functions[function]["instructions"][i])) & missing),
                     "prefix references removed storage/type")
        return {"policy": POLICY, "status": "matched", "authorizing": False,
                "source_conformance_checked": False, "entry_obligations_checked": False,
                "function": function, "relation": relation,
                "relation_sha256": canonical_sha256_v3(relation),
                "common_helpers": len(original_functions) - 1,
                "removed_automatic_objects": sum(not original_symbols[name]["isType"] for name in missing),
                "frontier_properties": sorted({entry_functions[function]["instructions"][j][
                    "sourceLocation"]["propertyId"] for _, j in relation["frontiers"]})}
    except BisimulationRefinementError:
        raise
    except (KeyError, TypeError, IndexError, ValueError) as error:
        raise BisimulationRefinementError("entry prefix correspondence: malformed compiler inventory: " + str(error)) from error


def inspect_source_entry_prefix(task, model, directory, *, timeout_seconds):
    """Bind a diagnostic correspondence to both actual public compiled models.

    Entry safety/coverage and query routing are deliberately separate. In
    particular, identical helper bodies do not qualify a selected runtime law.
    """
    import hashlib
    import json
    import subprocess
    import time

    from .bisimulation_compilation import workspace_compile_command

    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    result = {"policy": POLICY, "authorizing": False,
              "original_goto_model_sha256": digest(task["goto_model"]),
              "entry_goto_model_sha256": digest(model),
              "entry_function": task["proof_function"] + "_relation"}
    inventory = {}
    inventory_milliseconds = 0
    requests = [("original_symbols", "--show-symbol-table", task["goto_model"], "symbolTable"),
                ("original_functions", "--show-goto-functions", task["goto_model"], "functions"),
                ("entry_functions", "--show-goto-functions", model, "functions")]
    try:
        inventory["entry_symbols"] = next(row["symbolTable"] for row in
            json.loads((directory / "1.stdout").read_text()) if "symbolTable" in row)
        paths = {"entry_symbols": directory / "1.stdout"}
        for index, (name, flag, path, field) in enumerate(requests, 2):
            arguments = [str(task["goto_instrument"]), flag, "--json-ui", str(path)]
            (directory / f"{index}.command.json").write_text(json.dumps(arguments, indent=2) + "\n")
            started = time.monotonic_ns()
            run = subprocess.run(workspace_compile_command(arguments, task["compile_workspace"]),
                                 capture_output=True, text=True, timeout=timeout_seconds)
            inventory_milliseconds += (time.monotonic_ns() - started) // 1_000_000
            paths[name] = directory / f"{index}.stdout"
            paths[name].write_text(run.stdout)
            (directory / f"{index}.stderr").write_text(run.stderr)
            _require(run.returncode == 0, "compiler inventory failed: " + run.stderr[-1000:])
            values = [row[field] for row in json.loads(run.stdout) if field in row]
            _require(len(values) == 1, "ambiguous compiler inventory")
            if field == "functions":
                inventory[name] = {row["name"]: row for row in values[0]}
                _require(len(inventory[name]) == len(values[0]), "duplicate compiler function")
            else:
                inventory[name] = values[0]
        for name in ("original_functions", "entry_functions"):
            root = inventory[name].get(result["entry_function"], {})
            _require(root.get("isBodyAvailable") is True and root.get("parameterIdentifiers") == [],
                     "selected relation entry point is missing or parameterized")
        started = time.monotonic_ns()
        checked = check_compiled_entry_prefix(**inventory, function=task["source_entry_candidate"]["binding"]["function"])
        comparison_milliseconds = (time.monotonic_ns() - started) // 1_000_000
        sites = sorted([{"property_id": row["sourceLocation"].get("propertyId"),
                         "description": row["sourceLocation"].get("comment"),
                         "source_function": row["sourceLocation"].get("function")}
                        for function in inventory["entry_functions"].values()
                        for row in function.get("instructions", []) if row["instructionId"] == "ASSERT"],
                       key=lambda row: str(row["property_id"]))
        _require(sites and all(isinstance(value, str) and value for row in sites for value in row.values())
                 and len({row['property_id'] for row in sites}) == len(sites), "compiled assertion sites are ambiguous")
        (directory / "prefix-relation.json").write_text(json.dumps(checked, indent=2) + "\n")
        relation = checked["relation"]
        result.update(status="matched", relation_sha256=checked["relation_sha256"],
            frontier_properties=checked["frontier_properties"], common_helpers=checked["common_helpers"],
            matched_instruction_pairs=len(relation["instruction_pairs"]), unknown_branches=relation["unknown_branches"],
            false_assumption_exits=len(relation["false_assumption_exits"]),
            required_assertion_descriptions=["spx-source-entry:escaped-cut"], assertion_sites=sites,
            inventory_milliseconds=inventory_milliseconds, comparison_milliseconds=comparison_milliseconds,
            inventory_sha256={name: digest(path) for name, path in paths.items()})
    except subprocess.TimeoutExpired as error:
        for name in ("stdout", "stderr"):
            data = getattr(error, name, None) or b""
            (directory / f"{index}.{name}").write_bytes(data if isinstance(data, bytes) else data.encode())
        result.update(status="incomplete", detail="entry prefix inventory timed out")
    except (OSError, ValueError, TypeError, KeyError, StopIteration) as error:
        result.update(status="incomplete", detail=str(error) or "entry prefix inventory unavailable")
    (directory / "prefix-correspondence.json").write_text(json.dumps(result, indent=2) + "\n")
    return result
