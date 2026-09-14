"""Experimental consumption of scalar facts at a compiler-matched entry prefix.

This checks a program relation, not fact truth or activation authority. Keep it
with the experimental test tooling until complete qualification and production
summary routing are implemented.
"""

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import (
    _function_payload, _identifiers, _payload, _require, _semantic, _symbol_payload,
    check_compiled_entry_prefix,
)
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError


def _scalar_fact_guard(expression, symbols):
    """Reevaluation must only read stable scalar values, never dereference or call."""
    kind = expression.get("id")
    operands = expression.get("sub", [])
    if kind == "symbol":
        identity = expression.get("namedSub", {}).get("identifier", {}).get("id")
        typ = symbols.get(identity, {}).get("type", {})
        return typ.get("id") in {"bool", "c_bool", "signedbv", "unsignedbv"} and not any(
            "#volatile" in node.get("namedSub", {}) for node in _walk(typ))
    if kind == "constant":
        return expression.get("namedSub", {}).get("type", {}).get("id") in {
            "bool", "c_bool", "signedbv", "unsignedbv"}
    if kind == "typecast" and expression.get("namedSub", {}).get("type", {}).get("id") not in {
            "bool", "c_bool", "signedbv", "unsignedbv"}:
        return False
    arities = {"not": {1}, "typecast": {1}, "equal": {2}, "notequal": {2},
               "=": {2}, "!=": {2}, "<": {2}, "<=": {2}, ">": {2}, ">=": {2}}
    if kind not in {"and", "or"} and len(operands) not in arities.get(kind, set()):
        return False
    return bool(operands) and all(_scalar_fact_guard(value, symbols) for value in operands)


def _fact_condition(expression):
    # Both instructions test truth. C's _Bool parameter may introduce another
    # bool/c_bool conversion on ASSERT; never erase integer-width conversions.
    while (expression.get("id") == "typecast" and len(expression.get("sub", [])) == 1
           and expression.get("namedSub", {}).get("type", {}).get("id") in {"bool", "c_bool"}):
        expression = expression["sub"][0]
    return _semantic(expression)


def check_compiled_entry_fact_transport(*, original_functions, entry_functions, consumer_functions,
                                      original_symbols, entry_symbols, consumer_symbols,
                                      function, fact_function, assertion_description):
    """Check the program relation for consuming one prefix-qualified fact.

    This does not check the fact's truth, safety, unwind completeness or coverage,
    and does not authorize a summary. Those obligations must bind the actual
    entry model and root separately. The guard must use stable scalar snapshots,
    without dereferences, calls or volatile reads. Consumption must add one
    identical assume immediately after the selected assertion, and that every
    possible use of that helper is a direct call in the matched prefix. All
    inventories must have complete compiler function-pointer lowering (or
    already contain direct calls only), bound to each model and tool by the
    caller. Thus the prefix relation also checks lowered target alternatives.
    A later call, callback, address escape or changed helper requires new
    qualification.
    """
    try:
        for functions in (original_functions, entry_functions, consumer_functions):
            _require(all(row["instructionId"] != "FUNCTION_CALL" or _symbol(row["code"]["sub"][1]) is not None
                         for body in functions.values() for row in body.get("instructions", [])),
                     "fact transport requires complete compiler function-pointer lowering")
        prefix = check_compiled_entry_prefix(original_functions=original_functions,
            entry_functions=entry_functions, original_symbols=original_symbols,
            entry_symbols=entry_symbols, function=function)
        _require(fact_function != function and fact_function in entry_functions,
                 "fact must belong to a shared helper")
        _require(original_functions.keys() == consumer_functions.keys()
                 and original_symbols.keys() == consumer_symbols.keys(), "fact consumer universe differs")
        for identity in original_symbols:
            _require(_symbol_payload(original_symbols[identity]) == _symbol_payload(consumer_symbols[identity]),
                     "fact consumer symbol differs: " + identity)
        selected = [(index, row) for index, row in enumerate(entry_functions[fact_function]["instructions"])
                    if row["instructionId"] == "ASSERT"
                    and row.get("sourceLocation", {}).get("comment") == assertion_description]
        _require(len(selected) == 1, "fact assertion is missing or ambiguous")
        _, assertion = selected[0]
        _require(_scalar_fact_guard(assertion["guard"], entry_symbols), "fact guard is not a stable scalar expression")
        rows = consumer_functions[fact_function]["instructions"]
        sites = [index for index, row in enumerate(rows) if row["instructionId"] == "ASSERT"
                 and row.get("sourceLocation", {}).get("comment") == assertion_description]
        _require(len(sites) == 1 and sites[0] + 1 < len(rows), "consumer fact assertion is missing or ambiguous")
        site = sites[0] + 1
        assumed = rows[site]
        _require(assumed["instructionId"] == "ASSUME"
                 and _fact_condition(assumed["guard"]) == _fact_condition(assertion["guard"]),
                 "fact assumption is not the immediately preceding assertion")
        _require(_payload(assumed) == {**_payload(rows[site - 1]), "instructionId": "ASSUME",
                 "guard": _semantic(assumed["guard"]), "property": {}},
                 "fact assumption has additional semantics")
        _require(not any(assumed["locationNumber"] in row.get("targets", []) for row in rows),
                 "control flow bypasses the fact assertion")
        reduced = {**consumer_functions[fact_function], "instructions": rows[:site] + rows[site + 1:]}
        for identity, before in original_functions.items():
            after = reduced if identity == fact_function else consumer_functions[identity]
            _require(_function_payload(before) == _function_payload(after),
                     "fact consumer changes more than the checked assumption: " + identity)
        calls = []
        for side, functions, symbols, column in (("original", original_functions, original_symbols, 0),
                                                ("entry", entry_functions, entry_symbols, 1)):
            matched = {pair[column] for pair in prefix["relation"]["instruction_pairs"]}
            for name, row in symbols.items():
                _require(fact_function not in _identifiers(row.get("value", {})),
                         "fact helper escapes through a symbol value: " + name)
            for name, body in functions.items():
                for index, row in enumerate(body.get("instructions", [])):
                    if fact_function not in _identifiers(row):
                        continue
                    operands = row.get("code", {}).get("sub", [])
                    _require(row["instructionId"] == "FUNCTION_CALL" and len(operands) == 3
                             and _symbol(operands[1]) == fact_function,
                             "fact helper has a non-direct use")
                    residual = {**row, "code": {**row["code"], "sub": [operands[0], operands[2]]}}
                    _require(fact_function not in _identifiers(residual), "fact helper address escapes in a call")
                    _require(name == function and index in matched, "fact use lies outside the matched prefix")
                    calls.append({"side": side, "function": name, "instruction_index": index})
        _require({row["side"] for row in calls} == {"original", "entry"}, "fact lacks matched call sites")
        return {"status": "matched", "authorizing": False, "entry_obligations_checked": False,
                "prefix_relation_sha256": prefix["relation_sha256"], "fact_function": fact_function,
                "assertion_description": assertion_description,
                "entry_property_id": assertion["sourceLocation"]["propertyId"],
                "guard_sha256": canonical_sha256_v3(_semantic(assertion["guard"])), "calls": calls,
                "direct_call_inventories_checked": True}
    except BisimulationRefinementError:
        raise
    except (KeyError, TypeError, IndexError, ValueError) as error:
        raise BisimulationRefinementError("entry fact transport: malformed compiler inventory: " + str(error)) from error


def check_compiled_fact_consumption(*, original_functions, consumer_functions,
                                    original_symbols, consumer_symbols, facts):
    """Consume selected facts proved on the same whole program and query domain.

    The caller must bind the original proof, root, assumptions, bounds and tools.
    Unlike prefix qualification, this grants no independence from edited bodies:
    every function and symbol must remain identical except the selected adjacent
    assumes. It proves neither fact truth nor completeness of the supplied query.
    """
    try:
        _require(facts and all(names and len(names) == len(set(names)) for names in facts.values()),
                 "fact selection is empty or duplicated")
        _require(original_functions.keys() == consumer_functions.keys()
                 and original_symbols.keys() == consumer_symbols.keys(), "fact consumer universe differs")
        for identity in original_symbols:
            _require(_symbol_payload(original_symbols[identity]) == _symbol_payload(consumer_symbols[identity]),
                     "fact consumer symbol differs: " + identity)
        _require(facts.keys() <= original_functions.keys(), "fact helper is absent")
        bindings = []
        for function, before in original_functions.items():
            after = consumer_functions[function]
            removed = set()
            for description in facts.get(function, []):
                assertions = [(i, row) for i, row in enumerate(before['instructions'])
                              if row['instructionId'] == 'ASSERT'
                              and row.get('sourceLocation', {}).get('comment') == description]
                sites = [(i, row) for i, row in enumerate(after['instructions'])
                         if row['instructionId'] == 'ASSERT'
                         and row.get('sourceLocation', {}).get('comment') == description]
                _require(len(assertions) == len(sites) == 1, "fact assertion is missing or ambiguous")
                _, assertion = assertions[0]
                index, consumer_assertion = sites[0]
                _require(_scalar_fact_guard(assertion['guard'], original_symbols),
                         "fact guard is not a stable scalar expression")
                _require(_payload(assertion) == _payload(consumer_assertion), "fact assertion differs")
                _require(index+1 < len(after['instructions']), "fact assumption is absent")
                assumed = after['instructions'][index+1]
                _require(assumed['instructionId'] == 'ASSUME'
                         and _fact_condition(assumed['guard']) == _fact_condition(assertion['guard']),
                         "fact assumption is not the immediately preceding assertion")
                _require(_payload(assumed) == {**_payload(consumer_assertion), 'instructionId': 'ASSUME',
                         'guard': _semantic(assumed['guard']), 'property': {}},
                         "fact assumption has additional semantics")
                _require(not any(assumed['locationNumber'] in row.get('targets', []) for row in after['instructions']),
                         "control flow bypasses the fact assertion")
                removed.add(index+1)
                bindings.append({'function': function, 'description': description,
                                 'original_property_id': assertion['sourceLocation']['propertyId'],
                                 'guard_sha256': canonical_sha256_v3(_semantic(assertion['guard']))})
            reduced = {**after, 'instructions': [row for i, row in enumerate(after.get('instructions', [])) if i not in removed]}
            _require(_function_payload(before) == _function_payload(reduced),
                     "fact consumer changes more than the checked assumptions: " + function)
        return {'status': 'matched-same-program-fact-consumption', 'authorizing': False, 'facts': bindings,
                'fact_truth_checked': False, 'query_domain_checked': False, 'body_independent': False}
    except BisimulationRefinementError:
        raise
    except (KeyError, TypeError, IndexError, ValueError) as error:
        raise BisimulationRefinementError('fact consumption: malformed compiler inventory: '+str(error)) from error


def check_compiled_fact_substitution(*, original_functions, consumer_functions,
                                    original_symbols, consumer_symbols, function, description):
    """Check one scalar assignment that is an identity under a qualified equality.

    The equality must be separately proved on this original whole program and
    query domain. Its immediately following assignment copies the equal scalar
    into a nonvolatile automatic local. Keep the call producing that local and
    all of its effects. This is deliberately limited to direct, equally typed
    integer symbols; it does not infer memory, pointer or cast correspondence.
    No body independence, fact truth, query coverage or activation is granted.
    """
    try:
        _require(original_functions.keys() == consumer_functions.keys()
                 and original_symbols.keys() == consumer_symbols.keys(), "substitution universe differs")
        for identity in original_symbols:
            _require(_symbol_payload(original_symbols[identity]) == _symbol_payload(consumer_symbols[identity]),
                     "substitution symbol differs: " + identity)
        before, after = original_functions[function], consumer_functions[function]
        selected = [[(i, row) for i, row in enumerate(body['instructions'])
                     if row['instructionId'] == 'ASSERT'
                     and row.get('sourceLocation', {}).get('comment') == description]
                    for body in (before, after)]
        _require(all(len(sites) == 1 for sites in selected), "substitution equality is missing or ambiguous")
        _, assertion = selected[0][0]
        index, consumer_assertion = selected[1][0]
        _require(_payload(assertion) == _payload(consumer_assertion), "substitution equality differs")
        guard = _fact_condition(assertion['guard'])
        operands = guard.get('sub', [])
        _require(guard.get('id') in {'=', 'equal'} and len(operands) == 2
                 and all(_symbol(v) is not None and _scalar_fact_guard(v, original_symbols) for v in operands),
                 "substitution requires direct stable scalar equality")
        left, right = operands
        _require(left['namedSub']['type'] == right['namedSub']['type'], "substitution scalar types differ")
        target = original_symbols[_symbol(left)]
        _require(target.get('isStaticLifetime') is False and target.get('isLvalue') is True
                 and target.get('isVolatile') is False
                 and target.get('location', {}).get('function') == function,
                 "substitution target must be an automatic local")
        _require(index + 1 < len(after['instructions']), "substitution assignment is absent")
        assignment = after['instructions'][index + 1]
        _require(_payload(assignment) == {
            'instructionId': 'ASSIGN', 'property': {},
            'code': {'id': 'code', 'namedSub': {'statement': {'id': 'assign'}, 'type': {'id': 'empty'}},
                     'sub': [left, right]}}, "substitution is not the adjacent equality-preserving assignment")
        _require(not any(assignment['locationNumber'] in row.get('targets', []) for row in after['instructions']),
                 "control flow bypasses the substitution equality")
        reduced = {**after, 'instructions': after['instructions'][:index+1] + after['instructions'][index+2:]}
        for identity, body in original_functions.items():
            _require(_function_payload(body) == _function_payload(reduced if identity == function
                                                                 else consumer_functions[identity]),
                     "substitution changes additional semantics: " + identity)
        return {'status': 'matched-same-program-scalar-substitution', 'authorizing': False,
                'function': function, 'description': description,
                'original_property_id': assertion['sourceLocation']['propertyId'],
                'guard_sha256': canonical_sha256_v3(guard), 'target': _symbol(left), 'value': _symbol(right),
                'fact_truth_checked': False, 'query_domain_checked': False, 'body_independent': False}
    except BisimulationRefinementError:
        raise
    except (KeyError, TypeError, IndexError, ValueError) as error:
        raise BisimulationRefinementError('fact substitution: malformed compiler inventory: '+str(error)) from error
