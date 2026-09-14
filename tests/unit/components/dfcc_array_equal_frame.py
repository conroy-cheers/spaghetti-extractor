"""Restricted frame argument for CBMC 6.9's retained array_equal instructions.

DFCC warns about this opcode. CBMC's symex_other.cpp implements it by reading
two operands and assigning only the third. Verify that this destination is a
fresh compiler Boolean, and that instrumentation retains the original operation.
This does not prove memory-read safety, comparison truth or general DFCC soundness.
"""

from collections import Counter
import re

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import _payload


WARNING = ("dfcc_instrument::instrument_other: statement type 'array_equal' "
           "is not supported, analysis may be unsound")


def _require(condition, message):
    if not condition:
        raise ValueError('DFCC array equality frame: ' + message)


def _operations(functions, symbols, *, instrumented):
    operations = []
    for name, function in functions.items():
        rows = function.get('instructions', [])
        for index, row in enumerate(rows):
            code = row.get('code', {})
            if code.get('namedSub', {}).get('statement', {}).get('id') != 'array_equal':
                continue
            args = code.get('sub', [])
            _require(row['instructionId'] == 'OTHER' and len(args) == 3 and not row.get('targets'),
                     'unexpected intrinsic shape')
            identity = _symbol(args[2])
            symbol = symbols.get(identity, {})
            owner = symbol.get('location', {}).get('function')
            _require(identity and owner and name in {owner, owner + '_wrapped_for_contract_checking'}
                     and symbol.get('isAuxiliary') is True and symbol.get('isStaticLifetime') is False
                     and symbol.get('isParameter') is False and symbol.get('type', {}).get('id') == 'bool'
                     and args[2].get('namedSub', {}).get('type') == symbol['type'],
                     'result is not a private compiler Boolean')
            _require(not any({'#volatile', 'C_volatile'} & v.get('namedSub', {}).keys()
                             for v in _walk(symbol['type'])), 'volatile result')
            declarations = [i for i, r in enumerate(rows) if r['instructionId'] == 'DECL'
                            and _symbol(r.get('code', {}).get('sub', [{}])[0]) == identity]
            _require(len(declarations) == 1 and declarations[0] < index, 'missing fresh result declaration')
            _require(not any(row['locationNumber'] in r.get('targets', []) for r in rows),
                     'control flow bypasses result declaration')
            # The raw compiler emits DECL immediately before this intrinsic.
            # DFCC may insert private-object registration between the two.
            if not instrumented:
                _require(declarations == [index - 1], 'raw result is not freshly declared')
                _require(not any(n.get('id') == 'address_of' and any(_symbol(v) == identity for v in _walk(n))
                                 for r in rows for n in _walk(r.get('code', {}))),
                         'raw result address escapes')
            _require(not any(v.get('id') in {'side_effect', 'nondet_symbol', 'code'}
                             for arg in args[:2] for v in _walk(arg)), 'input expression has an effect')
            _require(all(arg.get('namedSub', {}).get('type', {}).get('id') == 'pointer'
                         for arg in args[:2]), 'inputs are not pointers')
            operations.append({'owner': owner, 'result': identity,
                               'file': row.get('sourceLocation', {}).get('file'),
                               'line': row.get('sourceLocation', {}).get('line'),
                               'payload_sha256': canonical_sha256_v3(_payload(row))})
    return operations


def check_array_equal_frame(*, original_functions, original_symbols,
                            instrumented_functions, instrumented_symbols, warnings):
    """Account only for these warnings; any other diagnostic remains a rejection."""
    _require(warnings and all(line.startswith('file ') and line.endswith(WARNING) for line in warnings),
             'unrecognized instrumentation diagnostic')
    original = _operations(original_functions, original_symbols, instrumented=False)
    retained = _operations(instrumented_functions, instrumented_symbols, instrumented=True)
    key = lambda v: (v['owner'], v['result'], v['payload_sha256'])
    before, after = Counter(map(key, original)), Counter(map(key, retained))
    _require(not after - before, 'instrumentation changed an intrinsic')
    location = lambda v: (v['file'], v['line'], v['owner'])
    emitted = []
    for warning in warnings:
        match = re.fullmatch(r'file (.+) line ([0-9]+) function ([^:]+): ' + re.escape(WARNING), warning)
        _require(match is not None, 'unrecognized diagnostic location')
        emitted.append(match.groups())
    raw_locations, kept_locations = Counter(map(location, original)), Counter(map(location, retained))
    diagnostic_locations = Counter(emitted)
    _require(not diagnostic_locations - raw_locations and not kept_locations - diagnostic_locations,
             'diagnostic coverage differs')
    # DFCC diagnoses before removing unused functions. Account for those
    # warnings only when the entire original helper body is absent afterward.
    pruned = diagnostic_locations - kept_locations
    for _, _, owner in pruned:
        _require(not any(instrumented_functions.get(name, {}).get('isBodyAvailable')
                         for name in [owner, owner + '_wrapped_for_contract_checking']),
                 'diagnostic lost from a surviving body')
    return {'status': 'checked-private-array-equality-frame', 'authorizing': False,
            'retained_operations': retained, 'removed_operations': sum((before - after).values()),
            'pruned_body_diagnostics': sum(pruned.values()),
            'memory_read_safety_checked': False, 'comparison_truth_checked': False,
            'callee_contract_checked': False,
            'semantics_source': 'https://github.com/diffblue/cbmc/blob/cbmc-6.9.0/src/goto-symex/symex_other.cpp#L201'}
