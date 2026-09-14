"""Bind compiled contract clauses and their declarations, without importing proofs.

CBMC keeps specifications on ``contract::<function>``, separately from the
ordinary function signature. Equal signatures do not establish equal contracts.
This deliberately checks identity, not logical implication or compatibility.
Input-state correspondence, callee qualification and evidence binding remain
separate obligations. Contract helpers need a separate semantic dependency rule.
"""

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import _semantic
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError


POLICY = 'compiled-contract-identity-v1'
_CLAUSES = frozenset({'#spec_requires', '#spec_ensures', '#spec_assigns', '#spec_frees'})
_STORAGE = ('isStaticLifetime', 'isThreadLocal', 'isFileLocal', 'isType', 'isMacro', 'isLvalue')


def _require(condition, detail):
    if not condition:
        raise BisimulationRefinementError('compiled contract binding: ' + detail)


def _free_symbols(node, bound=frozenset()):
    if isinstance(node, list):
        return set().union(*(_free_symbols(child, bound) for child in node))
    if not isinstance(node, dict):
        return set()
    if node.get('id') == 'lambda':
        operands = node.get('sub', [])
        _require(len(operands) == 2 and operands[0].get('id') == 'tuple', 'unsupported clause binder')
        parameters = operands[0].get('sub', [])
        names = [_symbol(v) for v in parameters]
        _require(all(names) and len(names) == len(set(names)), 'invalid clause parameters')
        return _free_symbols(operands[1], bound | set(names))
    identity = _symbol(node)
    found = {identity} if identity and identity not in bound else set()
    for key, value in node.items():
        if key != '#source_location':
            found.update(_free_symbols(value, bound))
    return found


def _declaration(symbol):
    return {'type': _semantic(symbol['type']), **{key: symbol.get(key) for key in _STORAGE}}


def check_compiled_contract_identity(*, qualified_symbols, consumer_symbols, function):
    """Compare exact clause ASTs, free storage declarations and recursive type layout."""
    contract_name = 'contract::' + function
    _require(all(name in symbols for symbols in (qualified_symbols, consumer_symbols)
                 for name in (function, contract_name)), 'missing compiled contract or function')
    signature = _semantic(qualified_symbols[function]['type'])
    _require(signature.get('id') == 'code' and signature == _semantic(consumer_symbols[function]['type']),
             'function signature differs')
    contract = _semantic(qualified_symbols[contract_name]['type'])
    _require(contract.get('id') == 'code', 'contract is not a function specification')
    clauses = {key for key in contract.get('namedSub', {}) if key.startswith('#spec_')}
    _require(clauses == _CLAUSES, 'missing or unsupported contract clauses')
    _require(contract == _semantic(consumer_symbols[contract_name]['type']), 'contract clauses differ')
    _require(not any(node.get('id') == 'side_effect' for node in _walk(contract)),
             'contract helper needs separate semantic binding: call or effect expression')
    # Initializers belong to caller-domain qualification, not contract identity.
    # Storage class and object/type identity must still match.
    declarations = []
    pending = [signature, contract]
    for identity in sorted(_free_symbols(contract)):
        _require(identity in qualified_symbols and identity in consumer_symbols,
                 'missing contract dependency: ' + identity)
        left, right = qualified_symbols[identity], consumer_symbols[identity]
        _require(left.get('type', {}).get('id') != 'code',
                 'contract helper needs separate semantic binding: ' + identity)
        _require(left.get('isStaticLifetime') is True, 'unbound automatic contract dependency: ' + identity)
        declaration = _declaration(left)
        _require(declaration == _declaration(right), 'contract dependency declaration differs: ' + identity)
        declarations.append({'symbol': identity, 'declaration_sha256': canonical_sha256_v3(declaration)})
        pending.append(left['type'])
    tags = {}
    while pending:
        for node in _walk(pending.pop()):
            if node.get('id') not in {'struct_tag', 'union_tag', 'c_enum_tag'}:
                continue
            identity = node.get('namedSub', {}).get('identifier', {}).get('id')
            _require(identity in qualified_symbols and identity in consumer_symbols, 'missing aggregate definition')
            if identity in tags:
                continue
            left, right = qualified_symbols[identity], consumer_symbols[identity]
            _require(left.get('isType') is True and right.get('isType') is True, 'aggregate tag is not a type')
            definition = _semantic(left['type'])
            _require(definition == _semantic(right['type']), 'aggregate definition differs: ' + identity)
            tags[identity] = canonical_sha256_v3(definition)
            pending.append(definition)
    return {'policy': POLICY, 'status': 'matched', 'authorizing': False, 'function': function,
            'signature_sha256': canonical_sha256_v3(signature), 'contract_sha256': canonical_sha256_v3(contract),
            'clause_counts': {key.removeprefix('#spec_'): len(contract['namedSub'][key].get('sub', []))
                              for key in sorted(_CLAUSES)},
            'storage_dependencies': declarations, 'aggregate_definitions': dict(sorted(tags.items())),
            'callee_body_checked': False, 'input_domain_checked': False, 'theorem_import_authorized': False}
