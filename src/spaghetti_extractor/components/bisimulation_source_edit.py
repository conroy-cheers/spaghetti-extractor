"""Compare finite scalar decisions, optionally after an identical effect prefix.

This experimental profile admits only comparisons, truth operations and
value-preserving integer casts. Only newly introduced, nonescaping automatic
temporaries may be written. Consequently all preexisting storage, including
unobserved heap contents, is unchanged. Context and inert-marker checks remain
mandatory. An optional identical prefix preserves its calls, effects and early
returns on both sides; only its changed suffix is pure. CBMC must separately
establish equality of the outgoing ports for every suffix input.
"""

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_cut_state import _symbol, _walk
from spaghetti_extractor.components.bisimulation_entry_conformance import _semantic, _truth
from .bisimulation_region_context import _region, check_region_context_transport
from .bisimulation_edit_prefix import common_effect_prefix


POLICY = 'pure-scalar-region-comparison-v1'


def _require(condition, message):
    if not condition:
        raise ValueError('pure region comparison: ' + message)


def _type(value):
    value = _semantic(value)
    kind, attributes = value.get('id'), value.get('namedSub', {})
    _require(set(value) <= {'id', 'namedSub'}, 'unsupported scalar type payload')
    if kind == 'bool':
        _require(not attributes, 'qualified Boolean type')
        return ('bool', 1)
    _require(kind in {'signedbv', 'unsignedbv'} and set(attributes) <= {'width', '#c_type', '#typedef'},
             'only unqualified integer scalars are supported')
    width = attributes.get('width', {}).get('id')
    _require(width in {'8', '16', '32', '64'}, 'unsupported integer width')
    return kind, int(width)


def _ctype(typ):
    kind, width = typ
    return '_Bool' if kind == 'bool' else ('int' if kind == 'signedbv' else 'uint') + str(width) + '_t'


def _bounds(typ):
    kind, width = typ
    if kind == 'bool':
        return 0, 1
    return (-(1 << (width - 1)), (1 << (width - 1)) - 1) if kind == 'signedbv' else (0, (1 << width) - 1)


def prepare_pure_region_comparison(*, original_functions, original_symbols, edited_functions,
                                   edited_symbols, function, entry, exits):
    """Return a CBMC input, not evidence or authorization to import prior results."""
    arguments = dict(original_functions=original_functions, original_symbols=original_symbols,
                     edited_functions=edited_functions, edited_symbols=edited_symbols,
                     function=function, entry=entry, exits=exits)
    context = check_region_context_transport(**arguments)
    region_inputs = [_region(bodies, function, entry, exits) for bodies in (original_functions, edited_functions)]
    prefix = common_effect_prefix(bodies=[original_functions[function], edited_functions[function]], regions=region_inputs)
    if prefix is not None:
        prefix_binding, region_inputs = prefix
    else:
        _require('@return' not in context['ports'], 'function returns require result-state transport')
    added = set(context['new_private_scalars'])
    inputs, functions, regions = {}, [], []
    port_ids = {name: i + 1 for i, name in enumerate(sorted(region_inputs[0][2]))}

    for side, bodies, symbols in [('original', original_functions, original_symbols),
                                   ('edited', edited_functions, edited_symbols)]:
        start, owned, ports = region_inputs[0 if side == 'original' else 1]
        rows = bodies[function]['instructions']
        locations = {row['locationNumber']: i for i, row in enumerate(rows)}
        private = added if side == 'edited' else set()
        names = {name: 'private_' + str(i) for i, name in enumerate(sorted(private))}
        side_inputs, declarations = {}, set()

        def object_type(identity):
            symbol = symbols.get(identity, {})
            _require(symbol.get('isStaticLifetime') is False
                     and symbol.get('location', {}).get('function') == function,
                     'scalar input is not an automatic object of this function')
            return _type(symbol['type'])

        def expression(node, initialized):
            kind, operands, named = node.get('id'), node.get('sub', []), node.get('namedSub', {})
            _require(set(node) <= {'id', 'sub', 'namedSub'}, 'unsupported expression payload')
            allowed = {'type', '#source_location'} | ({'identifier'} if kind == 'symbol' else {'value'} if kind == 'constant' else set())
            _require(set(named) <= allowed, 'unsupported expression attributes')
            typ = _type(named.get('type', {}))
            if kind == 'symbol':
                identity = _symbol(node)
                _require(not operands and object_type(identity) == typ, 'scalar occurrence type differs')
                if identity in private:
                    _require(identity in initialized, 'private scalar used before definite initialization')
                    return names[identity], typ
                _require(typ[0] != 'bool', 'Boolean input representation is unsupported')
                side_inputs[identity] = typ
                return 'input_' + str(input_ids[identity]), typ
            if kind == 'constant':
                _require(not operands, 'constant has operands')
                value = named.get('value', {}).get('id')
                if typ[0] == 'bool':
                    _require(value in {'true', 'false'}, 'invalid Boolean constant')
                    return ('1' if value == 'true' else '0'), typ
                bits = int(value, 16)
                _require(0 <= bits < (1 << typ[1]), 'integer constant exceeds its type')
                if typ[0] == 'signedbv' and bits >= 1 << (typ[1] - 1):
                    bits -= 1 << typ[1]
                literal = '(-9223372036854775807LL - 1LL)' if bits == -(1 << 63) else str(bits) + ('LL' if typ[0] == 'signedbv' else 'ULL')
                return '(' + _ctype(typ) + ')(' + literal + ')', typ
            values = [expression(v, initialized) for v in operands]
            if kind == 'typecast' and len(values) == 1:
                lo, hi = _bounds(values[0][1])
                target_lo, target_hi = _bounds(typ)
                _require(target_lo <= lo and hi <= target_hi, 'cast is not value preserving')
                return '(' + _ctype(typ) + ')(' + values[0][0] + ')', typ
            if kind == 'not' and len(values) == 1 and typ == ('bool', 1) and values[0][1] == typ:
                return '!(' + values[0][0] + ')', typ
            if kind in {'equal', 'notequal'} and len(values) == 2 and typ == ('bool', 1):
                _require(values[0][1] == values[1][1], 'comparison operand types differ')
                return '(' + values[0][0] + ')' + ('==' if kind == 'equal' else '!=') + '(' + values[1][0] + ')', typ
            raise ValueError('pure region comparison: unsupported expression: ' + str(kind))

        # Stable argument names are derived from the actual compiled symbol
        # inventory. No operator-provided list can omit a dependency.
        referenced = {_symbol(n) for i in owned for n in _walk([rows[i].get('code', {}), rows[i].get('guard', {})]) if _symbol(n)}
        input_ids = {name: i for i, name in enumerate(sorted(referenced - private))}
        # Full caller instruction numbers are context bindings, not local
        # semantics. Dense local labels let the same checked region be consumed
        # in an instrumented proof harness without changing its solver query.
        labels = {index: 'label_' + str(i) for i, index in enumerate(sorted(owned))}
        labels.update({index: 'exit_' + str(port_ids[name]) for name, index in ports.items()})

        def destination(index):
            seen = set()
            while index not in owned and index not in ports.values():
                _require(index not in seen and 0 <= index < len(rows), 'invalid exit path')
                seen.add(index)
                _require(rows[index]['instructionId'] in {'SKIP', 'LOCATION'}, 'unaccounted exit instruction')
                index += 1
            return index

        # Analyze each node after all incoming paths. Intersect initialization
        # sets at joins; never treat one successful path as definite assignment.
        edges = {}
        for index in owned:
            row = rows[index]
            kind = row['instructionId']
            _require(kind in {'DECL', 'ASSIGN', 'DEAD', 'GOTO', 'SKIP', 'LOCATION'},
                     'effect or unsupported instruction: ' + kind)
            _require(not row.get('targets') or kind == 'GOTO', 'target on a non-branch')
            guard = _truth(row.get('guard', {}), {}) if kind == 'GOTO' else False
            edges[index] = ([destination(locations[row['targets'][0]])] if guard is not False else []) + (
                [destination(index + 1)] if guard is not True else [])
        incoming = {i: [] for i in owned}
        for index, successors in edges.items():
            for successor in set(successors) & owned:
                incoming[successor].append(index)
        initialized_after, live_after, emitted = {}, {}, {}
        pending = set(owned)
        while pending:
            ready = sorted(i for i in pending if set(incoming[i]) <= initialized_after.keys())
            _require(ready, 'cyclic private initialization')
            for index in ready:
                initialized = set.intersection(*(initialized_after[i] for i in incoming[index])) if incoming[index] else set()
                live = set.intersection(*(live_after[i] for i in incoming[index])) if incoming[index] else set()
                row = rows[index]
                kind, code = row['instructionId'], row.get('code', {})
                values = code.get('sub', [])
                statement = ''
                if kind in {'DECL', 'ASSIGN', 'DEAD'}:
                    _require(code.get('id') == 'code' and code.get('namedSub', {}).get('statement', {}).get('id') == kind.lower(),
                             'instruction statement differs')
                    _require(len(values) == (2 if kind == 'ASSIGN' else 1), 'invalid scalar instruction operands')
                    identity = _symbol(values[0])
                    _require(identity in private, 'write or lifetime change to preexisting storage')
                    typ = object_type(identity)
                    _require(_type(values[0]['namedSub']['type']) == typ, 'write occurrence type differs')
                    if kind == 'DECL':
                        _require(identity not in declarations, 'repeated private declaration')
                        declarations.add(identity)
                        initialized.discard(identity)
                        live.add(identity)
                    elif kind == 'ASSIGN':
                        _require(identity in live, 'assignment outside private lifetime')
                        value, value_type = expression(values[1], initialized)
                        _require(value_type == typ, 'assignment changes scalar type')
                        statement = names[identity] + ' = ' + value + ';'
                        initialized.add(identity)
                    else:
                        _require(identity in live, 'end of absent private lifetime')
                        initialized.discard(identity)
                        live.remove(identity)
                if kind == 'GOTO':
                    value, typ = expression(row['guard'], initialized)
                    _require(typ == ('bool', 1), 'non-Boolean branch guard')
                    target = destination(locations[row['targets'][0]])
                    statement = 'if (' + value + ') goto ' + labels[target] + ';'
                    if _truth(row['guard'], {}) is not True:
                        statement += ' goto ' + labels[destination(index + 1)] + ';'
                else:
                    statement += ' goto ' + labels[destination(index + 1)] + ';'
                emitted[index] = labels[index] + ':; ' + statement
                initialized_after[index] = initialized
                live_after[index] = live
                pending.remove(index)
        _require(declarations == private, 'private declaration is outside the region')
        parameters = ', '.join(_ctype(side_inputs[name]) + ' input_' + str(input_ids[name]) for name in sorted(side_inputs)) or 'void'
        lines = ['static unsigned int region_' + side + '(' + parameters + ') {']
        lines += ['  ' + _ctype(object_type(name)) + ' ' + names[name] + ';' for name in sorted(private)]
        lines += ['  goto ' + labels[destination(start + 1)] + ';']
        lines += ['  ' + emitted[i] for i in sorted(emitted)]
        lines += [labels[index] + ':; return ' + str(port_ids[name]) + 'U;' for name, index in sorted(ports.items())]
        lines += ['}']
        functions.append('\n'.join(lines))
        inputs.update(side_inputs)
        regions.append({'side': side, 'inputs': side_inputs, 'indices': sorted(owned),
                        'labels': {str(index): label for index, label in sorted(labels.items())},
                        'body_sha256': canonical_sha256_v3([_semantic(rows[i]) for i in sorted(owned)])})
    input_names = {name: 'value_' + str(i) for i, name in enumerate(sorted(inputs))}
    calls = ['region_' + row['side'] + '(' + ', '.join(input_names[name] for name in sorted(row['inputs'])) + ')' for row in regions]
    parameters = ', '.join(_ctype(inputs[name]) + ' ' + value for name, value in input_names.items()) or 'void'
    source = '#include <stdint.h>\n' + '\n'.join(functions) + '\nvoid compare_regions(' + parameters + ') {\n'
    source += '  unsigned int original_port = ' + calls[0] + ';\n  unsigned int edited_port = ' + calls[1] + ';\n'
    source += '  __CPROVER_assert(original_port == edited_port, "pure-region:exit-port");\n}\n'
    binding = {'policy': POLICY, 'context': context, 'regions': regions, 'port_ids': port_ids,
               'inputs': inputs, 'source_sha256': canonical_sha256_v3(source)}
    if prefix is not None:
        binding['policy'] = 'common-prefix-pure-suffix-comparison-v1'
        binding['common_prefix'] = prefix_binding
    return {'status': 'prepared', 'authorizing': False, 'source': source, 'binding': binding,
            'binding_sha256': canonical_sha256_v3(binding), 'preexisting_storage_unchanged': prefix is None,
            **({'common_prefix_effects_preserved': True, 'suffix_preexisting_storage_unchanged': True} if prefix is not None else {}),
            'local_behavior_checked': False, 'parent_evidence_imported': False}
