"""Byte-backed transport of checked regional private-cell representations.

The model checks actual private accessor clauses and preserves arbitrary bytes
outside each update. It does not qualify physical accessibility or lifetime.
"""
import re

from .bisimulation_compaction_contract import require


def _function(source, name):
    match = re.search(r'static (?:uint32_t|void) ' + name + r'\([^)]*\)\s*\{', source)
    require(match is not None, 'missing private accessor ' + name)
    start, depth = match.end(), 1
    for index in range(start, len(source)):
        depth += (source[index] == '{') - (source[index] == '}')
        if depth == 0:
            return source[start:index]
    raise ValueError('unterminated private accessor ' + name)


def private_cell_layout(source, *, anchor_delta):
    """Accept the generated direct scalar clauses; retain their exact syntax."""
    read, write = (_function(source, n) for n in ['machine_read', 'machine_write'])
    guard = r'if\(address==m->(entry|stack)([+-])(\d+)U? && width==([124])U\)'
    read_pattern = guard + r'return m->((?:word_\d+)|(?:private_\w+));'
    write_pattern = guard + r'\{m->((?:word_\d+)|(?:private_\w+))=(?:\(uint(?:8|16|32)_t\))?value;return;\}'
    # Loop offsets always contain '+0U'; entry/tail use the same affine form.
    reads, writes = list(re.finditer(read_pattern, read)), list(re.finditer(write_pattern, write))
    require(reads and writes, 'missing supported private accesses')
    for body, pattern in [(read, read_pattern), (write, write_pattern)]:
        require(not re.search(r'm->(?:word_\d+|private_\w+)', re.sub(pattern, '', body)),
                'private accessor has an unsupported cell effect or alias')
    cells, seen, guards = [], set(), set()
    for match in reads:
        anchor, sign, offset, width, field = match.groups()
        offset, width = int(offset) * (1 if sign == '+' else -1), int(width)
        declarations = re.findall(r'uint(8|16|32)_t\s+' + field + r'\s*;', source)
        require(declarations and set(declarations) == {str(width * 8)} and field not in seen,
                'private cell type or identity differs')
        require((offset, width) not in guards, 'ambiguous private guard precedence')
        guards.add((offset, width))
        seen.add(field)
        cells.append({'field': field, 'offset': offset, 'width': width, 'read': match[0]})
    anchors = {m[1] for m in reads + writes}
    require(len(anchors) == 1, 'private accessors use different anchors')
    by_field = {c['field']: c for c in cells}; mutable = set()
    for match in writes:
        _, sign, offset, width, field = match.groups()
        require(field in by_field and field not in mutable, 'private write has no unique readable cell')
        cell = by_field[field]
        require(cell['offset'] == int(offset) * (1 if sign == '+' else -1) and cell['width'] == int(width),
                'private read/write views differ')
        cast = re.search(r'=\(uint(8|16|32)_t\)value', match[0])
        require(cast is None or int(cast[1]) >= 8 * cell['width'], 'private store narrows before cell assignment')
        mutable.add(field); cell['write'] = match[0]
    # Service adapters can update private words directly instead of calling
    # machine_write. The inductive store lemma must also cover those updates.
    direct = set(re.findall(r'm->((?:word_\d+)|(?:private_\w+))\s*(?:=(?!=)|[+*/%&|^-]=|(?:<<|>>)=|\+\+|--)', source))
    direct.update(re.findall(r'(?:\+\+|--)\s*m->((?:word_\d+)|(?:private_\w+))', source))
    require(direct <= mutable, 'direct private mutation is outside the checked writable cells')
    require(not re.search(r'&\s*m->(?:word_\d+|private_\w+)', source), 'private cell address escapes')
    return {'anchor': next(iter(anchors)), 'anchor_delta': anchor_delta, 'cells': cells,
            'direct_writes': sorted(direct)}


def cleanup_private_transport_domain(models):
    layouts = {n: private_cell_layout(models[n], anchor_delta=0 if n == 'entry' else -12)
               for n in ['entry', 'loop', 'tail']}
    # Bind the meaning of the values carried by the byte relation to actual
    # checked entry/return assertions, not merely to similarly named fields.
    require('memory.word_9==initial.ebp && memory.word_4==initial.ebx && memory.word_3==initial.esi && memory.word_10==return_word'
        in models['entry'], 'missing checked entry saved-frame guarantee')
    require('saved_esi=memory.word_11,saved_ebx=memory.word_12,saved_ebp=memory.word_17,return_word=memory.word_18'
        in models['tail'] and 'state.esp==stack+16U && state.esi==saved_esi && state.ebx==saved_ebx && state.ebp==saved_ebp && step.value==return_word'
        in models['tail'], 'missing checked terminal saved-frame guarantee')
    frame = {'esi': ['word_3', 'word_11'], 'ebx': ['word_4', 'word_12'],
             'ebp': ['word_9', 'word_17'], 'return_word': ['word_10', 'word_18']}
    low = min(c['offset'] + layout['anchor_delta'] for layout in layouts.values() for c in layout['cells'])
    high = max(c['offset'] + layout['anchor_delta'] + c['width'] for layout in layouts.values() for c in layout['cells'])
    require(low == -72 and high == 4 and [len(layouts[n]['cells']) for n in layouts] == [11, 3, 19],
            'unsupported complete private span or cell inventory')
    return {'profile': 'cleanup-private-byte-transport-v1', 'low': low, 'high': high,
        'layouts': layouts, 'saved_frame': frame, 'removed': ['word_7', 'private_removed', 'word_15'],
        'requires': ['Checked regional private accessor clauses under the proposed spatial envelope.',
            'Normal entry saved-frame and terminal restoration guarantees from the imported regional proofs.'],
        'scope': 'Inductive private-cell/byte correspondence and saved-frame transport only; physical accessibility, public heap contents and lifetimes remain unqualified.'}



def private_transport_data(domain):
    layouts = domain['layouts']
    data = {'PRIVATE_SIZE': domain['high'] - domain['low'],
            'CELL_CAPACITY': max(len(v['cells']) for v in layouts.values())}
    for role, layout in layouts.items():
        data[role+'_cells'] = [[c['offset']+layout['anchor_delta']-domain['low'], c['width']] for c in layout['cells']]
        data[role+'_writable'] = [[i] for i, c in enumerate(layout['cells']) if 'write' in c]
    index = lambda role, field: next(i for i, c in enumerate(layouts[role]['cells']) if c['field'] == field)
    data['saved_frame'] = [[index('entry', pair[0]), index('tail', pair[1])]
                           for _, pair in sorted(domain['saved_frame'].items())]
    data['removed_cells'] = [[index(role, field)] for role, field in zip(['entry', 'loop', 'tail'], domain['removed'], strict=True)]
    data['partial_word'] = [[index(role, field)] for role, field in [
        ('entry', 'word_8'), ('tail', 'word_16'), ('loop', 'private_c'), ('loop', 'private_b')]]
    return data


def private_transport_header(domain):
    lines = []
    for name, value in private_transport_data(domain).items():
        if isinstance(value, int):
            lines.append(f'#define {name} {value}U')
        else:
            values = ','.join('{'+','.join(str(v)+'U' for v in row)+'}' for row in value)
            lines.append(f'static const uint32_t {name}[{len(value)}][{len(value[0])}]={{{values}}};')
    return '\n'.join(lines) + '\n'


def check_private_transport_header(header, domain):
    """Parse data declarations; importing a proof does not regenerate its model."""
    values = {}
    for line in header.splitlines():
        macro = re.fullmatch(r'#define ([A-Z_]+) (\d+)U', line)
        array = re.fullmatch(r'static const uint32_t (\w+)\[(\d+)\]\[(\d+)\]=(\{[{},0-9U]+\});', line)
        require(macro is not None or array is not None, 'unsupported private transport header declaration')
        if macro is not None:
            name, value = macro[1], int(macro[2])
        else:
            import json
            name = array[1]
            value = json.loads(array[4].replace('U', '').replace('{', '[').replace('}', ']'))
            require(len(value) == int(array[2]) and all(len(row) == int(array[3]) for row in value),
                    'private transport table dimensions differ')
        require(name not in values, 'duplicate private transport table')
        values[name] = value
    require(values == private_transport_data(domain), 'private transport tables differ from checked accessors')
