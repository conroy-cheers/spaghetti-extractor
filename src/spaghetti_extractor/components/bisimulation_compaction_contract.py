"""Explicit domain for a conditional local byte-compaction iteration theorem."""
import re

REGISTERS = {'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi'}
FLAGS = {'cf', 'zf', 'sf', 'of', 'pf', 'df', 'eflags'}
PROFILE = 'local-byte-compaction-step-v1'


def require(condition, detail):
    if not condition:
        raise ValueError('local compaction contract: ' + detail)


def checked_compaction_contract(value):
    require(isinstance(value, dict) and set(value) - {'runtime_revision'} == {
        'profile', 'graph_index', 'entry_cut', 'exit_cut', 'regions', 'begin',
        'source_locals', 'text_parameter', 'entry_rva', 'exit_rva', 'image_base',
        'registers', 'private_cells', 'private_extent', 'stack_offsets', 'clobbers'}, 'fields differ')
    require(value['profile'] == PROFILE, 'unsupported runtime profile')
    require(type(value.get('runtime_revision', 2)) is int and value.get('runtime_revision', 2) in {2, 3},
            'unsupported runtime revision')
    for key in ['graph_index', 'entry_rva', 'exit_rva', 'image_base', 'private_extent']:
        require(type(value[key]) is int and 0 <= value[key] < 2**32, 'invalid ' + key)
    require(0 < value['private_extent'] <= 4096 and value['entry_rva'] != value['exit_rva']
            and 0 < value['entry_rva'] < 0xffffffff and 0 < value['exit_rva'] < 0xffffffff, 'invalid span or cuts')
    identifier = lambda v: isinstance(v, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', v)
    require(all(identifier(value[k]) for k in ['entry_cut', 'exit_cut', 'text_parameter']), 'invalid source role')
    roles = value['source_locals']
    require(isinstance(roles, dict) and set(roles) == {'input', 'output', 'removed', 'scratch'}
            and all(identifier(v) for v in roles.values()) and len(set(roles.values())) == 4, 'invalid source locals')
    entries = value['regions']
    require(isinstance(entries, list) and entries and all(identifier(v) for v in entries)
            and len(set(entries)) == len(entries) and value['entry_cut'] in entries
            and value['exit_cut'] not in entries, 'invalid selected regions')
    begin = value['begin']
    require(isinstance(begin, dict) and set(begin) == {'position', 'text'}
            and begin['position'] in {'before', 'after'} and isinstance(begin['text'], str)
            and begin['text'].endswith('\n') and begin['text'].strip(), 'invalid BEGIN anchor')
    registers = value['registers']
    require(isinstance(registers, dict) and set(registers) == {'input', 'output', 'text', 'scratch'}
            and all(isinstance(v, str) and v in REGISTERS for v in registers.values())
            and len(set(registers.values())) == 4, 'invalid register mapping')
    offsets = value['stack_offsets']
    require(isinstance(offsets, dict) and set(offsets) == {'esp', 'ebp'} and all(
        type(v) is int and -4096 <= v <= 4096 for v in offsets.values()), 'invalid stack mapping')
    clobbers = value['clobbers']
    require(isinstance(clobbers, list) and all(isinstance(v, str) for v in clobbers)
            and len(set(clobbers)) == len(clobbers) and set(clobbers) <= REGISTERS | FLAGS
            and not {registers['text'], registers['scratch']} & set(clobbers), 'invalid frame')
    cells = value['private_cells']
    require(isinstance(cells, list) and 1 <= len(cells) <= 16, 'invalid private cell count')
    occupied, names = set(), set()
    for row in cells:
        require(isinstance(row, dict) and set(row) == {'name', 'offset', 'width'}
                and identifier(row['name']) and row['name'] not in names
                and type(row['offset']) is int and type(row['width']) is int
                and row['width'] in {1, 2, 4} and 0 <= row['offset']
                and row['offset'] + row['width'] <= value['private_extent'], 'invalid private cell')
        span = set(range(row['offset'], row['offset'] + row['width']))
        require(not span & occupied, 'overlapping private cells')
        occupied |= span
        names.add(row['name'])
    require(sum(r['name'] == 'removed' and r['width'] == 4 for r in cells) == 1, 'missing private count word')
    return value


def compaction_runtime_contract(value):
    if isinstance(value, dict) and value.get('profile') == 'local-text-cleanup-entry-v1':
        from .bisimulation_fresh_buffer_contract import fresh_buffer_runtime_contract
        return fresh_buffer_runtime_contract(value)
    if isinstance(value, dict) and value.get('profile') == 'local-text-cleanup-tail-v1':
        from .bisimulation_cleanup_contract import cleanup_runtime_contract
        return cleanup_runtime_contract(value)
    checked_compaction_contract(value)
    result = {'id': PROFILE, 'revision': value.get('runtime_revision', 2),
        'incoming': 'Live nonwrapping text span; disjoint live scratch or null allocation failure; input within text, output <= input, removed = input - output. Live scratch covers input, ends no later than text, and its corresponding last text byte is NUL. The text span may extend beyond this NUL. Scratch suffix from output is zero.',
        'memory': 'Related arbitrary current public bytes; no contents reconstructed from pointers. One public byte store per iteration; exact private cells are disjoint from public spans. Unmodeled access fails.',
        'lifetime': 'Text, live scratch, descriptors and byte-access context remain live and unchanged during the region. No allocation, release, callback or service invocation occurs in this local step.',
        'outgoing': 'Whole public memory and count/cursor relation agree; normal exits transport the complete scratch view. A repeated cut advances input strictly and preserves the incoming cursor/scratch domain. Regional memory faults correspond to UINT32_MAX, without qualifying that exported ABI.',
        'compatibility': 'Caller admission, concrete runtime behavior, origin/lifetime transport and complete operation coverage remain separate obligations.'}
    if result['revision'] == 3:
        result['incoming'] += ' Text has a complete writable descriptor. Null scratch requires input zero or in-span CR/LF bytes at input and input+1.'
        result['outgoing'] += ' Both normal cuts preserve every incoming public-memory predicate, including the null-scratch pending CR/LF condition. Writable text metadata is preserved; it does not permit additional source effects.'
    return result
