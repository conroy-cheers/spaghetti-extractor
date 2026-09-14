"""Explicit entry and outgoing conventions for the local fresh-buffer proof."""
import re

PROFILE = 'local-text-cleanup-entry-v1'
ROLES = {'context', 'text', 'suppress_notice', 'main_window', 'edit_window', 'caption'}


def require(condition, detail):
    if not condition:
        raise ValueError('fresh buffer entry contract: ' + detail)


def checked_fresh_buffer_contract(value):
    require(isinstance(value, dict) and set(value) == {'profile', 'runtime_revision', 'graph_index',
        'entry_cut', 'exit_cut', 'regions', 'source_locals', 'parameter_roles', 'entry_rva', 'exit_rva',
        'image_base', 'length_pointer', 'calls'}, 'fields differ')
    require(value['profile'] == PROFILE and type(value['runtime_revision']) is int and value['runtime_revision'] == 1,
            'unsupported runtime revision')
    identifier = lambda v: isinstance(v, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', v)
    require(all(type(value[k]) is int and 0 <= value[k] < 2**32 for k in
                ['graph_index', 'entry_rva', 'exit_rva', 'image_base', 'length_pointer'])
            and 0 < value['entry_rva'] < 0xffffffff and 0 < value['exit_rva'] < 0xffffffff
            and value['entry_rva'] != value['exit_rva'] and value['length_pointer'] <= 2**32-4,
            'invalid machine domain')
    require(all(identifier(value[k]) for k in ['entry_cut', 'exit_cut']) and isinstance(value['regions'], list)
            and value['regions'] and all(identifier(n) for n in value['regions'])
            and len(set(value['regions'])) == len(value['regions']) and value['entry_cut'] in value['regions']
            and value['exit_cut'] not in value['regions'], 'invalid source cuts')
    for key, roles in [('source_locals', {'input', 'output', 'removed', 'scratch'}), ('parameter_roles', ROLES)]:
        require(isinstance(value[key], dict) and set(value[key]) == roles
                and all(identifier(n) for n in value[key].values())
                and len(set(value[key].values())) == len(roles), 'invalid ' + key)
    calls = value['calls']
    require(isinstance(calls, dict) and set(calls) == {'length_before', 'allocate', 'length_after'}, 'call roles differ')
    for row in calls.values():
        require(isinstance(row, dict) and set(row) == {'entry', 'instruction', 'successor'}
                and all(type(v) is int and 0 < v < 2**32 for v in row.values()), 'invalid call site')
    require(len({r['entry'] for r in calls.values()}) == 3
            and calls['length_before']['successor'] == calls['allocate']['entry']
            and calls['allocate']['successor'] == calls['length_after']['entry'], 'call continuations differ')
    return value


def fresh_buffer_runtime_contract(value):
    checked_fresh_buffer_contract(value)
    return {'id': PROFILE, 'revision': 1,
        'incoming': 'Live nonwrapping writable text view; length is below its extent and the corresponding text byte is NUL. Successful allocation produces a disjoint nonwrapping zero-filled span of length+1 bytes; failure is a null span. Private entry stack [-40,+4), public spans and the bound length-function pointer cell are disjoint. High unsigned lengths remain admitted.',
        'representation': 'Entry EDI is text and ESP is stack, with valid DF. Text and scratch are domain 1, objects 1/2, generation 1, offset 0, permissions 3. Length function target is nonzero. At loop entry the stack anchor is stack-12: ESI=input, ECX=output, EBX=scratch, ESP=anchor-16 and EBP=anchor+8; removed is at anchor. Saved ESI/EBX/EBP/return are at anchor-16/-12/+8/+12.',
        'services': 'Two equal normal length results around one allocation call, flags 64 and size length+1. Both allocation outcomes are admitted. Text and unrelated current memory are preserved; successful new scratch bytes are zero. No callbacks, release, nonlocal exits or other service effects occur.',
        'memory': 'Actual short-input byte accesses execute on both sides. Complete current public memory agrees at exit; the eight compaction revision-3 public predicates hold at the loop cut, including zero suffix and null-scratch pending CR/LF. Complete scratch descriptor transport and saved machine frame are asserted.',
        'outgoing': 'Matching loop cut with ESI/ECX/count/view correspondence, or matching memory fault encoded as UINT32_MAX. Every path and local loop retains complete safety and unwinding checks.',
        'compatibility': 'Concrete length/allocation implementations, incoming contents and object lifetime, exported fault ABI, whole-image/private admission for the tail and entry/loop/tail receipt composition remain separate unqualified obligations.'}
