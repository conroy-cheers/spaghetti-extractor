"""Versioned local cleanup-tail domain; deployment qualification remains separate."""
import re

PROFILE = 'local-text-cleanup-tail-v1'
ROLES = {'context', 'text', 'suppress_notice', 'main_window', 'edit_window', 'caption'}


def require(condition, detail):
    if not condition:
        raise ValueError('cleanup tail contract: ' + detail)


def checked_cleanup_contract(value):
    require(isinstance(value, dict) and set(value) == {'profile', 'runtime_revision', 'graph_index',
        'entry_cut', 'regions', 'begin', 'source_locals', 'parameter_roles', 'entry_rva', 'image_base',
        'image_size', 'views', 'calls', 'supplier_call'}, 'fields differ')
    require(value['profile'] == PROFILE and type(value['runtime_revision']) is int
            and value['runtime_revision'] == 1, 'unsupported runtime revision')
    ident = lambda v: isinstance(v, str) and re.fullmatch('[A-Za-z_][A-Za-z0-9_]*', v)
    require(all(type(value[k]) is int and 0 <= value[k] < 2**32
                for k in ['graph_index', 'entry_rva', 'image_base', 'image_size'])
            and value['entry_rva'] > 0 and value['image_size'] > 0
            and value['image_base']+value['image_size'] <= 2**32, 'invalid machine domain')
    require(ident(value['entry_cut']) and isinstance(value['regions'], list) and value['regions']
            and all(ident(n) for n in value['regions']) and value['entry_cut'] in value['regions']
            and len(set(value['regions'])) == len(value['regions']), 'invalid source cuts')
    for key, roles in [('source_locals', {'input', 'output', 'removed', 'scratch'}), ('parameter_roles', ROLES)]:
        require(isinstance(value[key], dict) and set(value[key]) == roles
                and all(ident(n) for n in value[key].values())
                and len(set(value[key].values())) == len(roles), 'invalid ' + key)
    anchor = value['begin']
    require(isinstance(anchor, dict) and set(anchor) == {'position', 'text'} and anchor['position'] in {'before', 'after'}
            and isinstance(anchor['text'], str) and anchor['text'].strip() and anchor['text'].endswith('\n'), 'invalid BEGIN anchor')
    views = value['views']
    require(isinstance(views, dict) and set(views) == {'notice', 'window', 'edit', 'caption'}, 'view roles differ')
    for name, row in views.items():
        require(isinstance(row, dict) and set(row) == {'address', 'extent'}
                and all(type(v) is int for v in row.values())
                and value['image_base'] <= row['address'] and row['extent'] > 0
                and row['address']+row['extent'] <= value['image_base']+value['image_size']
                and (name == 'caption' or row['extent'] == 4), 'invalid ' + name + ' view')
    calls = value['calls']
    require(isinstance(calls, dict) and set(calls) == {'copy', 'release', 'resource_text', 'message', 'focus'}, 'call roles differ')
    for row in calls.values():
        require(isinstance(row, dict) and set(row) == {'entry', 'instruction', 'successor'}
                and all(type(v) is int and 0 < v < 2**32 for v in row.values()), 'invalid call site')
    require(len({row['entry'] for row in calls.values()}) == len(calls), 'ambiguous call sites')
    require(isinstance(value['supplier_call'], dict), 'missing supplier call domain')
    return value


def cleanup_runtime_contract(value):
    checked_cleanup_contract(value)
    return {'id': PROFILE, 'revision': 1,
        'incoming': 'Compaction revision-3 public byte domain, including nullable scratch, pending CR/LF and zero suffix. Text/scratch/private stack are nonwrapping, mutually disjoint and outside the bound image. Current image bytes are arbitrary.',
        'representation': 'ESI=input, ECX=output, EDI=text, EBX=scratch, ESP=stack-16, EBP=stack+8, removed at stack. Private words cover [-60,+16); saved ESI/EBX/EBP/return at -16/-12/+8/+12. Text/scratch are byte views in domain 1, objects 1/2, generation 1, offset 0, permissions 3; image descriptor roles are exact model bindings.',
        'memory': 'Whole current public memory corresponds at every service call and return. Two byte copies at most; copy may replace text contents and resource may replace its checked borrowed view. Preserved image spans require write-frame assertions. Full copy/message descriptors and release references must match.',
        'services': 'Exact ordered normal copy/release/resource/message/focus interactions. Copy returns destination reference/address. Release/message/focus share arbitrary scalar results. Resource consumes a validated supplier domain, complete reference, clobbers and private writes; its bodies are absent.',
        'lifetime': 'Text/image/descriptors/service table stay live. Scratch is live or null and released at most once; copy and writes require live scratch. No callbacks, origin rebinding or nonlocal exits are admitted.',
        'outgoing': 'Matching normal count result, return word, saved machine frame and whole public memory, or corresponding memory fault encoded as UINT32_MAX. All native/source loops retain complete unwinding assertions.',
        'compatibility': 'Entry/loop coverage, actual image/private admission, concrete copy/allocator/service and callback behavior, string validity and exported fault ABI remain separate unqualified obligations.'}
