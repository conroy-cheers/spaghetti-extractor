"""Extract spatial handoff obligations from the actual checked regional models.

This is an admission check, not a state-composition theorem. In particular, an
interval implication does not transport heap contents, origins or lifetimes.
"""
import re

from .bisimulation_compaction_contract import require

PREAMBLE = [
    'typedef unsigned char uint8_t; typedef unsigned int uint32_t; typedef unsigned long long uint64_t;',
    '#define UINT64_C(n) n##ULL',
    'uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);',
    'void check_admission(void){',
    ' uint32_t text_address,text_extent,length,scratch_address,stack,length_target;',
    ' uint32_t scratch_extent=scratch_address ? length+1U : 0U;',
]


def _assumptions(source):
    require(source.count('void check_iteration(void){') == 1, 'ambiguous regional entry')
    prefix = source.split('void check_iteration(void){', 1)[1].split('struct spx_mutable_world left=', 1)
    require(len(prefix) == 2, 'missing regional memory initialization')
    conditions = re.findall(r'__CPROVER_assume\((.*?)\);', prefix[0], re.S)
    require(conditions and all(';' not in c and '{' not in c for c in conditions), 'unsupported admission expression')
    return conditions


def cleanup_admission_domain(contracts, models):
    """Only admit the currently checked entry/iteration/terminal conventions."""
    require(set(contracts) == set(models) == {'entry', 'loop', 'tail'}, 'need entry, loop and tail')
    entry, loop, tail = (contracts[n] for n in ['entry', 'loop', 'tail'])
    require(entry['profile'] == 'local-text-cleanup-entry-v1' and entry['runtime_revision'] == 1
        and loop['profile'] == 'local-byte-compaction-step-v1' and loop.get('runtime_revision', 2) == 3
        and tail['profile'] == 'local-text-cleanup-tail-v1' and tail['runtime_revision'] == 1,
        'unsupported cleanup composition profile')
    require(entry['exit_rva'] == loop['entry_rva'] and loop['exit_rva'] == tail['entry_rva']
        and entry['exit_cut'] == loop['entry_cut'] and loop['exit_cut'] == tail['entry_cut'], 'disconnected regional cuts')
    require(entry['image_base'] == loop['image_base'] == tail['image_base'], 'different regional images')
    require(entry['source_locals'] == loop['source_locals'] == tail['source_locals']
        and entry['parameter_roles'] == tail['parameter_roles']
        and loop['text_parameter'] == entry['parameter_roles']['text'], 'different source state roles')
    require(loop['registers'] == {'input': 'esi', 'output': 'ecx', 'text': 'edi', 'scratch': 'ebx'}
        and loop['stack_offsets'] == {'esp': -16, 'ebp': 8}
        and loop['private_extent'] == 8
        and sorted(loop['private_cells'], key=lambda r: r['offset']) == [
            {'name': 'removed', 'offset': 0, 'width': 4}, {'name': 'c', 'offset': 6, 'width': 1},
            {'name': 'b', 'offset': 7, 'width': 1}], 'unsupported private state convention')
    # These assertions, in the exact proved model, establish the coordinate
    # conversion. Merely matching contract declarations would not do so.
    require('state.esp==stack-28U && state.ebp==stack-4U && state.edi==text_address && state.ebx==scratch_address'
        in models['entry'], 'entry lacks checked loop register transport')
    # JSON object order may reverse these independent register assignments.
    # Admit only the two exact consecutive orders, with no intervening effects.
    stack_initializers = ('initial.esp=stack-16U;initial.ebp=stack+8U;',
                          'initial.ebp=stack+8U;initial.esp=stack-16U;')
    require(all(sum(models[n].count(block) for block in stack_initializers) == 1
                for n in ['loop', 'tail']), 'consumer stack initialization differs')
    require(not {'esp', 'ebp', 'edi', 'ebx'} & set(loop['clobbers']), 'iteration changes persistent addresses')
    all_conditions = {n: _assumptions(models[n]) for n in models}
    # The first eight loop/tail conditions are the public byte domain already
    # checked at both predecessor exits. Spatial admission follows it. Retain
    # all conditions in the domain so changes cannot silently evade invalidation.
    require(len(all_conditions['entry']) == 11 and len(all_conditions['loop']) == 11
        and len(all_conditions['tail']) == 14, 'regional admission inventory changed')
    spatial = {n: all_conditions[n][8:] for n in ['loop', 'tail']}
    require(all('stack' in p for p in spatial['loop'])
        and all('stack' in p for p in spatial['tail'][:4]), 'unexpected spatial admission order')
    base, end = tail['image_base'], tail['image_base'] + tail['image_size']
    # Future scratch placement is an allocator guarantee, not a caller input.
    envelope = {
        'caller-private-span': 'stack>=72U && (uint64_t)stack+4U<=UINT64_C(4294967296)',
        'caller-private-text-separation': '(uint64_t)stack+4U<=text_address || (uint64_t)text_address+text_extent<=stack-72U',
        'caller-private-image-separation': f'(uint64_t)stack+4U<={base}U || (uint64_t)stack-72U>=UINT64_C({end})',
        'caller-text-image-separation': f'(uint64_t)text_address+text_extent<={base}U || text_address>=UINT64_C({end})',
        'allocator-private-separation': '(uint64_t)stack+4U<=scratch_address || (uint64_t)scratch_address+scratch_extent<=stack-72U',
        'allocator-image-separation': f'(uint64_t)scratch_address+scratch_extent<={base}U || scratch_address>=UINT64_C({end})',
    }
    return {'profile': 'cleanup-spatial-admission-v1', 'regional_assumptions': all_conditions,
        'consumer_spatial_assumptions': spatial, 'entry_to_loop_stack_delta': -12,
        'additional_requirements': envelope,
        'scope': 'Spatial admission only; no contents, frame extension, lifetime, service or whole-operation authority.'}


def render_cleanup_admission(domain, *, additional_requirements=()):
    require(isinstance(additional_requirements, (list, tuple))
        and len(set(additional_requirements)) == len(additional_requirements)
        and set(additional_requirements) <= domain['additional_requirements'].keys(), 'unknown or repeated admission requirement')
    lines = list(PREAMBLE)
    lines += [' __CPROVER_assume(' + p + ');' for p in domain['regional_assumptions']['entry']]
    lines += [' __CPROVER_assume(' + domain['additional_requirements'][n] + ');' for n in additional_requirements]
    lines += [' stack-=12U;']
    for name, predicates in domain['consumer_spatial_assumptions'].items():
        lines += [f' __CPROVER_assert({p},"{name}-spatial-admission-{i}");' for i, p in enumerate(predicates)]
    lines += ['}']
    return '\n'.join(lines) + '\n'


def check_cleanup_admission_transport(source, domain, requirements, *, nonempty):
    """Check every retained statement against the domain without invoking generation."""
    lines = source.splitlines()
    require(lines[:len(PREAMBLE)] == PREAMBLE and lines[-1:] == ['}'], 'admission declarations or scope differ')
    body = [line.strip() for line in lines[len(PREAMBLE):-1]]
    assumptions = domain['regional_assumptions']['entry'] + [domain['additional_requirements'][n] for n in requirements]
    for condition in assumptions:
        require(body and body.pop(0) == '__CPROVER_assume('+condition+');', 'admission premise transport differs')
    require(body and body.pop(0) == 'stack-=12U;', 'admission coordinate transport differs')
    for name, predicates in domain['consumer_spatial_assumptions'].items():
        for i, predicate in enumerate(predicates):
            row = re.fullmatch(r'__CPROVER_assert\((.*),"([^"]+)"\);', body.pop(0) if body else '')
            require(row and row[1] == predicate and row[2] == f'{name}-spatial-admission-{i}',
                    'consumer spatial assertion transport differs')
    require(body == (['__CPROVER_assert(0,"admission-domain-nonempty");'] if nonempty else []),
            'extra admission statements or missing nonvacuity assertion')
