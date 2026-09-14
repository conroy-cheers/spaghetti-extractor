"""Consume scoped regional guarantees for cleanup control and return-frame composition.

The registered regional profiles establish their own bounded segment termination.
This rule handles their unbounded repetition, not application-body execution.
Concrete runtime compatibility and complete state composition remain separate.
"""
import re

from .bisimulation_compaction_contract import require


def _compact(text):
    return re.sub(r'\s+', '', text)


def cleanup_postconditions(source):
    """Read the proof-only suffix, retaining the guard of every assertion.

    Only assertions, conditionals and the existing arbitrary machine-frame probe
    are supported after the authored call. Additional assumptions or effects
    could change a guarantee's meaning and must not be silently accepted.
    """
    require(source.count('void check_iteration(void){') == 1, 'cleanup composition needs one regional harness')
    harness = source.split('void check_iteration(void){', 1)[1]
    matches = list(re.finditer(r'uint32_t result=[A-Za-z_]\w*\([^;]*\);', harness))
    require(len(matches) == 1, 'cleanup composition needs one authored result')
    text = _compact(harness[matches[0].end():]); index = 0; clauses = {}

    def parenthesized():
        nonlocal index
        require(index < len(text) and text[index] == '(', 'cleanup postcondition missing condition')
        start = index+1; depth = 1; index += 1
        while index < len(text):
            depth += (text[index] == '(') - (text[index] == ')')
            index += 1
            if depth == 0:
                return text[start:index-1]
        raise ValueError('cleanup postcondition has unclosed condition')

    def statement(guards):
        nonlocal index
        if text.startswith('if(', index):
            index += 2; condition = parenthesized(); statement([*guards, condition]); return
        if text.startswith('{', index):
            index += 1; block(guards); return
        if text.startswith('__CPROVER_assert(', index):
            index += len('__CPROVER_assert'); body = parenthesized()
            match = re.fullmatch(r'(.*),"([A-Za-z0-9_.-]+)"', body)
            require(match is not None and match[2] not in clauses, 'cleanup assertion is malformed or ambiguous')
            clauses[match[2]] = {'expression': match[1], 'guards': guards}
            require(text.startswith(';', index), 'cleanup assertion lacks terminator'); index += 1; return
        probe = 'uint32_tcontinuation_slot,continuation_byte;'
        admission = '__CPROVER_assume(continuation_slot<8U&&continuation_byte<10U);'
        for silent in [probe, admission]:
            if not guards and text.startswith(silent, index):
                index += len(silent); return
        raise ValueError('cleanup proof suffix has an unsupported assumption, effect or control statement')

    def block(guards):
        nonlocal index
        while index < len(text) and text[index] != '}':
            statement(guards)
        require(index < len(text), 'cleanup proof suffix has unclosed block'); index += 1

    block([])
    require(index == len(text), 'cleanup proof suffix has extra top-level code')
    return clauses


def cleanup_control_domain(models, contracts, graph, private_transport):
    require(set(models) == set(contracts) == {'entry', 'loop', 'tail'}, 'cleanup control needs three regions')
    entry, loop, tail = (contracts[n] for n in ['entry', 'loop', 'tail'])
    require(entry['entry_cut'] == 'entry' and entry['exit_cut'] == loop['entry_cut'] == 'loop'
        and loop['exit_cut'] == tail['entry_cut'] == 'tail'
        and entry['exit_rva'] == loop['entry_rva'] and loop['exit_rva'] == tail['entry_rva'],
        'cleanup control boundaries differ')
    normal = ['result!=UINT32_MAX']; loop_rva = loop['entry_rva']
    required = {
        'entry': {
            'entry-loop-successor': (f'result=={loop_rva}U&&step.target_rva==result', normal),
            'entry-loop-register-domain': ('state.esp==stack-28U&&state.ebp==stack-4U&&state.edi==text_address&&state.ebx==scratch_address', normal),
            'entry-saved-frame': ('memory.word_9==initial.ebp&&memory.word_4==initial.ebx&&memory.word_3==initial.esi&&memory.word_10==return_word', normal),
            'entry-fault-correspondence': ('(step.kind==SPX_MEMORY_FAULT)==(result==UINT32_MAX)', []),
        },
        'loop': {
            'loop-control-successor': ('(step.kind==SPX_BRANCH||step.kind==SPX_FALLTHROUGH||step.kind==SPX_JUMP)&&step.target_rva==result', normal),
            'loop-progress-and-domain': ('state.esi>input&&state.esi<text_extent', [*normal, f'result=={loop_rva}U']),
            'loop-counter-invariant': ('state.ecx<=state.esi&&memory.private_removed==state.esi-state.ecx', normal),
            'loop-fault-outcome': ('(step.kind==SPX_MEMORY_FAULT)==(result==UINT32_MAX)', []),
        },
        'tail': {
            'tail-return-value': ('step.kind==SPX_RETURN&&state.eax==result&&result==removed', normal),
            'tail-return-frame': ('state.esp==stack+16U&&state.esi==saved_esi&&state.ebx==saved_ebx&&state.ebp==saved_ebp&&step.value==return_word', normal),
            'tail-fault-correspondence': ('(step.kind==SPX_MEMORY_FAULT)==(result==UINT32_MAX)', []),
        },
    }
    clauses = {name: cleanup_postconditions(source) for name, source in models.items()}
    for name, expectations in required.items():
        for identity, (expression, guards) in expectations.items():
            require(clauses[name].get(identity) == {'expression': expression, 'guards': guards},
                    'cleanup scoped guarantee differs: '+identity)
    frame = {'entry': 'entry-preserved-machine-frame', 'loop': 'loop-preserved-register-frame',
             'tail': 'tail-preserved-machine-state'}
    for name, identity in frame.items():
        clause = clauses[name].get(identity, {})
        fields = ['edi'] if name != 'loop' else ['edi', 'ebx', 'ebp', 'esp']
        require(clause.get('guards') == [] and all('state.'+f+'==initial.'+f in
            clause.get('expression', '').split('&&') for f in fields), 'cleanup persistent register guarantee differs')

    nodes = {r['entry']: r for r in graph['regions']}
    ownership = {cut: role for role, c in contracts.items() for cut in c['regions']}
    require(len(ownership) == sum(len(c['regions']) for c in contracts.values())
        and set(ownership) == set(nodes) and graph['uncovered_reachable_instruction_count'] == 0
        and not graph['unselected_cut_regions'], 'cleanup control has missing or overlapping source ownership')
    instruction_owners = {}
    for cut, node in nodes.items():
        for instruction in node['instruction_indices']:
            instruction_owners.setdefault(instruction, set()).add(ownership[cut])
    edges, returns = set(), set()
    for cut, node in nodes.items():
        role = ownership[cut]
        for interior in node['external_interior_entries']:
            require(instruction_owners.get(interior['source_instruction']) == {role},
                    'cleanup control crosses a proof boundary through an interior entry')
        for kind, target in node['exits']:
            if kind == 'cut':
                require(target in ownership, 'cleanup control has an unproved successor')
                destination = ownership[target]
                if destination != role or target == contracts[role]['entry_cut']:
                    require(target == contracts[destination]['entry_cut'], 'cleanup control enters a successor interior')
                    edges.add((role, destination))
            else:
                require(kind == 'return' and target == 'SET_RETURN_VALUE', 'cleanup control has an unsupported exit')
                returns.add(role)
    require(edges == {('entry', 'loop'), ('loop', 'loop'), ('loop', 'tail')}
        and returns == {'entry', 'loop', 'tail'}, 'cleanup collapsed control graph differs')
    layouts = private_transport['layouts']
    def span(role, cell):
        start = layouts[role]['anchor_delta'] + cell['offset']
        return start, start+cell['width']
    saved = {}
    for role, fields in private_transport['saved_frame'].items():
        pair = []
        require(len(fields) == 2, 'cleanup saved-word field pair differs')
        for name, field in zip(['entry', 'tail'], fields):
            matches = [c for c in layouts[name]['cells'] if c['field'] == field]
            require(len(matches) == 1, 'cleanup saved-word field is missing or ambiguous')
            pair.append(matches[0])
        begin, end = span('entry', pair[0])
        require(span('tail', pair[1]) == (begin, end) and end-begin == 4,
                'cleanup saved-word coordinates differ')
        for cell in layouts['loop']['cells']:
            if 'write' in cell:
                low, high = span('loop', cell)
                require(high <= begin or end <= low, 'cleanup loop write overlaps a saved return word')
        saved[role] = {'entry_field': fields[0], 'tail_field': fields[1], 'low': begin, 'high': end}
    require(set(saved) == {'esi', 'ebx', 'ebp', 'return_word'}, 'cleanup saved-word inventory differs')
    return {'profile': 'cleanup-scoped-control-and-return-frame-v1',
        'regional_postconditions': clauses, 'edges': [list(e) for e in sorted(edges)],
        'return_regions': sorted(returns), 'source_cover': {cut: nodes[cut]['semantic_sha256'] for cut in sorted(nodes)},
        'saved_word_transport': saved,
        'rank': 'entry: 2^33; loop: 2^32 + text_extent - input; tail: 1; normal/fault terminal: 0',
        'requires': ['Validated complete regional queries, including safety and unwinding assertions, and source/cut transport.',
            'The public/private memory, descriptor and spatial relations instantiate each successor with the predecessor current state.',
            'The checked private-byte store/frame rule applies to every allowed loop update; saved-word coordinates and separation are checked here.',
            'Dependency contracts preserve the required state relation and terminate each admitted invocation.'],
        'scope': 'Conditional coarse control, loop ranking and normal return-frame algebra; not concrete runtime qualification or full state/trace composition.'}


TEMPLATE = r'''typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define UINT64_C(x) x##ULL
static uint64_t rank(uint32_t phase,uint32_t extent,uint32_t input){
 if(phase==0U)return UINT64_C(8589934592);
 if(phase==1U)return UINT64_C(4294967296)+(uint64_t)extent-input;
 return phase==2U?1U:0U;
}
void check_admission(void){
 uint32_t phase,next,extent,input,after_input,fault;
 __CPROVER_assume(phase<3U && fault<=1U && extent>0U && input<extent);
 if(fault)next=4U;
 else if(phase==0U){next=1U;__CPROVER_assume(after_input<extent);}
 else if(phase==1U){
  __CPROVER_assume(next==1U || next==2U);
  __CPROVER_assume(after_input<extent);
  if(next==1U)__CPROVER_assume(after_input>input);
 }else next=3U;
 __CPROVER_assert(rank(next,extent,after_input)<rank(phase,extent,input),"cleanup-composed-strict-rank");
 __CPROVER_assert(!fault || next==4U,"cleanup-fault-is-terminal");
 __CPROVER_assert(next!=3U || phase==2U,"cleanup-normal-return-only-from-tail");
 uint32_t output,removed;
 __CPROVER_assume(output<=input && removed==input-output);
 __CPROVER_assert(removed!=4294967295U,"cleanup-normal-result-not-fault-sentinel");
 uint32_t stack,esi,ebx,ebp,edi,return_word;
 __CPROVER_assume(stack>=72U && (uint64_t)stack+4U<=UINT64_C(4294967296));
 uint32_t entry_esp=stack-28U,entry_ebp=stack-4U;
 uint32_t loop_stack=stack-12U;
 __CPROVER_assert(entry_esp==loop_stack-16U && entry_ebp==loop_stack+8U,"cleanup-entry-loop-register-transport");
 /* These equalities instantiate the imported private-byte correspondence and
    saved-word frame; they do not assume fresh memory or physical accessibility. */
 uint32_t tail_saved_esi=esi,tail_saved_ebx=ebx,tail_saved_ebp=ebp,tail_return=return_word;
 uint32_t final_esi=tail_saved_esi,final_ebx=tail_saved_ebx,final_ebp=tail_saved_ebp,final_edi=edi;
 uint32_t final_esp=loop_stack+16U;
 __CPROVER_assert(final_esp==stack+4U,"cleanup-composed-return-stack");
 __CPROVER_assert(final_esi==esi && final_ebx==ebx && final_ebp==ebp && final_edi==edi && tail_return==return_word,"cleanup-composed-saved-register-return");
}
'''
