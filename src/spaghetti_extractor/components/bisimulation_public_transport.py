"""Bind current-memory substitution to the actual checked cleanup cuts.

The incoming byte function is instantiated with the predecessor's entire current
memory, not chosen afresh. This is a pointwise rule over arbitrary addresses;
it carries no application history and does not establish object lifetimes.
"""
import re

from .bisimulation_compaction_contract import require
from .bisimulation_compaction_domain import compaction_public_domain


def _compact(text):
    return re.sub(r'\s+', '', text)


def _predicates(reader, *, input_value='input', output_value='output', removed_value='removed'):
    byte = lambda address: reader.replace('$address', address)
    return compaction_public_domain(
        text_nul_byte=byte('text_address+scratch_extent-1U'), scratch_probe_byte=byte('probe'),
        input_value=input_value, output_value=output_value, removed_value=removed_value,
        pending_bytes=(byte('text_address+'+input_value), byte('text_address+'+input_value+'+1U')))


TAIL_BASE = '''static uint8_t current_byte(uint32_t address){
 if(address>=initial_scratch+initial_output && (uint64_t)address<(uint64_t)initial_scratch+initial_extent)return 0U;
 return __CPROVER_uninterpreted_readonly_byte(address);
}'''


def cleanup_public_transport_domain(models):
    """Called only after validating each complete regional evidence envelope.

    These exact statement checks bind the instantiation rule to the registered
    models. They are not an arbitrary-C control-flow or quantifier checker.
    """
    require(set(models) == {'entry', 'loop', 'tail'}, 'public transport needs all regional models')
    bindings = {}
    for role, source in models.items():
        statements = []
        if role in {'entry', 'loop'}:
            prefix = 'entry-consumer-' if role == 'entry' else 'loop-all-exits-'
            predicates = _predicates('spx_mutable_byte(&right,$address)', input_value='state.esi',
                output_value='state.ecx', removed_value='memory.word_7' if role == 'entry' else 'memory.private_removed')
            statements += [f'__CPROVER_assert({p},"{prefix}{n}");' for n, p in predicates.items()]
        if role in {'loop', 'tail'}:
            reader = '__CPROVER_uninterpreted_readonly_byte($address)' if role == 'loop' else 'current_byte($address)'
            statements += [f'__CPROVER_assume({p});' for p in _predicates(reader).values()]
            statements += ['struct spx_mutable_world left={0},right={0};']
            base = '__CPROVER_uninterpreted_readonly_byte(address)' if role == 'loop' else 'current_byte(address)'
            statements += ['uint8_t result = '+base+';']
        statements += [f'__CPROVER_assert(spx_mutable_byte(&left,probe)==spx_mutable_byte(&right,probe),"{role}-whole-post-memory");']
        if role == 'tail':
            statements += [TAIL_BASE,
                'initial_scratch=scratch_address;initial_extent=scratch_extent;initial_output=output;']
        compact = _compact(source)
        for statement in statements:
            require(compact.count(_compact(statement)) == 1,
                'missing or ambiguous checked public-memory clause in '+role+': '+statement)
        bindings[role] = statements
    return {'profile': 'cleanup-current-memory-substitution-v1', 'regional_clauses': bindings,
        'edges': [['entry', 'loop'], ['loop', 'loop'], ['loop', 'tail']],
        'substitution': 'Instantiate both successor incoming byte functions with the same predecessor current-memory function at every physical address.',
        'requires': ['Validated regional proofs and their normal outgoing public-memory predicates.',
            'The zero-suffix predicate holds for every address; the query uses an arbitrary probe.',
            'Separate control, private-state, descriptor and lifetime transport.'],
        'scope': 'Pointwise current-memory and public-predicate transport only; descriptor lifetime and concrete caller/runtime compatibility remain unqualified.'}


def public_transport_statements():
    """A small query over complete current bytes, independent of event history."""
    incoming = _predicates('__CPROVER_uninterpreted_current_byte($address)')
    outgoing = _predicates('rebased_byte($address,scratch_address,scratch_extent,output)')
    return ([f'__CPROVER_assume({p});' for p in incoming.values()]
        + [f'__CPROVER_assert({p},"public-cut-{n}");' for n, p in outgoing.items()])


def render_public_transport():
    return TEMPLATE.replace('@PREDICATES@', '\n '.join(public_transport_statements()))


def check_public_transport(source):
    """Check the retained recipe without reconstructing or compiling a model."""
    before, after = TEMPLATE.split('@PREDICATES@')
    require(source.startswith(before) and source.endswith(after), 'public transport recipe changed')
    body = source[len(before):len(source)-len(after)]
    lines = iter(body.splitlines())
    for kind, reader in [('assume', '__CPROVER_uninterpreted_current_byte($address)'),
                         ('assert', 'rebased_byte($address,scratch_address,scratch_extent,output)')]:
        for name, predicate in _predicates(reader).items():
            line = next(lines, '').strip()
            match = re.fullmatch(r'__CPROVER_'+kind+r'\((.*)\);', line)
            expected = predicate + (',"public-cut-'+name+'"' if kind == 'assert' else '')
            require(match is not None and match[1] == expected, 'public transport predicates changed')
    require(next(lines, None) is None, 'public transport predicates changed')


TEMPLATE = r'''typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#define UINT64_C(x) x##ULL
uint8_t __CPROVER_uninterpreted_current_byte(uint32_t);
static uint8_t rebased_byte(uint32_t address,uint32_t scratch,uint32_t extent,uint32_t output){
 if(address>=scratch+output && (uint64_t)address<(uint64_t)scratch+extent)return 0U;
 return __CPROVER_uninterpreted_current_byte(address);
}
void check_admission(void){
 uint32_t text_address,text_extent,scratch_address,scratch_extent,input,output,removed,probe;
 @PREDICATES@
 __CPROVER_assert(rebased_byte(probe,scratch_address,scratch_extent,output)==__CPROVER_uninterpreted_current_byte(probe),"public-cut-whole-current-memory");
 /* Two independently addressed aliases must observe the same transported byte.
    Physical translation and object liveness are separate admission obligations. */
 uint32_t base_a,base_b,offset_a,offset_b;
 __CPROVER_assume((uint64_t)base_a+offset_a==probe && (uint64_t)base_b+offset_b==probe);
 __CPROVER_assert(rebased_byte(base_a+offset_a,scratch_address,scratch_extent,output)==rebased_byte(base_b+offset_b,scratch_address,scratch_extent,output),"public-cut-alias-coherence");
}
'''
