"""Compose checked public-memory observations and normalized service prefixes.

The model contains records only. Regional proofs establish their equality at an
arbitrary byte probe; current-memory transport carries the resulting contents
between segments. Native service failure and nonreturning calls are separate.
"""
import hashlib
import re

from .bisimulation_compaction_contract import require
from .bisimulation_cleanup_composition import _compact


def _body(source, name):
    matches = list(re.finditer(r'(?:static\s+)?(?:void|uint8_t|uint32_t|spx_call_status|spx_view_v5|spx_ref_v5)\s+'
                              +re.escape(name)+r'\([^{}]*?\)\s*\{', source))
    require(len(matches) == 1, 'cleanup observation helper missing or ambiguous: '+name)
    start = matches[0].end(); depth = 1
    for index in range(start, len(source)):
        depth += (source[index] == '{') - (source[index] == '}')
        if depth == 0:
            return source[start:index]
    raise ValueError('cleanup observation helper has unclosed body: '+name)


ENTRY_EVENT = '''
 __CPROVER_assert(e->world->count==0U,"entry-service-current-memory-is-incoming");
'''
TAIL_EVENT = '''
 __CPROVER_assert(e->count<5U,"tail-call-capacity");__CPROVER_assume(e->count<5U);
 if(!e->side){uint32_t result;calls[e->count]=(struct call_record){kind,a,b,c,d,spx_mutable_byte(e->world,probe),result};}
 else{
  struct call_record expected=calls[e->count];
  __CPROVER_assert(kind==expected.kind && a==expected.a && b==expected.b && c==expected.c && d==expected.d,"tail-call-order-and-arguments");
  __CPROVER_assert(spx_mutable_byte(e->world,probe)==expected.byte,"tail-call-current-memory");
 }
 if(kind==1U){
  __CPROVER_assert(!e->released && e->scratch && e->scratch_extent,"tail-copy-live-source");
  spx_mutable_event(e->world,e->text,e->text_extent,0U,1U,e->count);
 }
 if(kind==2U){__CPROVER_assert(!e->released,"tail-release-once");e->released=1U;}
 if(kind==3U)spx_mutable_event(e->world,RESOURCE,500U,0U,1U,e->count);
 return calls[e->count++].result;
'''
LOOP_EVENT = '''
 (void)r;(void)e;(void)i;(void)o;__CPROVER_assert(0,"loop-no-service-call");return SPX_CALL_UNIMPLEMENTED;
'''

# Supported proof-model helper bodies, not application implementations. Binding
# complete bodies prevents a moved/conditional recorder, early return or hidden
# pre-record mutation from passing a mere call-site/label inventory. Their code
# is retained readably in the composition fixture and original regional models.
# A changed service model needs review of this observation profile as well as a
# new local proof. Compatible application supplier edits keep these bodies fixed.
PROFILE_HELPERS = {
    'entry:fresh_zero_byte': 'a6fada5d1e4918752d08e82b1057d141f502fdc41ecc6599fc89fd1e538a5a77',
    'entry:spx_mutable_byte': 'e1be8a966c10080361035afcf5a2b4c368040e6588f99fe1ff30f423da2753a1',
    'entry:length_contract': '127b27ae7d60687b1fbbe21ebe1f46be49c682a98f1ec60196b164706076e89d',
    'entry:allocate_contract': 'adc5fc7ae01783cf147f5662f6547d19d382913f72666262b699515f9f1b78ca',
    'entry:spx_invoke_call': '702f5cedbf38170545cc802b0d6d9b182ae66520bdc7ece6190ef0d98ff4f285',
    'tail:copy_contract': '646561b133b7615a1857a7463fe535e953aba36011b67bda99d9a1d24ab0d416',
    'tail:release_contract': '2e581baa1b0e17f8d710694b94fea4168d920ff0ce6af62f0cf4a11b1daf86e2',
    'tail:resource_contract': '596cb6f17ac239d65ea2210c53ff5c39d44acd584ee84343134b973d31545914',
    'tail:message_contract': '1c4521f072b0ab2fdf31eb68b61c78b35a28bee8a99b887c09af9bd8d5eeccfa',
    'tail:focus_contract': '2d847d038c1ca984e97adb95c79ac44cba1c8a23bd6d56a95bc533070355c804',
    'tail:spx_invoke_call': '4cfe2b077afdb1b99a8c8fb3eeca8a1d945718f0dd031bbae0f387eb093ff71d',
}


def _setup(source):
    body = _body(source, 'check_iteration')
    markers = list(re.finditer(r'uint32_t\s+result\s*=', body))
    require(len(markers) == 1, 'cleanup observation source invocation is ambiguous')
    return _compact(body[:markers[0].start()])


SETUP_CONTRACTS = {'entry': 'cf2ba2fff05465f64976125d2893809f841fc249ab179e00c39f308be9c9d771', 'tail': 'd72c1f64752b4afea9ef6b1e95ba0a3542e0cc9e78de83234b5b6149f07bef07'}


def cleanup_observation_domain(models, control):
    require(set(models) == {'entry', 'loop', 'tail'}, 'cleanup observations need the complete operation')
    # Bind setup as well as callbacks: a changed source/native side selector,
    # counter reset or probe initialization can otherwise bypass observation.
    for role, expected in SETUP_CONTRACTS.items():
        require(hashlib.sha256(_setup(models[role]).encode()).hexdigest() == expected,
                'cleanup observation setup contract changed: '+role)
    post = control['regional_postconditions']; obligations = {}
    for role in models:
        name = role+'-whole-post-memory'
        expected = {'expression': 'spx_mutable_byte(&left,probe)==spx_mutable_byte(&right,probe)', 'guards': []}
        require(post[role].get(name) == expected, 'cleanup memory equality does not cover every outcome: '+role)
        obligations[role] = {name: expected}
    for role, name, expression in [
        ('entry', 'entry-three-service-invocations', 'a.phase==3U&&b.phase==3U'),
        ('tail', 'tail-complete-service-trace', 'a.count==b.count&&a.released==b.released')]:
        expected = {'expression': expression, 'guards': []}
        require(post[role].get(name) == expected, 'cleanup service prefix is incomplete on some outcome')
        obligations[role][name] = expected
    helpers = {}
    for role, name, expected in [('entry', 'entry_before_service', ENTRY_EVENT), ('tail', 'transition', TAIL_EVENT),
                                  ('loop', 'spx_invoke_call', LOOP_EVENT)]:
        actual = _body(models[role], name)
        require(_compact(actual) == _compact(expected), 'cleanup observation rule differs: '+role)
        helpers[role] = _compact(actual)
    for identity, expected in PROFILE_HELPERS.items():
        role, name = identity.split(':')
        actual = hashlib.sha256(_compact(_body(models[role], name)).encode()).hexdigest()
        require(actual == expected, 'cleanup observation helper contract changed: '+identity)
    # The entry has a stronger checked premise than paired snapshots: no public
    # writes before any call. Its exact reader therefore returns the common
    # incoming byte. Whole helper bindings above include arguments, order and
    # normalized results; no effect declaration is trusted on its own.
    entry = _compact(models['entry'])
    require(entry.count('entry_before_service(e);') == 4,
            'cleanup entry service observation is missing or duplicated')
    for statement in ['struct spx_mutable_world left={0},right={0};',
        'struct environment a={.world=&left,.text=text_address,.extent=text_extent,.length=length,.scratch=scratch_address};',
        'struct environment b={.world=&right,.text=text_address,.extent=text_extent,.length=length,.scratch=scratch_address};',
        'fresh_address=scratch_address;fresh_extent=scratch_extent;']:
        require(entry.count(_compact(statement)) == 1, 'cleanup entry incoming memory binding differs')
    for name in ['copy_contract', 'release_contract', 'resource_contract', 'message_contract', 'focus_contract', 'spx_invoke_call']:
        require(_body(models['tail'], name).count('transition(') == 1,
                'cleanup tail invocation is not represented by exactly one event')
    require('if(kind==1U)result=e->text;if(kind==3U)result=RESOURCE;' in _compact(_body(models['tail'], 'spx_invoke_call')),
            'cleanup pointer-result normalization differs')
    return {'profile': 'cleanup-memory-and-service-prefix-composition-v1',
        'regional_guarantees': obligations, 'checked_event_rules': helpers,
        'helper_contracts': dict(PROFILE_HELPERS), 'setup_contracts': dict(SETUP_CONTRACTS),
        'entry_calls': ['length', 'allocate', 'length'], 'loop_calls': [],
        'entry_memory': 'Every service entry has zero public write events, so the exact reader returns the shared incoming fresh-zero byte function.',
        'tail_call_limit': 5, 'complete_call_limit': 8,
        'record_relation': 'Ordered stage/kind, arguments, normalized results and public byte at each call; pointer results additionally use the checked view/reference relation.',
        'memory_relation': 'Each segment starts from corresponding current contents and establishes equal complete post-memory on both normal and modeled memory-fault exits.',
        'outcomes': ['normal-return', 'modeled-memory-fault'],
        'requires': ['All imported regional guarantees and current-memory, private-state, descriptor, accessor and control transport checks apply.',
            'Each regional byte probe ranges over every physical address; tail call records compare the same arbitrary probe.',
            'Entry allocation issues an already-zero scratch span in the model; concrete pre-allocation heap contents and allocation effects need separate qualification.',
            'The concrete service implementations satisfy the explicit regional runtime contracts and preserve the representation relation.'],
        'remaining': ['Full concrete adapter, caller and runtime qualification.',
            'Service invocation failures, nonreturning calls and observable native fault-register context.',
            'A consumer proof that imports the complete conditional operation contract.']}


TEMPLATE = r'''typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
struct record {uint32_t kind,a,b,c,d,result;uint8_t byte;};
static int same(struct record a,struct record b){
 return a.kind==b.kind && a.a==b.a && a.b==b.b && a.c==b.c && a.d==b.d && a.result==b.result && a.byte==b.byte;
}
void check_admission(void){
 struct record entry_left[3],entry_right[3],tail_left[5],tail_right[5];
 uint32_t phase,fault,left_tail_count,right_tail_count,ordinal;
 __CPROVER_assume(phase<3U && fault<=1U && (phase==2U || fault==1U));
 __CPROVER_assume(left_tail_count<=5U && right_tail_count==left_tail_count);
 if(phase!=2U)__CPROVER_assume(left_tail_count==0U);
 for(uint32_t i=0;i<3U;++i)__CPROVER_assume(same(entry_left[i],entry_right[i]));
 for(uint32_t i=0;i<5U;++i)if(i<left_tail_count)__CPROVER_assume(same(tail_left[i],tail_right[i]));
 uint32_t left_count=3U+left_tail_count,right_count=3U+right_tail_count;
 __CPROVER_assert(left_count==right_count && left_count<=8U,"cleanup-composed-complete-event-count");
 __CPROVER_assert(!fault || left_count>=3U,"cleanup-fault-retains-entry-prefix");
 __CPROVER_assert(phase==2U || left_count==3U,"cleanup-entry-loop-fault-has-no-tail-events");
 __CPROVER_assume(ordinal<left_count);
 uint32_t left_stage=ordinal<3U?0U:2U,right_stage=ordinal<3U?0U:2U;
 struct record left=ordinal<3U?entry_left[ordinal]:tail_left[ordinal-3U];
 struct record right=ordinal<3U?entry_right[ordinal]:tail_right[ordinal-3U];
 __CPROVER_assert(left_stage==right_stage && same(left,right),"cleanup-composed-ordered-event-observation");
}
'''
