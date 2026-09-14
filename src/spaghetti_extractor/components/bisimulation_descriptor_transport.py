"""Checked opaque-context substitution through the real cleanup view accessors.

Reference fields remain exact. Only inaccessible context identities may change,
with live storage and equivalent access hooks. Access revocation is not evidence
of physical deallocation or a successful external release.
"""
import re
from pathlib import Path

from .bisimulation_compaction_contract import require
from .machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION
from .bisimulation_cut_state import _symbol
from .bisimulation_entry_conformance import _payload, _truth
from .bisimulation_source_call_region import _path
from .bisimulation_source_region_transport import _integer
from ..artifacts.artifact_set import canonical_sha256_v3
from .bisimulation_call_evidence import read_json
from .bisimulation_compaction_inputs import read_inventory
from .bisimulation_source_call_check import checked_source_region_graphs

ACCESSORS = ('spx_component_view_read', 'spx_component_view_read_span',
             'spx_component_view_write', 'spx_component_view_write_span',
             'spx_view_read_u8', 'spx_view_write_u8')
HEADERS = ('portable-component-implementation.h', 'portable-component.h',
           'state-machine-runtime.h', 'stddef.h', 'stdint.h')
FIELDS = ('base.domain', 'base.object', 'base.generation', 'base.offset', 'base.extent', 'base.permissions',
          'extent', 'element_width', 'context', 'access_context', 'read_u8', 'write_u8', 'read', 'write')
RUNTIME_REQUIREMENTS = {
    'cleanup-scoped-scratch-borrow-v1': 'Allocation supplies the declared nullable descriptor and context storage that survives the complete borrow interval.',
    'cleanup-access-hook-frame-v1': 'Access hooks preserve descriptor/context metadata and grants, and corresponding calls agree on current bytes, results, faults and effects.',
    'cleanup-nonretaining-services-v1': 'Length and copy preserve outstanding grants and retain no borrowed descriptor or context after returning.',
    'cleanup-physical-release-outcome-v1': 'Qualify the release result and physical allocation-state effects separately from this component relinquishing access.',
}
GUARDED_WRITE = '''static void source_scratch_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 __CPROVER_assert(!source_environment->released,"tail-source-no-use-after-release");
 spx_mutable_write(opaque,address,width,value,fault);
}'''


def _function(source, name):
    matches = list(re.finditer(r'(?:static )?(?:uint32_t|void) '+name+r'\([^;{}]*\)\s*\{', source))
    require(len(matches) == 1, 'missing or ambiguous descriptor accessor '+name)
    match, = matches
    depth = 1
    for i in range(match.end(), len(source)):
        depth += (source[i] == '{') - (source[i] == '}')
        if depth == 0:
            return source[match.start():i+1]
    raise ValueError('unterminated descriptor accessor '+name)


def cleanup_descriptor_transport_domain(models, headers):
    require(set(models) == {'entry', 'loop', 'tail'} and set(headers) == set(HEADERS),
            'descriptor transport needs complete checked regions and ABI headers')
    functions = {name: _function(models['entry'], name) for name in ACCESSORS}
    for role, source in models.items():
        require(VIEW_CONTEXT_DECLARATION in source, 'descriptor context ABI differs in '+role)
        for name, text in functions.items():
            require(_function(source, name) == text, 'regional descriptor accessor differs: '+role+': '+name)
    clauses = {}
    for role, owner, prefix in [('entry', 'observed_view', 'entry-full-view-'),
                                ('loop', 'spx_cut.scratch', 'loop-observer-view-')]:
        clauses[role] = [f'__CPROVER_assert(scratch->{field}=={owner}.{field},"{prefix}{field}");' for field in FIELDS]
        for statement in clauses[role]:
            require(statement in models[role], 'missing complete outgoing descriptor guarantee: '+statement)
    require(_function(models['tail'], 'source_scratch_write') == GUARDED_WRITE,
            'terminal scratch lifetime guard differs')
    clauses['entry'].append('__CPROVER_assert(a.phase==3U && b.phase==3U,"entry-three-service-invocations");')
    clauses['tail'] = [GUARDED_WRITE,
        'if(kind==2U){__CPROVER_assert(!e->released,"tail-release-once");e->released=1U;}']
    for role, statements in clauses.items():
        require(all(s in models[role] for s in statements), 'descriptor service protocol differs in '+role)
    return {'profile': 'cleanup-live-view-context-substitution-v1', 'headers': headers,
        'accessors': functions, 'regional_clauses': clauses,
        'runtime_requirements': {name: {'status': 'unverified', 'requirement': text}
                                 for name, text in RUNTIME_REQUIREMENTS.items()},
        'requires': ['Checked regional source footprints prohibit observing, modifying or escaping opaque context identities.',
            'The caller and allocator provide live descriptor, context and access-hook storage for the complete borrow interval.',
            'Corresponding access hooks have the same current memory, arguments, results, faults and effects.',
            'The scratch access grant is active before the terminal release; physical release success is separate.'],
        'scope': 'Exact reference fields and live opaque-context/accessor substitution, including the terminal write guard. Physical lifetime, release success and concrete service compatibility remain unqualified.'}


def descriptor_files(domain):
    return {**domain['headers'], 'descriptor-accessors.h': VIEW_CONTEXT_DECLARATION
            + '\n'.join(domain['accessors'][name] for name in ACCESSORS) + '\n'}


def check_descriptor_files(proof, domain):
    """Import the retained ABI and accessor code without generating a header."""
    require(set(domain['headers']) == set(HEADERS) and set(domain['accessors']) == set(ACCESSORS),
            'descriptor input inventory changed')
    for name in HEADERS:
        require((Path(proof)/name).read_text() == domain['headers'][name], 'descriptor ABI input changed')
    remaining = (Path(proof)/'descriptor-accessors.h').read_text()
    require(remaining.startswith(VIEW_CONTEXT_DECLARATION), 'descriptor context declaration changed')
    remaining = remaining[len(VIEW_CONTEXT_DECLARATION):]
    for name in ACCESSORS:
        text = domain['accessors'][name]
        require(remaining.startswith(text) and remaining[len(text):].startswith('\n'),
                'descriptor accessor input changed')
        remaining = remaining[len(text)+1:]
    require(not remaining, 'extra descriptor accessor input')


def checked_cleanup_grant_protocol(body, *, context_parameter):
    """Check the complete owned source CFG with a three-state grant automaton.

    This consumes the existing compiler inventory after regional source-footprint
    validation. Loops reach a fixed point over (instruction, grant state), rather
    than enumerating paths or bounding the number of cleanup iterations. External
    services still owe their named preservation and non-retention contracts.
    """
    rows = body['instructions']; locations = {r['locationNumber']: i for i, r in enumerate(rows)}
    require(rows and len(locations) == len(rows), 'grant protocol has duplicate or missing locations')
    prefix = (context_parameter, '*', 'services', '*')
    pending, visited, calls, returns = [(0, 'unissued')], set(), {}, set()
    while pending:
        index, grant = pending.pop()
        if (index, grant) in visited:
            continue
        require(0 <= index < len(rows), 'grant protocol falls off the source function')
        visited.add((index, grant)); row = rows[index]; kind = row['instructionId']
        require(not row.get('targets') or kind == 'GOTO', 'grant protocol target on non-branch')
        if kind == 'SET_RETURN_VALUE':
            values = row.get('code', {}).get('sub', [])
            require(len(values) == 1, 'grant protocol malformed return')
            fault = _integer(values[0]) == 0xffffffff
            require(fault or grant == 'revoked', 'normal return retains an unrevoked scratch grant')
            returns.add((index, 'fault' if fault else 'normal', grant))
            continue
        require(kind in {'DECL', 'DEAD', 'ASSIGN', 'FUNCTION_CALL', 'GOTO', 'SKIP', 'LOCATION'},
                'grant protocol unsupported instruction '+kind)
        if kind == 'FUNCTION_CALL':
            operands = row.get('code', {}).get('sub', [])
            require(len(operands) == 3, 'grant protocol malformed call')
            name = _symbol(operands[1]); path = () if name else _path(operands[1])
            if name is None and len(path) == 6 and path[:4] == prefix and path[-1] == '*':
                name = path[4]
            elif name is None and len(path) == 4 and path[1:] == ('*', 'read', '*'):
                name = 'read-shared-view'
            require(name in {'length', 'allocate', 'copy', 'release', 'resource_text', 'message', 'focus',
                             'spx_view_read_u8', 'spx_view_write_u8', 'read-shared-view'},
                    'grant protocol unknown dependency')
            calls[index] = name
            if name == 'allocate':
                require(grant == 'unissued', 'scratch grant is issued more than once'); grant = 'active'
            elif name in {'copy', 'spx_view_write_u8', 'release'}:
                require(grant == 'active', 'scratch access or release lacks an active grant')
                if name == 'release':
                    grant = 'revoked'
            elif name in {'resource_text', 'message', 'focus', 'read-shared-view'}:
                require(grant == 'revoked', 'terminal interaction precedes scratch grant revocation')
            elif name == 'length':
                require(grant != 'revoked', 'length service follows scratch revocation')
        if kind == 'GOTO':
            targets = row.get('targets', [])
            require(len(targets) == 1 and targets[0] in locations, 'grant protocol invalid branch target')
            known = _truth(row['guard'], {})
            successors = ([locations[targets[0]]] if known is not False else []) + ([index+1] if known is not True else [])
        else:
            successors = [index+1]
        pending.extend((next_index, grant) for next_index in successors)
    require(any(outcome == 'normal' for _, outcome, _ in returns)
        and list(calls.values()).count('allocate') == list(calls.values()).count('release') == 1,
        'grant protocol lacks the complete allocation/release operation')
    return {'status': 'checked-conditional-scratch-grant-protocol', 'authorizing': False,
        'body_sha256': canonical_sha256_v3([_payload(row) for row in rows]),
        'reachable_instructions': len({index for index, _ in visited}), 'abstract_states': len(visited),
        'calls': [{'instruction': i, 'dependency': calls[i]} for i in sorted(calls)],
        'returns': [list(row) for row in sorted(returns)],
        'normal_return_grant': 'revoked', 'physical_deallocation_checked': False,
        'runtime_requirements': sorted(RUNTIME_REQUIREMENTS),
        'requires': ['Allocation issues a scoped nullable scratch access grant with persistent context storage.',
            'Length, copy and access hooks preserve outstanding grants and do not retain borrowed contexts.',
            'Release revokes this component\'s access grant; its result determines physical deallocation separately.'],
        'scope': 'Owned-source control and scratch-use protocol; functional equivalence, progress and external lifetime behavior are separate.'}


def cleanup_source_grant_protocol(preparation, contracts):
    """Bind the protocol to a complete graph covered by the imported proofs."""
    preparation = Path(preparation)
    artifacts = preparation/'source-region-graph-models'
    graphs = checked_source_region_graphs(read_json(preparation/'compiler-checks.json')['source_region_graphs'],
                                         artifacts=artifacts)
    require(len(graphs) == 1 and all(c['graph_index'] == 0 for c in contracts.values()),
            'grant protocol needs the shared complete source graph')
    graph, = graphs
    covered = [region for c in contracts.values() for region in c['regions']]
    require(len(covered) == len(set(covered)) and set(covered) == {r['entry'] for r in graph['regions']}
        and graph['uncovered_reachable_instruction_count'] == 0 and not graph['unselected_cut_regions'],
        'grant protocol has an unproved source region or reachable coverage hole')
    ordinary = read_inventory(artifacts/'0000-ordinary')
    result = checked_cleanup_grant_protocol(ordinary['functions'][graph['function']],
        context_parameter=graph['function']+'::'+contracts['entry']['parameter_roles']['context'])
    result['source_cover'] = {r['entry']: r['semantic_sha256'] for r in graph['regions']}
    return result


TEMPLATE = r'''#include "state-machine-runtime.h"
#include "portable-component-implementation.h"
#include "descriptor-accessors.h"
struct access_record {uint32_t count,kind,address,width,value;};
static uint32_t read_result,access_fault;
static uint32_t record_read(void *opaque,uint32_t address,uint32_t width,uint32_t *fault){
 struct access_record *r=opaque;*r=(struct access_record){r->count+1U,1U,address,width,0U};
 *fault=access_fault;return read_result;
}
static void spx_mutable_write(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault){
 struct access_record *r=opaque;*r=(struct access_record){r->count+1U,2U,address,width,value};*fault=access_fault;
}
struct environment {uint32_t released;};
static struct environment *source_environment;
@GUARDED_WRITE@
static uint32_t access_view(spx_view_v5 *v,uint32_t kind,uint64_t index,uint32_t width,uint64_t value,uint64_t *result){
 if(kind==0U){uint8_t byte=0;uint32_t status=spx_view_read_u8(v,index,&byte);*result=byte;return status;}
 if(kind==1U)return spx_view_write_u8(v,index,(uint8_t)value);
 if(kind==2U)return v->read(v->access_context,v->base,index,width,result);
 return v->write(v->access_context,v->base,index,width,value);
}
void check_admission(void){
 uint32_t address,extent,kind,width,input_result,input_fault;uint64_t index,value;
 spx_ref_v5 reference;
 __CPROVER_assume((uint64_t)address+extent<=UINT64_C(4294967296) && kind<4U);
 read_result=input_result;access_fault=input_fault;
 struct access_record a={0},b={0};struct environment environment={0};source_environment=&environment;
 spx_runtime left_runtime={.context=&a,.read=record_read,.write=spx_mutable_write};
 spx_runtime right_runtime={.context=&b,.read=record_read,.write=source_scratch_write};
 spx_component_view_context left_context={&left_runtime,address,extent,3U};
 spx_component_view_context right_context={&right_runtime,address,extent,3U};
 spx_view_v5 left={.base=reference,.extent=extent,.element_width=1U,
  .context=&left_context,.access_context=&left_context,.read_u8=spx_component_view_read,
  .write_u8=spx_component_view_write,.read=spx_component_view_read_span,.write=spx_component_view_write_span};
 spx_view_v5 right=left;right.context=&right_context;right.access_context=&right_context;
 __CPROVER_assert(right.base.domain==left.base.domain && right.base.object==left.base.object &&
  right.base.generation==left.base.generation && right.base.offset==left.base.offset &&
  right.base.extent==left.base.extent && right.base.permissions==left.base.permissions &&
  right.extent==left.extent && right.element_width==left.element_width,"descriptor-public-reference-preserved");
 uint64_t left_value=0,right_value=0;
 uint32_t left_status=access_view(&left,kind,index,width,value,&left_value);
 uint32_t right_status=access_view(&right,kind,index,width,value,&right_value);
 __CPROVER_assert(a.count<=1U && b.count<=1U,"descriptor-single-access-hook");
 __CPROVER_assert(left_status==right_status && left_value==right_value,"descriptor-access-result-and-fault");
 __CPROVER_assert(a.count==b.count && a.kind==b.kind && a.address==b.address &&
  a.width==b.width && a.value==b.value,"descriptor-access-effect-arguments");
}
'''.replace('@GUARDED_WRITE@', GUARDED_WRITE)
