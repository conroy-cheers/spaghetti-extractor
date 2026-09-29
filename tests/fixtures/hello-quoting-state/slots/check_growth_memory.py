"""Check successful slot-growth contents through actual original/C boundaries.

The original resumes after xpalloc with explicit success, frame and lifetime
premises; the complete ordinary C runs to the same clearing call. With --connected,
start at actual entry and continue through normal clearing and count publication.
Old/new lengths are symbolic within nonwrapping PE32 spans. No allocation,
lifetime, growth-body, full-operation or native-admission theorem is claimed.
--concrete-case is an explicitly restricted diagnostic, never a symbolic proof.
"""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import time

from spaghetti_extractor.components.bisimulation_call_evidence import checker_options
from spaghetti_extractor.components.bisimulation_call_relations import ScalarBinding, constant, lower_call_relation, parameter
from spaghetti_extractor.components.bisimulation_caller_memory import U32
from spaghetti_extractor.components.bisimulation_caller_records import render_record_transport, record_type_check_source
from spaghetti_extractor.components.bisimulation_caller_local_records import LocalRecordBinding, local_record_runtime
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.bisimulation_compilation import workspace_compile_command
from spaghetti_extractor.components.bisimulation_execution import property_checker_command
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_property_replay import _RetainedQueries, check_partitioned_model
from spaghetti_extractor.components.bisimulation_query_evidence import CbmcQueryEvidence, _output_digests
from spaghetti_extractor.components.cbmc_backend import discover_cbmc_assertions, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import compile_component_interface_v5
from spaghetti_extractor.util import sha256_file
from spaghetti_extractor.transfer.plan import load_executable_transfer_plan

from prepare import interface
from record_layout import record_types

HERE=Path(__file__).resolve().parent


def concrete_case_inputs(case):
    """Small admitted layouts for debugging, separate from the symbolic domain."""
    if case is None:
        return {}
    assert case in {'static','moved','inplace'}
    old=0x420054 if case=='static' else 0x500000
    new=old if case=='inplace' else 0x510000
    count=1 if case=='static' else 2
    return {'old_address':old,'new_address':new,'old_count':count,'new_count':count+1,
        'index_value':count,'stack_base':0x10000,'probe':new+8*count,
        'errno_address':0x600000,'errno_target':0x123456,
        'argument_word':0,'options_word':0,'size_word':0}


def restrict_case(source, values):
    if not values:
        return source
    words={'errno_address','errno_target','argument_word','options_word','size_word'}
    for marker, selected, before in [(' preallocated=old_address==0x420054U;',set(values)-words,True),
                                     (' errno_address=inputs[3];errno_target=inputs[4];',words,False)]:
        assert source.count(marker)==1
        assumptions=''.join(f'\n __CPROVER_assume({name}=={values[name]}U);' for name in sorted(selected))
        source=source.replace(marker,assumptions+'\n'+marker if before else marker+assumptions)
    return source


def growth_record_transport(bundle, *, connected=False):
    types=[row for row in record_types() if row['id'] in {'quote_table','quote_bytes'}]
    types[0].update(representation='identity',extent=0)
    for field in types[1]['fields']:field['writable']=False
    definition={'event_capacity':9 if connected else 8,'services':[{'id':'allocate_buffer','maximum_calls':1}],
        'records':{'header':'quote-objects.h','lifetime':'operation','types':types,
        'objects':[{'id':'initial','type_id':'quote_table','count':1,'address':constant(0x420054).to_payload()},
            {'id':'buffer','type_id':'quote_bytes','count':1,'address':parameter('initial_buffer',U32).to_payload()}],
        'projections':[{'id':'globals','type_id':'quote_state','fields':[
            {'path':['count'],'kind':'word','writable':connected,'address':constant(0x42005c).to_payload()}]}],
        'state':{'slots':'globals'}}}
    if connected:
        types.append({'id':'quote_options','extent':0,'fields':[],'subobjects':[],'representation':'identity'})
        definition['records']['objects'] += [
            {'id':'argument','type_id':'quote_bytes','count':1,'address':parameter('argument',U32).to_payload()},
            {'id':'options','type_id':'quote_options','count':1,'address':parameter('options',U32).to_payload()}]
    bindings={'initial_buffer':ScalarBinding(U32,'old_buffer')}
    if connected:
        bindings.update(argument=ScalarBinding(U32,'argument_word'),options=ScalarBinding(U32,'options_word'))
    records=render_record_transport(definition,bundle,lambda raw:lower_call_relation(raw,
        parameters=bindings),bulk_operations=True)
    text='\n'.join([*records.declarations,*records.runtime,'static void spx_growth_record_initialize(void){',
                    *records.initializers,'}'])+'\n'
    return text,record_type_check_source(definition,bundle),definition


def connected_exact(retained, manifest, out):
    """Use the existing exact emitter's real barrier, retaining all owned units."""
    inventory=retained.parent/'inventory.json'; metadata=json.loads(inventory.read_text())
    plan=Path(metadata['plan']);assert sha256_file(plan)==metadata['plan_sha256']
    assert manifest['bindings']['executable_transfer_plan_sha256']==metadata['plan_sha256']
    _,transfers=load_executable_transfer_plan(plan,require_complete=False)
    cut=next(row.identity for row in transfers if row.rva_start==0x4f62)
    intent=ComponentBisimulationIntentV1.create(component_id=manifest['component_id'],operations=[{
        'operation_id':'quote','syncs':[{'id':'grown','exact_unit_id':cut,'invariant':{'op':'true'},
            'captures':[{'kind':'parameter','id':'slot_index','mode':'machine_codec',
                'projection':{'kind':'register','register':'esi','width':32,'at':'entry'},
                'encoding':{'op':'parameter','name':'slot_index'},'decoding':None}],
            'derived':[]}]}])
    # This intent only requests an exact stop label. Its trivial relation grants
    # no theorem: the generated harness checks the actual outgoing state.
    (out/'cut-intent.json').write_text(json.dumps(intent.to_payload(),indent=2)+'\n')
    exact=write_component_exact_c_slice_v1(component_id=manifest['component_id'],transfers=transfers,
        operations=[{'operation_id':'quote','unit_ids':manifest['root_unit_ids'],
            'context_unit_ids':manifest['root_context_unit_ids'],'entry_rvas':manifest['entry_rvas']}],
        intent=intent,executable_transfer_plan_sha256=metadata['plan_sha256'],
        summary_entry_rvas=[0x1b34,0x36ea,0x6255,0x63ac],out=out)
    assert exact['root_unit_ids']==manifest['root_unit_ids'] and exact['forced_label_rvas']==[0x4f62]
    assert exact['root_unit_ids']==exact['root_context_unit_ids'] and len(exact['functions'])==1
    return {str(inventory):sha256_file(inventory),str(plan):sha256_file(plan)}


def check(retained, out, *, mutation=None, previous=None, record_snapshots=False, connected=False, prepare_only=False,
          concrete_case=None):
    assert not connected or record_snapshots,'connected growth requires checked record snapshots'
    assert connected or mutation not in {'wrong-publication','wrong-saved-errno'},'continuation mutations require --connected'
    assert concrete_case is None or connected,'concrete cases require the actual-entry connection'
    concrete_inputs=concrete_case_inputs(concrete_case)
    input_scope='concrete-case-diagnostic' if concrete_case else 'symbolic-growth-domain'
    started=time.monotonic();out.mkdir(parents=True)
    manifest=json.loads((retained/'component-exact-c-slice-v1.json').read_text())
    assert len(manifest['root_unit_ids'])==40 and manifest['root_unit_ids']==manifest['root_context_unit_ids']
    inputs={str(retained/'component-exact-c-slice-v1.json'):sha256_file(retained/'component-exact-c-slice-v1.json')}
    # Bind the producers used for this run before checking. A later working-tree
    # edit must not relabel an already-generated model as the new implementation.
    import spaghetti_extractor.components.bisimulation_mutable_memory as memory
    inputs.update({str(path):sha256_file(path) for path in [HERE/'check_growth_memory.py',HERE/'prepare.py',Path(memory.__file__)]})
    if record_snapshots:
        import spaghetti_extractor.components.bisimulation_caller_records as records
        inputs.update({str(path):sha256_file(path) for path in [HERE/'record_layout.py',Path(records.__file__)]})
    if connected:
        import spaghetti_extractor.components.bisimulation_caller_local_records as local_records
        import spaghetti_extractor.components.component_exact_c_slice as exact_slice
        inputs.update({str(path):sha256_file(path) for path in [Path(local_records.__file__),Path(exact_slice.__file__)]})
    for row in manifest['files']:
        path=retained/row['path'];assert sha256_file(path)==row['sha256']
        inputs[str(path)]=row['sha256'];shutil.copyfile(path,out/row['path'])
    if connected:
        inputs.update(connected_exact(retained,manifest,out))
    bundle=compile_component_interface_v5(interface())
    for name,text in render_component_c_headers_v5(bundle,{'quote':'quote_slots'}).items():
        (out/name).write_text(text)
    for name in ['quote-slots.c','quote-objects.h','growth-memory.c']:
        inputs[str(HERE/name)]=sha256_file(HERE/name);shutil.copyfile(HERE/name,out/name)
    if record_snapshots:
        path=out/'growth-memory.c';path.write_text('#define SPX_GROWTH_RECORD_SNAPSHOTS 1\n'+path.read_text())
    if connected:
        path=out/'growth-memory.c';path.write_text('#define SPX_GROWTH_CONNECTED 1\n'+path.read_text())
        source=out/'quote-slots.c';text=source.read_text()
        marker='    struct spx_opaque_quote_table_v5 *slot = &slots[slot_index];'
        assert text.count(marker)==1
        source.write_text(text.replace(marker,
            '    check_growth_continuation(state, slots, slot_index, saved_errno, argument, argument_size, options);\n'+marker))
    if concrete_inputs:
        path=out/'growth-memory.c';path.write_text(restrict_case(path.read_text(),concrete_inputs))
    if mutation:
        before,after={'wrong-copy':('slots[0] = state->initial_table[0];',
                                  '{ slots[0] = state->initial_table[0]; slots[0].size ^= 1U; }'),
                      'wrong-clear':('new_count.value - state->count);','new_count.value - state->count - 1U);'),
                      'wrong-publication':('state->count = new_count.value;','state->count = new_count.value - 1U;'),
                      'wrong-saved-errno':('uint32_t saved_errno = read_word(services->errno_cell(environment));',
                                          'uint32_t saved_errno = read_word(services->errno_cell(environment)) ^ 1U;')}[mutation]
        path=out/'quote-slots.c';text=path.read_text();assert text.count(before)==1
        path.write_text(text.replace(before,after))
    preparation=time.monotonic()-started;start=time.monotonic()
    (out/'sparse-memory.h').write_text('\n'.join(sparse_mutable_memory_runtime(
        9 if connected else 8,bulk_operations=True,representation_hooks=record_snapshots,
        preserved_spans=[(0x420054,8 if connected else 12)]))+'\n')
    if record_snapshots:
        records,types,definition=growth_record_transport(bundle,connected=connected)
        (out/'record-transport.h').write_text(records);(out/'record-types.c').write_text(types)
        (out/'record-definition.json').write_text(json.dumps(definition,indent=2)+'\n')
    if connected:
        layout=next(row for row in record_types() if row['id']=='quote_word')
        helper=local_record_runtime({'count':LocalRecordBinding('quote_word','0U','4U',3,layout)})
        (out/'local-record-transport.h').write_text('\n'.join(helper)+'\n')
    _write_cbmc_stdint(out/'stdint.h');(out/'stddef.h').write_text('typedef unsigned int size_t;\n#define NULL ((void *)0)\n')
    model=time.monotonic()-start
    compiler=Path(shutil.which('goto-cc'));checker=Path(shutil.which('cbmc'))
    type_compilation=None
    if record_snapshots:
        type_command=[str(compiler),'--i386-linux','-nostdinc','-I','.', 'record-types.c',
                      '--function','spx_check_record_types','-o','record-types.goto']
        start=time.monotonic();checked=subprocess.run(workspace_compile_command(type_command,out),capture_output=True,text=True)
        type_compilation={'command':type_command,'seconds':time.monotonic()-start,'exit_code':checked.returncode,'stderr':checked.stderr}
        (out/'record-type-compilation.json').write_text(json.dumps(type_compilation,indent=2)+'\n')
        assert checked.returncode==0,checked.stderr
    command=[str(compiler),'--i386-win32','-nostdinc','-I','.','growth-memory.c','behavioral-support.c',
             'behavioral-fn-00004eb3.c','--function','check_growth_memory','-o','model.goto']
    start=time.monotonic();result=subprocess.run(workspace_compile_command(command,out),capture_output=True,text=True)
    compilation={'command':command,'seconds':time.monotonic()-start,'exit_code':result.returncode,'stderr':result.stderr}
    (out/'compilation.json').write_text(json.dumps(compilation,indent=2)+'\n');assert result.returncode==0,result.stderr
    if prepare_only:
        # Reuse the same exact emitter, record renderer and compiler path for
        # focused diagnosis before another expensive complete check. This is
        # only a prepared model; it supplies no proof or qualification result.
        prepared={'scope':'Prepared diagnostic model; no proof queries or admission witnesses executed.',
            'authorizing':False,'activation_authorized':False,'whole_component_complete':False,
            'connected':connected,'record_snapshots':record_snapshots,'mutation':mutation,'inputs':inputs,
            'input_scope':input_scope,'concrete_case':concrete_case,'concrete_inputs':concrete_inputs,
            'universal_region_complete':False,
            'model_sha256':sha256_file(out/'model.goto'),'compilation':compilation,
            'record_type_compilation':type_compilation,
            'tools':{'compiler':str(compiler),'compiler_sha256':sha256_file(compiler),
                     'checker':str(checker),'checker_sha256':sha256_file(checker)},
            'phases':{'preparation':preparation,'model':model,
                'compiler':compilation['seconds']+(type_compilation['seconds'] if type_compilation else 0),
                'solver':0,'native_link':0},'seconds':time.monotonic()-started}
        (out/'model-preparation.json').write_text(json.dumps(prepared,indent=2)+'\n')
        print(json.dumps({'prepared':str(out),'seconds':prepared['seconds'],'proof_checked':False}),flush=True)
        return
    start=time.monotonic();previous_queries=None
    if previous is not None:
        old=json.loads((previous/'validation.json').read_text())
        records=sorted((previous/'query-evidence').glob('*/query.json'));assert records
        tools=json.loads(records[0].read_text())['binding']['tools']
        hashes={'goto_cc':tools['compiler_sha256'],'cbmc':tools['checker_sha256']}
        # Verify retained process bytes and exact tool/model/command bindings.
        # Current preparation and compilation still run; a changed GOTO or tool
        # cannot hit this cache. Only outputs bound in the old result are offered.
        _RetainedQueries(model=previous/'model.goto',query_root=previous/'query-evidence',tool_hashes=hashes)
        previous_queries={'directory':previous/'query-evidence','outputs':_output_digests(old['queries']),
            'goto_model_sha256':sha256_file(previous/'model.goto'),
            'checker':{'goto_cc_sha256':hashes['goto_cc'],'cbmc_sha256':hashes['cbmc']}}
    import_seconds=time.monotonic()-start
    evidence=CbmcQueryEvidence(model=out/'model.goto',compiler=compiler,checker=checker,
                              output=out/'query-evidence',previous=previous_queries)
    queries={};property_model=None
    domains=[concrete_case] if concrete_case else ['static','moved','inplace']
    entries=[(name+'-domain','check_'+name+'_domain') for name in domains]
    if concrete_case:
        entries.append(('continuation-domain','check_growth_continuation_domain'))
    entries.append(('growth-memory','check_growth_memory'))
    for name,entry in entries:
        start=time.monotonic()
        if name=='growth-memory':
            query,property_model=check_partitioned_model(model=out/'model.goto',entry=entry,
                command=property_checker_command([],source_unwind_limit=32,smt_solver=None,
                                                 application_first=bool(mutation)),cbmc=checker,
                evidence=evidence,timeout_seconds=60,subject={'subject':'real-quoting-growth-memory'})
        elif name=='continuation-domain':
            policy=property_checker_command([],source_unwind_limit=32,smt_solver=None)
            inventory=discover_cbmc_assertions(command=[str(checker),str(out/'model.goto'),
                *[entry if arg=='$PROPERTY_FUNCTION' else arg for arg in policy['discovery_arguments']]],
                timeout_seconds=60,query_evidence=evidence)
            assert inventory['status']=='satisfied'
            sites=[row for row in inventory['assertions'] if row['description']=='growth-connected-continuation-witness']
            assert len(sites)==1
            options=[entry if arg=='$PROPERTY_FUNCTION' else sites[0]['property_id'] if arg=='$PROPERTY_ID' else arg
                     for arg in policy['assertion_arguments']]
            query=run_cbmc_properties(command=[str(checker),str(out/'model.goto'),*options],
                cwd=out,timeout_seconds=60,query_evidence=evidence,output_prefix=out/name)
        else:
            query=run_cbmc_properties(command=[str(checker),'model.goto','--function',entry,
                *checker_options(32,None)],cwd=out,timeout_seconds=60,query_evidence=evidence,output_prefix=out/name)
        queries[name]={'result':query,'seconds':time.monotonic()-start}
        print(json.dumps({'query':name,'status':query['status'],'seconds':queries[name]['seconds'],
                          'comment':query.get('source',{}).get('comment'),'detail':query.get('detail')}),flush=True)
    record={'scope':('Conditional actual entry through successful growth, normal clear return and count publication. '
                    'Allocator lifetime, following selected-slot access and complete-operation admission remain open.'
                    if connected else __doc__),
        'authorizing':False,'activation_authorized':False,'whole_component_complete':False,
        'input_scope':input_scope,'concrete_case':concrete_case,'concrete_inputs':concrete_inputs,
        'universal_region_complete':not concrete_case and queries['growth-memory']['result']['status']=='satisfied'
            and all(queries[name+'-domain']['result'].get('source',{}).get('comment')=='growth-memory-'+name+'-domain'
                    and queries[name+'-domain']['result']['status']=='violated' for name in domains),
        'entry_rvas':[0x4eb3] if connected else [0x4f2c,0x505c],
        'cut_rva':0x4f62 if connected else 0x4f54,'connected':connected,'mutation':mutation,'inputs':inputs,'queries':queries,
        'compilation':compilation,'record_snapshots':record_snapshots,'record_type_compilation':type_compilation,
        'property_model':property_model,'seconds':time.monotonic()-started,
        'reuse':{'previous':str(previous) if previous else None,
                 'previous_result_sha256':sha256_file(previous/'validation.json') if previous else None,
                 'executed_queries':evidence.executed,'reused_queries':evidence.reused},
        'phases':{'preparation':preparation,'model':model,
                  'compiler':compilation['seconds']+(type_compilation['seconds'] if type_compilation else 0),
                  'evidence_import':import_seconds,'solver':sum(row['seconds'] for row in queries.values()),'native_link':0},
        'runtime_premises':['Successful xpalloc returns a live nonnull nonwrapping slot span and a larger count.',
            'Relocation preserves the old prefix; in-place growth preserves its existing bytes.',
            'New span and private frame are disjoint from the accessed global words; relocated allocations are disjoint.',
            'The static table has one slot; initial bytes and buffer identities correspond.',
            'Growth preserves the table/count and initial-slot globals; other public bytes may change arbitrarily.',
            'The declared private stack words and post-call register relation hold at the resumed native cut.',
            'Memset returns normally after writing exactly its declared destination span.',
            'Allocation/release generations, exceptional outcomes and prefix-to-continuation applicability are unproved.']}
    if connected:
        record['runtime_premises']=[row for row in record['runtime_premises']
            if not row.startswith(('The declared private stack','Allocation/release generations'))]
        record['runtime_premises'] += [
            'Entry errno returns normally with unchanged public memory and a related nonnull four-byte cell outside the private frame.',
            'Errno, successful growth and memset preserve callee-saved registers and the private frame except the explicit count output.',
            'Services are synchronous; callback/reentrant/concurrent observations are outside this regional rule.',
            'Allocation/release generations, exceptional outcomes, selected-slot array transport and final native admission are unproved.']
    if concrete_case:
        record['scope']='Restricted input diagnostic for '+concrete_case+'. No symbolic region theorem. '+record['scope']
    (out/'validation.json').write_text(json.dumps(record,indent=2)+'\n')
    for name in [name+'-domain' for name in domains]:
        query=queries[name]['result'];assert query['status']=='violated'
        assert query['source']['comment']=='growth-memory-'+name
    if concrete_case:
        query=queries['continuation-domain']['result']
        assert query['status']=='violated' and query['source']['comment']=='growth-connected-continuation-witness'
    query=queries['growth-memory']['result'];assert query['status']==('violated' if mutation else 'satisfied')
    if mutation:
        # The existing parser understands both complete and stop-on-fail JSON.
        expected={'wrong-copy':{'growth-memory-call-time-bytes','growth-memory-post-clear-bytes','growth-memory-copied-size'},
                  'wrong-clear':{'growth-memory-source-clear-arguments','growth-memory-post-clear-bytes'},
                  'wrong-publication':{'growth-connected-count-table-publication'},
                  'wrong-saved-errno':{'growth-connected-source-continuation-inputs'}}
        assert query.get('source',{}).get('comment') in expected[mutation]


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('retained',type=Path);parser.add_argument('out',type=Path)
    parser.add_argument('--mutation',choices=['wrong-copy','wrong-clear','wrong-publication','wrong-saved-errno'])
    parser.add_argument('--previous',type=Path)
    parser.add_argument('--record-snapshots',action='store_true')
    parser.add_argument('--connected',action='store_true')
    parser.add_argument('--prepare-only',action='store_true',help='emit the same compiled model for focused diagnostics, without running proofs')
    parser.add_argument('--concrete-case',choices=['static','moved','inplace'],
                        help='restrict inputs for diagnosis and check actual continuation reachability; never a symbolic proof')
    args=parser.parse_args();check(args.retained.resolve(),args.out.resolve(),mutation=args.mutation,
                                 previous=args.previous.resolve() if args.previous else None,
                                 record_snapshots=args.record_snapshots,connected=args.connected,prepare_only=args.prepare_only,
                                 concrete_case=args.concrete_case)
