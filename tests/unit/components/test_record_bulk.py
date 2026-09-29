"""Copy snapshots include ordinary C fields and retain historical aliases."""
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import constant, lower_call_relation
from spaghetti_extractor.components.bisimulation_caller_records import render_record_transport
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.service_authoring import signature

TESTKIT={'fixtures':('cbmc','compiler')}


def record_model(body, *, capacity=4, writable=True, returned_identity=False, preserved_spans=(), helpers=''):
    signatures=[signature('run',[],'unit')]
    services=[];identity_types=[]
    if returned_identity:
        signatures.append(signature('allocate',[],'token'))
        signatures[-1][1]['results'][0]['nullable']=True
        services=[{'id':'allocate','signature_id':'allocate','effect_ids':[],
                   'interaction_contract_id':'fixture.allocate'}]
        identity_types=[{'id':'token','kind':'opaque','nominal_id':'fixture.token'}]
    schema=BoundarySchemaV1.create(schema_id='record-snapshot',types=[
        {'id':'unit','kind':'void'},{'id':'cell','kind':'opaque','nominal_id':'fixture.cell'},
        *identity_types,*[row[0] for row in signatures]],signatures=[row[1] for row in signatures])
    intent=ComponentInterfaceIntentV1.create(component_id='record-snapshot',schema=schema,state=[],services=services,effects=[],
        protocol_states=['ready'],initial_protocol_state='ready',operations=[{
            'id':'run','signature_id':'run','pre_states':['ready'],'post_states':['ready'],
            'allowed_service_ids':[row['id'] for row in services],'effect_ids':[],'source_values':[],'projection_entries':[],
            'lifecycle_bindings':[],'lifecycle_additional_roots':{'state':[]},'checked_interaction_contract_ids':[]}])
    definition={'event_capacity':capacity,'records':{'header':'objects.h','lifetime':'operation',
        'types':[{'id':'cell','extent':8,'fields':[
            {'path':[name],'offset':offset,'kind':'word','writable':writable} for name,offset in [('a',0),('b',4)]],
            'subobjects':[]}],
        'objects':[{'id':'cell','type_id':'cell','count':1,'address':constant(100).to_payload()}],
        'projections':[],'state':{}}}
    if returned_identity:
        definition['services']=[{'id':'allocate','maximum_calls':1}]
        definition['records']['types'].append({'id':'token','extent':0,'fields':[],
                                               'subobjects':[],'representation':'identity'})
    records=render_record_transport(definition,compile_component_interface_v5(intent),
        lambda raw:lower_call_relation(raw,parameters={}),bulk_operations=True)
    model='#include "stdint.h"\n'+'\n'.join(sparse_mutable_memory_runtime(capacity,
        bulk_operations=True,representation_hooks=True,preserved_spans=preserved_spans))+'\n'
    model+='\n'.join([*records.declarations,*records.runtime])+'\n'
    model+=helpers+'\n'
    model+='void check(void){\n'+'\n'.join(records.initializers)+'\n'
    model+='''struct spx_mutable_world world={.representation=&world,
 .read_representation=spx_record_read,.write_representation=spx_record_apply,
 .snapshot_representation=spx_record_snapshot,.read_representation_snapshot=spx_record_snapshot_read};
struct spx_opaque_cell_v5 *cell=&spx_record_object_0[0];(void)cell;
'''+body+'\n}\n'
    return model


class RecordBulkTests(unittest.TestCase):
    def check_model(self, body, *, failure=None, **options):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary);_write_cbmc_stdint(root/'stdint.h')
            (root/'objects.h').write_text('struct spx_opaque_cell_v5 {uint32_t a,b;};\n')
            (root/'model.c').write_text(record_model(body,**options))
            result=run_cbmc_properties(command=[shutil.which('cbmc'),'model.c','--i386-win32','-I','.',
                '--function','check',*mutable_checker_options(16)],cwd=root,timeout_seconds=90)
        self.assertEqual(result['status'],'violated' if failure else 'satisfied',result.get('detail'))
        if failure:self.assertEqual(result['source']['comment'],failure)

    def test_symbolic_copy_and_direct_field_changes_preserve_snapshot(self):
        self.check_model('''
uint32_t a,b,source,destination,probe,next;uint64_t extent;
__CPROVER_assume(extent<=UINT64_C(4294967296)-source && extent<=UINT64_C(4294967296)-destination);
cell->a=a;cell->b=b;
uint8_t expected=spx_mutable_byte(&world,probe);
if(probe>=destination && (uint64_t)probe-destination<extent)
 expected=spx_mutable_byte(&world,source+(probe-destination));
spx_mutable_copy(&world,destination,source,extent);
__CPROVER_assert(spx_mutable_byte(&world,probe)==expected,"record-snapshot-copy-and-frame");
cell->a=next;
if(probe>=100U && probe<104U)expected=(uint8_t)(next>>(8U*(probe-100U)));
__CPROVER_assert(spx_mutable_byte(&world,probe)==expected,"record-copy-survives-later-source-change");
''',capacity=1)

    def test_overlapping_copy_and_fill_match_independent_byte_array(self):
        self.check_model('''
uint32_t a,b;uint8_t bytes[8],snapshot[8],probe;
__CPROVER_assume(probe<8U);cell->a=a;cell->b=b;
for(uint32_t i=0;i<8U;i++)bytes[i]=(uint8_t)((i<4U?a:b)>>(8U*(i%4U)));
for(uint32_t step=0;step<3U;step++){
 uint8_t from,to,length,fill;uint32_t copy;
 __CPROVER_assume(from<=8U && to<=8U && length<=8U-from && length<=8U-to);
 for(uint32_t i=0;i<8U;i++)snapshot[i]=bytes[i];
 if(copy)spx_mutable_copy(&world,100U+to,100U+from,length);
 else spx_mutable_fill(&world,100U+to,length,fill);
 for(uint32_t i=0;i<length;i++)bytes[to+i]=copy?snapshot[from+i]:fill;
}
__CPROVER_assert(spx_mutable_byte(&world,100U+probe)==bytes[probe],"record-independent-array-history");
''',capacity=3)

    def test_service_snapshot_observes_prior_effects_before_writeback(self):
        self.check_model('''
uint32_t initial;cell->a=initial;cell->b=0U;
spx_record_begin_service();
spx_mutable_fill(&world,100U,4U,0x42U);
spx_mutable_copy(&world,200U,100U,4U);
spx_mutable_fill(&world,100U,4U,0x99U);
spx_record_end_service();
uint32_t i;__CPROVER_assume(i<4U);
__CPROVER_assert(spx_mutable_byte(&world,200U+i)==0x42U,"record-service-effect-order");
__CPROVER_assert(cell->a==0x99999999U && cell->b==0U,"record-service-final-writeback");
''',capacity=3)

    def test_nested_copies_include_record_and_unrepresented_history(self):
        self.check_model('''
uint32_t a,b,probe;cell->a=a;cell->b=b;
__CPROVER_assume(probe<12U);
uint8_t expected=spx_mutable_byte(&world,98U+probe);
spx_mutable_copy(&world,200U,98U,12U);
cell->a=0U;cell->b=0U;
spx_mutable_fill(&world,98U,2U,0U);
spx_mutable_copy(&world,300U,200U,12U);
spx_mutable_fill(&world,200U,12U,0U);
__CPROVER_assert(spx_mutable_byte(&world,300U+probe)==expected,"record-nested-history");
''')

    def test_returned_identity_capacity_does_not_limit_copy_history(self):
        self.check_model('''
uint32_t address,a,b,probe;__CPROVER_assume(probe<8U);
spx_record_return_token(address);
struct spx_opaque_token_v5 *token=spx_record_decode_token(address);
__CPROVER_assert(spx_record_encode_token(token)==address,"record-returned-identity");
cell->a=a;cell->b=b;
uint8_t expected=spx_mutable_byte(&world,100U+probe);
spx_mutable_copy(&world,200U,100U,8U);
cell->a=0U;cell->b=0U;
spx_mutable_copy(&world,300U,200U,8U);
spx_mutable_copy(&world,400U,300U,8U);
__CPROVER_assert(spx_mutable_byte(&world,400U+probe)==expected,"record-copy-history-with-returned-identity");
''',capacity=3,returned_identity=True)

    def test_event_callback_observes_the_actual_appended_slot(self):
        self.check_model('''
world.write_representation=check_event_slot;
world.snapshot_representation=check_snapshot_slot;
spx_mutable_fill(&world,100U,4U,7U);
spx_mutable_copy(&world,200U,100U,8U);
spx_mutable_fill(&world,104U,4U,9U);
__CPROVER_assert(world.count==3U && cell->a==0x07070707U && cell->b==0x09090909U,
 "record-fixed-slot-effects");
''',capacity=3,helpers='''
static void check_snapshot_slot(void *opaque,uint32_t index){
 struct spx_mutable_world *world=opaque;
 __CPROVER_assert(world->count==index,"record-snapshot-before-append");
 spx_record_snapshot(opaque,index);
}
static void check_event_slot(void *opaque,const struct spx_mutable_event *event){
 struct spx_mutable_world *world=opaque;
 __CPROVER_assert(world->count>0U && world->count<=3U,"record-callback-count");
 __CPROVER_assert(event==&world->events[world->count-1U],"record-callback-stored-event");
 spx_record_apply(opaque,event);
}
''')

    def test_exhausted_events_and_snapshot_counter_mutation_reject(self):
        # Total extraction must still reject a false byte-domain obligation.
        self.check_model('(void)spx_record_byte(0U,4U);',failure='spx-record-byte-index')
        self.check_model('''
spx_mutable_fill(&world,200U,1U,0U);
spx_mutable_fill(&world,201U,1U,0U);
''',capacity=1,failure='spx-shared-memory-event-capacity')
        self.check_model('''
world.snapshot_representation=change_history_in_snapshot;
spx_mutable_copy(&world,200U,100U,8U);
''',capacity=2,failure='spx-shared-memory-snapshot-frame',helpers='''
static void change_history_in_snapshot(void *opaque,uint32_t index){
 spx_record_snapshot(opaque,index);
 ((struct spx_mutable_world *)opaque)->count++;
}
''')

    def test_readonly_fields_and_missing_snapshot_hooks_reject(self):
        self.check_model('spx_mutable_fill(&world,100U,1U,0U);',writable=False,
            failure='spx-record-service-frame',capacity=1)
        self.check_model('spx_mutable_copy(&world,99U,200U,2U);',writable=False,
            failure='spx-record-service-frame',capacity=1)
        self.check_model('spx_mutable_fill(&world,107U,2U,0U);',writable=False,
            failure='spx-record-service-frame',capacity=1)
        self.check_model('world.snapshot_representation=0;spx_mutable_copy(&world,200U,100U,4U);',
            failure='spx-shared-memory-representation-snapshot-hooks',capacity=1)

    def test_readonly_copy_frame_with_symbolic_spans_and_empty_effect(self):
        self.check_model('''
uint32_t source,destination,probe;uint64_t extent;
__CPROVER_assume(extent<=UINT64_C(4294967296)-source && extent<=UINT64_C(4294967296)-destination);
__CPROVER_assume(extent==0U || (uint64_t)destination+extent<=100U || destination>=108U);
uint32_t a=cell->a,b=cell->b;
uint8_t expected=spx_mutable_byte(&world,probe);
if(probe>=destination && (uint64_t)probe-destination<extent)
 expected=spx_mutable_byte(&world,source+(probe-destination));
spx_mutable_copy(&world,destination,source,extent);
spx_mutable_fill(&world,102U,0U,255U);
__CPROVER_assert(cell->a==a && cell->b==b,"record-readonly-field-preservation");
__CPROVER_assert(spx_mutable_byte(&world,probe)==expected,"record-readonly-copy-bytes");
spx_record_frame();
''',capacity=2,writable=False)

    def test_preserved_history_frame_keeps_current_record_reads_and_snapshots(self):
        self.check_model('''
uint32_t a,b,probe;__CPROVER_assume(probe<8U);cell->a=a;cell->b=b;
uint8_t expected=(uint8_t)((probe<4U?a:b)>>(8U*(probe%4U)));
__CPROVER_assert(spx_mutable_byte(&world,100U+probe)==expected,"record-framed-current-byte");
spx_mutable_copy(&world,200U,100U,8U);
cell->a=0U;cell->b=0U;
__CPROVER_assert(spx_mutable_byte(&world,200U+probe)==expected,"record-framed-snapshot-byte");
__CPROVER_assert(spx_mutable_byte(&world,100U+probe)==0U,"record-framed-later-field-byte");
''',capacity=1,preserved_spans=[(100,8)])
        self.check_model('spx_mutable_fill(&world,400U,1U,0U);',capacity=1,
            preserved_spans=[(400,8)],failure='spx-shared-preserved-span-0')
