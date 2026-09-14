"""Nullable input decoding uses the actual native allocation/reference runtime."""
import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.machine_overlay_result_views import result_view_runtime_helpers
from spaghetti_extractor.components.machine_overlay_v5 import _view_projection_lines, render_component_machine_overlay_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.normalized_component import NormalizedComponentContract
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.transfer.model import _Action, _Transfer
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source
from tests.unit.components.test_bisimulation_lifetime_admission import interface_fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def projection():
    return {'kind': 'view', 'at': 'entry',
        'base': {'kind': 'stack', 'at': 'entry', 'offset': 12, 'width': 32},
        'requested_extent': {'kind': 'constant', 'width': 32, 'value': 1},
        'extent': {'kind': 'origin_remainder'},
        'authority': {'id': 'scratch', 'kind': 'external', 'lifetime': 'allocation'}}


def decoder_source(*, access='read_write', projection_value=None, selector='allocation', mutant=None):
    value = SimpleNamespace(nullable=True, access=access,
        extent={'kind': 'none', 'bytes': None, 'value_id': None})
    lines = _view_projection_lines(value=value, projection=projection_value or projection(),
        name='scratch', scalar_arguments={}, authority_selectors={'scratch': selector})
    source = '\n'.join(result_view_runtime_helpers(input_view_decoder=True))
    source += '''
static uint32_t spx_component_read(spx_runtime *rt, uint32_t address, uint32_t width, uint32_t *fault) {
  if (rt == 0 || rt->read == 0) { *fault=1U; return 0U; }
  return rt->read(rt->context, address, width, fault);
}
static spx_step_result decode_input(spx_runtime *rt, spx_machine_state *state, spx_view_v5 *output) {
  uint32_t memory_fault=0U;
''' + '\n'.join(lines) + '''
  *output=scratch_view;
  return (spx_step_result){SPX_RETURN,0U,0U};
}
'''
    if mutant == 'pointer-fault':
        source = source.replace('  if (memory_fault != 0U)\n    return (spx_step_result){ SPX_MEMORY_FAULT, 0U, 0U };', '')
    if mutant == 'fixed-extent':
        source = source.replace('.extent = reference.extent - reference.offset,', '.extent = 1U,')
    return source


def input_overlay(*, with_contract=False):
    original=interface_fixture(buffer_view=True).intent.to_payload()
    value=copy.deepcopy(next(s for s in original['schema']['signatures'] if s['id']=='allocate')['results'][0])
    value.update(id='scratch',extent={'kind':'none','bytes':None,'value_id':None})
    result=next(s for s in original['schema']['signatures'] if s['id']=='run')['results'][0]
    types=[t for t in original['schema']['types'] if t['id'] in {'u8','u32','buffer'}]
    types.append({'id':'run.fn','kind':'function','calling_convention':'cdecl',
        'parameter_type_ids':['buffer'],'result_type_id':'u32','variadic':False})
    schema=BoundarySchemaV1.create(schema_id='owned',types=types,
        signatures=[{'id':'run','function_type_id':'run.fn','parameters':[value],'results':[result]}])
    operation=copy.deepcopy(original['operations'][0])
    operation.update(allowed_service_ids=[],source_values=[value,result],projection_entries=[
        {'source_id':v['id'],'target':{'root':root,'value_id':v['id'],'fields':[]}}
        for v,root in [(value,'parameter'),(result,'result')]])
    bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.create(component_id='owned',schema=schema,
        state=[],effects=[],services=[],protocol_states=['ready'],initial_protocol_state='ready',operations=[operation]))
    unit='semantic-transfer:original-cutpoint-00001000-00001010'
    machine={'operation_id':'run','entry_unit_ids':[unit],'exit_unit_ids':[unit],
        'parameters':[{'id':'scratch','projection':projection()}],
        'results':[{'id':'value','projection':{'kind':'register','register':'eax','width':32,'at':'exit'}}],
        'state':[],'preserved_state_ids':[],'effects':[],'callback_operation_ids':[],'continuation_unit_ids':[]}
    binding=ComponentMachineBindingIntentV1.create(component_id='owned',operations=[{
        'id':'run','kind':'operation','unit_ids':[unit],'entry_rvas':[0x1000],'transfer_ids':[unit],
        'effect_ids':[],'service_ids':[],'callback_ids':[],'outcome_protocol_ids':[],
        'machine_projection':{'operation':machine,'service_bindings':[]},'object_authority_selectors':[],
        'pointer_views':[],'relation_receipt_sha256s':[],'induction_evidence_sha256':None}],blockers=[])
    contract=NormalizedComponentContract.create(interface=bundle.interface,
        machine_semantics=[row.semantics for row in binding.operations])
    transfer=_Transfer(unit,'a'*64,'b'*64,0x1000,(),(),(_Action('outcome_fallthrough',(0x1010,)),),(),())
    overlay=render_component_machine_overlay_v5(bundle=bundle,contract=contract,
        operation_symbols={'run':'authored_run'},transfers=[transfer])
    return (bundle, overlay, contract) if with_contract else (bundle, overlay)


def native_source(body, *, access='read_write', mutant=None, overlay=None):
    # Memory backing is a bounded fixture. Registration, release, origin lookup
    # and realization are the generated production bodies, not proof-world code.
    callbacks = '''
static uint8_t bytes[16];
static uint32_t pointer_word, deny_pointer, deny_bytes, byte_reads, byte_writes;
static uint32_t read_memory(void *opaque,uint32_t address,uint32_t width,uint32_t *fault) {
  (void)opaque; *fault=0U;
  if (address==0x80000cU && width==4U) {
    *fault=deny_pointer;return deny_pointer ? 0U : pointer_word;
  }
  if (deny_bytes || address<4096U || width==0U || width>4U || address>4112U-width) {
    *fault=1U; return 0U;
  }
  byte_reads++;
  uint32_t result=0U;
  for(uint32_t i=0U;i<width;i++) result|=(uint32_t)bytes[address-4096U+i]<<(8U*i);
  return result;
}
static void write_memory(void *opaque,uint32_t address,uint32_t width,uint32_t value,uint32_t *fault) {
  (void)opaque; *fault=0U;
  if (deny_bytes || address<4096U || width==0U || width>4U || address>4112U-width) {
    *fault=1U; return;
  }
  byte_writes++;
  for(uint32_t i=0U;i<width;i++) bytes[address-4096U+i]=(uint8_t)(value>>(8U*i));
}
static spx_runtime runtime = {.context=&spx_native_context_value,
  .read=read_memory,.write=write_memory,
  .resolve_reference=spx_native_resolve_reference,.realize_reference=spx_native_realize_reference};
'''
    return ('#include "portable-component.h"\n' + allocation_fixture_source(callbacks,
        extent_mode=1, minimum_extent=1) + (overlay if overlay is not None else decoder_source(access=access, mutant=mutant)) +
        spx_portable_reference_runtime_v5_source() + '''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(value) ((void)0)
#endif
int main(void) {
  spx_machine_state state={0};state.esp=0x800000U;
  spx_view_v5 view={0};
''' + body + '\n  __CPROVER_cover(1);\n}\n')


class NullableInputViewTests(unittest.TestCase):
    def check(self, body, *, failure=None, access='read_write', mutant=None, full_overlay=False):
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            bundle,overlay=input_overlay() if full_overlay else (interface_fixture(buffer_view=True),None)
            if overlay is not None:
                body=body.replace('OVERLAY',overlay.entries[0]['symbol'])
            for name, text in render_component_c_headers_v5(bundle, {'run':'authored_run'}).items():
                (root/name).write_text(text)
            native_overlay=None if overlay is None else overlay.source+'''
static uint32_t consumer_calls;
uint32_t authored_run(spx_owned_context_v5 *context, const spx_view_v5 *scratch) {
  (void)context; consumer_calls++; return (uint32_t)scratch->extent;
}
'''
            (root/'input.c').write_text(native_source(body, access=access, mutant=mutant,overlay=native_overlay))
            command=[shutil.which('cbmc'),str(root/'input.c'),'--json-ui','--unwind','17','--sat-solver','cadical']
            result=run_cbmc_properties(command=[*command,'--trace','--unwinding-assertions','--bounds-check',
                '--pointer-check','--signed-overflow-check','--undefined-shift-check'],timeout_seconds=40)
            self.assertEqual(result['status'],'violated' if failure else 'satisfied',result.get('detail'))
            if failure:
                self.assertEqual(result['detail'],failure)
            else:
                cover=run_cbmc_cover(command=[*command,'-DSPX_TEST_COVER','--cover','cover'],
                    expected_functions=['main'],timeout_seconds=40)
                self.assertEqual(cover['status'],'satisfied',cover)

    def test_complete_native_adapter_imports_null_but_proof_admission_stays_closed(self):
        bundle,_=input_overlay()
        with self.assertRaisesRegex(ValueError,'nullable logical view contract'):
            _logical_projection(bundle)
        self.check('''
  spx_step_result result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_FALLTHROUGH && result.target_rva==0x1010U &&
    consumer_calls==1U && state.eax==0U,"native adapter admits empty input to consumer");
  deny_pointer=1U;
  result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_MEMORY_FAULT && consumer_calls==1U,
    "pointer storage fault prevents consumer execution");
  deny_pointer=0U;pointer_word=4096U;
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"register input");
  result=OVERLAY(&runtime,&state);
  __CPROVER_assert(result.kind==SPX_FALLTHROUGH && consumer_calls==2U && state.eax==16U,
    "native adapter retains real extent");
''',full_overlay=True)

    def test_complete_native_adapter_compiles_on_host_and_pe32(self):
        bundle,overlay=input_overlay()
        with tempfile.TemporaryDirectory() as temporary:
            root=Path(temporary)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            for name,text in render_component_c_headers_v5(bundle,{'run':'authored_run'}).items():
                (root/name).write_text(text)
            (root/'overlay.c').write_text(overlay.source)
            for compiler in ('cc','i686-w64-mingw32-gcc'):
                executable=shutil.which(compiler)
                self.assertIsNotNone(executable,compiler)
                result=subprocess.run([executable,'-std=c11','-Wall','-Wextra','-Werror','-I',str(root),
                    '-c',str(root/'overlay.c'),'-o',str(root/'overlay.o')],capture_output=True,text=True)
                self.assertEqual(result.returncode,0,result.stderr)

    def test_null_input_and_unreadable_pointer_storage_remain_distinct(self):
        self.check('''
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"null input is representable");
  __CPROVER_assert(view.base.object==0U && view.base.domain==0U && view.base.generation==0U &&
    view.base.offset==0U && view.base.extent==0U && view.base.permissions==0U && view.extent==0U &&
    view.element_width==0U && view.context==0 && view.access_context==0 && view.read==0 && view.write==0 &&
    view.read_u8==0 && view.write_u8==0,"canonical empty input");
  uint8_t byte=7U;
  __CPROVER_assert(spx_view_read_u8(&view,0U,&byte)!=SPX_REF_OK &&
    spx_view_write_u8(&view,0U,9U)!=SPX_REF_OK && byte_reads==0U && byte_writes==0U,
    "null input grants no byte access");
  deny_pointer=1U;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_MEMORY_FAULT,
    "pointer read fault is not null input");
''')
        self.check('''deny_pointer=1U;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_MEMORY_FAULT,
    "pointer read fault is not null input");''', mutant='pointer-fault',
    failure='pointer read fault is not null input')

    def test_runtime_extent_and_interior_alias_are_not_fixed_one_byte(self):
        body='''
  uint32_t size,offset;
  __CPROVER_assume(size>0U && size<=UINT32_MAX-4096U && offset<size);
  __CPROVER_assert(spx_native_add_external_range(4096U,size,100U,1U,7U,55U)==SPX_CALL_OK,
    "register arbitrary representable extent");
  pointer_word=4096U+offset;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"decode live interior input");
  __CPROVER_assert(view.base.offset==offset && view.base.extent==size && view.extent==size-offset,
    "input keeps actual remaining extent");
'''
        self.check(body)
        self.check(body,mutant='fixed-extent',failure='input keeps actual remaining extent')

    def test_import_does_not_rewrite_bytes_and_aliases_observe_each_other(self):
        self.check('''
  uint8_t original[16];
  for(uint32_t i=0U;i<16U;i++) { uint8_t arbitrary; bytes[i]=arbitrary;original[i]=arbitrary; }
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"register input");
  pointer_word=4096U;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"decode whole view");
  spx_view_v5 alias={0};pointer_word=4099U;
  __CPROVER_assert(decode_input(&runtime,&state,&alias).kind==SPX_RETURN,"decode alias");
  for(uint32_t i=0U;i<16U;i++) __CPROVER_assert(bytes[i]==original[i],"decoding preserves contents");
  __CPROVER_assert(byte_reads==0U && byte_writes==0U,"decoding has no byte effects");
  __CPROVER_assert(spx_view_write_u8(&alias,0U,71U)==SPX_REF_OK,"write interior alias");
  uint8_t observed=0U;
  __CPROVER_assert(spx_view_read_u8(&view,3U,&observed)==SPX_REF_OK && observed==71U,
    "aliases share current bytes");
''')

    def test_access_rechecks_lifetime_after_release_and_address_reuse(self):
        self.check('''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"register input");pointer_word=4096U;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"decode original lifetime");
  spx_view_v5 old=view;
  __CPROVER_assert(spx_native_release_external_range(4096U,101U)==SPX_CALL_OK,"release input");
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"reuse address");
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"decode new lifetime");
  __CPROVER_assert(view.base.generation!=old.base.generation,"distinct lifetime");
  __CPROVER_assert(spx_view_write_u8(&old,0U,19U)!=SPX_REF_OK && byte_writes==0U,"old input never revives");
  __CPROVER_assert(spx_view_write_u8(&view,0U,19U)==SPX_REF_OK && byte_writes==1U,"new input is live");
''')

    def test_metadata_bounds_permissions_and_backend_faults_are_checked(self):
        self.check('''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"register input");pointer_word=4096U;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"decode input");
  uint8_t byte=7U;
  __CPROVER_assert(spx_view_read_u8(&view,16U,&byte)!=SPX_REF_OK,"one past cannot read");
  __CPROVER_assert(view.write(view.access_context,view.base,15U,2U,1U)!=0U,"crossing span rejected");
  __CPROVER_assert(view.write(view.access_context,view.base,UINT64_MAX,1U,1U)!=0U,"offset overflow rejected");
  spx_view_v5 forged=view;forged.base.generation++;
  __CPROVER_assert(spx_view_write_u8(&forged,0U,1U)!=SPX_REF_OK,"forged generation rejected");
  forged=view;forged.base.extent++;
  __CPROVER_assert(spx_view_write_u8(&forged,0U,1U)!=SPX_REF_OK,"forged extent rejected");
  deny_bytes=1U;
  __CPROVER_assert(spx_view_write_u8(&view,0U,1U)!=SPX_REF_OK &&
    spx_view_read_u8(&view,0U,&byte)!=SPX_REF_OK && byte==7U,"backend fault retained");
  __CPROVER_assert(byte_reads==0U && byte_writes==0U,"rejected accesses have no byte effects");
''')
        self.check('''
  __CPROVER_assert(allocate(4096U)==SPX_CALL_OK,"register input");pointer_word=4096U;
  __CPROVER_assert(decode_input(&runtime,&state,&view).kind==SPX_RETURN,"decode read-only input");
  __CPROVER_assert(view.write==0 && view.write_u8==0 &&
    spx_view_write_u8(&view,0U,1U)!=SPX_REF_OK,"read-only input has no writer");
''',access='read')

    def test_unsupported_extent_forms_reject_before_rendering(self):
        for kind in ('constant','register'):
            row=copy.deepcopy(projection())
            row['extent']={'kind':'constant','width':32,'value':8} if kind=='constant' else {
                'kind':'register','register':'eax','width':32,'at':'entry'}
            with self.subTest(kind=kind),self.assertRaisesRegex(ValueError,'origin-remainder input contract'):
                decoder_source(projection_value=row)


if __name__=='__main__':
    unittest.main()
