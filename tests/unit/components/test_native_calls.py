"""Native call instantiation checks real ABI words, events and outcome frames."""

from copy import deepcopy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from spaghetti_extractor.components.bisimulation_call_relations import ScalarBinding, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_memory import (
    U32, access, constant, entry_offset, entry_register, native_memory_initialization, native_memory_runtime,
)
from spaghetti_extractor.components.bisimulation_mutable_memory import sparse_mutable_memory_runtime
from spaghetti_extractor.components.bisimulation_native_calls import (
    call_definition, checked_return, equal, register, render_native_calls, requirement, stack_word, summary_return,
)
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint


FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save'
TESTKIT={'fixtures':('compiler','cbmc'),'resources':('tests/fixtures/metapad-cleanup-save',)}
EVENT={'kind':'internal','source_rva':10,'instruction_rva':11,'target_rva':20,'return_rva':12,
       'call_index':0,'argument_count':0,'stack_input_count':0}
NORMAL={'result_field':'eax','stack_delta':4,'preserved_fields':['ebx']}


class NativeCallTests(unittest.TestCase):
    def definition(self, *, imported=False, normal=None):
        event={**EVENT,'kind':'import','target_rva':0,'dll':'test.dll','symbol':'Invoke'} if imported else EVENT
        return call_definition('service',event,[stack_word(0)],
            [requirement('expected-argument',equal(parameter('argument_0',U32),parameter('expected',U32)))],
            NORMAL if normal is None else normal,entry_stack_delta=-4)

    def check_c(self, *, mutate='', suffix='', failures=(), fallback=False, imported=False, normal=None,
                terminal_outcomes=False, zero_arguments=False, indirect=None):
        address=expression('add',U32,entry_register('esp'),constant(2**32-4)) if fallback else entry_offset('esp',-4)
        rows=[access('argument',address,write=True,storage='private')]
        definition=self.definition(imported=imported,normal=normal)
        if zero_arguments:definition.update(arguments=[],requires=[])
        if indirect:
            definition['event']={**EVENT,'kind':'indirect','target_rva':0}
            definition['captured_target_projection']={'kind':indirect,'at':'entry','width':32,
                **({'register':'ebp'} if indirect=='register' else {'rva':256})}
            if indirect=='static_slot':rows.append(access('target-slot',constant(256),read=True))
        dispatch=render_native_calls([definition],native_memory=rows,
            callbacks={'service':('callback','m->env->fault')+(('m->env->terminal',) if terminal_outcomes else ())},
            parameters={'expected':ScalarBinding(U32,'expected')})
        self.assertEqual('spx_caller_private_value(&m->memory' in dispatch,fallback)
        source='\n'.join(['#include "state-machine-runtime.h"',*sparse_mutable_memory_runtime(2),*native_memory_runtime(len(rows))])
        source+='''
struct environment { uint32_t value,fault; };
struct machine { struct environment *env; const spx_machine_state *entry; struct spx_caller_memory memory; };
static uint32_t expected;
static uint32_t callback(struct environment *env,uint32_t argument){return env->value;}
'''+dispatch+'''
void check(void){
 spx_machine_state initial,input,output;initial.esp=100U;input=initial;input.esp=96U;
 uint32_t value,fault,arg;__CPROVER_assume(fault<=1U);expected=arg;
 struct environment env={value,fault};struct machine m={.env=&env,.entry=&initial};
 struct spx_mutable_world world={0};spx_runtime rt={.context=&m};
'''+native_memory_initialization(rows,instance='m.memory',world='&world',private_low='96U',private_high='100U')+'''
 m.memory.slots[0].value=arg;m.memory.slots[0].initialized=1U;
 spx_call_event event={.kind=@KIND@,.source_rva=10U,.instruction_rva=11U,.target_rva=@TARGET@,.return_rva=12U@IMPORT@};
'''+mutate+'''
 spx_call_status status=spx_invoke_call(&rt,&event,&input,&output);
 if(fault)__CPROVER_assert(status==SPX_CALL_MEMORY_FAULT,"fault-status");
 else __CPROVER_assert(status==SPX_CALL_OK && output.eax==value && output.esp==100U && output.ebx==input.ebx,"normal-result-and-frame");
'''+suffix+'\n}\n'
        source=source.replace('@KIND@','SPX_CALL_EXTERNAL_IMPORT' if imported else 'SPX_CALL_INTERNAL_DIRECT')
        source=source.replace('@TARGET@','0U' if imported else '20U').replace('@IMPORT@',',.dll="test.dll",.symbol="Invoke"' if imported else '')
        if indirect:
            source=source.replace('uint32_t value,fault;','uint32_t value,fault;uint32_t native_target;')
            source=source.replace('spx_call_event event={.kind=SPX_CALL_INTERNAL_DIRECT',
                                  'spx_call_event event={.kind=SPX_CALL_INDIRECT')
            setup=('initial.ebp=20U;event.target_rva=initial.ebp;' if indirect=='register' else
                'uint32_t target_fault=0U;event.target_rva=spx_caller_read(&m.memory,256U,4U,&target_fault);'
                '__CPROVER_assume(event.target_rva!=0U);')
            source=source.replace('};\n'+mutate+'\n spx_call_status status=',
                                  '};\n'+setup+'\n'+mutate+'\n spx_call_status status=')
        if zero_arguments:source=source.replace('callback(struct environment *env,uint32_t argument)',
                                               'callback(struct environment *env)')
        if terminal_outcomes:
            source=source.replace('uint32_t value,fault;','uint32_t value,fault,terminal;')
            source=source.replace('struct environment env={value,fault};',
                'uint32_t terminal;__CPROVER_assume(terminal<=1U && (!fault || !terminal));\n'
                'struct environment env={value,fault,terminal};')
            source=source.replace('else __CPROVER_assert(status==SPX_CALL_OK',
                'else if(terminal)__CPROVER_assert(status==SPX_CALL_NONLOCAL,"terminal-status");\n'
                'else __CPROVER_assert(status==SPX_CALL_OK')
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);_write_cbmc_stdint(root/'stdint.h')
            shutil.copyfile(FIXTURE/'exact/state-machine-runtime.h',root/'state-machine-runtime.h')
            (root/'pair.c').write_text(source)
            compiler,checker=shutil.which('goto-cc'),shutil.which('cbmc')
            self.assertIsNotNone(compiler);self.assertIsNotNone(checker)
            compiled=subprocess.run([compiler,'--i386-win32','-nostdinc','-I','.',
                'pair.c','--function','check','-o','model.goto'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(compiled.returncode,0,compiled.stderr)
            result=subprocess.run([checker,'model.goto','--function','check','--json-ui','--unwind','16',
                '--unwinding-assertions','--bounds-check','--pointer-check','--signed-overflow-check',
                '--undefined-shift-check'],cwd=root,capture_output=True,text=True,timeout=60)
            self.assertEqual(result.returncode,10 if failures else 0,result.stdout[-3000:]+result.stderr)
            properties=[r for b in json.loads(result.stdout) for r in b.get('result',[])]
            self.assertTrue(properties)
            self.assertEqual({r['description'] for r in properties if r['status']=='FAILURE'},set(failures))
            self.assertTrue(all(r['status'] in {'SUCCESS','FAILURE'} for r in properties))

    def test_normal_uint32_and_fault_frame_remain_separate(self):
        self.check_c()
        self.check_c(suffix='__CPROVER_assert(!fault || output.ebx==input.ebx,"fault-frame-not-exported");',
                     failures=('fault-frame-not-exported',))
        self.check_c(suffix='__CPROVER_assert(fault || value!=UINT32_MAX,"normal-max-admitted");',
                     failures=('normal-max-admitted',))

    def test_terminal_outcome_exports_no_normal_frame_or_continuation(self):
        self.check_c(terminal_outcomes=True)
        self.check_c(terminal_outcomes=True,
            suffix='__CPROVER_assert(!terminal || output.ebx==input.ebx,"terminal-frame-not-exported");',
            failures=('terminal-frame-not-exported',))
        self.check_c(terminal_outcomes=True,
            suffix='__CPROVER_assert(!terminal || output.esp==100U,"terminal-stack-not-exported");',
            failures=('terminal-stack-not-exported',))

    def test_indexed_argument_checks_location_contents_and_fallback(self):
        self.check_c(fallback=True)
        self.check_c(mutate='m.memory.slots[0].address++;',failures=('spx-native-call-argument-location',))
        self.check_c(mutate='m.memory.slots[0].initialized=0U;',failures=('spx-native-call-argument-initialized',))
        self.check_c(mutate='m.memory.slots[0].value++;',failures=('expected-argument',))

    def test_call_event_and_stack_transport_are_checked(self):
        self.check_c(mutate='event.return_rva++;',failures=('spx-native-call-event',))
        self.check_c(mutate='input.esp++;',failures=('spx-native-call-entry-stack','spx-native-call-argument-location','normal-result-and-frame'))
        self.check_c(mutate='event.source_rva++;',failures=('spx-native-call-covered','normal-result-and-frame'))

    def test_import_identity_is_part_of_the_call_contract(self):
        self.check_c(imported=True)
        self.check_c(imported=True,mutate='event.symbol="Another";',failures=('spx-native-call-event',))

    def test_zero_argument_import_retains_result_frame_and_event_checks(self):
        self.check_c(imported=True,zero_arguments=True)
        self.check_c(imported=True,zero_arguments=True,mutate='event.symbol="Another";',
                     failures=('spx-native-call-event',))

    def test_captured_indirect_targets_use_entry_register_or_current_image_slot(self):
        for projection in ('register','static_slot'):
            with self.subTest(projection=projection):
                self.check_c(indirect=projection,zero_arguments=True)
                self.check_c(indirect=projection,zero_arguments=True,mutate='event.target_rva^=1U;',
                             failures=('spx-native-captured-target',))
        self.check_c(indirect='static_slot',zero_arguments=True,
            mutate='spx_mutable_event(&world,256U,4U,event.target_rva^1U,0U,0U);',
            failures=('spx-native-captured-target',))

    def test_summary_frame_quantifiers_and_exact_equalities(self):
        contract=json.loads((FIXTURE/'summary-input.json').read_text())['contract']
        normal=summary_return(contract);self.assertEqual(normal['stack_delta'],0)
        # The toy call uses a four-byte stdcall pop; only this separately supplied
        # stack adjustment differs from the imported physical frame conjunction.
        normal['stack_delta']=4
        self.check_c(normal=normal,suffix='''
 uint32_t slot,byte;__CPROVER_assume(slot<8U && byte<10U);
 if(!fault)__CPROVER_assert(output.x87_stack[slot].value_bytes[byte]==input.x87_stack[slot].value_bytes[byte] &&
  output.x87_stack[slot].tag==input.x87_stack[slot].tag && output.x87_control==input.x87_control,"complete-physical-frame");
''')
        for edit in ('equality','quantifier','delta'):
            bad=deepcopy(contract)
            if edit=='equality':bad['normal_return']['preserved_equalities']=['state.ebx==initial.esi']
            if edit=='quantifier':bad['normal_return']['frame_quantifiers']['continuation_slot']=[0,7]
            if edit=='delta':bad['normal_return']['stack_delta']=8
            with self.subTest(edit=edit):
                with self.assertRaises(ValueError):summary_return(bad)

    def test_unknown_projections_conflicting_frames_and_dispatch_fail_closed(self):
        for fields in [['eax'],['esp'],['ebx; abort()']]:
            with self.assertRaises(ValueError):checked_return({**NORMAL,'preserved_fields':fields})
        row=self.definition();rows=[access('argument',entry_offset('esp',-4),write=True,storage='private')]
        kwargs={'native_memory':rows,'callbacks':{'service':('callback','0U')},'parameters':{'expected':ScalarBinding(U32,'expected')}}
        with self.assertRaisesRegex(ValueError,'ambiguous native dispatch'):render_native_calls([row,row],**kwargs)
        bad=deepcopy(row);bad['arguments'][0]=register('edi','callee_entry').to_payload()
        with self.assertRaisesRegex(ValueError,'machine place binding'):render_native_calls([bad],**kwargs)
        bad=deepcopy(row);bad['requires'][0]['expression']='input->edi==0U'
        with self.assertRaises(ValueError):render_native_calls([bad],**kwargs)
