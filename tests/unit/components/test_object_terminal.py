"""Terminal paths retain paired outcome, memory, frame and progress obligations."""
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.bisimulation_object_model import render_object_source_model, object_source_shape
from spaghetti_extractor.components.bisimulation_object_machine_model import render_object_machine_model
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_object_initialization import fixture as initializer_fixture

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def fixture():
    original, binding, domain = initializer_fixture()
    bound = binding.operations[0].to_payload()
    bound.update(service_ids=['stop'], outcome_protocol_ids=['normal', 'terminates'])
    binding = ComponentMachineBindingIntentV1.create(component_id='initializer', operations=[bound])
    schema = original.intent.schema.to_payload()
    schema['types'].append({'id': 'stop.fn', 'kind': 'function', 'calling_convention': 'cdecl',
                           'parameter_type_ids': [], 'result_type_id': 'unit', 'variadic': False})
    schema['signatures'].append({'id': 'stop', 'function_type_id': 'stop.fn', 'parameters': [], 'results': []})
    operations = copy.deepcopy(list(original.intent.operations))
    operations[0]['allowed_service_ids'] = ['stop']
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.create(component_id='initializer',
        schema=BoundarySchemaV1.create(schema_id=schema['schema_id'], types=schema['types'], signatures=schema['signatures']),
        state=[], services=[{'id': 'stop', 'signature_id': 'stop', 'effect_ids': [], 'interaction_contract_id': 'runtime.stop'}],
        effects=[], protocol_states=['ready'], initial_protocol_state='ready', operations=operations))
    terminal = [{'service_id': 'stop', 'id': 'runtime.stop', 'revision': 1, 'status': 'unverified',
                 'disposition': 'terminates', 'requires': 'Same runtime environment.',
                 'ensures': 'The service has no continuation in this invocation.',
                 'unverified': ['Concrete terminal runtime applicability and effects.']}]
    bindings = [{'service_id': 'stop', 'event': {'kind': 'import', 'source_rva': 4096, 'instruction_rva': 4096,
        'target_rva': 0, 'return_rva': 4097, 'call_index': 0, 'argument_count': 0, 'stack_input_count': 0,
        'dll': 'runtime.dll', 'symbol': 'stop'}}]
    return bundle, binding, domain, terminal, bindings


class ObjectTerminalTests(unittest.TestCase):
    def check(self, *, condition='value==10U', before='', after='', original_before='', kind='original_equivalence'):
        bundle, binding, domain, terminal, bindings = fixture()
        if kind == 'original_equivalence':
            model, entry = render_object_machine_model(bundle=bundle, operation_id='initialize', symbol='authored_initialize',
                binding_intent=binding.to_payload(), machine_domain=domain, terminal_services=terminal, service_bindings=bindings)
        else:
            model, entry = render_object_source_model(bundle=bundle, operation_id='initialize', symbol='authored_initialize',
                kind=kind, terminal_services=terminal)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'pair.c').write_text(model)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t;\n#define NULL ((void *)0)\n')
            for name, text in render_component_c_headers_v5(bundle, {'initialize': 'authored_initialize'}).items():
                (root/name).write_text(text)
            (root/'behavioral-c.h').write_text('#include "state-machine-runtime.h"\nspx_step_result spx_sub_00001000(spx_runtime *,spx_machine_state *,uint32_t);\n')
            (root/'original.c').write_text('''#include "behavioral-c.h"
spx_step_result spx_sub_00001000(spx_runtime *rt,spx_machine_state *state,uint32_t entry){
 uint32_t fault=0U;(void)entry;
 if(state->edx==10U){
  BEFORE
  const spx_call_event event={.kind=SPX_CALL_EXTERNAL_IMPORT,.source_rva=4096U,.instruction_rva=4096U,
   .return_rva=4097U,.dll="runtime.dll",.symbol="stop"};
  spx_machine_state output;
  spx_call_status status=spx_invoke_call(rt,&event,state,&output);
  *state=output;
  return (spx_step_result){status==SPX_CALL_NONLOCAL?SPX_NONLOCAL:SPX_UNIMPLEMENTED,0U,0U};
 }
 for(uint32_t i=0;i<2U;i++)rt->write(rt->context,state->eax+4U*i,4U,state->edx,&fault);
 uint32_t target=rt->read(rt->context,state->esp,4U,&fault);state->esp+=4U;
 return (spx_step_result){SPX_RETURN,0U,target};
}
'''.replace('BEFORE', original_before))
            (root/'source.c').write_text('''#include "portable-component-implementation.h"
static uint32_t calls;
void authored_initialize(spx_initializer_context_v5 *context,const spx_view_v5 *output,uint32_t value){
 if(CONDITION){
  BEFORE
  context->services->stop(context->services->context);
  AFTER
 }
 for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);
}
'''.replace('CONDITION', condition).replace('BEFORE', before).replace('AFTER', after))
            files = ['pair.c', 'source.c'] + (['original.c'] if kind == 'original_equivalence' else [])
            result = run_cbmc_properties(command=[shutil.which('cbmc'), *files, '--i386-win32', '-I', '.',
                '--function', entry, *mutable_checker_options(16)], cwd=root, timeout_seconds=60, output_prefix=root/'check')
            if result['status'] in {'satisfied', 'violated'}:
                raw = json.loads((root/'check.stdout').read_text())
                result['failed_descriptions'] = [r['description'] for block in raw for r in block.get('result', [])
                                                 if r['status'] == 'FAILURE']
            return result

    def test_both_outcomes_and_normal_initialization_pass(self):
        result = self.check()
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_a_void_signature_alone_does_not_supply_a_terminal_premise(self):
        bundle, _, _, services, _ = fixture()
        self.assertIsNone(object_source_shape(bundle))
        self.assertEqual(object_source_shape(bundle, terminal_services=services), ('initialize',))
        changed = copy.deepcopy(services);changed[0]['status'] = 'checked'
        with self.assertRaisesRegex(ValueError, 'unverified termination premise'):
            object_source_shape(bundle, terminal_services=changed)

    def test_wrong_abort_condition_checks_both_directions(self):
        for condition in ('value==11U', 'value==10U || value==11U', '0U'):
            with self.subTest(condition=condition):
                result = self.check(condition=condition)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertTrue(any('outcome' in v for v in result['failed_descriptions']))

    def test_terminal_memory_is_observed_before_the_service(self):
        result = self.check(before='output->write(output->access_context,output->base,0U,4U,77U);')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('spx-object-terminal-current-memory', result['detail'])

    def test_first_terminating_source_invocation_still_checks_the_second(self):
        result = self.check(kind='input_dependence')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check(kind='input_dependence',
            before='calls++;output->write(output->access_context,output->base,0U,4U,calls);')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('spx-object-terminal-current-memory', result['detail'])

    def test_the_barrier_does_not_erase_an_earlier_original_frame_failure(self):
        result = self.check(original_before='rt->write(rt->context,state->eax+8U,4U,77U,&fault);')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('spx-object-writable-frame', result['failed_descriptions'])

    def test_code_after_the_terminal_call_is_not_executed(self):
        result = self.check(after='for(;;){}')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
