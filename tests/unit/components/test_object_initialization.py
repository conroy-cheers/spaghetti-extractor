"""Initialization requires actual writes, even when both implementations agree."""
import copy
from pathlib import Path
import shutil
import tempfile
import unittest

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.bisimulation_object_initialization import checked_initialization_requests
from spaghetti_extractor.components.bisimulation_object_machine_model import render_object_machine_model
from spaghetti_extractor.components.bisimulation_object_model import object_source_shape
from spaghetti_extractor.components.bisimulation_readonly_model import mutable_checker_options
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from spaghetti_extractor.transfer.model import _Action, _Node, _Transfer

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def fixture():
    empty = {'kind': 'none', 'bytes': None, 'value_id': None}
    common = {'nullable': False, 'resource_kind': None, 'provider_domain': None}
    parameters = [dict(common, id='output', type_id='bytes', interpretation='view', access='write',
                       extent={'kind': 'fixed', 'bytes': 8, 'value_id': None}),
                  dict(common, id='value', type_id='u32', interpretation='value', access='none', extent=empty)]
    schema = BoundarySchemaV1.create(schema_id='initializer', types=[
        {'id': 'u8', 'kind': 'integer', 'signed': False, 'width_bits': 8},
        {'id': 'u32', 'kind': 'integer', 'signed': False, 'width_bits': 32},
        {'id': 'unit', 'kind': 'void'},
        {'id': 'bytes', 'kind': 'pointer', 'pointee_type_id': 'u8', 'qualifiers': []},
        {'id': 'initialize.fn', 'kind': 'function', 'calling_convention': 'cdecl', 'parameter_type_ids': ['bytes', 'u32'],
         'result_type_id': 'unit', 'variadic': False}], signatures=[
        {'id': 'initialize', 'function_type_id': 'initialize.fn', 'parameters': parameters, 'results': []}])
    operation = {'id': 'initialize', 'signature_id': 'initialize', 'pre_states': ['ready'], 'post_states': ['ready'],
        'allowed_service_ids': [], 'effect_ids': [], 'source_values': parameters,
        'projection_entries': [{'source_id': p['id'], 'target': {'root': 'parameter', 'value_id': p['id'], 'fields': []}} for p in parameters],
        'lifecycle_bindings': [], 'lifecycle_additional_roots': {'state': []}, 'checked_interaction_contract_ids': []}
    bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.create(component_id='initializer', schema=schema,
        state=[], services=[], effects=[], protocol_states=['ready'], initial_protocol_state='ready', operations=[operation]))
    extent = {'kind': 'constant', 'value': 8, 'width': 32}
    units = ['semantic-transfer:original-cutpoint-00001000-00001001']
    projection = {'operation_id': 'initialize', 'entry_unit_ids': units, 'exit_unit_ids': units, 'parameters': [
        {'id': 'output', 'projection': {'kind': 'view', 'at': 'entry',
            'base': {'kind': 'register', 'at': 'entry', 'register': 'eax', 'width': 32},
            'extent': extent, 'requested_extent': extent, 'authority': {'id': 'output', 'kind': 'external', 'lifetime': 'invocation'}}},
        {'id': 'value', 'projection': {'kind': 'register', 'at': 'entry', 'register': 'edx', 'width': 32}}],
        'results': [], 'state': [], 'effects': [], 'preserved_state_ids': [], 'callback_operation_ids': [], 'continuation_unit_ids': []}
    binding = ComponentMachineBindingIntentV1.create(component_id='initializer', operations=[{
        'id': 'initialize', 'kind': 'operation', 'unit_ids': units, 'transfer_ids': units, 'entry_rvas': [4096],
        'effect_ids': [], 'service_ids': [], 'callback_ids': [], 'outcome_protocol_ids': ['normal'],
        'machine_projection': {'operation': projection, 'service_bindings': []},
        'object_authority_selectors': [], 'pointer_views': [], 'relation_receipt_sha256s': [], 'induction_evidence_sha256': None}])
    domain = {'image_base': 0x400000, 'private_accesses': [{'offset': 0, 'bytes': 4}], 'private_writes': [],
        'clobbers': [], 'stack_delta': 4, 'initializes': [{'parameter': 'output', 'offset': 0, 'extent': 8}]}
    return bundle, binding, domain


def initializer_transfer():
    unit = fixture()[1].operations[0].semantics.unit_ids[0]
    nodes = (_Node('reg', aux=0), _Node('reg', aux=3), _Node('const', immediate=4),
             _Node('add32', (0, 2)), _Node('reg', aux=7), _Node('load', (4,), aux=4),
             _Node('add32', (4, 2)))
    return _Transfer(unit, 'a'*64, 'b'*64, 4096, nodes, (),
        (*(_Action('eval_word', (i,)) for i in range(len(nodes))),
         _Action('memory_write', (0, 1), aux=4), _Action('memory_write', (3, 1), aux=4),
         _Action('set_reg', (6,), aux=7), _Action('outcome_return', (5,))), (), ())


class ObjectInitializationTests(unittest.TestCase):
    def check(self, *, original_words=2, source_words=2, claims=True):
        bundle, binding, domain = fixture()
        if not claims:
            domain.pop('initializes')
        source, entry = render_object_machine_model(bundle=bundle, operation_id='initialize', symbol='authored_initialize',
            binding_intent=binding.to_payload(), machine_domain=domain)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root/'pair.c').write_text(source)
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            _write_cbmc_stdint(root/'stdint.h')
            (root/'stddef.h').write_text('typedef unsigned int size_t;\n#define NULL ((void *)0)\n')
            for name, text in render_component_c_headers_v5(bundle, {'initialize': 'authored_initialize'}).items():
                (root/name).write_text(text)
            (root/'behavioral-c.h').write_text('#include "state-machine-runtime.h"\nspx_step_result spx_sub_00001000(spx_runtime *,spx_machine_state *,uint32_t);\n')
            (root/'original.c').write_text('''#include "behavioral-c.h"
spx_step_result spx_sub_00001000(spx_runtime *rt,spx_machine_state *state,uint32_t entry){
 uint32_t fault=0U; (void)entry;
 for(uint32_t i=0;i<WORDS;i++)rt->write(rt->context,state->eax+4U*i,4U,state->edx,&fault);
 uint32_t target=rt->read(rt->context,state->esp,4U,&fault);state->esp+=4U;
 return (spx_step_result){SPX_RETURN,0U,target};}
'''.replace('WORDS', str(original_words)))
            (root/'source.c').write_text('''#include "portable-component-implementation.h"
void authored_initialize(spx_initializer_context_v5 *context,const spx_view_v5 *output,uint32_t value){
 (void)context;
 for(uint32_t i=0;i<WORDS;i++)output->write(output->access_context,output->base,4U*i,4U,value);
}
'''.replace('WORDS', str(source_words)))
            return run_cbmc_properties(command=[shutil.which('cbmc'), 'pair.c', 'source.c', 'original.c',
                '--i386-win32', '-I', '.', '--function', entry, *mutable_checker_options(16)], cwd=root, timeout_seconds=30)

    def test_complete_writes_prove_normal_initialization_and_equivalence(self):
        self.assertEqual(object_source_shape(fixture()[0]), ('initialize',))
        result = self.check()
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_agreeing_partial_writes_do_not_establish_initialization(self):
        self.assertEqual(self.check(original_words=1, source_words=1, claims=False)['status'], 'satisfied')
        result = self.check(original_words=1, source_words=1)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('spx-object-initialized:left:output:0:8', result['detail'])

    def test_source_must_establish_its_own_initialization(self):
        result = self.check(source_words=1)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('spx-object-initialized:right:output:0:8', result['detail'])

    def test_invalid_requests_and_entry_register_bindings_reject(self):
        bundle, binding, domain = fixture()
        signature = bundle.intent.schema.signature_index['initialize']
        for rows in ([{'parameter': 'value', 'offset': 0, 'extent': 4}],
                     [{'parameter': [], 'offset': 0, 'extent': 4}],
                     [{'parameter': 'output', 'offset': 0, 'extent': 9}],
                     [{'parameter': 'output', 'offset': 0, 'extent': 0}],
                     domain['initializes'] * 2):
            with self.subTest(rows=rows), self.assertRaises(ValueError):
                checked_initialization_requests(rows, signature=signature)
        for register in ('eax', 'esp'):
            raw = copy.deepcopy(binding.operations[0].to_payload())
            raw['machine_projection']['operation']['parameters'][1]['projection']['register'] = register
            changed = ComponentMachineBindingIntentV1.create(component_id='initializer', operations=[raw])
            with self.subTest(register=register), self.assertRaisesRegex(ValueError, 'distinct entry word registers'):
                render_object_machine_model(bundle=bundle, operation_id='initialize', symbol='authored_initialize',
                    binding_intent=changed.to_payload(), machine_domain=domain)
