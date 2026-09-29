"""Initialization facts require the complete public original/source evidence."""
import copy
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_object_call import checked_object_call_supplier, checked_object_supplier_facts
from spaghetti_extractor.components.binding_intent import ComponentMachineBindingIntentV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.components.machine_overlay_services_v5 import _c_identifier
from spaghetti_extractor.components.component_exact_c_slice import write_component_exact_c_slice_v1
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator.source_check import write_component_source_check
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator import source_operation_call_check as caller_checker
from tests.unit.components.test_object_initialization import fixture, initializer_transfer
from tests.unit.components.object_initializer_caller_fixture import prepare_caller

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def prepare(root, *, edited=False, component='initializer', entry=4096):
    bundle, binding, domain = fixture()
    original = bundle.intent
    intent = ComponentInterfaceIntentV1.create(component_id=component, schema=original.schema,
        state=list(original.state), operations=list(original.operations), effects=list(original.effects),
        services=list(original.services), protocol_states=list(original.protocol_states),
        initial_protocol_state=original.initial_protocol_state)
    operation = binding.operations[0].to_payload()
    unit = f'semantic-transfer:original-cutpoint-{entry:08x}-{entry+1:08x}'
    operation.update(unit_ids=[unit], transfer_ids=[unit], entry_rvas=[entry])
    operation['machine_projection']['operation'].update(entry_unit_ids=[unit], exit_unit_ids=[unit])
    binding = ComponentMachineBindingIntentV1.create(component_id=component, operations=[operation])
    (root/'interface').mkdir(parents=True)
    (root/'interface/component-interface-intent-v1.json').write_text(json.dumps(intent.to_payload()))
    transfer = replace(initializer_transfer(), identity=unit, rva_start=entry)
    write_component_exact_c_slice_v1(component_id=component, transfers=[transfer],
        operations=[{'operation_id': 'initialize', 'unit_ids': [unit], 'entry_rvas': [entry]}],
        intent=None, executable_transfer_plan_sha256='c'*64, out=root/'exact')
    source = root/'initialize.c'
    source.write_text('''#include "portable-component-implementation.h"
void authored_initialize(spx_initializer_context_v5 *context,const spx_view_v5 *output,uint32_t value){
 (void)context;
 for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);
}
'''.replace('for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);',
        'output->write(output->access_context,output->base,0U,4U,value);\n'
        ' output->write(output->access_context,output->base,4U,4U,value);' if edited else
        'for(uint32_t i=0;i<2U;i++)output->write(output->access_context,output->base,4U*i,4U,value);')
        .replace('spx_initializer_context_v5', f'spx_{_c_identifier(component)}_context_v5'))
    build_component_source_package(lift_unit_id=component, files={'initialize.c': source},
        shared_inputs={}, operation_symbols={'initialize': 'authored_initialize'}, out_dir=root/'source')
    return binding, domain


class SourceObjectInitializationTests(unittest.TestCase):
    @classmethod
    def check_supplier(cls, name, *, edited=False, weaker=False):
        root = cls.root/name
        binding, domain = prepare(root, edited=edited)
        if weaker:
            domain['initializes'][0]['extent'] = 4
        status = write_component_source_check(target_id='fixture', component_id='initializer',
            interface_package=root/'interface', source_package=root/'source', out=root/'feedback',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')),
            cbmc=Path(shutil.which('cbmc')), contract_workspace=root/'contracts', contract_timeout_seconds=60,
            original_comparison={'exact_c_slice': root/'exact', 'binding_intent': binding.to_payload(),
                                 'machine_domain': domain})
        if status['status'] != 'complete':
            raise AssertionError((root/'feedback/source-check-details.json').read_text())

    @classmethod
    def prepare_caller(cls, name, *, wrong=False):
        root = cls.root/name
        contract = prepare_caller(root, wrong=wrong)
        status = write_component_source_check(target_id='fixture', component_id='initialization-consumer',
            interface_package=root/'interface', source_package=root/'source', out=root/'preparation',
            host_compiler=Path(shutil.which('cc')), pe32_compiler=Path(shutil.which('cc')))
        if status['status'] != 'complete':
            raise AssertionError(status)
        return contract

    @classmethod
    def call(cls, name, *, supplier='supplier', caller='caller', previous=None):
        root, output = cls.root/caller, cls.root/name
        status = write_component_source_call_check(target_id='fixture', component_id='initialization-consumer',
            preparation=root/'preparation', exact=root/'exact', supplier=cls.root/supplier/'feedback', contract=cls.contract,
            source_package=root/'source', interface_package=root/'interface', out=output/'feedback',
            workspace=output/'work', goto_cc=Path(shutil.which('goto-cc')), cbmc=Path(shutil.which('cbmc')),
            smt_solver=None, unwind=16, timeout_seconds=60, previous=previous)
        result = json.loads((output/'feedback/caller-comparison/result.json').read_text())
        return status, result

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.check_supplier('supplier')
        cls.contract = cls.prepare_caller('caller')
        cls.status, cls.result = cls.call('baseline')
        if cls.status['status'] != 'complete':
            raise AssertionError(cls.result.get('checks'))

    def test_public_caller_uses_checked_initialization_with_the_supplier_body_absent(self):
        with patch('subprocess.run', side_effect=AssertionError('evidence reader must not run tools')):
            checked = checked_object_call_supplier(self.root/'supplier/feedback')
            adapted, _ = checked_object_supplier_facts(self.root/'supplier/feedback', ['eax'])
            caller_checker.validate_operation_call_result(self.result, self.root/'baseline/feedback/caller-comparison')
        facts = checked['contract']
        self.assertFalse(checked['activation_authorized'])
        self.assertEqual(facts['initializes'], fixture()[2]['initializes'])
        self.assertEqual([a['entry_register'] for a in facts['arguments']], ['eax', 'edx'])
        self.assertEqual(facts['results'], [])
        self.assertEqual(adapted['normal_return'], {'result_field': None, 'stack_delta': 0, 'preserved_fields': ['eax']})
        self.assertNotIn('behavioral-fn-00001000.c', self.result['proof_key']['bindings']['original_files'])
        self.assertFalse(self.result['activation_authorized'])

    def test_a_compatible_initializer_edit_reuses_the_caller_without_proof_work(self):
        self.check_supplier('edited', edited=True)
        before = checked_object_call_supplier(self.root/'supplier/feedback')
        after = checked_object_call_supplier(self.root/'edited/feedback')
        self.assertEqual(before['contract_sha256'], after['contract_sha256'])
        self.assertNotEqual(before['transition']['supplier_receipt_sha256'], after['transition']['supplier_receipt_sha256'])
        with (patch.object(caller_checker, 'render_caller_boundary', side_effect=AssertionError('reuse rendered a caller')),
                patch('subprocess.run', side_effect=AssertionError('reuse ran a tool'))):
            status, result = self.call('reused', supplier='edited', previous=self.root/'baseline/feedback')
        self.assertEqual(status['status'], 'complete', result.get('checks'))
        self.assertEqual(result['reuse'], {'status': 'reused', 'model_generation': 0, 'compiler_runs': 0, 'solver_runs': 0})

    def test_a_checked_weaker_initialization_contract_does_not_initialize_other_bytes(self):
        self.check_supplier('weaker', weaker=True)
        status, result = self.call('weaker-reuse', supplier='weaker', previous=self.root/'baseline/feedback')
        self.assertNotEqual(status['status'], 'complete', result.get('checks'))
        self.assertNotEqual(result.get('reuse', {}).get('status'), 'reused')
        status, result = self.call('weaker-caller', supplier='weaker')
        self.assertEqual(status['status'], 'violated', result.get('checks'))
        self.assertIn('spx-caller-private-byte-initialized', json.dumps(result['checks']))

    def test_a_wrong_caller_result_is_rejected(self):
        self.prepare_caller('wrong', wrong=True)
        status, result = self.call('wrong-caller', caller='wrong')
        self.assertEqual(status['status'], 'violated', result.get('checks'))
        self.assertIn('result-equivalence', json.dumps(result['checks']))

    def test_initialization_claim_and_model_tampering_reject(self):
        path = self.root/'supplier/feedback/original-comparison/result.json'
        original = path.read_text()
        changed = copy.deepcopy(json.loads(original))
        changed['bindings']['machine_domain']['initializes'][0]['extent'] = 4
        changed['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in changed.items() if k != 'receipt_sha256'})
        try:
            path.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, 'model meaning differs'):
                checked_object_call_supplier(self.root/'supplier/feedback')
        finally:
            path.write_text(original)
        model = self.root/'supplier/feedback/original-comparison/pair.c'
        original = model.read_text()
        try:
            model.write_text(original.replace('"spx-object-initialized:left:output:0:8"', '"removed-claim"'))
            with self.assertRaisesRegex(ValueError, 'model meaning differs'):
                checked_object_call_supplier(self.root/'supplier/feedback')
        finally:
            model.write_text(original)
