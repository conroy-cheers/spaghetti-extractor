"""Checked opaque-address transport into a body-independent scalar supplier."""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_call_relations import parameter
from spaghetti_extractor.components.bisimulation_caller_boundary import U32, add, constant, value
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator.source_check import write_component_source_check
from tests.unit.components.finite_caller_fixture import leaf, parent

TESTKIT = {'fixtures': ('compiler', 'cbmc'), 'commands': ('component check',)}


def reference_parent(root, interface, transfers, *, source_edit=None):
    contract = parent(root, supplier_interface=interface, supplier_transfers=transfers)
    intent_file = root/'interface/component-interface-intent-v1.json'
    intent = json.loads(intent_file.read_text())
    schema = intent['schema']
    schema['types'].append({'id': 'buffer', 'kind': 'opaque', 'nominal_id': 'fixture.buffer'})
    original = next(s for s in schema['signatures'] if s['id'] == 'run')
    def argument(name):
        return {**original['parameters'][0], 'id': name, 'type_id': 'buffer', 'nullable': True}
    operation = deepcopy(original)
    operation.update(id='caller', function_type_id='caller.fn', parameters=[argument(n) for n in ('input','next','alias')])
    service = deepcopy(original)
    service.update(id='reference', function_type_id='reference.fn', parameters=[argument('buffer')])
    function = next(t for t in schema['types'] if t['id'] == original['function_type_id'])
    for signature in (operation, service):
        schema['signatures'].append(signature)
        schema['types'].append({**function, 'id': signature['function_type_id'],
                                'parameter_type_ids': ['buffer']*len(signature['parameters'])})
    intent['services'][0]['signature_id'] = 'reference'
    op = intent['operations'][0]
    op.update(signature_id='caller', source_values=operation['parameters'], projection_entries=[
        {'source_id': p['id'], 'target': {'root': 'parameter','value_id': p['id'],'fields': []}}
        for p in operation['parameters']])
    rebuilt = ComponentInterfaceIntentV1.create(component_id=intent['id'],
        schema=BoundarySchemaV1.create(schema_id=schema['schema_id'],types=schema['types'],signatures=schema['signatures']),
        state=intent['state'],effects=intent['effects'],services=intent['services'],operations=intent['operations'],
        protocol_states=intent['protocol']['states'],initial_protocol_state=intent['protocol']['initial_state'])
    intent_file.write_text(json.dumps(rebuilt.to_payload()))
    source = '''#include "portable-component-implementation.h"
void authored(spx_finite_parent_2_context_v5 *context,struct spx_opaque_buffer_v5 *input,
    struct spx_opaque_buffer_v5 *next,struct spx_opaque_buffer_v5 *alias) {
  if(input!=alias) return;
  context->services->child(context->services->context,input);
  context->services->child(context->services->context,next);
}
'''
    (root/'caller.c').write_text(source_edit(source) if source_edit else source)
    (root/'identities.h').write_text('/* No native bytes are represented by opaque identities. */\n')
    build_component_source_package(lift_unit_id=contract['component_id'],
        files={name: root/name for name in ('caller.c','identities.h')}, shared_inputs={},
        operation_symbols={'run':'authored'},out_dir=root/'source-reference')
    boundary = contract['boundary']
    boundary['values'].extend([
        {'id':'next','sort':U32.to_payload(),'expression':add(value('input'),constant(1)).to_payload()},
        {'id':'alias','sort':U32.to_payload(),'expression':value('input').to_payload()}])
    boundary['records'] = {'header':'identities.h','lifetime':'operation',
        'types':[{'id':'buffer','extent':0,'fields':[],'subobjects':[],'representation':'identity'}],
        'objects':[{'id':name,'type_id':'buffer','count':1,'address':value(name).to_payload()}
                   for name in ('input','next','alias')], 'projections':[], 'state':{}}
    contract['source_services'][0]['arguments'] = [parameter('buffer',U32).to_payload()]
    contract['suppliers']['child']['parameter_transport'] = {
        'input': {'parameter':'buffer','relation':'record-address'}}
    return contract


class SourceReferenceSupplierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(); cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name); cls.transfers = []
        cls.leaf_contract = leaf(cls.root/'leaf',transfers_out=cls.transfers)
        cls.prepare('leaf',cls.leaf_contract,'source')
        status,cls.leaf_result = cls.invoke('leaf',cls.leaf_contract,source='source')
        if status['status'] != 'complete': raise AssertionError(cls.leaf_result['checks'])
        cls.contract = cls.make_parent('parent')
        status,cls.baseline = cls.invoke('parent',cls.contract)
        if status['status'] != 'complete': raise AssertionError(cls.baseline['checks'])

    @classmethod
    def prepare(cls,name,contract,source):
        root=cls.root/name
        status=write_component_source_check(target_id='fixture',component_id=contract['component_id'],
            interface_package=root/'interface',source_package=root/source,out=root/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if status['status']!='complete': raise AssertionError(status)

    @classmethod
    def make_parent(cls,name,**kwargs):
        contract=reference_parent(cls.root/name,cls.root/'leaf/interface/component-interface-intent-v1.json',
                                  cls.transfers,**kwargs)
        cls.prepare(name,contract,'source-reference')
        return contract

    @classmethod
    def invoke(cls,name,contract,*,output='baseline',source='source-reference',previous=None,supplier=None):
        root=cls.root/name; out=root/output
        status=write_component_source_call_check(target_id='fixture',component_id=contract['component_id'],
            preparation=root/'preparation',exact=root/'exact',supplier=(supplier or {'child':cls.root/'leaf/baseline/feedback'})
                if contract['suppliers'] else {},contract=contract,source_package=root/source,interface_package=root/'interface',
            out=out/'feedback',workspace=out/'work',goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),
            smt_solver=None,unwind=16,timeout_seconds=60,previous=previous)
        return status,json.loads((out/'feedback/caller-comparison/result.json').read_text())

    def test_null_aliases_memory_and_body_absence_are_checked(self):
        self.assertFalse(self.baseline['activation_authorized'])
        bindings=self.baseline['proof_key']['bindings']
        self.assertEqual(bindings['runtime_contract']['parameter_transport'],{
            'child':{'input':{'parameter':'buffer','relation':'record-address'}}})
        self.assertEqual(bindings['runtime_contract']['record_identities']['relation'],'native-address')
        proof=self.root/'parent/baseline/feedback/caller-comparison/proof'
        self.assertFalse((proof/'behavioral-fn-00002000.c').exists())
        self.assertIn('record-types.goto',self.baseline['proof_files'])

    def test_changed_supplier_reuses_neighbor_without_any_proof_tools(self):
        edited=leaf(self.root/'edited',edited=True)
        self.prepare('edited',edited,'source-edited')
        status,result=self.invoke('edited',edited,source='source-edited')
        self.assertEqual(status['status'],'complete',result['checks'])
        with patch('subprocess.run',side_effect=AssertionError('reuse invoked tools')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('reuse generated caller')):
            status,result=self.invoke('parent',self.contract,output='reused',
                previous=self.root/'parent/baseline/feedback',supplier={'child':self.root/'edited/baseline/feedback'})
        self.assertEqual(status['status'],'complete',result['checks'])
        self.assertEqual(result['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.assertEqual(result['proof_key'],self.baseline['proof_key'])
        self.assertEqual(result['proof_files'],self.baseline['proof_files'])

    def test_wrong_reference_and_identity_dereference_reject(self):
        for name,edit in [('wrong',lambda s:s.replace('context,input);','context,next);')),
                          ('read',lambda s:s.replace('  if(input!=alias)',
                              '  if(input) { uint8_t observed=*((uint8_t *)input); (void)observed; }\n  if(input!=alias)'))]:
            with self.subTest(name=name):
                contract=self.make_parent(name,source_edit=edit)
                status,result=self.invoke(name,contract)
                self.assertEqual(status['status'],'violated',result['checks'])
                if name=='wrong': self.assertIn('spx-paired-call-arguments',json.dumps(result['checks']))
                else: self.assertIn(result['query']['source']['propertyClass'],
                                    {'array bounds','pointer','pointer arithmetic','pointer dereference'})

    def test_unchecked_surface_changes_fail_before_compilation(self):
        for name,edit in [('missing',lambda c:c['suppliers']['child'].pop('parameter_transport')),
                         ('wrong',lambda c:c['suppliers']['child']['parameter_transport']['input'].update(parameter='absent')),
                         ('arithmetic',lambda c:c['source_services'][0].update(
                             arguments=[add(parameter('buffer',U32),constant(1)).to_payload()])),
                         ('storage',lambda c:c['boundary']['records']['types'][0].update(extent=1)),
                         ('projection',lambda c:c['boundary']['records']['projections'].append(
                             {'id':'forged','type_id':'buffer','fields':[]})),
                         ('extra',lambda c:c['suppliers']['child']['parameter_transport'].update(extra={}))]:
            contract=deepcopy(self.contract); edit(contract)
            with self.subTest(name=name),patch('subprocess.run',side_effect=AssertionError('invalid relation invoked tools')):
                status,result=self.invoke('parent',contract,output=name)
            self.assertEqual(status['status'],'incomplete',result['checks'])
            self.assertEqual(result['reuse']['compiler_runs'],0)

    def test_record_caller_cannot_export_unproved_lifetime_or_memory(self):
        with self.assertRaisesRegex(ValueError,'checked callable lifetime and enclosing memory transport'):
            checker.checked_caller_supplier(self.root/'parent/baseline/feedback',[])
