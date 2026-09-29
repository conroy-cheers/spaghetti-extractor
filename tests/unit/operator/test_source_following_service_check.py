"""Actual resource caller transports a live result into its next runtime import.

Supplier fixture transitions are premises, not locally minted proof authority.
The retained public workflow separately checks their original source certificates.
"""
from copy import deepcopy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_supplier_facts import checked_borrowed_supplier_facts
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, write_component_interface_package_v5
from spaghetti_extractor.components.source import build_component_source_package
from spaghetti_extractor.operator import source_operation_call_check as checker
from spaghetti_extractor.operator.source_call_check import write_component_source_call_check
from spaghetti_extractor.operator.source_check import write_component_source_check

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-resource-callers/following-service'
TESTKIT={'fixtures':('compiler','cbmc'),'commands':('component check',),
         'resources':('tests/fixtures/metapad-resource-callers',)}


class SourceFollowingServiceTests(unittest.TestCase):
    fixture=FIXTURE
    component_id='resource-notice-prefix'
    operation_id='prepare'
    symbol='prepare_notice'
    source_filename='prepare.c'
    entry_rva=0x5646
    resource_id=31

    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory();cls.root=Path(cls.temp.name)
        cls.contract=json.loads((cls.fixture/'caller-contract.json').read_text())
        transition=json.loads((cls.fixture/'transition.json').read_text())
        facts,required=checked_borrowed_supplier_facts(transition,
            original=json.loads((cls.fixture/'supplier-exact.json').read_text()),required_frame=cls.contract['required_frame'])
        cls.supplier=(facts,{'contract_sha256':transition['domain_sha256'],'consumer_requirements':required,
            'evidence':{k:transition[k] for k in ('supplier_receipt_sha256','source_certificate_sha256')}})
        cls.original=(cls.fixture/cls.source_filename).read_text()
        cls.prepare('source',cls.original)
        cls.invoke('baseline')
        if cls.result('baseline')['status']!='satisfied':raise AssertionError(cls.result('baseline')['checks'])

    @classmethod
    def tearDownClass(cls):cls.temp.cleanup()

    @classmethod
    def prepare(cls,name,source,*,interface=None):
        d=cls.root/name;d.mkdir();(d/'ordinary.c').write_text(source)
        build_component_source_package(lift_unit_id=cls.component_id,files={'components/'+cls.component_id+'.c':d/'ordinary.c'},
            shared_inputs={},operation_symbols={cls.operation_id:cls.symbol},out_dir=d/'source')
        result=write_component_source_check(target_id='metapad',component_id=cls.component_id,
            interface_package=cls.fixture if interface is None else interface,source_package=d/'source',out=d/'preparation',
            host_compiler=Path(shutil.which('cc')),pe32_compiler=Path(shutil.which('cc')))
        if result['status']!='complete':raise AssertionError(result)

    @classmethod
    def invoke(cls,name,*,source='source',contract=None,previous=None,interface=None):
        d=cls.root/name;d.mkdir()
        with patch.object(checker,'checked_caller_supplier',return_value=cls.supplier):
            return write_component_source_call_check(target_id='metapad',component_id=cls.component_id,
                preparation=cls.root/source/'preparation',exact=cls.fixture/'exact',supplier=cls.root/'supplier',
                contract=deepcopy(cls.contract if contract is None else contract),source_package=cls.root/source/'source',
                interface_package=cls.fixture if interface is None else interface,
                out=d/'feedback',workspace=d/'work',goto_cc=Path(shutil.which('goto-cc')),cbmc=Path(shutil.which('cbmc')),
                smt_solver=None,previous=previous,timeout_seconds=60)

    @classmethod
    def result(cls,name):return json.loads((cls.root/name/'feedback/caller-comparison/result.json').read_text())

    def failures(self,name,diagnostic):
        r=self.result(name);self.assertEqual(r['status'],'violated',r['checks'])
        query=json.loads((self.root/name/'feedback/caller-comparison/proof/query.stdout').read_text())
        self.assertIn(diagnostic,{r.get('description') for b in query for r in b.get('result',[]) if r['status']=='FAILURE'})

    def test_real_two_call_scope_allows_future_stack_slot_and_keeps_supplier_absent(self):
        r=self.result('baseline');self.assertEqual(r['admission']['status'],'satisfied')
        self.assertNotIn('behavioral-fn-00001284.c',r['proof_files'])
        self.assertFalse(r['activation_authorized']);self.assertEqual(r['runtime_compatibility'],'unverified')
        proof=self.root/'baseline/feedback/caller-comparison/proof/pair.c'
        source=proof.read_text()
        self.assertIn('supplier-call-live-slot-window-argument-0',source)
        self.assertIn('.initialized',source)
        self.assertIn('MessageBoxA',(proof.parent/f'behavioral-fn-{self.entry_rva:08x}.c').read_text())

    def test_stale_window_and_forged_returned_view_are_rejected(self):
        get=f'  spx_view_v5 text = context->services->resource_text(context->services->context, {self.resource_id}U);\n'
        call='  return context->services->message_box'
        cases=[('stale',self.original.replace(get,'').replace(call,get+call),'spx-paired-call-arguments'),
            ('view',self.original.replace(call,'  text.base.generation++;\n'+call),'message-live-views'),
            ('flags',self.original.replace('48U','49U'),'spx-paired-call-arguments')]
        for name,source,diagnostic in cases:
            with self.subTest(name=name):
                self.prepare('source-'+name,source);self.invoke(name,source='source-'+name);self.failures(name,diagnostic)

    def test_missing_stack_write_and_current_window_read_are_rejected(self):
        for name,slot,permission,diagnostic in [
            ('stack','window-argument','write','spx-caller-writable-frame'),
            ('window','main-window','read','spx-caller-readable-frame')]:
            contract=deepcopy(self.contract)
            # Remove an access entirely when it has no other permission.
            row=next(r for r in contract['native_memory'] if r['id']==slot)
            if permission=='read':contract['native_memory'].remove(row)
            else:row[permission]=False
            self.invoke(name,contract=contract);self.failures(name,diagnostic)

    def test_repair_reuses_the_complete_consumer_without_processes(self):
        with patch('subprocess.run',side_effect=AssertionError('repair ran a process')),patch.object(
                checker,'render_caller_boundary',side_effect=AssertionError('repair rendered a model')):
            self.assertEqual(self.invoke('repair',previous=self.root/'baseline/feedback')['status'],'complete')
        self.assertEqual(self.result('repair')['proof_files'],self.result('baseline')['proof_files'])

    def test_zero_argument_runtime_projection_pairs_results_and_retains_its_premise(self):
        # Exercise the native/typed-source/paired path with an explicitly assumed
        # no-argument import contract. This does not prove MessageBox applicability.
        intent=ComponentInterfaceIntentV1.parse(json.loads((self.fixture/'component-interface-intent-v1.json').read_text()))
        schema=intent.schema.to_payload()
        service=next(s for s in intent.services if s['id']=='message_box')
        signature=next(s for s in schema['signatures'] if s['id']==service['signature_id'])
        signature['parameters']=[]
        next(t for t in schema['types'] if t['id']==signature['function_type_id'])['parameter_type_ids']=[]
        changed=ComponentInterfaceIntentV1.create(component_id=intent.component_id,
            schema=BoundarySchemaV1.create(schema_id=schema['schema_id'],types=schema['types'],signatures=schema['signatures']),
            state=list(intent.state),operations=list(intent.operations),effects=list(intent.effects),services=list(intent.services),
            protocol_states=list(intent.protocol_states),initial_protocol_state=intent.initial_protocol_state)
        interface=self.root/'zero-interface';write_component_interface_package_v5(interface,changed)
        contract=deepcopy(self.contract)
        next(c for c in contract['native_calls'] if c['id']=='message_box')['arguments']=[]
        next(c for c in contract['source_services'] if c['id']=='message_box').update(arguments=[],views={})
        source=self.original[:self.original.index('  return context->services->message_box')]+'''
  (void)text; (void)window; (void)caption;
  return context->services->message_box(context->services->context);
}
'''
        self.prepare('zero-source',source,interface=interface)
        status=self.invoke('zero-check',source='zero-source',contract=contract,interface=interface)
        self.assertEqual(status['status'],'complete',self.result('zero-check')['checks'])
        self.assertEqual(self.result('zero-check')['runtime_compatibility'],'unverified')
        with patch('subprocess.run',side_effect=AssertionError('zero-argument reuse executed tools')):
            status=self.invoke('zero-reuse',source='zero-source',contract=contract,interface=interface,
                previous=self.root/'zero-check/feedback')
        self.assertEqual(status['status'],'complete',self.result('zero-reuse')['checks'])
        self.assertEqual(self.result('zero-reuse')['reuse'],{'status':'reused','model_generation':0,'compiler_runs':0,'solver_runs':0})
        self.prepare('zero-wrong-source',source.replace('  return context->services->message_box(context->services->context);',
            '  return context->services->message_box(context->services->context) ^ 1U;'),interface=interface)
        self.invoke('zero-wrong',source='zero-wrong-source',contract=contract,interface=interface)
        self.failures('zero-wrong','caller-result')


class ReservedErrorNoticeTests(SourceFollowingServiceTests):
    """Preselected ID-97 operation authored after the shared rule was frozen."""
    fixture=FIXTURE.parent/'error-notice'
    component_id='resource-error-notice'
    operation_id='notice'
    symbol='show_resource_error'
    source_filename='show-error.c'
    entry_rva=0x12c0
    resource_id=97
