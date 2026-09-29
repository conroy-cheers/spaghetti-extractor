"""Fact selection preserves conditional semantics and rejects unsupported claims."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_supplier_facts import checked_supplier_facts, checked_borrowed_supplier_facts, check_supplier_service
from spaghetti_extractor.components.bisimulation_caller_definition import selected_definition, instantiate_definition
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save'
BORROWED=FIXTURE.parent/'metapad-resource-callers'
TESTKIT={'resources':('tests/fixtures/metapad-cleanup-save','tests/fixtures/metapad-resource-callers')}


class SupplierFactsTests(unittest.TestCase):
    def setUp(self):
        self.summary=json.loads((FIXTURE/'summary-input.json').read_text())
        self.c=self.summary['contract']
        self.intent=ComponentInterfaceIntentV1.parse(json.loads((FIXTURE/'component-interface-intent-v1.json').read_text()))

    def facts(self,frame=None):
        self.summary['contract_sha256']=canonical_sha256_v3(self.c)
        return checked_supplier_facts(self.summary,['ebp','ebx','esi'] if frame is None else frame)

    def test_unused_frame_withdrawal_and_supplier_growth_do_not_enter_local_facts(self):
        baseline,_=self.facts()
        self.c['normal_return']['preserved_equalities'].remove('state.edi==initial.edi')
        # An internal invocation bound is evidence about the supplier's body,
        # not a request to expand it in the parent model.
        self.c['all_outcomes']['maximum_service_calls']=4096
        current,required=self.facts()
        self.assertEqual(current,baseline)
        self.assertEqual(required['missing_guarantees'],[])
        _,required=self.facts(['ebp','ebx','edi','esi'])
        self.assertEqual(required['missing_guarantees'],['state.edi==initial.edi'])
        self.assertEqual(required['status'],'requires-recheck')

    def test_evidence_binding_and_conditional_assurance_are_mandatory(self):
        self.c['private_frame']['low']=-80
        with self.assertRaisesRegex(ValueError,'binding differs'):
            checked_supplier_facts(self.summary,['ebp'])
        for key,value in [('authorizing',True),('activation_authorized',True),('runtime_compatibility','verified'),('status','incomplete')]:
            changed=deepcopy(self.summary);changed[key]=value
            with self.subTest(key=key),self.assertRaisesRegex(ValueError,'conditional checked summary'):
                checked_supplier_facts(changed,['ebp'])

    def test_unsupported_guarantees_and_raw_predicates_fail_closed(self):
        cases=[(('input_relation','public_memory'),'Pointers are equal.','incoming public memory'),
            (('input_relation','views'),'Same view base address.','incoming view correspondence'),
            (('input_relation','entry_admission'),['arbitrary_c();'],'checked typed rule'),
            (('memory_fault','source_result'),0,'memory fault'),
            (('normal_return','return_target'),'Any continuation.','normal return target'),
            (('normal_return','preserved_equalities'),['state.eax==initial.ebx'],'normal frame relation'),
            (('normal_return','result','excluded_values'),[],'fault sentinel'),
            (('all_outcomes','public_memory','scope'),'Entire heap including freed objects.','public post-memory'),
            (('private_frame','scope'),'The caller declares this private.','private frame scope'),
            (('termination',),'Always terminates.','conditional progress')]
        original=deepcopy(self.c)
        for path,value,diagnostic in cases:
            self.c=deepcopy(original);self.summary['contract']=self.c
            target=self.c
            for key in path[:-1]:target=target[key]
            target[path[-1]]=value
            with self.subTest(path=path),self.assertRaisesRegex(ValueError,diagnostic):self.facts()

    def test_runtime_premises_are_visible_exact_and_never_guarantees(self):
        before,_=self.facts()
        self.c['runtime_requirements']['named']['new-service-premise']='Calls return under this unverified premise.'
        after,_=self.facts()
        self.assertNotEqual(before,after)
        self.assertEqual(after['runtime_assumptions']['status'],'unverified')
        self.assertEqual(after['runtime_assumptions']['requirements'],self.c['runtime_requirements'])
        self.assertFalse(after['assurance']['activation_authorized'])
        self.assertEqual(before['normal_return'],after['normal_return'])

    def test_current_projection_and_private_frame_feed_actual_model_definitions(self):
        self.c['native_projection']['image_views']['caption']['address']+=32
        self.c['native_projection']['image_views']['caption']['extent']=600
        self.c['private_frame']['low']=-80
        self.c['normal_return']['result']['excluded_values']=[17,2**32-1]
        facts,_=self.facts()
        contract=json.loads((FIXTURE/'caller-contract.json').read_text())
        definition,calls,_,_=instantiate_definition(contract,selected_definition(contract),facts,self.intent)
        caption=next(v for v in definition['views'] if v['id']=='caption')
        self.assertEqual(caption['address']['attributes']['value'],4252612)
        self.assertEqual(caption['extent']['attributes']['value'],600)
        # The current larger callee frame enters a mandatory containment check;
        # it does not silently widen the author's declared private region.
        required=next(row for row in calls[0]['requires'] if row['id']=='supplier-call-output-private-scope')
        self.assertIn('80',json.dumps(required))
        self.assertEqual(definition['services'][0]['normal_excludes'],[17,2**32-1])
        self.assertEqual(calls[0]['normal_return'],facts['normal_return'])
        check_supplier_service(facts,self.intent,'cleanup')

    def test_equal_signature_does_not_hide_different_native_view_extent(self):
        self.c['native_projection']['image_views']['main_window']['extent']=8
        facts,_=self.facts()
        with self.assertRaisesRegex(ValueError,'native view extent'):
            check_supplier_service(facts,self.intent,'cleanup')

    def test_normalized_entry_ir_has_no_legacy_c_or_unselected_frame(self):
        facts,_=self.facts()
        text=json.dumps(facts)
        self.assertNotIn('__CPROVER',text)
        self.assertNotIn('preserved_equalities',text)
        self.assertEqual(facts['normal_return']['preserved_fields'],['ebp','ebx','esi'])
        self.assertTrue(all(isinstance(row['expression'],dict) for row in facts['entry_relations']))
        self.c['input_relation']['entry_admission']=[s.replace(' ', '  ') for s in self.c['input_relation']['entry_admission']]
        self.assertEqual(self.facts()[0],facts)


class BorrowedSupplierFactsTests(unittest.TestCase):
    def setUp(self):
        self.transition=json.loads((BORROWED/'transition.json').read_text())
        self.original=json.loads((BORROWED/'finite-caller/supplier-exact.json').read_text())

    def facts(self,frame):
        self.transition['domain_sha256']=canonical_sha256_v3(self.transition['domain'])
        return checked_borrowed_supplier_facts(self.transition,original=self.original,required_frame=frame)

    def test_selected_frame_and_evidence_are_separate_from_the_consumed_facts(self):
        baseline,_=self.facts(['ebx'])
        self.transition['supplier_receipt_sha256']='1'*64
        self.transition['source_certificate_sha256']='2'*64
        self.transition['domain']['machine_domain']['clobbers']=sorted({
            *self.transition['domain']['machine_domain']['clobbers'],'edi'})
        current,required=self.facts(['ebx'])
        self.assertEqual(current,baseline)
        self.assertEqual(required['missing_guarantees'],[])
        self.assertEqual(self.facts(['edi'])[1]['missing_guarantees'],['state.edi==initial.edi'])
        self.assertEqual(current['result_view'],{'state_id':'buffer','address':0x413d20,'extent':500})
        self.assertEqual(current['normal_return']['preserved_fields'],['ebx'])
        self.assertFalse(current['assurance']['activation_authorized'])
        self.assertNotIn('view_has_zero',json.dumps(current))

    def test_original_identity_and_runtime_premises_remain_bound(self):
        baseline,_=self.facts([])
        self.transition['domain']['runtime_contract']['lifetime']+=' Additional requirement.'
        self.assertNotEqual(self.facts([])[0],baseline)
        self.original['slice_sha256']='3'*64
        with self.assertRaisesRegex(ValueError,'original identity differs'):self.facts([])

    def test_unsupported_frame_requests_reject(self):
        for frame in (['ebx','ebx'],['edi','ebx'],[{}],['invented']):
            with self.subTest(frame=frame):
                with self.assertRaisesRegex(ValueError,'requested borrowed frame'):self.facts(frame)
