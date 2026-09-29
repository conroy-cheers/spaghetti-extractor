"""Real caller definitions derive footprints and retain every call premise."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from spaghetti_extractor.components.bisimulation_caller_boundary import render_caller_boundary
from spaghetti_extractor.components.bisimulation_caller_definition import selected_definition, instantiate_definition, checked_caller_scope
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5

FIXTURE=Path(__file__).parents[2]/'fixtures/hello-quoting-state/caller'
TESTKIT={'resources':('tests/fixtures/hello-quoting-state',)}


class ObjectCallerDefinitionTests(unittest.TestCase):
    def setUp(self):
        read=lambda name:json.loads((FIXTURE/name).read_text())
        self.contract=read('caller-contract.json');self.facts=read('supplier-facts.json')
        self.intent=ComponentInterfaceIntentV1.parse(read('component-interface-intent-v1.json'))
        self.exact=read('exact/component-exact-c-slice-v1.json')

    def instantiate(self):
        return instantiate_definition(self.contract,selected_definition(self.contract),self.facts,self.intent)

    def test_complete_public_definition_has_no_callee_body_or_unchecked_native_frame(self):
        boundary,calls,services,premises=self.instantiate()
        checked_caller_scope(self.exact,selected_definition(self.contract),calls,self.facts['original_transfer_plan_sha256'])
        self.assertEqual(self.exact['functions'][0]['entries'],[0x5494])
        self.assertEqual(len(self.exact['root_unit_ids']),12)
        self.assertEqual(self.exact['root_unit_ids'],self.exact['root_context_unit_ids'])
        self.assertFalse(any(r['path'] in {'behavioral-fn-000050e1.c','behavioral-fn-00004eb3.c'} for r in self.exact['files']))
        self.assertEqual(calls[0]['normal_return'],self.facts['normal_return'])
        self.assertEqual(boundary['services'][0]['objects'][0]['local_view'],'local_options')
        self.assertEqual(boundary['services'][1]['objects'][0]['permissions'],1)
        self.assertEqual(premises['services']['quote']['status'],'unverified')
        model=render_caller_boundary(boundary,'authored_quote_character',interface_bundle=compile_component_interface_v5(self.intent),
            native_memory=self.contract['native_memory'],native_calls=calls,source_services=services)
        self.assertIn('step.kind==SPX_RETURN',model)
        self.assertIn('spx_check_boundary_admission',model)
        self.assertNotIn('spx_sub_000050e1(',model)
        self.assertNotIn('spx_sub_00004eb3(',model)

    def test_wrong_supplier_projection_and_authored_guarantees_reject(self):
        original=deepcopy(self.contract)
        for change in ('native','source','frame','footprint','terminal'):
            self.contract=deepcopy(original)
            if change=='native':self.contract['native_calls'][0]['arguments'].reverse()
            elif change=='source':self.contract['source_services'][0]['arguments'].reverse()
            elif change=='frame':self.contract['native_calls'][0]['normal_return']=self.facts['normal_return']
            else:self.contract['boundary']['services'][0]['terminal_services' if change=='terminal' else 'objects']=[]
            with self.subTest(change=change),self.assertRaises(ValueError):self.instantiate()

    def test_runtime_footprint_and_lifetime_premises_cannot_be_silently_omitted(self):
        original=deepcopy(self.contract)
        for change in ('verified','omitted','empty','unknown'):
            self.contract=deepcopy(original);runtime=self.contract['runtime_contracts']['quote']
            if change=='verified':runtime['status']='verified'
            elif change=='omitted':runtime['objects'].pop(0)
            elif change=='empty':runtime['unverified']=[]
            else:runtime['objects'][0]['parameter']='unknown'
            with self.subTest(change=change),self.assertRaises(ValueError):self.instantiate()

    def test_untyped_local_mapping_and_missing_original_call_reject(self):
        self.contract['boundary']['local_views'][0]['address']='invented_pointer()'
        with self.assertRaises(ValueError):self.instantiate()
        self.setUp();boundary,calls,_,_=self.instantiate()
        for change in ('edge','boundary','return'):
            original=deepcopy(self.exact)
            if change=='edge':original['internal_direct_call_closure']['call_edges'].pop()
            elif change=='boundary':original['internal_direct_call_closure']['summary_entry_rvas'].append(0x9999)
            else:original['functions'][0]['unit_rvas'].pop()
            with self.subTest(change=change),self.assertRaises(ValueError):
                checked_caller_scope(original,selected_definition(self.contract),calls,self.facts['original_transfer_plan_sha256'])
