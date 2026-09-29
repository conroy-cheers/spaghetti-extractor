"""Checked boundary definitions reject malformed structure and unbound facts."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from spaghetti_extractor.components.bisimulation_caller_boundary import render_caller_boundary, value
from spaghetti_extractor.components.bisimulation_caller_definition import selected_definition, instantiate_definition
from spaghetti_extractor.components.bisimulation_supplier_facts import checked_supplier_facts
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1,compile_component_interface_v5

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save'
TESTKIT={'resources':('tests/fixtures/metapad-cleanup-save',)}


class CallerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.contract,_=checked_supplier_facts(json.loads((FIXTURE/'summary-input.json').read_text()),['ebp','ebx','esi'])
        self.bundle=compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
            json.loads((FIXTURE/'component-interface-intent-v1.json').read_text())))
        self.public=json.loads((FIXTURE/'caller-contract.json').read_text())
        selected=selected_definition(self.public)
        self.definition,self.calls,self.services,_=instantiate_definition(self.public,selected,self.contract,self.bundle.intent)

    def render(self,definition):
        return render_caller_boundary(definition,'prepare_save',interface_bundle=self.bundle,
            native_memory=self.public['native_memory'],native_calls=self.calls,source_services=self.services)

    def test_unbound_values_and_raw_c_are_not_admission(self):
        for bad in ('1U',value('not_bound').to_payload()):
            d=deepcopy(self.definition);d['admission'][0]['expression']=bad
            with self.assertRaises(ValueError):self.render(d)
        d=deepcopy(self.definition);d['values'][0]['expression']=value('text_address').to_payload()
        with self.assertRaisesRegex(ValueError,'binding or sort'):self.render(d)

    def test_view_and_service_coverage_cannot_be_omitted(self):
        for key in ('views','services'):
            d=deepcopy(self.definition);d[key].pop()
            with self.assertRaises(ValueError):self.render(d)
        d=deepcopy(self.definition);d['views'][0]['address']='(uint32_t) arbitrary'
        with self.assertRaises(ValueError):self.render(d)

    def test_bounds_and_exit_shapes_are_checked(self):
        for key in ('event_capacity','call_capacity'):
            for bad in (0,65,True):
                d=deepcopy(self.definition);d[key]=bad
                with self.assertRaises(ValueError):self.render(d)
        for bad in ([],[{**self.definition['outcomes'][0],'exit':{'kind':'return','rva':None,'diagnostic':'unimplemented'}}]):
            d=deepcopy(self.definition);d['outcomes']=bad
            with self.assertRaises(ValueError):self.render(d)

    def test_outcome_observation_bindings_remain_typed_and_phase_specific(self):
        d=deepcopy(self.definition);d['outcomes'][0]['assertions'][0]['expression']=value('result.unknown').to_payload()
        with self.assertRaisesRegex(ValueError,'binding or sort'):self.render(d)
        d=deepcopy(self.definition);d['admission'][0]['expression']=value('left.calls.cleanup').to_payload()
        with self.assertRaisesRegex(ValueError,'binding or sort'):self.render(d)
