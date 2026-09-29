"""Editable definitions preserve scope, supplier authority and interface semantics."""
from copy import deepcopy
import json
from pathlib import Path
import unittest

from spaghetti_extractor.components.bisimulation_caller_definition import (
    selected_definition,instantiate_definition,checked_caller_interface,checked_caller_scope,
)
from spaghetti_extractor.components.bisimulation_supplier_facts import checked_supplier_facts
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1

FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save'
TESTKIT={'resources':('tests/fixtures/metapad-cleanup-save','tests/fixtures/metapad-cleanup-replace')}


class CallerDefinitionTests(unittest.TestCase):
    def setUp(self):
        self.contract=json.loads((FIXTURE/'caller-contract.json').read_text())
        self.summary=json.loads((FIXTURE/'summary-input.json').read_text())
        self.facts,_=checked_supplier_facts(self.summary,self.contract['required_frame'])
        self.intent=ComponentInterfaceIntentV1.parse(json.loads((FIXTURE/'component-interface-intent-v1.json').read_text()))
        self.original=json.loads((FIXTURE/'exact/component-exact-c-slice-v1.json').read_text())

    def instantiate(self):
        return instantiate_definition(self.contract,selected_definition(self.contract),self.facts,self.intent)

    def test_definition_cannot_grant_supplier_frames_or_outcomes(self):
        for field in ('normal_return','fault','normal_excludes','objects','terminal_services','captured_target_projection'):
            c=deepcopy(self.contract)
            if field=='normal_return':self.contract['native_calls'][0][field]=self.facts['normal_return']
            else:self.contract['boundary']['services'][0][field]=[]
            with self.subTest(field=field),self.assertRaisesRegex(ValueError,'must be derived'):self.instantiate()
            self.contract=c

    def test_omitting_admission_does_not_omit_current_call_obligations(self):
        self.contract['boundary']['admission']=[]
        self.contract['boundary'].pop('supplier_admission')
        boundary,calls,_,_=self.instantiate()
        self.assertEqual(boundary['admission'],[])
        requires=calls[0]['requires']
        self.assertTrue({ 'supplier-call-'+row['id'] for row in self.facts['entry_relations']} <= {r['id'] for r in requires})
        text=json.dumps(requires)
        self.assertIn('call_memory',text)
        self.assertNotIn('entry_memory',text)
        self.assertIn('caller_before',text)
        self.assertTrue({'supplier-call-input-private-scope','supplier-call-output-private-scope'} <= {r['id'] for r in requires})

    def test_operator_cannot_select_an_unrelated_projection_or_untyped_witness(self):
        for key in ('arguments','witness'):
            old=deepcopy(self.contract)
            if key=='arguments':self.contract['native_calls'][0]['arguments']=[]
            else:self.contract['witnesses']['length']='arbitrary C'
            with self.subTest(key=key),self.assertRaises(ValueError):self.instantiate()
            self.contract=old
        self.contract['source_services'][0]['views']['caption']='length'
        with self.assertRaisesRegex(ValueError,'supplier view reference differs'):self.instantiate()

    def test_missing_units_extra_entries_and_unmatched_edges_reject(self):
        selected=selected_definition(self.contract);_,calls,_,_=self.instantiate()
        for kind in ('unit','entry','edge','alias'):
            original=deepcopy(self.original)
            if kind=='unit':original['root_unit_ids'].pop();original['root_context_unit_ids']=original['root_unit_ids']
            elif kind=='entry':original['root_entry_rvas'].append(0x5c34)
            elif kind=='edge':original['internal_direct_call_closure']['call_edges'].pop()
            else:original['source_map'].append(original['source_map'][0])
            with self.subTest(kind=kind),self.assertRaises(ValueError):
                checked_caller_scope(original,selected,calls,self.facts['original_transfer_plan_sha256'])

    def test_state_labels_are_semantics_not_a_full_interface_hash(self):
        operations=deepcopy(list(self.intent.operations))
        operations[0]['pre_states']=operations[0]['post_states']=['idle']
        changed=ComponentInterfaceIntentV1.create(component_id=self.intent.component_id,schema=self.intent.schema,
            state=[],operations=operations,effects=[],services=list(self.intent.services),
            protocol_states=['idle'],initial_protocol_state='idle')
        self.assertNotEqual(changed.intent_sha256,self.intent.intent_sha256)
        checked_caller_interface(changed,'prepare',self.contract['source_services'])
        operations[0]['allowed_service_ids']=[]
        changed=ComponentInterfaceIntentV1.create(component_id=self.intent.component_id,schema=self.intent.schema,
            state=[],operations=operations,effects=[],services=list(self.intent.services),
            protocol_states=['idle'],initial_protocol_state='idle')
        with self.assertRaisesRegex(ValueError,'service coverage differs'):
            checked_caller_interface(changed,'prepare',self.contract['source_services'])

    def test_runtime_service_is_explicitly_unverified(self):
        fixture=FIXTURE.parent/'metapad-cleanup-replace'
        c=json.loads((fixture/'caller-contract.json').read_text());s=selected_definition(c)
        facts,_=checked_supplier_facts(json.loads((fixture/'summary-input.json').read_text()),c['required_frame'])
        intent=ComponentInterfaceIntentV1.parse(json.loads((fixture/'component-interface-intent-v1.json').read_text()))
        c['runtime_contracts']['send_message']['status']='verified'
        with self.assertRaisesRegex(ValueError,'explicit unverified import contract'):
            instantiate_definition(c,s,facts,intent)

    def test_state_views_do_not_silently_admit_other_lifetime_or_initialization_contracts(self):
        state=deepcopy(self.intent.schema.signature_index['prepare'].parameters[1].to_payload())
        state['id']='settings'
        def intent(value,initial=None):
            operations=deepcopy(list(self.intent.operations))
            operations[0]['lifecycle_additional_roots']={'state':[value]}
            return ComponentInterfaceIntentV1.create(component_id=self.intent.component_id,schema=self.intent.schema,
                state=[{'value':value,'initial':initial}],operations=operations,effects=[],services=list(self.intent.services),
                protocol_states=['ready'],initial_protocol_state='ready')
        checked_caller_interface(intent(state),'prepare',self.contract['source_services'])
        bad=[({**state,'nullable':True},None),
             ({**state,'extent':{'kind':'nul_terminated','bytes':None,'value_id':None}},None),
             ({**state,'access':'write'},None),(state,{'assume_zero':True})]
        for value,initial in bad:
            with self.subTest(value=value,initial=initial),self.assertRaisesRegex(ValueError,'caller state needs'):
                checked_caller_interface(intent(value,initial),'prepare',self.contract['source_services'])

    def test_private_bytes_cannot_inherit_unchecked_supplier_preservation(self):
        from spaghetti_extractor.components.bisimulation_caller_memory import private_bytes, entry_offset
        self.contract['native_memory'].append(private_bytes('buffer',entry_offset('esp',-64),16))
        self.contract['boundary']['private_byte_capacity']=128
        with self.assertRaisesRegex(ValueError,'checked supplier effects and lifetime composition'):
            self.instantiate()
