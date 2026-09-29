"""Interface adapters reject unsupported correspondence without adding premises."""
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from spaghetti_extractor.components.bisimulation_call_relations import constant, expression, parameter
from spaghetti_extractor.components.bisimulation_caller_interface import source_operation_invocation, source_service_adapters
from spaghetti_extractor.components.bisimulation_caller_memory import U32
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.relation_ir import RelationSortV1


TESTKIT={'resources':('tests/fixtures/metapad-cleanup-save',)}
FIXTURE=Path(__file__).parents[2]/'fixtures/metapad-cleanup-save/component-interface-intent-v1.json'


class CallerInterfaceTests(unittest.TestCase):
    def setUp(self):
        self.intent=ComponentInterfaceIntentV1.parse(json.loads(FIXTURE.read_text()))
        self.bundle=compile_component_interface_v5(self.intent)
        self.definitions=json.loads((FIXTURE.parent/'caller-contract.json').read_text())['source_services']

    def render(self, definitions=None):
        return source_service_adapters(self.bundle,'prepare',
            self.definitions if definitions is None else definitions,callbacks={'cleanup':'checked_callback'})

    def test_missing_extra_or_unmapped_services_reject(self):
        for definitions in ([],self.definitions*2,[{**self.definitions[0],'id':'another'}]):
            with self.assertRaisesRegex(ValueError,'service coverage differs'):self.render(definitions)
        with self.assertRaisesRegex(ValueError,'checked service callbacks differ'):
            source_service_adapters(self.bundle,'prepare',self.definitions,callbacks={})

    def test_unbound_or_injected_projections_reject(self):
        for bad in ('text->base.object',parameter('unbound',U32).to_payload()):
            rows=deepcopy(self.definitions);rows[0]['arguments']=[bad]
            with self.assertRaises(ValueError):self.render(rows)
        rows=deepcopy(self.definitions);rows[0]['views']['text']='missing'
        with self.assertRaisesRegex(ValueError,'view correspondence differs'):self.render(rows)
        rows=deepcopy(self.definitions);del rows[0]['views']['caption']
        with self.assertRaisesRegex(ValueError,'view correspondence differs'):self.render(rows)

    def test_projection_cannot_read_memory_without_an_accessor(self):
        view=parameter('text',RelationSortV1('view',type_id='bytes'))
        byte=expression('byte_read',RelationSortV1('bitvector',width=8),view,constant(0))
        rows=deepcopy(self.definitions);rows[0]['arguments']=[expression('zero_extend',U32,byte).to_payload()]
        with self.assertRaisesRegex(ValueError,'current-memory accessor is absent'):self.render(rows)

    def test_renamed_interface_uses_the_same_adapter(self):
        # This is a naming unit test, not the reserved real definition-only case.
        operations=deepcopy(list(self.intent.operations));operations[0]['id']='invoke'
        operations[0]['allowed_service_ids']=['dependency']
        services=deepcopy(list(self.intent.services));services[0]['id']='dependency'
        intent=ComponentInterfaceIntentV1.create(component_id='other-consumer',schema=self.intent.schema,
            state=[],operations=operations,effects=[],services=services,
            protocol_states=['ready'],initial_protocol_state='ready')
        bundle=compile_component_interface_v5(intent)
        definitions=deepcopy(self.definitions);definitions[0]['id']='dependency'
        _,names=source_service_adapters(bundle,'invoke',definitions,callbacks={'dependency':'checked_callback'})
        invoke,frame=source_operation_invocation(bundle,'invoke','authored',arguments={
            v.identity:f'&env_right.views[{i}]' for i,v in enumerate(intent.schema.signature_index['prepare'].parameters)},
            callbacks=names,result_name='result',diagnostic='context-frame')
        self.assertIn('spx_other_consumer_context_v5',invoke)
        self.assertIn('services.dependency==spx_source_service_0',frame)
        self.assertNotIn('cleanup',invoke+frame)

    def test_missing_inputs_and_stateful_context_require_a_rule(self):
        _,names=self.render()
        kwargs={'arguments':{},'callbacks':names,'result_name':'result','diagnostic':'frame'}
        with self.assertRaisesRegex(ValueError,'operation argument coverage differs'):
            source_operation_invocation(self.bundle,'prepare','authored',**kwargs)
        stateful=replace(self.bundle,interface=replace(self.bundle.interface,protocol_states=('ready','busy')))
        with self.assertRaisesRegex(ValueError,'stateful caller context requires'):
            source_operation_invocation(stateful,'prepare','authored',**kwargs)
