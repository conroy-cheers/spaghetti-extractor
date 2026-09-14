"""Conditional body-free state/service boundaries; no provider admission."""

import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_connected import render_connected_summary_wrapper
from spaghetti_extractor.components.bisimulation_shared_summary import SHARED_STRATEGY
from spaghetti_extractor.components.bisimulation_evidence import _validate_model_and_shard_evidence
from .shared_summary_fixture import summary_inputs, check_shared_pair

TESTKIT = {'fixtures': ('cbmc','compiler'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text','profiles/pe32-user32-resource-text-runtime-v1.json')}


class SharedSummaryTests(unittest.TestCase):
    def test_summary_has_no_callee_body_or_buffer_length_expansion(self):
        models=[]
        for extent in (8,1000000):
            bundle,_,contract=summary_inputs(extent)
            models.append(render_connected_summary_wrapper(bundle=bundle,operation_symbols={'get':'resource_text'},
                summary_ids={'get':0},checked_mutable_transport=True,shared_contract=contract))
        self.assertNotIn('spx_proof_connected_impl_',models[0])
        for kind in ('view', 'domain', 'transport'):
            self.assertEqual(models[0].count(
                f'"spx-bisimulation-connected-summary-mutable-{kind}:resource-text:get"'), 1)
        self.assertIn('(&context->state.buffer)->extent == UINT64_C(8)', models[0])
        self.assertIn('(&context->state.module)->extent == UINT64_C(4)', models[0])
        self.assertEqual(models[0].count('\n'),models[1].count('\n'))
        self.assertLess(abs(len(models[0])-len(models[1])),128)
        bundle,_,contract=summary_inputs()
        contract['maximum_memory_events']=64
        self.assertEqual(models[0],render_connected_summary_wrapper(bundle=bundle,operation_symbols={'get':'resource_text'},
            summary_ids={'get':0},checked_mutable_transport=True,shared_contract=contract))
        del contract['service_contracts']
        with self.assertRaisesRegex(ValueError,'selected service premises'):
            render_connected_summary_wrapper(bundle=bundle,operation_symbols={'get':'resource_text'},
                summary_ids={'get':0},checked_mutable_transport=True,shared_contract=contract)

    def test_experimental_summary_cannot_authorize_a_provider(self):
        fields=('binding_intent_sha256','implementation_sha256','source_profile_sha256','qualification_sha256',
            'contextual_refinement_sha256','proof_receipt_sha256','machine_overlay_sha256','proof_overlay_sha256',
            'machine_overlay_entries_sha256')
        connected={field:'a'*64 for field in fields}
        connected.update(component_id='probe',trusted_adapter_lowering_receipt_sha256=None,
                         summary_strategy=SHARED_STRATEGY,source_summary_certificate=None)
        with self.assertRaisesRegex(ValueError,'connected summary strategy is malformed'):
            _validate_model_and_shard_evidence(proof_plan={},shard_results=[],
                models={'operation_models':[],'connected_components':[connected]})

    def test_two_invocations_preserve_current_shared_memory_and_local_returned_views(self):
        with tempfile.TemporaryDirectory() as directory:
            result=check_shared_pair(Path(directory))
            self.assertEqual(result['status'],'satisfied',result.get('detail'))

    def test_shared_aliases_retain_current_writes(self):
        with tempfile.TemporaryDirectory() as directory:
            result=check_shared_pair(Path(directory),overlap=True)
            self.assertEqual(result['status'],'satisfied',result.get('detail'))

    def test_changed_memory_and_stale_or_foreign_transport_reject(self):
        for mutation,diagnostic in (
            ('spx_proof_source_write(0,0x413d20U,1U,~spx_proof_exact_byte(0x413d20U),&fault);','summary-memory'),
            ('right.state.buffer.base.generation += 1U;','mutable-transport'),
            ('right.state.buffer.write = 0;','mutable-transport'),
        ):
            with self.subTest(mutation=mutation),tempfile.TemporaryDirectory() as directory:
                result=check_shared_pair(Path(directory),mutation=mutation)
                self.assertEqual(result['status'],'violated',result.get('detail'))
                self.assertIn(diagnostic,result.get('detail',''))
