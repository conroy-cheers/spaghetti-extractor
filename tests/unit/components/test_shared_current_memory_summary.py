"""Body-free current-memory export, replay and current lifetime consumers."""
import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_connected import render_connected_summary_wrapper
from spaghetti_extractor.components.bisimulation_shared_services import normalize_shared_service_bindings
from spaghetti_extractor.components.bisimulation_shared_composition import shared_summary_bounds
from .shared_summary_fixture import summary_inputs, check_shared_pair
from .test_shared_current_memory_postcondition import current_memory_intent
from .test_shared_output_termination import selected_output
from .test_bisimulation_heap_call_ranges import program
from .test_bisimulation_call_ranges import buffer_binding, check_buffer_program
from . import test_bisimulation_allocation_calls as calls

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'tests/fixtures/hand-defined-boundaries/resource-text', 'profiles/pe32-user32-resource-text-runtime-v1.json',
    'profiles/pe32-kernel32-runtime-v1.json', 'nix/jq/strong-contextual-proof.jq')}


def inputs(extent=8):
    bundle, binding, contract = summary_inputs(extent)
    binding['external_effect_contract'] = selected_output()['external_effect_contract']
    contract.update(relation_intent=current_memory_intent(), maximum_memory_events=2,
                    service_contracts=normalize_shared_service_bindings(bundle, [binding]))
    return bundle, binding, contract


class SharedCurrentMemorySummaryTests(unittest.TestCase):
    def test_independent_reader_preserves_the_result_projection_for_both_contracts(self):
        from .borrowed_state_fixture import prepare_borrowed_state
        bundle, binding, *_ = prepare_borrowed_state()
        expression = current_memory_intent()['operations'][0]['requirements'][0]['expression']
        for memory in (False, True):
            for mutation in ('none', 'wrong-projection', 'read-only'):
                interface = copy.deepcopy(bundle.intent.to_payload())
                bound = copy.deepcopy(binding.to_payload()['operations'][0])
                if mutation == 'wrong-projection':
                    bound['machine_projection']['operation']['results'][0]['projection']['extent'] = {
                        'kind':'constant', 'width':32, 'value':7}
                if mutation == 'read-only':
                    next(s for s in interface['state'] if s['value']['id'] == 'buffer')['value']['access'] = 'read'
                payload = {'interface':interface, 'binding':bound, 'expression':expression if memory else expression['args'][0]}
                p = run_jq_reader([shutil.which('jq'), '-L', 'nix/jq',
                    'include "strong-contextual-proof"; . as $input | .expression | spx_shared_result_binding($input.interface; $input.binding)'],
                    input=json.dumps(payload), capture_output=True, text=True, check=True, timeout=10)
                with self.subTest(memory=memory, mutation=mutation):
                    self.assertEqual(json.loads(p.stdout), mutation == 'none' or (mutation == 'read-only' and not memory))

    def test_summary_is_body_free_and_budgets_depend_on_contract_not_callee_growth(self):
        models = []
        for extent in (8, 1000000):
            bundle, _, contract = inputs(extent)
            render = lambda: render_connected_summary_wrapper(bundle=bundle, operation_symbols={'get':'resource_text'},
                summary_ids={'get':0}, checked_mutable_transport=True, shared_contract=contract)
            before = render()
            contract['maximum_memory_events'] = 64
            self.assertEqual(before, render())
            self.assertNotIn('spx_proof_connected_impl_', before)
            self.assertIn('zero_offset', before)
            models.append(before)
            connected = [{'summary_strategy':'image-shared-body-free-v1', 'entry_contract':{
                'proof_system':{'proof':{'models':{'source_summary_contracts':{'certificate':{
                    'shared_contract':contract, 'interface_intent':bundle.intent.to_payload()}}}}}}}]
            self.assertEqual(shared_summary_bounds(connected), (3, 1))
        self.assertEqual(models[0].count('\n'), models[1].count('\n'))
        self.assertLess(abs(len(models[0])-len(models[1])), 170)

    def test_both_body_free_invocations_export_a_current_prefix_in_both_worlds(self):
        bundle, binding, contract = inputs()
        after = '''
  uint64_t original_extent = spx_proof_borrowed_nul_extent(&spx_exact_world, 0x413d20U, 8U);
  uint64_t portable_extent = spx_proof_borrowed_nul_extent(&spx_source_world, 0x413d20U, 8U);
  __CPROVER_assert(original_extent > 0U && original_extent <= 8U && original_extent == portable_extent,
      "summary exports paired bounded current prefixes");
  __CPROVER_assert(spx_proof_exact_byte(0x413d20U + original_extent - 1U) == 0U &&
      spx_proof_source_byte(0x413d20U + portable_extent - 1U) == 0U,
      "summary prefixes end in current zeros");
'''
        with tempfile.TemporaryDirectory() as directory:
            result = check_shared_pair(Path(directory), bundle=bundle, binding=binding, contract=contract, after_calls=after)
            self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_written_witness_rechecks_alias_overwrite_and_visible_bounds(self):
        result = check_buffer_program('''
  spx_proof_exact_write(0, 0x413d23U, 1U, 0U, &fault);
  __CPROVER_assert(spx_proof_borrowed_nul_extent(&spx_exact_world, 0x413d20U, 8U) == 4U,
      "current store witnesses a prefix");
  __CPROVER_assert(spx_proof_borrowed_nul_extent(&spx_exact_world, 0x413d20U, 3U) == 3U,
      "out-of-view store cannot witness a prefix");
  spx_proof_exact_write(0, 0x413d23U, 1U, 93U, &fault);
  __CPROVER_assert(spx_proof_borrowed_nul_extent(&spx_exact_world, 0x413d20U, 8U) == 8U,
      "overwritten store returns to the adapter final-byte obligation");
''', world_options={'summary_current_zero':True})
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_historical_zero_store_never_restores_a_retired_readable_origin(self):
        body = program('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  spx_proof_exact_write(0, 4099U, 1U, 0U, &fault);
  spx_proof_source_write(0, 4099U, 1U, 0U, &fault);
  __CPROVER_assert(spx_proof_terminated_read_span(&spx_source_world, 4096U) == 4U,
      "live readable origin admits current store prefix");
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) == 0U, "paired release");
  __CPROVER_assert(spx_proof_terminated_read_span(&spx_source_world, 4096U) == 0U,
      "historical zero store cannot revive retired memory");
''', buffer_binding())
        calls.AllocationCallTests.check(self, body, unwind=7, typed_source=True, typed_exact=True,
            max_calls=3, extra_bindings=(buffer_binding(),), summary_current_zero=True)
