"""Replay real-shaped service buffers through the existing connected interval.

These world checks do not admit a shared-state body-free supplier. They verify
the effect transport needed by that rule before its shape rejection can change.
"""

import unittest

from spaghetti_extractor.components.bisimulation_connected import _connected_replay_source
from spaghetti_extractor.components.bisimulation_call_ranges import call_range_write_capacity
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from . import test_bisimulation_call_ranges as fixture

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "tests/fixtures/hand-defined-boundaries/resource-text",)}


class ConnectedRangeTests(unittest.TestCase):
    def check(self, *, before="", before_replay="", after="", world_options=None):
        replay = "\n".join(_connected_replay_source(
            [{"summary_id": 0, "summary_capacity": 1}],
            max_writes=6, max_calls=2, max_atomics=1,
            call_range_writes_per_call=call_range_write_capacity(_proof_call_specs([fixture.buffer_binding()]))))
        return fixture.check_buffer_program('''
  spx_proof_reset_connected_summaries();
  spx_runtime exact_runtime = spx_proof_runtime(&spx_exact_world);
  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);
  spx_proof_connected_service_prefix exact_service = {&exact_runtime};
  spx_proof_connected_service_prefix source_service = {&source_runtime};
''' + before + '''
  uint32_t position = spx_proof_connected_0000_begin(&exact_service);
  original(0x413d20U, 500U);
  spx_proof_exact_write(0, 0x413d21U, 1U, 93U, &fault);
  original(0x413d22U, 498U);
  spx_proof_connected_0000_finish(position);
''' + before_replay + '''
  position = spx_proof_connected_0000_begin(&source_service);
  spx_proof_connected_0000_replay(position);
  __CPROVER_assert(spx_proof_connected_summaries_equal(), "paired summary count");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "range summary post-memory");
  __CPROVER_assert(spx_proof_source_byte(0x413d21U) == 93U, "intervening store preserved");
  if (address >= 0x413d22U && address < 0x413f14U)
    __CPROVER_assert(spx_proof_source_byte(address) ==
      __CPROVER_uninterpreted_spx_call_byte(1U, address), "old alias sees current range");
  if (address < 0x413d20U || address >= 0x413f14U)
    __CPROVER_assert(spx_proof_source_byte(address) == spx_proof_exact_byte(address), "outside frame preserved");
  __CPROVER_assert(spx_source_world.call_count == 2U &&
    spx_source_world.calls[0].arguments[2] == 0x413d20U &&
    spx_source_world.calls[1].arguments[2] == 0x413d22U, "service order preserved");
''' + after, extra_source=replay, world_options=world_options)

    def test_range_replay_preserves_current_aliases_and_intervening_stores(self):
        result = self.check()
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_overwrite_does_not_hide_mismatched_summary_input(self):
        result = self.check(before='''
  spx_proof_exact_write(0, 0x413d20U, 1U, 17U, &fault);
  spx_proof_source_write(0, 0x413d20U, 1U, 23U, &fault);
''')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertEqual(result['detail'], 'spx-bisimulation-connected-summary-memory:0')

    def test_range_budget_replays_events_beyond_the_instruction_store_bound(self):
        result = self.check(before='\n'.join(
            f'spx_proof_{side}_write(0, 0x413d30U+{i}U, 1U, {i}U, &fault);'
            for i in range(5) for side in ('exact', 'source')))
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_replay_rejects_private_range_and_foreign_call_position(self):
        for change in (
            'spx_source_world.private_low = 0x413d20U; spx_source_world.private_high = 0x413f14U;',
            'spx_exact_world.writes[0].value = 2U;',
        ):
            with self.subTest(change=change):
                result = self.check(before_replay=change)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertEqual(result['detail'], 'spx-bisimulation-connected-summary-range-replay-authority')

    def test_replay_does_not_invent_a_terminated_string(self):
        result = self.check(after='''
  __CPROVER_assume(spx_source_world.calls[1].response_eax == 0U);
  __CPROVER_assert(spx_proof_source_byte(0x413f13U) == 0U, "invented summary terminator");
''')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertEqual(result['detail'], 'invented summary terminator')
