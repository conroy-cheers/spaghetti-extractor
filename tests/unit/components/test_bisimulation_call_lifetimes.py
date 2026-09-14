"""Call replay observes allocation lifetimes at the call, before later release."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class CallLifetimeTests(unittest.TestCase):
    def check(self, *, typed_source=False, typed_exact=False, early_release=False,
              late_birth=False, two_calls=False, mutant=False, different_widths=False):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        binding = {'service_id': 'observe', 'provider_kind': 'external_call',
            'external_effect_contract': {'memory_effect': 'none', 'world_effect': 'none'},
            "external_contract_identity_sha256": "b" * 64,
            'abi_template': 'pe32-cdecl-v1', 'argument_offsets': [0],
            'events': [{'instruction_rva': 100, 'event_index': 0, 'return_rva': 105}]}
        spec = _proof_call_specs([binding])[0]['spec_id']
        world = _world_source(max_writes=4, max_private_writes=1, max_calls=2,
            max_atomics=1, max_shadow_bytes=2, max_nul_views=1,
            service_bindings=[binding], private_ranges=(), typed_exact_recording=typed_exact)
        if mutant:
            original = 'if (!spx_proof_replay_call_allocations(call)) return UINT32_C(0);'
            assert original in world
            world = world.replace(original, '')
        def call(exact, typed):
            side = 'exact' if exact else 'source'
            if typed:
                return (f'spx_proof_typed_service_begin(&spx_{side}_world, {spec}U);\n'
                        'spx_proof_typed_service_argument(0U, 4096U);\n'
                        'spx_proof_typed_service_finish();')
            return f'spx_proof_{side}_external_call(0, &event, &input, &output);'
        def allocate(side):
            return (f'__CPROVER_assert(spx_proof_allocate(&spx_{side}_world, 4096U, 16U, 1U, 0U, 1U)'
                    f' == SPX_BOUNDARY_OK, "{side} allocation");')
        def release(side):
            return (f'__CPROVER_assert(spx_proof_release_allocation(&spx_{side}_world, 4096U, 1U, 0U, 1U)'
                    f' == SPX_BOUNDARY_OK, "{side} release");')
        exact_call, source_call = call(True, typed_exact), call(False, typed_source)
        # Both final worlds have the same zero bytes and the same retired
        # allocation. Only the lifetime at the call can expose early release.
        body = f'''
int main(void) {{
  uint32_t fault;
  spx_machine_state input = {{0}}, output = {{0}};
  spx_call_event event = {{.kind=SPX_CALL_EXTERNAL_IMPORT, .instruction_rva=100U,
      .call_index=0U, .return_rva=105U}};
  spx_proof_reset_worlds(8388608U, 256U);
  input.esp = 8388608U;
  spx_proof_exact_write(0, input.esp, 4U, 4096U, &fault);
  spx_proof_source_write(0, input.esp, 4U, 4096U, &fault);
  {allocate('exact')}
  {'spx_proof_exact_write(0, 4096U, 2U, 0U, &fault);' if different_widths else ''}
  {exact_call}
  {release('exact')}
  {exact_call if two_calls else ''}
  {'' if late_birth else allocate('source')}
  {'spx_proof_source_write(0, 4096U, 1U, 0U, &fault); spx_proof_source_write(0, 4097U, 1U, 0U, &fault);' if different_widths else ''}
  {release('source') if early_release else ''}
  {source_call}
  {allocate('source') if late_birth else ''}
  {'' if early_release else release('source')}
  {source_call if two_calls else ''}
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "same final bytes and lifetimes");
}}
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'call-lifetimes.c'
            path.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + world + body)
            return run_cbmc_properties(command=[cbmc, str(path), '--json-ui', '--trace',
                '--unwind', '3', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check', '--sat-solver', 'cadical'],
                timeout_seconds=30)

    def test_early_release_cannot_be_hidden_by_equal_bytes_and_later_exact_release(self):
        for typed_source, typed_exact in ((False, False), (True, False), (True, True)):
            with self.subTest(typed_source=typed_source, typed_exact=typed_exact):
                result = self.check(typed_source=typed_source, typed_exact=typed_exact, early_release=True)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn('call-public-memory', result['detail'])

    def test_replay_uses_the_retained_live_state_not_the_final_exact_state(self):
        for typed_source, typed_exact in ((False, False), (True, False), (True, True)):
            with self.subTest(typed_source=typed_source, typed_exact=typed_exact):
                result = self.check(typed_source=typed_source, typed_exact=typed_exact)
                self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_a_late_birth_cannot_repair_a_missing_call_time_instance(self):
        result = self.check(typed_source=True, late_birth=True)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('call-public-memory', result['detail'])

    def test_each_call_retains_its_own_lifetime_snapshot(self):
        result = self.check(typed_source=True, typed_exact=True, two_calls=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_write_width_does_not_become_allocation_identity(self):
        result = self.check(typed_source=True, different_widths=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_removing_lifetime_snapshot_check_reproduces_false_acceptance(self):
        result = self.check(early_release=True, mutant=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
