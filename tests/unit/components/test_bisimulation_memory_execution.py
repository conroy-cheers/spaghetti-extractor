"""Solver checks of crossing stores against byte-level memory semantics."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
from spaghetti_extractor.components.bisimulation_world_memory import allocation_byte_projection_assurance
from spaghetti_extractor.components.contextual_bisimulation import _balanced
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class SparseMemoryExecutionTests(unittest.TestCase):
    def projection_law(self, *, writes=2, shadows=2, allocations=2, mutation=None, summaries=False,
                       observation=False):
        from .test_bisimulation_reference_authority import authority_payload
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        options = dict(max_writes=writes, max_private_writes=2, max_calls=1,
            maximum_input_allocations=allocations-1, max_atomics=1,
            max_shadow_bytes=shadows, max_nul_views=1, service_bindings=(),
            private_ranges=((4096, 3),), summary_ranges=summaries,
            reference_authority=authority_payload(), image_size=131072,
            memory_fact_capacity=int(observation))
        original = _world_source(**options)
        assurance = allocation_byte_projection_assurance()
        projected = _world_source(**options, runtime_assurance=assurance)
        added = []
        for side in ('exact', 'source'):
            name = f'spx_proof_{side}_byte'
            start = projected.index('static uint8_t '+name+'(')
            end = _balanced(projected, projected.index('{', start), '{', '}')
            reader = projected[start:end+1].replace(name+'(', name+'_projected(', 1)
            if mutation is not None:
                before, after = {
                    'imported': (f'  if (selected < spx_{side}_world.input_allocation_count) return spx_proof_initial_byte(address);', ''),
                    'history': ('write_floor = object.write_floor;', 'write_floor = UINT32_C(0);'),
                    'shadow': ('shadow_floor = object.shadow_floor;', 'shadow_floor = UINT32_C(0);'),
                    'lifetime': ('visible = object.live;', 'visible = UINT32_C(1);'),
                    'oracle': (f'__CPROVER_uninterpreted_spx_summary_byte(spx_{side}_world.writes[0].value, address)',
                               f'__CPROVER_uninterpreted_spx_call_byte(spx_{side}_world.writes[0].value, address)'),
                    'observation': ('  const uint32_t selected =',
                                    '  spx_initial_fill_observed = 1U;\n  const uint32_t selected ='),
                }[mutation]
                self.assertEqual(reader.count(before), 1)
                reader = reader.replace(before, after)
            added.append(reader)
        checks = '''
  __CPROVER_assert(spx_proof_exact_byte(address) == spx_proof_exact_byte_projected(address), "projection:exact");
  __CPROVER_assert(spx_proof_source_byte(address) == spx_proof_source_byte_projected(address), "projection:source");
'''
        if observation:
            checks = '''
  spx_initial_fill_count = spx_nondet_u32();
  __CPROVER_assume(spx_initial_fill_count <= 1U);
  spx_initial_fill arbitrary_fill;
  spx_initial_fills[0] = arbitrary_fill;
  uint32_t observation_before = spx_nondet_u32();
  spx_initial_fill_observed = observation_before;
  uint8_t exact_expected = spx_proof_exact_byte(address);
  uint32_t exact_observation = spx_initial_fill_observed;
  spx_initial_fill_observed = observation_before;
  uint8_t exact_actual = spx_proof_exact_byte_projected(address);
  __CPROVER_assert(exact_expected == exact_actual, "projection:exact");
  __CPROVER_assert(spx_initial_fill_observed == exact_observation, "projection:exact-observation");
  spx_initial_fill_observed = observation_before;
  uint8_t source_expected = spx_proof_source_byte(address);
  uint32_t source_observation = spx_initial_fill_observed;
  spx_initial_fill_observed = observation_before;
  uint8_t source_actual = spx_proof_source_byte_projected(address);
  __CPROVER_assert(source_expected == source_actual, "projection:source");
  __CPROVER_assert(spx_initial_fill_observed == source_observation, "projection:source-observation");
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            source = root/'projection.c'
            source.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n'+original+'\n'+'\n'.join(added)+'''
int main(void) {
  spx_proof_world input;
  uint32_t address;
  spx_exact_world = input;
  spx_source_world = input;
''' + checks + '''
}
''')
            return run_cbmc_properties(command=[cbmc, str(source), '--json-ui', '--trace',
                '--unwind', '3', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check', '--sat-solver', 'cadical',
                *runtime_assurance_defines(assurance)], timeout_seconds=60)

    def test_allocation_projection_matches_arbitrary_world_records_at_different_bounds(self):
        for writes, shadows, allocations, summaries in ((1, 1, 1, False), (6, 3, 3, True)):
            with self.subTest(writes=writes, shadows=shadows, allocations=allocations):
                result = self.projection_law(writes=writes, shadows=shadows,
                                             allocations=allocations, summaries=summaries)
                self.assertEqual(result['status'], 'satisfied', result)

    def test_projection_must_preserve_imported_bytes_lifetime_and_both_history_floors(self):
        for mutation in ('imported', 'lifetime', 'history', 'shadow', 'oracle'):
            with self.subTest(mutation=mutation):
                result = self.projection_law(mutation=mutation, summaries=mutation == 'oracle')
                self.assertEqual(result['status'], 'violated', result)
                self.assertIn('projection:', result['detail'])

    def test_projection_must_preserve_initial_memory_observation_bookkeeping(self):
        result = self.projection_law(observation=True)
        self.assertEqual(result['status'], 'satisfied', result)
        result = self.projection_law(mutation='observation', observation=True)
        self.assertEqual(result['status'], 'violated', result)
        self.assertIn(result['detail'], ('projection:exact-observation', 'projection:source-observation'))

    def _check(self, body: str, *, stale_cache: bool = False) -> dict:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            world = _world_source(max_writes=4, max_private_writes=4, max_calls=1,
                max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
                service_bindings=(), private_ranges=((4096, 1), (4098, 1)),
                exact_stack_accesses=((4, 4),))
            if stale_cache:
                world = world.replace("spx_proof_exact_stack_valid_0000 = UINT32_C(0);",
                                      "spx_proof_exact_stack_valid_0000 = UINT32_C(1);")
            source = root / "memory.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + world + '''
int main(void) {
  uint32_t fault = 0;
  spx_proof_reset_worlds(8192U, 8U);
''' + body + '\n}\n')
            return run_cbmc_properties(command=[cbmc, str(source), "--json-ui", "--trace",
                "--unwind", "5", "--unwinding-assertions", "--bounds-check",
                "--pointer-check", "--signed-overflow-check", "--sat-solver", "cadical"],
                timeout_seconds=60)

    def test_arbitrary_overlapping_stores_match_last_written_byte(self) -> None:
        result = self._check('''
  uint32_t sample = spx_nondet_u32();
  uint8_t expected = spx_proof_initial_byte(sample);
  for (uint32_t i = 0; i < 3U; ++i) {
    uint32_t address = spx_nondet_u32(), width = spx_nondet_u32();
    uint32_t value = spx_nondet_u32();
    __CPROVER_assume(width >= 1U && width <= 4U);
    __CPROVER_assume(address <= UINT32_MAX - width + 1U);
    if (sample >= address && sample - address < width)
      expected = (uint8_t)(value >> (8U * (sample - address)));
    spx_proof_exact_write(0, address, width, value, &fault);
    __CPROVER_assert(fault == 0U, "valid-store");
    spx_proof_source_write(0, address, width, value, &fault);
    __CPROVER_assert(fault == 0U, "valid-source-store");
    __CPROVER_assert(spx_proof_exact_byte(sample) == expected, "exact-last-byte");
    __CPROVER_assert(spx_proof_source_byte(sample) == expected, "source-last-byte");
  }
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_private_islands_and_stack_cache_partial_aliases(self) -> None:
        body = '''
  spx_proof_exact_write(0, 4095U, 4U, 0x44332211U, &fault);
  spx_proof_exact_write(0, 4096U, 1U, 0xaaU, &fault);
  spx_proof_exact_write(0, 4097U, 1U, 0xbbU, &fault);
  __CPROVER_assert(spx_proof_exact_read(0, 4095U, 4U, &fault) == 0x44bbaa11U,
      "private-island-word");
  __CPROVER_assert(spx_proof_exact_read(0, 4096U, 3U, &fault) == 0x44bbaaU,
      "private-endpoints-public-interior");
  __CPROVER_assert(!spx_proof_typed_service_public_range(4095U, 3U), "interior-private-byte");
  spx_proof_reset_worlds(8192U, 8U);
  spx_proof_exact_write(0, 8196U, 4U, 0x44332211U, &fault);
  spx_proof_exact_write(0, 8199U, 2U, 0xbbaaU, &fault);
  __CPROVER_assert(spx_proof_exact_read(0, 8196U, 4U, &fault) == 0xaa332211U,
      "partial-cache-alias");
  __CPROVER_assert(spx_proof_exact_byte(8200U) == 0xbbU, "crossing-public-byte");
  spx_proof_exact_write(0, 8196U, 4U, 0x88776655U, &fault);
  __CPROVER_assert(spx_proof_exact_read(0, 8196U, 4U, &fault) == 0x88776655U,
      "full-cache-replacement");
  uint32_t count = spx_exact_world.write_count;
  spx_proof_exact_write(0, UINT32_MAX, 2U, 0U, &fault);
  __CPROVER_assert(fault == 1U && spx_exact_world.write_count == count,
      "overflow-store-fault");
'''
        result = self._check(body)
        self.assertEqual(result["status"], "satisfied", result)
        stale = self._check(body, stale_cache=True)
        self.assertEqual(stale["status"], "violated", stale)
        self.assertEqual(stale["detail"], "partial-cache-alias", stale)
