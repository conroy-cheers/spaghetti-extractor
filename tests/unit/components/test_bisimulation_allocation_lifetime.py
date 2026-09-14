"""Bounded allocation epochs use the actual sparse proof memory and references."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def allocation_world(body, *, mutant=None):
    source = _world_source(max_writes=8, max_private_writes=2, max_calls=3,
        max_atomics=1, max_shadow_bytes=4, max_nul_views=1, service_bindings=(),
        private_ranges=((12288, 4),), immutable_bytes=((20480, 7),))
    if mutant == 'history':
        original = 'position >= (shadow ? allocation->shadow_floor : allocation->write_floor)'
        assert original in source
        source = source.replace(original, '1')
    elif mutant == 'generation':
        original = '''!spx_proof_allocation_reference_live((spx_proof_world *)opaque,
          selected.base, selected.extent, selected.lifetime_generation, one_past)'''
        assert original in source
        source = source.replace(original, '0')
        # Old metadata membership remains present: this mutant tests the live
        # allocation-generation check, not an accidentally missing registry row.
    elif mutant == 'snapshot':
        original = 'if (index == UINT32_C(0)) return world->allocations[0];'
        assert original in source
        source = source.replace(original,
            'if (index == UINT32_C(0)) return world->allocations[1];')
    elif mutant == 'write_record':
        original = 'world->writes[0].call_range = UINT32_C(0);'
        assert original in source
        source = source.replace(original, 'world->writes[0].call_range = UINT32_C(1);')
    return '#include "state-machine-runtime.h"\n#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + source + '''
static spx_machine_reference_v1 borrow(spx_proof_world *world, uint32_t base, uint32_t size) {
  spx_machine_reference_v1 result;
  __CPROVER_assert(spx_proof_resolve_reference(world, base, size, 3U, 0, 0U, 0U, &result)
      == SPX_BOUNDARY_OK, "borrow checked live range");
  return result;
}
static void start(void) { spx_proof_reset_worlds(8388608U, 256U); }
''' + body


class ProofAllocationLifetimeTests(unittest.TestCase):
    def test_constant_index_appends_preserve_symbolic_records_and_neighbors(self):
        body = '''
int main(void) {
  spx_proof_world actual, expected;
  uint32_t address, width, value;
  uint8_t byte;
  __CPROVER_assume(actual.write_count < 8U && actual.private_write_count < 2U && actual.shadow_count < 4U);
  expected = actual;
  uint32_t position = expected.write_count++;
  expected.writes[position].address = address;
  expected.writes[position].width = width;
  expected.writes[position].value = value;
  expected.writes[position].call_range = 0U;
  position = expected.private_write_count++;
  expected.private_writes[position].address = address;
  expected.private_writes[position].width = width;
  expected.private_writes[position].value = value;
  spx_proof_append_write(&actual, address, width, value);
  spx_proof_append_private_write(&actual, address, width, value);
  spx_source_world = actual;
  position = expected.shadow_count++;
  expected.shadow[position].address = address;
  expected.shadow[position].value = byte;
  spx_proof_initialize_source_byte(address, byte);
  __CPROVER_assert(spx_source_world.write_count == expected.write_count &&
      spx_source_world.private_write_count == expected.private_write_count &&
      spx_source_world.shadow_count == expected.shadow_count, "append counters correspond");
  for (uint32_t i = 0; i < 8; ++i)
    __CPROVER_assert(spx_source_world.writes[i].address == expected.writes[i].address &&
        spx_source_world.writes[i].width == expected.writes[i].width &&
        spx_source_world.writes[i].value == expected.writes[i].value &&
        spx_source_world.writes[i].call_range == expected.writes[i].call_range,
        "public record and every neighboring slot correspond");
  for (uint32_t i = 0; i < 2; ++i)
    __CPROVER_assert(spx_source_world.private_writes[i].address == expected.private_writes[i].address &&
        spx_source_world.private_writes[i].width == expected.private_writes[i].width &&
        spx_source_world.private_writes[i].value == expected.private_writes[i].value,
        "private record and every neighboring slot correspond");
  for (uint32_t i = 0; i < 4; ++i)
    __CPROVER_assert(spx_source_world.shadow[i].address == expected.shadow[i].address &&
        spx_source_world.shadow[i].value == expected.shadow[i].value,
        "incoming byte and every neighboring slot correspond");
}
'''
        result = self.check(body, unwind=9)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check(body, unwind=9, mutant='write_record')
        self.assertEqual(result['status'], 'violated', result.get('detail'))

    def test_constant_index_appends_still_reject_capacity_exhaustion(self):
        for setup, call, expected in [
            ('write_count=8', 'spx_proof_append_write(&spx_source_world, 1, 1, 1)', 'public-write-capacity'),
            ('private_write_count=2', 'spx_proof_append_private_write(&spx_source_world, 1, 1, 1)', 'private-write-capacity'),
            ('shadow_count=4', 'spx_proof_initialize_source_byte(1, 1)', 'shadow-entry-frame'),
        ]:
            with self.subTest(expected=expected):
                result = self.check('int main(void) { start(); spx_source_world.' + setup + '; ' + call + '; }')
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn(expected, result.get('detail', ''))

    def test_snapshot_preserves_arbitrary_lifetime_queries(self):
        # The reference keeps the previous indexed load. Both queries see all
        # possible metadata, including retired/reused and overlapping records;
        # constructor premises are deliberately unnecessary for this rewrite.
        reference = '''
static uint32_t indexed_generation(const spx_proof_world *world, uint32_t address,
    uint64_t extent, uint32_t one_past, uint64_t *generation) {
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index == UINT32_MAX && extent == 0 && one_past) {
    for (uint32_t position = 3; position > 0; --position) {
      uint32_t i = position - 1;
      if (world->allocation_count > i &&
          (uint64_t)address == (uint64_t)world->allocations[i].base + world->allocations[i].size) {
        index = i; break;
      }
    }
  }
  if (index != UINT32_MAX) {
    const spx_proof_allocation *allocation = &world->allocations[index];
    if (!allocation->live || address < allocation->base ||
        (uint64_t)address - allocation->base > allocation->size ||
        extent > allocation->size - ((uint64_t)address - allocation->base)) return 0;
    *generation = allocation->generation;
    return 1;
  }
  for (uint32_t i = 0; i < 3; ++i)
    if (world->allocation_count > i && spx_proof_allocation_overlap(address, extent,
        world->allocations[i].base, world->allocations[i].size)) return 0;
  *generation = 1;
  return 1;
}
static uint32_t indexed_history(const spx_proof_world *world, uint32_t position,
    uint32_t address, uint32_t shadow) {
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index == UINT32_MAX) return 1;
  const spx_proof_allocation *allocation = &world->allocations[index];
  return allocation->live && position >= (shadow ? allocation->shadow_floor : allocation->write_floor);
}
static uint8_t indexed_byte(const spx_proof_world *world, uint32_t address) {
  uint32_t index = spx_proof_allocation_at(world, address);
  if (index == UINT32_MAX) return spx_proof_initial_byte(address);
  const spx_proof_allocation *allocation = &world->allocations[index];
  if (!allocation->live) return 0;
  if (index < world->input_allocation_count) return spx_proof_initial_byte(address);
  if (allocation->zero_initialized) return 0;
  return __CPROVER_uninterpreted_spx_allocation_byte(allocation->generation, address - allocation->base);
}
int main(void) {
  spx_proof_world world;
  uint32_t address, one_past, position, shadow;
  uint64_t extent, before;
  uint64_t left = before, right = before;
  uint32_t a = indexed_generation(&world, address, extent, one_past, &left);
  uint32_t b = spx_proof_allocation_reference_generation(&world, address, extent, one_past, &right);
  __CPROVER_assert(a == b && left == right, "snapshot preserves status and output on every path");
  __CPROVER_assert(indexed_history(&world, position, address, shadow) ==
      spx_proof_allocation_history_visible(&world, position, address, shadow), "snapshot preserves history visibility");
  __CPROVER_assert(indexed_byte(&world, address) == spx_proof_allocation_initial_byte(&world, address),
      "snapshot preserves incoming and birth bytes");
}
'''
        result = self.check(reference, unwind=4)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check(reference, unwind=4, mutant='snapshot')
        self.assertEqual(result['status'], 'violated', result.get('detail'))

    def test_snapshot_rejects_an_index_outside_retained_storage(self):
        result = self.check('''
int main(void) {
  spx_proof_world world;
  (void)spx_proof_allocation_snapshot(&world, 3U);
}
''')
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('spx-bisimulation-allocation-selection', result.get('detail', ''))

    def check(self, body, *, mutant=None, unwind=2):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'allocation.c'
            path.write_text(allocation_world(body, mutant=mutant))
            return run_cbmc_properties(command=[cbmc, str(path), '--json-ui', '--trace',
                '--unwind', str(unwind), '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check', '--sat-solver', 'cadical'],
                timeout_seconds=30)

    def test_reuse_expires_old_refs_and_preserves_an_unrelated_allocation(self):
        body = '''
int main(void) {
  start(); uint32_t address, fault;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "first allocation");
  spx_machine_reference_v1 old = borrow(&spx_source_world, 4096U, 16U);
  spx_machine_reference_v1 interior = borrow(&spx_source_world, 4100U, 4U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 8192U, 16U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "unrelated allocation");
  spx_machine_reference_v1 other = borrow(&spx_source_world, 8192U, 16U);
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "release original");
  (void)spx_proof_source_read(0, 4100U, 1U, &fault);
  __CPROVER_assert(fault != 0U, "read of freed bytes fails");
  spx_proof_source_write(0, 4100U, 1U, 7U, &fault);
  __CPROVER_assert(fault != 0U, "write of freed bytes fails");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 8U, 2U, 88U, 0U)
      == SPX_BOUNDARY_OK, "address reused by new family and owner");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &old, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_EXPIRED, "old allocation reference stays expired");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &interior, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_EXPIRED, "old interior reference stays expired");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &other, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 8192U, "unrelated reference stays live");
  spx_machine_reference_v1 fresh = borrow(&spx_source_world, 4096U, 8U);
  __CPROVER_assert(fresh.generation != old.generation, "fresh epoch");
  (void)spx_proof_source_read(0, 4103U, 2U, &fault);
  __CPROVER_assert(fault != 0U, "crossing into retired tail fails");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        mutant = self.check(body, mutant='generation')
        self.assertEqual(mutant['status'], 'violated', mutant.get('detail'))

    def test_one_past_reference_keeps_its_owner_when_an_adjacent_allocation_appears(self):
        result = self.check('''
int main(void) {
  start(); uint32_t address;
  spx_machine_reference_v1 end;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "first allocation");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, 4112U, 0U, 3U,
      0, 0U, 1U, &end) == SPX_BOUNDARY_OK, "resolve explicit one-past origin");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4112U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "adjacent allocation");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &end, 1U, 0U, 1U, &address)
      == SPX_BOUNDARY_OK && address == 4112U, "one-past belongs to original live instance");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "release original");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &end, 1U, 0U, 1U, &address)
      == SPX_BOUNDARY_EXPIRED, "adjacent live bytes cannot revive expired one-past reference");
}
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_raw_access_cannot_cross_an_allocation_boundary(self):
        result = self.check('''
int main(void) {
  start(); uint32_t fault;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "first allocation");
  (void)spx_proof_source_read(0, 4111U, 2U, &fault);
  __CPROVER_assert(fault != 0U, "read cannot escape into untracked bytes");
  spx_proof_source_write(0, 4095U, 2U, 7U, &fault);
  __CPROVER_assert(fault != 0U, "write cannot enter allocation from untracked bytes");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4112U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "adjacent allocation");
  spx_proof_source_write(0, 4111U, 2U, 7U, &fault);
  __CPROVER_assert(fault != 0U, "write cannot span adjacent live instances");
  (void)spx_proof_source_read(0, 4110U, 2U, &fault);
  __CPROVER_assert(fault == 0U, "access ending at boundary remains valid");
}
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_fresh_bytes_replace_old_writes_and_shadow_after_reuse(self):
        body = '''
int main(void) {
  start(); uint32_t fault;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "zero initialization");
  __CPROVER_assert(spx_proof_source_read(0, 4096U, 4U, &fault) == 0U && fault == 0U,
      "fresh zero bytes");
  spx_proof_source_write(0, 4096U, 1U, 17U, &fault);
  spx_proof_initialize_source_byte(4097U, 23U);
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "release populated allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "fresh uninitialized allocation");
  __CPROVER_assert(spx_proof_source_read(0, 4096U, 1U, &fault) ==
      __CPROVER_uninterpreted_spx_allocation_byte(3U, 0U) && fault == 0U,
      "previous write cannot determine fresh bytes");
  __CPROVER_assert(spx_proof_source_read(0, 4097U, 1U, &fault) ==
      __CPROVER_uninterpreted_spx_allocation_byte(3U, 1U) && fault == 0U,
      "previous shadow cannot determine fresh bytes");
  spx_proof_source_write(0, 4096U, 1U, 42U, &fault);
  __CPROVER_assert(spx_proof_source_read(0, 4096U, 1U, &fault) == 42U && fault == 0U,
      "current write is visible");
}
'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        mutant = self.check(body, mutant='history')
        self.assertEqual(mutant['status'], 'violated', mutant.get('detail'))

    def test_wrong_owner_release_failure_and_double_release(self):
        result = self.check('''
int main(void) {
  start(); uint32_t address;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "allocate input");
  spx_machine_reference_v1 live = borrow(&spx_source_world, 4096U, 16U);
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 88U, 1U)
      == SPX_BOUNDARY_TYPE_MISMATCH, "wrong owner rejected");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 2U, 77U, 1U)
      == SPX_BOUNDARY_TYPE_MISMATCH, "wrong family rejected");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4100U, 1U, 77U, 1U)
      == SPX_BOUNDARY_MEMORY_FAULT, "interior release rejected");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "failed release recorded");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &live, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK, "failure and rejection preserve live origin");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "successful release");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_EXPIRED, "double release rejected");
}
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_zero_size_capacity_and_freshness_boundaries(self):
        result = self.check('''
int main(void) {
  start(); uint32_t fault, address;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 0U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK && spx_source_world.allocation_count == 0U, "null has no instance");
  spx_machine_reference_v1 borrowed = borrow(&spx_source_world, 16384U, 16U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 16388U, 4U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "cannot allocate inside borrowed input");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 8388608U, 1U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "cannot allocate in private stack");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 12288U, 1U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "cannot allocate in static state");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 20480U, 1U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "cannot allocate over immutable input");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 0U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "zero size still has lifetime");
  (void)spx_proof_source_read(0, 4096U, 1U, &fault);
  __CPROVER_assert(fault != 0U, "zero size grants no byte access");
  spx_machine_reference_v1 empty = borrow(&spx_source_world, 4096U, 0U);
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "zero size can be released");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &empty, 1U, 0U, 1U, &address)
      == SPX_BOUNDARY_EXPIRED, "zero-size reference expires");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "reuse zero-size address");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4100U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "overlap rejected");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 8192U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "last bounded instance");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 24576U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "capacity cannot silently drop an allocation");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &borrowed, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK, "borrowed input preserved");
}
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_paired_memory_compares_live_instances_independently_of_write_width(self):
        result = self.check('''
int main(void) {
  start(); uint32_t fault;
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 4096U, 16U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "exact allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "source allocation");
  spx_proof_exact_write(0, 4096U, 2U, 0x1234U, &fault);
  spx_proof_source_write(0, 4096U, 1U, 0x34U, &fault);
  spx_proof_source_write(0, 4097U, 1U, 0x12U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "different widths preserve effective bytes");
  __CPROVER_assert(spx_proof_release_allocation(&spx_exact_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "exact release");
  __CPROVER_assert(!spx_proof_world_public_memory_equal(), "lifetime mismatch is observable");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "source release");
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 4096U, 16U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "exact reuse");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "source reuse");
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "write-history floors are not semantic identity");
}
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
