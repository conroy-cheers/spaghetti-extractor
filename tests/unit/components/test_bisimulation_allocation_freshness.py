"""Fresh heap storage cannot replace mapped-image or live borrowed authority."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_range_ownership import ownership_fixture
from .test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def freshness_world(*, authority=True, image_size=131072):
    return _world_source(max_writes=2, max_private_writes=1, max_calls=2,
        max_atomics=1, max_shadow_bytes=1, max_nul_views=1, service_bindings=(),
        private_ranges=(), reference_authority=authority_payload() if authority else None,
        image_size=image_size)


def freshness_source(body, *, native=False, authority=True, mutant=None):
    cover = '''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
'''
    if native:
        source = ownership_fixture(cover + 'int main(void) {\n' + body + '\n__CPROVER_cover(1);\n}\n')
        if mutant == 'image':
            before, after = 'context->image_size != 0U &&', '0 &&'
        elif mutant == 'borrowed':
            # Restore the ownership filter on the entire disjunction.
            before = '''if (pointer == range->start ||
          ((uint64_t)pointer < (uint64_t)range->start + range->size &&
           (uint64_t)range->start < (uint64_t)pointer + size))'''
            after = '''if (range->ownership_family != 0U && (pointer == range->start ||
          ((uint64_t)pointer < (uint64_t)range->start + range->size &&
           (uint64_t)range->start < (uint64_t)pointer + size)))'''
    else:
        source = ('#include "state-machine-runtime.h"\n'
                  '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + cover +
                  freshness_world(authority=authority) + '''
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
''' + body + '\n__CPROVER_cover(1);\n}\n')
        if mutant == 'image':
            before = 'spx_proof_allocation_overlap(base, size, SPX_PROOF_IMAGE_BASE, UINT64_C(131072))'
            after = '0'
            # Incoming allocation admission has its own image check. This
            # counterexample removes only the allocator's freshness guard.
            start = source.index('static spx_boundary_status spx_proof_allocate(')
            end = source.index('\n}', start)
            allocator = source[start:end]
            assert allocator.count(before) == 1
            return source[:start] + allocator.replace(before, after) + source[end:]
    if mutant:
        assert source.count(before) == 1
        source = source.replace(before, after)
    return source


class AllocationFreshnessTests(unittest.TestCase):
    def check(self, body, *, native=False, authority=True, mutant=None, failure=None):
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'freshness.c'
            path.write_text(freshness_source(body, native=native, authority=authority, mutant=mutant))
            command = [cbmc, str(path), '--json-ui', '--unwind', '6', '--sat-solver', 'cadical']
            if not native and authority:
                command += reference_authority_unwind_arguments(authority_payload())
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check'], timeout_seconds=30)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertIn(failure, result['detail'])
            else:
                cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                    expected_functions=['main'], timeout_seconds=30)
                self.assertEqual(cover['status'], 'satisfied', cover)

    def test_proof_rejects_symbolic_image_allocation_before_any_borrow(self):
        body = '''
  uint32_t offset, size;
  __CPROVER_assume(offset < 131072U && size <= 32U);
  __CPROVER_assert(spx_source_origins.count == 0U, "no borrowed origins yet");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4194304U + offset, size, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "fresh heap cannot occupy mapped image");
  __CPROVER_assert(spx_source_world.allocation_count == 0U, "rejection creates no lifetime");
'''
        for authority in (True, False):
            with self.subTest(authority=authority):
                self.check(body, authority=authority)
        self.check(body, mutant='image', failure='fresh heap cannot occupy mapped image')

    def test_proof_checks_crossing_ranges_but_allows_adjacent_allocations(self):
        self.check('''
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4194296U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "allocation cannot cross image start");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4325372U, 8U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "allocation cannot cross image end");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4194296U, 8U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "allocation immediately before image");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4325376U, 8U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "allocation immediately after image");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 0U, 8U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK && spx_source_world.allocation_count == 2U,
      "nullable failure creates no lifetime");
''')

    def test_image_reference_keeps_its_borrowed_lifetime_after_rejection(self):
        self.check('''
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference;
  uint32_t address;
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4198400U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "image allocation rejected before enrollment");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U,
      "image-buffer", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "image authority still resolves");
  __CPROVER_assert(reference.generation == 17U &&
      spx_source_origins.entries[0].lifetime_generation == 1U, "image has no heap lifetime");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4198400U, 1U, 0U, 1U)
      == SPX_BOUNDARY_MEMORY_FAULT, "cannot free image as heap");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 4198404U, "image reference remains live");
''')

    def test_native_owned_allocation_cannot_occupy_image(self):
        body = '''
  uint32_t offset, size;
  __CPROVER_assume(offset < 131072U && size <= 32U);
  spx_native_context_value.image_base = 4194304U;
  spx_native_context_value.image_size = 131072U;
  __CPROVER_assert(add(77U, 4194304U + offset, size) == SPX_CALL_UNIMPLEMENTED,
      "native heap cannot occupy image");
  __CPROVER_assert(spx_native_diagnostic_reason == 0x2113U &&
      spx_native_context_value.external_range_count == 0U &&
      spx_native_context_value.external_lifecycle_sequence == 0U,
      "image freshness rejection preserves inventory and generations");
'''
        self.check(body, native=True)
        self.check(body, native=True, mutant='image', failure='native heap cannot occupy image')

    def test_native_borrowed_ranges_keep_identity_when_overlapping_heap_is_rejected(self):
        body = '''
  uint32_t address;
  __CPROVER_assert(spx_native_add_external_range(4096U, 32U, 99U, 1U, 1U, 55U)
      == SPX_CALL_OK, "existing borrowed range");
  spx_machine_reference_v1 reference = borrow(4100U);
  uint32_t generation = spx_native_context_value.external_lifecycle_sequence;
  __CPROVER_assert(add(77U, 4100U, 16U) == SPX_CALL_UNIMPLEMENTED,
      "fresh heap cannot occupy borrowed range");
  __CPROVER_assert(add(77U, 4096U, 32U) == SPX_CALL_UNIMPLEMENTED,
      "fresh heap cannot replace borrowed range");
  __CPROVER_assert(spx_native_diagnostic_reason == 0x2111U &&
      spx_native_context_value.external_range_count == 1U &&
      spx_native_context_value.external_lifecycle_sequence == generation &&
      spx_native_context_value.external_ranges[0].ownership_family == 0U,
      "borrowed ownership and generation are preserved");
  __CPROVER_assert(realize(reference, &address) == SPX_BOUNDARY_OK && address == 4100U,
      "borrowed reference remains live");
'''
        self.check(body, native=True)
        self.check(body, native=True, mutant='borrowed', failure='fresh heap cannot occupy borrowed range')

    def test_native_boundary_checks_preserve_adjacent_and_null_allocations(self):
        self.check('''
  spx_native_context_value.image_base = 4194304U;
  spx_native_context_value.image_size = 131072U;
  __CPROVER_assert(add(77U, 4194296U, 16U) == SPX_CALL_UNIMPLEMENTED, "cross image start");
  __CPROVER_assert(add(77U, 4325372U, 8U) == SPX_CALL_UNIMPLEMENTED, "cross image end");
  __CPROVER_assert(add(77U, 4194296U, 8U) == SPX_CALL_OK, "adjacent before image");
  __CPROVER_assert(add(77U, 4325376U, 0U) == SPX_CALL_OK, "zero extent at image end");
  __CPROVER_assert(add(77U, 0U, 32U) == SPX_CALL_OK &&
      spx_native_context_value.external_range_count == 2U, "nullable result is unchanged");
''', native=True)

    def test_proof_image_extent_rejects_malformed_values(self):
        for size in (0, -1, True, 4294967296, '131072'):
            with self.subTest(size=size), self.assertRaises(BisimulationRefinementError):
                freshness_world(authority=False, image_size=size)

    def test_native_freshness_helpers_compile_for_pe32_and_execute_on_host(self):
        host, pe32 = shutil.which('cc'), shutil.which('i686-w64-mingw32-gcc')
        if host is None or pe32 is None:
            self.skipTest('host and PE32 compilers unavailable')
        body = '''
  spx_native_context_value.image_base = 4194304U;
  spx_native_context_value.image_size = 131072U;
  __CPROVER_assert(add(77U, 4198400U, 16U) == SPX_CALL_UNIMPLEMENTED, "image collision");
  __CPROVER_assert(spx_native_add_external_range(4096U, 32U, 99U, 1U, 1U, 55U)
      == SPX_CALL_OK, "borrowed range");
  __CPROVER_assert(add(77U, 4100U, 16U) == SPX_CALL_UNIMPLEMENTED, "borrowed collision");
  __CPROVER_assert(add(77U, 4128U, 16U) == SPX_CALL_OK, "fresh adjacent range");
  __CPROVER_assert(release(1U, 77U, 4128U, 1U) == SPX_CALL_OK, "release owned range");
  __CPROVER_assert(add(77U, 4128U, 8U) == SPX_CALL_OK, "reuse released storage");
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            source = root / 'native.c'
            source.write_text('#define __CPROVER_assert(c,m) do { if (!(c)) __builtin_trap(); } while (0)\n'
                              + freshness_source(body, native=True))
            for command in ([host, '-std=c11', str(source), '-o', str(root / 'native')],
                            [pe32, '-std=c11', '-c', str(source), '-o', str(root / 'native.obj')],
                            [str(root / 'native')]):
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stderr)
