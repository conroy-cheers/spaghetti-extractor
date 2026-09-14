"""Checked allocating calls expose live objects through the ordinary runtime API."""

import unittest

from . import test_bisimulation_allocation_calls as calls
from .test_bisimulation_allocation_namespace import inputs

TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


class LocalAllocationReferenceTests(unittest.TestCase):
    def check(self, body, *, native=False, **options):
        _, requirements = inputs()
        return calls.AllocationCallTests.check(self, body, unwind=7, typed_source=True,
            local_requirements=None if native else requirements, **options)

    def test_runtime_reference_supports_write_and_release(self):
        body = '''
  uint32_t pointer = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(pointer == 4096U);
  spx_proof_exact_write(0, pointer + 3U, 1U, 7U, &fault);
  __CPROVER_assume(invoke(1U, 0U, pointer, 0U) == 0U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == pointer, "paired allocation");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {0};
  uint32_t address = 0U;
  __CPROVER_assert(runtime.resolve_reference(runtime.context, pointer + 3U, 1U, 3U,
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "ordinary runtime resolves a locally born object");
  __CPROVER_assert(reference.domain == 3U && reference.object == 55U && reference.offset == 3U &&
      reference.extent == 16U && reference.permissions == 3U, "complete native tuple");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 3U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == pointer + 3U, "ordinary runtime realizes the source reference");
  spx_proof_source_write(0, address, 1U, 7U, &fault);
  __CPROVER_assert(!fault, "write through realized source reference");
  __CPROVER_assert(invoke(0U, 0U, pointer, 0U) == 0U, "paired successful release");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_EXPIRED, "ordinary runtime rejects released reference");
'''
        for native in (False, True):
            with self.subTest(native=native):
                self.check(body, native=native, max_calls=2)
        self.check(body.replace('spx_proof_source_write(0, address, 1U, 7U,',
                               'spx_proof_source_write(0, address, 1U, 8U,'),
                   failure='lifetime-typed-arguments', max_calls=2)

    def test_birth_retains_native_metadata_and_one_past_checks(self):
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  uint32_t pointer = invoke(0U, 1U, 64U, 16U), address = 0U;
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {0}, changed;
  __CPROVER_assert(runtime.resolve_reference(runtime.context, pointer + 3U, 1U, 3U,
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "resolve locally born object");
  changed = reference; changed.extent++;
  __CPROVER_assert(runtime.realize_reference(runtime.context, &changed, 1U, 0U, 0U, &address)
      != SPX_BOUNDARY_OK, "birth does not authorize forged extent");
  changed = reference; changed.permissions = 7U;
  __CPROVER_assert(runtime.realize_reference(runtime.context, &changed, 1U, 0U, 0U, &address)
      != SPX_BOUNDARY_OK, "birth does not authorize forged permissions");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, pointer + 16U, 0U, 1U,
      0, 0U, 1U, &changed) == SPX_BOUNDARY_OK, "unnamed one-past resolution");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &changed, 1U, 0U, 1U, &address)
      == SPX_BOUNDARY_OK && address == pointer + 16U, "one-past realization");
''', max_calls=1)

    def test_smaller_reuse_does_not_revive_a_retired_reference(self):
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assume(invoke(1U, 1U, 64U, 8U) == 4096U);
  uint32_t pointer = invoke(0U, 1U, 64U, 16U), address = 0U;
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {0}, renewed = {0};
  __CPROVER_assert(runtime.resolve_reference(runtime.context, pointer + 3U, 1U, 1U,
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "resolve first lifetime");
  __CPROVER_assert(invoke(0U, 0U, pointer, 0U) == 0U, "paired successful release");
  __CPROVER_assert(invoke(0U, 1U, 64U, 8U) == pointer, "paired smaller reuse");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_EXPIRED, "old reference cannot revive on address reuse");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, pointer + 3U, 1U, 1U,
      "text", 0U, 0U, &renewed) == SPX_BOUNDARY_OK, "resolve reused storage");
  __CPROVER_assert(renewed.generation != reference.generation && renewed.extent == 8U,
      "new object generation and extent");
  __CPROVER_assert(spx_proof_source_read(0, pointer + 3U, 1U, &fault) == 0U && !fault,
      "new storage does not inherit retired writes");
''')

    def test_failed_release_and_null_response_keep_their_runtime_meaning(self):
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 0U);
  uint32_t pointer = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(pointer == 4096U);
  __CPROVER_assume(invoke(1U, 0U, pointer, 0U) != 0U);
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {0};
  uint32_t address = 0U;
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 0U, "paired null response");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 0U, 1U, 1U,
      "text", 1U, 0U, &reference) == SPX_BOUNDARY_OK && reference.object == 0U,
      "null response creates no reference origin");
  __CPROVER_assert(spx_source_world.allocation_count == 0U, "null response creates no instance");
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == pointer, "paired live response");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, pointer, 1U, 1U,
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "resolve live result");
  __CPROVER_assert(invoke(0U, 0U, pointer, 0U) != 0U, "paired failed release");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == pointer, "failed release preserves live reference");
''', typed_exact=True)

    def test_checked_class_does_not_admit_a_manually_seeded_instance(self):
        self.check('''
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "seed incoming diagnostic allocation");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 16U, 1U, 0U,
      1U, 55U, 17U) == SPX_BOUNDARY_OK, "seed matching class and generation");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {0};
  runtime.resolve_reference(runtime.context, 4096U, 1U, 1U, "text", 0U, 0U, &reference);
''', failure='spx-bisimulation-reference-locator-qualified')

    def test_wrong_class_or_missing_birth_cannot_supply_origin(self):
        for birth in (0, 2):
            with self.subTest(birth=birth):
                self.check(f'''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 4096U, "paired allocation");
  spx_source_world.allocations[0].birth_class_selector = {birth}U;
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {{0}};
  runtime.resolve_reference(runtime.context, 4096U, 1U, 1U, "text", 0U, 0U, &reference);
''', failure='spx-bisimulation-reference-locator-qualified')

    def test_call_prestate_checks_birth_correspondence(self):
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  invoke(0U, 1U, 64U, 16U);
  spx_source_world.allocations[0].birth_class_selector = 0U;
  invoke(0U, 0U, 4096U, 0U);
  __CPROVER_assume(0);
''', failure='lifetime-typed-arguments')
