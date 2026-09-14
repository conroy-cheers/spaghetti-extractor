"""Compose real allocator contracts with buffer effects through checked origins."""

import unittest

from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from . import test_bisimulation_allocation_calls as calls
from .test_bisimulation_call_ranges import buffer_binding

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler'),
           'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def program(body, binding=None):
    spec = _proof_call_specs([binding or buffer_binding()])[0]['spec_id']
    return f'''
#define BORROW(world) do {{ \
  spx_runtime runtime = spx_proof_runtime(world); \
  spx_machine_reference_v1 reference; \
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4096U, 1U, 3U, \
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "checked heap origin"); \
}} while (0)
#define BUFFER(world, base, size) do {{ \
  spx_proof_typed_service_begin(world, {spec}U); \
  spx_proof_typed_service_argument(0U, 7U); \
  spx_proof_typed_service_argument(1U, 42U); \
  spx_proof_typed_service_argument(2U, base); \
  spx_proof_typed_service_argument(3U, size); \
  (void)spx_proof_typed_service_result(); \
  spx_proof_typed_service_finish(); \
}} while (0)
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 4096U, "paired allocation");
''' + body


class HeapCallRangeTests(unittest.TestCase):
    def check(self, body, *, failure=None, max_calls=3):
        return calls.AllocationCallTests.check(self, program(body), failure=failure,
            unwind=7, typed_source=True, typed_exact=True, max_calls=max_calls,
            extra_bindings=(buffer_binding(),))

    def test_heap_service_preserves_aliases_frame_and_write_order(self):
        self.check('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  BUFFER(&spx_exact_world, 4099U, 5U);
  spx_proof_exact_write(0, 4101U, 1U, 93U, &fault);
  BUFFER(&spx_source_world, 4099U, 5U);
  spx_proof_source_write(0, 4101U, 1U, 93U, &fault);
  uint32_t address = spx_nondet_u32();
  if (address >= 4099U && address < 4104U && address != 4101U)
    __CPROVER_assert(spx_proof_source_byte(address) ==
        __CPROVER_uninterpreted_spx_call_byte(1U, address), "heap service bytes through alias");
  __CPROVER_assert(spx_proof_source_byte(4101U) == 93U, "later alias write wins");
  if (address >= 4096U && address < 4112U && (address < 4099U || address >= 4104U))
    __CPROVER_assert(spx_proof_source_byte(address) == 0U, "untouched allocation frame");
''', max_calls=2)

    def test_allocation_address_without_checked_origin_is_rejected(self):
        self.check('BUFFER(&spx_exact_world, 4096U, 16U);', failure='call-buffer-authority')

    def test_released_and_reused_addresses_require_fresh_origins(self):
        self.check('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) == 0U, "paired release");
  __CPROVER_assert(!spx_proof_call_range_admitted(&spx_exact_world, 4096U, 1U, 2U),
      "released buffer is unavailable");
  __CPROVER_assume(invoke(1U, 1U, 64U, 8U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 8U) == 4096U, "paired smaller reuse");
  __CPROVER_assert(!spx_proof_call_range_admitted(&spx_source_world, 4096U, 1U, 2U),
      "old origin cannot revive on address reuse");
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  __CPROVER_assert(spx_proof_call_range_admitted(&spx_source_world, 4096U, 8U, 2U),
      "new origin admits the current allocation");
  __CPROVER_assert(!spx_proof_call_range_admitted(&spx_source_world, 4096U, 9U, 2U),
      "new origin cannot expose retired tail bytes");
''')

    def test_heap_extent_and_changed_input_fail_before_replay(self):
        for body, diagnostic in (
            ('BUFFER(&spx_exact_world, 4110U, 3U);', 'call-buffer-authority'),
            ('''BUFFER(&spx_exact_world, 4096U, 16U);
                spx_proof_source_write(0, 4096U, 1U, 93U, &fault);
                BUFFER(&spx_source_world, 4096U, 16U);''', 'lifetime-typed-arguments')):
            with self.subTest(body=body):
                self.check('BORROW(&spx_exact_world); BORROW(&spx_source_world);\n' + body,
                           failure=diagnostic)

    def test_origin_permissions_identity_and_private_frame_are_checked(self):
        self.check('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  spx_proof_origins *origins = spx_proof_origins_for(&spx_source_world);
  __CPROVER_assert(origins->count == 1U, "one borrowed allocation origin");
  spx_proof_origin saved = origins->entries[0];
  origins->entries[0].permissions = 1U;
  __CPROVER_assert(!spx_proof_call_range_admitted(&spx_source_world, 4096U, 16U, 2U),
      "read-only origin does not authorize a write");
  origins->entries[0] = saved; origins->entries[0].domain++;
  __CPROVER_assert(!spx_proof_call_range_admitted(&spx_source_world, 4096U, 16U, 2U),
      "unselected object class does not authorize a write");
  origins->entries[0] = saved;
  uint32_t low = spx_source_world.private_low, high = spx_source_world.private_high;
  spx_source_world.private_low = 4098U; spx_source_world.private_high = 4104U;
  __CPROVER_assert(!spx_proof_call_range_admitted(&spx_source_world, 4096U, 16U, 2U),
      "checked heap origin does not override the private frame");
  spx_source_world.private_low = low; spx_source_world.private_high = high;
''', max_calls=1)


if __name__ == '__main__':
    unittest.main()
