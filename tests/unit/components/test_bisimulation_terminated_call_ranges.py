"""Memory-dependent call footprints retain entry state and current lifetimes."""

import copy
import unittest

from spaghetti_extractor.components.bisimulation_call_ranges import checked_call_ranges
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from . import test_bisimulation_allocation_calls as calls
from .test_bisimulation_call_ranges import buffer_binding
from .test_bisimulation_heap_call_ranges import program

TESTKIT = {'capabilities': ('cbmc',), 'fixtures': ('cbmc', 'compiler'),
           'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def terminated_binding(maximum=0xffffffff):
    binding = buffer_binding()
    size = {'kind': 'bounded_terminated', 'source_argument': 3, 'source_offset': 0,
            'unit_bytes': 1, 'sentinel': [0], 'max_units': maximum}
    binding['external_effect_contract']['memory_footprints'] = [
        {'access': access, 'base_argument': argument, 'offset': 0,
         'size': dict(size), 'nullable': False}
        for access, argument in (('write', 2), ('read', 3))]
    return binding


class TerminatedCallRangeTests(unittest.TestCase):
    def check(self, body, *, failure=None, binding=None, max_calls=2):
        selected = binding or terminated_binding()
        return calls.AllocationCallTests.check(self, program(body, selected), failure=failure,
            unwind=7, typed_source=True, typed_exact=True, max_calls=max_calls,
            extra_bindings=(selected,))

    def test_overlapping_footprints_use_pre_call_memory_and_preserve_frame(self):
        self.check('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  /* The writable range overlaps the source terminator. The later read
     footprint must be resolved before arbitrary service bytes replace it. */
  BUFFER(&spx_exact_world, 4100U, 4100U);
  BUFFER(&spx_source_world, 4100U, 4100U);
  uint32_t address = spx_nondet_u32();
  if (address >= 4100U && address < 4112U)
    __CPROVER_assert(spx_proof_source_byte(address) ==
        __CPROVER_uninterpreted_spx_call_byte(1U, address), "terminated range bytes");
  if (address >= 4096U && address < 4100U)
    __CPROVER_assert(spx_proof_source_byte(address) == 0U, "terminated range frame");
''')

    def test_birth_zero_is_not_a_current_terminator(self):
        self.check('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  spx_proof_exact_write(0, 4111U, 1U, 93U, &fault);
  BUFFER(&spx_exact_world, 4096U, 4096U);
''', failure='call-terminated-current-span')

    def test_missing_origin_and_retired_origin_reject(self):
        for setup in ('', '''
  BORROW(&spx_exact_world);
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
'''):
            with self.subTest(setup=setup):
                self.check(setup + 'BUFFER(&spx_exact_world, 4096U, 4096U);',
                           failure='call-terminated-current-span', max_calls=3)

    def test_extent_cap_destination_escape_and_source_wrap_reject(self):
        for selected, destination, source, diagnostic in (
            (terminated_binding(15), 4096, 4096, 'call-terminated-current-span'),
            (terminated_binding(), 4097, 4096, 'call-buffer-authority'),
            (terminated_binding(), 4096, 0xffffffff, 'call-terminated-current-span')):
            if source == 0xffffffff:
                for row in selected['external_effect_contract']['memory_footprints']:
                    row['size']['source_offset'] = 1
            with self.subTest(destination=destination, source=source):
                self.check('BORROW(&spx_exact_world);\n' +
                           f'BUFFER(&spx_exact_world, {destination}U, {source}U);',
                           failure=diagnostic, binding=selected)

    def test_smaller_current_nul_view_is_a_valid_bound(self):
        self.check('''
  BORROW(&spx_exact_world); BORROW(&spx_source_world);
  spx_exact_world.nul_view_count = spx_source_world.nul_view_count = 1U;
  spx_exact_world.nul_view_bases[0] = spx_source_world.nul_view_bases[0] = 4096U;
  spx_exact_world.nul_view_extents[0] = spx_source_world.nul_view_extents[0] = 8U;
  BUFFER(&spx_exact_world, 4096U, 4096U);
  BUFFER(&spx_source_world, 4096U, 4096U);
''', binding=terminated_binding(8))

    def test_unsupported_terminators_fail_closed(self):
        for key, value in (('unit_bytes', 2), ('sentinel', [False]), ('sentinel', [0, 0]),
                           ('source_offset', -1), ('max_units', 0), ('source_argument', 99)):
            selected = copy.deepcopy(terminated_binding())
            selected['external_effect_contract']['memory_footprints'][0]['size'][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                checked_call_ranges(_proof_call_specs([selected])[0])


if __name__ == '__main__':
    unittest.main()
