"""The actual Hello source must compare locations, not allocation-class IDs."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/ascii-string-compare.json",
    "targets/gnu-hello/source/components/ascii-string-compare.c",
)}
ROOT = Path(__file__).resolve().parents[3]


class AsciiCompareNativeReferenceTests(unittest.TestCase):
    def check(self, *, same_location=False, distinct_allocations=False, mutant=False, right_fault=False):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
            json.loads((ROOT / TESTKIT['resources'][0]).read_text())))
        authored = (ROOT / TESTKIT['resources'][1]).read_text()
        if mutant:
            old = '''spx_ref_difference(left->base, right->base, &base_difference) != SPX_REF_OK ||
      base_difference != INT64_C(0)'''
            assert old in authored
            authored = authored.replace(old, 'left->base.object != right->base.object')
        right = 4096 if same_location else 8192 if distinct_allocations else 4097
        body = '''
#include "portable-component-implementation.h"
''' + spx_portable_reference_runtime_v5_source() + authored + f'''
static uint32_t reads, lower_calls, events;
static uint8_t bytes[] = {{65U, 66U, 0U}};
static uint32_t read_byte(void *opaque, uint32_t index, uint8_t *result) {{
  uint32_t start = *(uint32_t *)opaque;
  ++reads;
  events = events * 10U + (start == 0U ? 1U : 3U);
  {'if (start == 1U) return 1U;' if right_fault else ''}
  if (index >= 3U - start) return 1U;
  *result = bytes[start + index]; return 0U;
}}
static uint32_t lower_ascii(void *unused, uint32_t value) {{
  (void)unused; ++lower_calls;
  events = events * 10U + 2U;
  return value >= 65U && value <= 90U ? value + 32U : value;
}}
static spx_ref_v1 logical(spx_machine_reference_v1 ref) {{
  return (spx_ref_v1){{ref.domain, ref.object, ref.generation,
      ref.offset, ref.extent, ref.permissions}};
}}
int main(void) {{
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "native allocation");
  {'__CPROVER_assert(allocate(8192U) == SPX_CALL_OK, "second native allocation");' if distinct_allocations else ''}
  spx_machine_reference_v1 left_ref = borrow(4096U), right_ref = borrow({right}U);
  uint32_t left_address, right_address;
  __CPROVER_assert(realize(left_ref, &left_address) == SPX_BOUNDARY_OK && left_address == 4096U,
      "left native reference realizes");
  __CPROVER_assert(realize(right_ref, &right_address) == SPX_BOUNDARY_OK && right_address == {right}U,
      "right native reference realizes");
  __CPROVER_assert(left_ref.object == right_ref.object, "native references share object class");
  uint32_t left_start = 0U, right_start = {0 if same_location else 1}U;
  spx_bytes_view_v2 left = {{.context=&left_start, .read_u8=read_byte,
      .base=logical(left_ref), .extent=3U, .element_width=1U}};
  spx_bytes_view_v2 right = {{.context=&right_start, .read_u8=read_byte,
      .base=logical(right_ref), .extent={3 if same_location else 2}U, .element_width=1U}};
  spx_ascii_string_compare_services_v5 services = {{.lower_ascii=lower_ascii}};
  spx_ascii_string_compare_context_v5 context = {{.services=&services}};
  int32_t result = gnu_hello_ascii_string_compare(&context, &left, &right);
  __CPROVER_assert(result == {0 if same_location or right_fault else -1}, "compare respects native reference locations");
  __CPROVER_assert(reads == {0 if same_location else 2}U && lower_calls == {0 if same_location else 1 if right_fault else 2}U,
      "only equal locations take the no-read shortcut");
  __CPROVER_assert(events == {0 if same_location else 123 if right_fault else 1232}U,
      "read and service call order preserves fault prefixes");
}}
'''
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            for name, content in render_component_c_headers_v5(bundle,
                    {'compare': 'gnu_hello_ascii_string_compare'}).items():
                (root / name).write_text(content)
            path = root / 'native-compare.c'
            path.write_text(allocation_fixture_source(body))
            return run_cbmc_properties(command=[cbmc, str(path), '--json-ui', '--trace',
                '--unwind', '6', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check', '--sat-solver', 'cadical'],
                timeout_seconds=30)

    def test_shared_allocation_slices_with_different_offsets_compare_bytes(self):
        result = self.check()
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_distinct_live_allocations_with_one_object_class_compare_bytes(self):
        result = self.check(distinct_allocations=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_same_native_location_preserves_the_shortcut(self):
        result = self.check(same_location=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_right_read_fault_retains_the_completed_left_conversion(self):
        result = self.check(right_fault=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_object_only_comparison_restores_the_native_mismatch(self):
        result = self.check(mutant=True)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('compare respects native reference locations', result['detail'])
