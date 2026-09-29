"""Check the actual native interface registration against its storage contract."""

import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import _function

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def interface_storage_fixture(body, *, erase_object_guard=False):
    rendered = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=()))
    registration = _function(rendered, 'spx_native_add_external_interface_ranges')
    if erase_object_guard:
        registration = registration.replace(
            'if (!spx_native_interface_storage_allowed(object, rule->minimum_size))',
            'if (0)')
    return '''
#include "state-machine-runtime.h"
#define SPX_NATIVE_MAX_INTERFACE_INSTANCES 2U
typedef struct { uint32_t object, vtable, class_index, generation; } spx_native_interface_instance;
typedef struct {
  uint32_t image_base, image_size, stack_low, stack_high;
  uint32_t external_lifecycle_sequence, interface_instance_count;
  spx_native_interface_instance interface_instances[2];
} spx_native_context;
typedef struct { uint32_t pointee_offset, nullable, minimum_size, size_value, interface_class_index; }
  spx_native_external_range_rule;
static const struct { uint32_t class_index; } spx_native_interface_classes[1] = {{1U}};
static const uint32_t spx_native_interface_class_count = 1U;
static spx_native_context spx_native_context_value;
static uint32_t output_object, output_vtable, reads, registrations;
static uint32_t spx_native_u32(uint32_t address) {
  ++reads;
  if (address == 0x1000U) return output_object;
  __CPROVER_assert(address == output_object, "registration reads only the returned object");
  return output_vtable;
}
/* Registration bookkeeping is a recorded dependency here. The test checks
   admission and ordering, not allocation origins, backing or lifetime. */
static spx_call_status spx_native_add_external_range_for_rule(
    const spx_native_external_range_rule *rule, uint32_t address, uint32_t size) {
  (void)rule; (void)address; (void)size;
  ++registrations; ++spx_native_context_value.external_lifecycle_sequence;
  return SPX_CALL_OK;
}
static void start(void) {
  spx_native_context_value = (spx_native_context){0};
  spx_native_context_value.image_base = 0x400000U;
  spx_native_context_value.image_size = 0x10000U;
  spx_native_context_value.stack_low = 0x800000U;
  spx_native_context_value.stack_high = 0x810000U;
  reads = registrations = 0U;
}
''' + _function(rendered, 'spx_native_interface_storage_allowed') + registration + body


class NativeInterfaceStorageTests(unittest.TestCase):
    def check(self, body, *, erase=False):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'interface.c'
            path.write_text(interface_storage_fixture(body, erase_object_guard=erase))
            return run_cbmc_properties(command=[shutil.which('cbmc'), str(path),
                '--json-ui', '--trace', '--stop-on-fail', '--unwind', '4', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check',
                '--undefined-shift-check', '--sat-solver', 'cadical'], timeout_seconds=30)

    def test_arbitrary_ranges_match_disjoint_complete_native_spans(self):
        result = self.check('''uint32_t nondet_u32(void);
int main(void) {
  start();
  uint32_t address = nondet_u32(), size = nondet_u32();
  uint64_t end = (uint64_t)address + size;
  uint32_t expected = address != 0U && size != 0U && end <= UINT32_MAX &&
    (end <= 0x400000U || address >= 0x410000U) &&
    (end <= 0x800000U || address >= 0x810000U);
  __CPROVER_assert(spx_native_interface_storage_allowed(address, size) == expected,
      "only whole nonwrapping external spans are admitted");
  spx_native_context_value.stack_high = spx_native_context_value.stack_low;
  __CPROVER_assert(!spx_native_interface_storage_allowed(address, size), "missing stack domain is rejected");
  start(); spx_native_context_value.image_size = 0U;
  __CPROVER_assert(!spx_native_interface_storage_allowed(address, size), "missing image domain is rejected");
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_both_domains_checked_before_registration(self):
        result = self.check('''uint32_t nondet_u32(void);
int main(void) {
  start();
  output_object = nondet_u32(); output_vtable = nondet_u32();
  __CPROVER_assume(output_object != 0x1000U);
  spx_native_external_range_rule rule = {0U, 0U, 4U, 24U, 1U};
  uint32_t admitted = spx_native_interface_storage_allowed(output_object, 4U) &&
      spx_native_interface_storage_allowed(output_vtable, 24U);
  spx_call_status result = spx_native_add_external_interface_ranges(&rule, 0x1000U);
  __CPROVER_assert((result == SPX_CALL_OK) == admitted, "registration enforces both storage domains");
  __CPROVER_assert(registrations == (admitted ? 2U : 0U), "invalid vtable cannot partially register an object");
  __CPROVER_assert(spx_native_context_value.interface_instance_count == admitted,
      "rejected storage cannot issue an interface instance");
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_nullable_result_and_adjacent_storage(self):
        result = self.check('''int main(void) {
  start();
  spx_native_external_range_rule rule = {0U, 1U, 4U, 24U, 1U};
  output_object = 0U;
  __CPROVER_assert(spx_native_add_external_interface_ranges(&rule, 0x1000U) == SPX_CALL_OK &&
      registrations == 0U && reads == 1U, "nullable zero needs no external storage");
  output_object = 0x400000U - 4U; output_vtable = 0x810000U;
  __CPROVER_assert(spx_native_add_external_interface_ranges(&rule, 0x1000U) == SPX_CALL_OK &&
      registrations == 2U, "adjacent disjoint ranges remain usable");
}''')
        self.assertEqual(result['status'], 'satisfied', result)

    def test_erased_guard_reproduces_private_stack_registration(self):
        body = '''int main(void) {
  start();
  spx_native_context_value.stack_low = 4294961668U;
  spx_native_context_value.stack_high = 4294966788U;
  output_object = 4294962831U; output_vtable = 0x500000U;
  spx_native_external_range_rule rule = {0U, 0U, 4U, 24U, 1U};
  __CPROVER_assert(spx_native_add_external_interface_ranges(&rule, 0x1000U) != SPX_CALL_OK &&
      registrations == 0U && reads == 1U, "private stack object is rejected before dereference or registration");
}'''
        result = self.check(body)
        self.assertEqual(result['status'], 'satisfied', result)
        result = self.check(body, erase=True)
        self.assertEqual(result['status'], 'violated', result)
        self.assertEqual(result['detail'], 'private stack object is rejected before dereference or registration', result)
