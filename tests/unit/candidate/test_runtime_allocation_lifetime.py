"""Small lifetime proofs execute the generated native runtime's actual bodies."""

import re
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.candidate.runtime_render_core import _native_runtime_source_core
from spaghetti_extractor.candidate.runtime_memory_access import (
    access_predicates_source, range_predicates_source, thread_environment_predicate_source,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def _function(source, name):
    match = re.search(r"(?m)^static [^\n]*\b" + name + r"\([^;{}]*\) \{", source)
    if match is None:
        raise AssertionError(f"generated function absent: {name}")
    depth = 1
    end = match.end()
    while depth and end < len(source):
        depth += (source[end] == "{") - (source[end] == "}")
        end += 1
    if depth:
        raise AssertionError(f"generated function unterminated: {name}")
    return source[match.start():end] + "\n"


def allocation_fixture_source(body, *, erase_exhaustion=False, domain=3, object_id=55, extent_mode=0, locator_offset=0,
                              identity="allocation", minimum_extent=16, native_admission=False):
    source = _native_runtime_source_core(SimpleNamespace(ingress_descriptors=()))
    if erase_exhaustion:
        source = source.replace(
            "if (context->external_lifecycle_sequence == 0xffffffffU) {",
            "if (0) {")
    functions = ["spx_native_next_external_lifecycle_sequence",
                 "spx_native_record_external_lifecycle", "spx_native_add_external_range",
                 "spx_native_release_external_range", "spx_native_object_rule_identity_equal",
                 "spx_native_dynamic_external_object_instance", "spx_native_resolve_reference",
                 "spx_native_realize_reference"]
    # Only the storage capacities and unrelated static-locator path are bounded
    # here. Allocation, release, origin resolution and realization bodies come
    # directly from the production renderer. No external API is being modeled.
    prelude = '''
#include "state-machine-runtime.h"
#define SPX_NATIVE_MAX_EXTERNAL_RANGES 4U
#define SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS 4U
typedef struct {
  uint32_t start, size, producer_rva, producer_action, generation;
  uint32_t external_range_rule_selector;
  uint64_t object_id;
  uint32_t ownership_family, ownership_owner;
} spx_native_external_range;
typedef struct {
  uint32_t sequence, operation, status, instruction_rva;
  uint32_t start, size, producer_rva, producer_action, generation;
} spx_native_external_lifecycle_event;
typedef struct {
  uint32_t image_base, image_size;
  uint32_t headers_size, section_table, section_count, stack_low, stack_high, owner_fs_base;
  spx_native_external_range external_ranges[SPX_NATIVE_MAX_EXTERNAL_RANGES];
  uint32_t external_range_count;
  spx_native_external_lifecycle_event external_lifecycle_events[SPX_NATIVE_MAX_EXTERNAL_LIFECYCLE_EVENTS];
  uint32_t external_lifecycle_count, external_lifecycle_next;
  uint32_t external_lifecycle_sequence, external_object_sequence;
} spx_native_context;
typedef struct {
  const char *identity;
  uint64_t domain, object_id, generation;
  uint32_t extent, permissions, locator_kind, locator_offset;
  uint32_t locator_subject_rva, interior_pointers, extent_mode;
} spx_native_object_authority_rule;
static const spx_native_object_authority_rule spx_native_object_authority_rules[] = {
  {"allocation", 3U, 55U, 1U, 16U, 3U, 5U, 0U, 7U, 1U, 0U}
};
static const uint32_t spx_native_object_authority_rule_count = 1U;
static spx_native_context spx_native_context_value;
static uint32_t spx_native_diagnostic_reason, spx_native_diagnostic_value;
static uint32_t spx_native_diagnostic_aux, spx_native_diagnostic_detail;
static uint32_t spx_native_range_end(uint32_t start, uint32_t width, uint32_t *end) {
  if (width == 0U || start > 0xffffffffU - width) return 0U;
  *end = start + width; return 1U;
}
static uint32_t spx_native_object_rule_base(spx_native_context *context,
    const spx_native_object_authority_rule *rule, uint32_t *base, uint64_t *generation) {
  __CPROVER_assert(0, "fixture must use dynamic allocation origins");
  return 0U;
}
'''
    prelude = prelude.replace('3U, 5U, 0U, 7U, 1U, 0U}',
                              f'3U, 5U, {locator_offset}U, 7U, 1U, {extent_mode}U}}')
    helpers = '''
static spx_call_status allocate(uint32_t address) {
  return spx_native_add_external_range(address, 16U, 100U, 1U, 7U, 55U);
}
static spx_machine_reference_v1 borrow(uint32_t address) {
  spx_machine_reference_v1 ref;
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value,
      address, 4U, 1U, 0, 0U, 0U, &ref) == SPX_BOUNDARY_OK, "borrow live allocation");
  return ref;
}
static spx_boundary_status realize(spx_machine_reference_v1 ref, uint32_t *address) {
  return spx_native_realize_reference(&spx_native_context_value, &ref, 1U, 0U, 0U, address);
}
'''
    prelude = prelude.replace('"allocation", 3U, 55U, 1U, 16U',
                              f'{json.dumps(identity)}, {domain}ULL, {object_id}ULL, 1U, {minimum_extent}U')
    helpers = helpers.replace('7U, 55U)', f'7U, {object_id}ULL)')
    admission = ''
    if native_admission:
        # This profile has no active frame/exception provider. Its absence is
        # an explicit fixture premise, not inferred from allocation origins.
        prelude = prelude.replace(_function(prelude, 'spx_native_range_end'),
                                  range_predicates_source())
        admission = '''
#define SPX_NATIVE_IMAGE_SCN_MEM_EXECUTE 0x20000000U
#define SPX_NATIVE_THREAD_ENVIRONMENT_BYTES 0x1000U
static uint32_t spx_native_u32(uint32_t address) {
  uint32_t value; memcpy(&value, (const void *)(uintptr_t)address, sizeof(value));
  return value;
}
''' + '\n'.join(f'''static uint32_t spx_native_{name}_memory_access(
    uint32_t address, uint32_t width, uint32_t write_access) {{
  (void)address; (void)width; (void)write_access; return 0U;
}}''' for name in ('physical_frame', 'captured_stack', 'unwind_service',
                  'exception_service', 'exception'))
        admission += thread_environment_predicate_source() + access_predicates_source()
    return prelude + "\n".join(_function(source, name) for name in functions) + helpers + admission + body


class AllocationLifetimeTests(unittest.TestCase):
    def _check(self, body, *, erase=False):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "allocation.c"
            source.write_text(allocation_fixture_source(body, erase_exhaustion=erase))
            return run_cbmc_properties(command=[cbmc, str(source), "--json-ui", "--trace",
                "--unwind", "6", "--unwinding-assertions", "--bounds-check", "--pointer-check",
                "--signed-overflow-check", "--sat-solver", "cadical"], timeout_seconds=30)

    def test_address_reuse_preserves_distinct_live_and_expired_origins(self):
        result = self._check('''
int main(void) {
  uint32_t address;
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "first allocation");
  spx_machine_reference_v1 old = borrow(4100U);
  __CPROVER_assert(allocate(8192U) == SPX_CALL_OK, "second live allocation");
  spx_machine_reference_v1 other = borrow(8196U);
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_OK && address == 4100U,
      "first origin stays live after second allocation");
  __CPROVER_assert(spx_native_release_external_range(4096U, 101U) == SPX_CALL_OK, "release original");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "released origin expires");
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "reuse address");
  spx_machine_reference_v1 fresh = borrow(4100U);
  __CPROVER_assert(fresh.generation != old.generation, "reused address has fresh generation");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "old reference never revives");
  __CPROVER_assert(realize(fresh, &address) == SPX_BOUNDARY_OK && address == 4100U, "fresh reference resolves");
  __CPROVER_assert(realize(other, &address) == SPX_BOUNDARY_OK && address == 8196U, "unrelated allocation remains live");
}
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_exhausted_generation_cannot_revive_a_released_reference(self):
        body = '''
int main(void) {
  uint32_t address;
  spx_native_context_value.external_lifecycle_sequence = 0xfffffffeU;
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "last fresh generation");
  spx_machine_reference_v1 old = borrow(4100U);
  __CPROVER_assert(spx_native_release_external_range(4096U, 101U) == SPX_CALL_OK, "release last generation");
  __CPROVER_assert(allocate(4096U) == SPX_CALL_UNIMPLEMENTED, "generation exhaustion rejects new allocation");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "exhaustion cannot revive stale reference");
}
'''
        result = self._check(body)
        self.assertEqual(result["status"], "satisfied", result)
        mutant = self._check(body, erase=True)
        self.assertEqual(mutant["status"], "violated", mutant)
        self.assertIn("generation exhaustion", mutant["detail"])

    def test_exhaustion_preserves_existing_origins_and_allows_cleanup(self):
        result = self._check('''
int main(void) {
  uint32_t address;
  spx_native_context_value.external_lifecycle_sequence = 0xfffffffeU;
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "last live allocation");
  spx_machine_reference_v1 old = borrow(4100U);
  __CPROVER_assert(allocate(4096U) == SPX_CALL_UNIMPLEMENTED, "replacement denied on exhaustion");
  __CPROVER_assert(allocate(8192U) == SPX_CALL_UNIMPLEMENTED, "new address denied on exhaustion");
  __CPROVER_assert(spx_native_context_value.external_range_count == 1U, "range inventory unchanged");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_OK && address == 4100U, "live reference preserved");
  __CPROVER_assert(spx_native_diagnostic_reason == 0x2103U, "stable exhaustion diagnostic");
  __CPROVER_assert(spx_native_release_external_range(4096U, 101U) == SPX_CALL_OK, "cleanup remains possible");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "cleanup expires last reference");
}
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_arbitrary_counter_state_cannot_reuse_a_live_generation(self):
        result = self._check('''
uint32_t nondet_counter(void);
int main(void) {
  uint32_t address, counter = nondet_counter();
  __CPROVER_assume(counter < 0xffffffffU);
  spx_native_context_value.external_lifecycle_sequence = counter;
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "available generation admitted");
  spx_machine_reference_v1 old = borrow(4100U);
  __CPROVER_assert(spx_native_release_external_range(4096U, 101U) == SPX_CALL_OK, "arbitrary generation released");
  spx_call_status status = allocate(4096U);
  __CPROVER_assert(status == SPX_CALL_OK || status == SPX_CALL_UNIMPLEMENTED, "allocation outcome explicit");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "all counter states preserve expiry");
}
''')
        self.assertEqual(result["status"], "satisfied", result)
