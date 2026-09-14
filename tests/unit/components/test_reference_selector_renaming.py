"""Native selector numbering can change only with a consistent class relation."""

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.reference_namespace import reference_namespace_source
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {'fixtures': ('cbmc', 'compiler')}


def namespace(prefix):
    return f'''
typedef selector_rule {prefix}_object_authority_rule;
typedef selector_range {prefix}_external_range;
typedef selector_context {prefix}_context;
static selector_rule {prefix}_object_authority_rules[2];
static const uint32_t {prefix}_object_authority_rule_count = 2U;
static uint32_t {prefix}_range_end(uint32_t start, uint32_t width, uint32_t *end) {{
  if (width == 0U || start > UINT32_MAX - width) return 0U;
  *end = start + width; return 1U;
}}
static uint32_t {prefix}_object_rule_base(const selector_context *context,
    const selector_rule *rule, uint32_t *base, uint64_t *generation) {{
  (void)context; (void)rule; (void)base; (void)generation;
  return 0U;
}}
''' + reference_namespace_source(prefix)


def fixture(mode, *, mutant=False):
    declarations = '''
#include "state-machine-runtime.h"
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
typedef struct {
  const char *identity;
  uint64_t domain, object_id, generation;
  uint32_t extent, permissions, locator_kind, locator_offset;
  uint32_t locator_subject_rva, interior_pointers, extent_mode;
} selector_rule;
typedef struct {
  uint32_t start, size, generation, external_range_rule_selector;
  uint64_t object_id;
} selector_range;
typedef struct { uint32_t external_range_count; selector_range external_ranges[2]; } selector_context;
static uint32_t word(void) { uint32_t value; return value; }
static uint64_t wide(void) { uint64_t value; return value; }
static selector_rule arbitrary_rule(void) {
  return (selector_rule){"a", wide(), wide(), wide(), word(), word(), word(), word(), word(), word(), word()};
}
static selector_range arbitrary_range(void) {
  return (selector_range){word(), word(), word(), word(), wide()};
}
static uint32_t same_reference(spx_machine_reference_v1 left, spx_machine_reference_v1 right) {
  return left.domain == right.domain && left.object == right.object && left.generation == right.generation &&
      left.offset == right.offset && left.extent == right.extent && left.permissions == right.permissions;
}
static void witness_success(uint32_t condition) { __CPROVER_cover(condition); }
static void witness_failure(uint32_t condition) { __CPROVER_cover(condition); }
static void witness_memory(uint32_t condition) { __CPROVER_cover(condition); }
static void witness_ambiguity(uint32_t condition) { __CPROVER_cover(condition); }
'''
    if mode == 'pair':
        body = '''
  selector_rule native_rule = arbitrary_rule(), model_rule = native_rule;
  selector_range native_range = arbitrary_range(), model_range = native_range;
  model_rule.locator_subject_rva = word();
  model_range.external_range_rule_selector = word();
  __CPROVER_assume(native_rule.locator_subject_rva != 0U && model_rule.locator_subject_rva != 0U);
  __CPROVER_assume((native_rule.locator_subject_rva == native_range.external_range_rule_selector) ==
      (model_rule.locator_subject_rva == model_range.external_range_rule_selector));
  MUTATION
  uint32_t native_base = 0U, model_base = 0U, native_extent = 0U, model_extent = 0U;
  uint64_t native_generation = 0U, model_generation = 0U;
  uint32_t native_result = actual_dynamic_external_object_instance(&native_rule, &native_range,
      &native_base, &native_generation, &native_extent);
  uint32_t model_result = logical_dynamic_external_object_instance(&model_rule, &model_range,
      &model_base, &model_generation, &model_extent);
  __CPROVER_assert(native_result == model_result, "class matching survives consistent selector renaming");
  __CPROVER_assert(!native_result || (native_base == model_base && native_extent == model_extent &&
      native_generation == model_generation), "instance fields survive selector renaming");
  witness_success(native_result && native_rule.locator_subject_rva != model_rule.locator_subject_rva);
  witness_failure(!native_result);
'''.replace('MUTATION', 'model_range.external_range_rule_selector = model_rule.locator_subject_rva;' if mutant else '')
    else:
        body = '''
  uint32_t selectors[2] = {word(), word()};
  __CPROVER_assume(selectors[0] != 0U && selectors[1] != 0U && selectors[0] != selectors[1]);
  selector_context native = {0}, model = {0};
  native.external_range_count = word();
  __CPROVER_assume(native.external_range_count <= 2U);
  model.external_range_count = native.external_range_count;
  for (uint32_t index = 0U; index < 2U; ++index) {
    selector_rule rule = arbitrary_rule();
    rule.identity = index ? "b" : "a";
    rule.domain = 3U + index;
    /* Object IDs need not be globally unique across domains. */
    rule.object_id = 55U;
    rule.locator_kind = 5U;
    rule.extent_mode &= 1U;
    rule.interior_pointers &= 1U;
    rule.permissions &= 7U;
    rule.locator_subject_rva = selectors[index];
    actual_object_authority_rules[index] = rule;
    rule.locator_subject_rva = MUTABLE_SELECTOR;
    logical_object_authority_rules[index] = rule;
    uint32_t owner = word() & 1U;
    selector_range range = arbitrary_range();
    range.object_id = 55U;
    range.external_range_rule_selector = selectors[owner];
    native.external_ranges[index] = range;
    range.external_range_rule_selector = MUTABLE_RANGE_SELECTOR;
    model.external_ranges[native.external_range_count == 2U ? 1U - index : index] = range;
  }
  uint32_t permissions = word() & 7U, nullable = word() & 1U, one_past = word() & 1U;
'''.replace('MUTABLE_RANGE_SELECTOR', '1U' if mutant else 'owner + 1U').replace(
            'MUTABLE_SELECTOR', '1U' if mutant else 'index + 1U')
        if mode == 'resolve':
            body += '''
  uint32_t address = word(), extent = word(), name = word() & 3U;
#ifdef SPX_SELECTOR_CASE
  name = SPX_SELECTOR_CASE;
#endif
  const char *selector = name == 0U ? 0 : name == 1U ? "a" : name == 2U ? "b" : "unknown";
  spx_machine_reference_v1 native_reference = {0}, model_reference = {0};
  spx_boundary_status a = actual_resolve_reference(&native, address, extent, permissions,
      selector, nullable, one_past, &native_reference);
  spx_boundary_status b = logical_resolve_reference(&model, address, extent, permissions,
      selector, nullable, one_past, &model_reference);
  __CPROVER_assert(a == b, "resolution status survives renaming and instance permutation");
  __CPROVER_assert(a != SPX_BOUNDARY_OK || same_reference(native_reference, model_reference),
      "full public reference survives renaming and instance permutation");
  witness_success(a == SPX_BOUNDARY_OK && address != 0U && selectors[0] != 1U);
  witness_failure(a == SPX_BOUNDARY_TYPE_MISMATCH);
  witness_memory(a == SPX_BOUNDARY_MEMORY_FAULT);
  witness_ambiguity(a == SPX_BOUNDARY_TYPE_MISMATCH && name != 3U && address != 0U);
'''
        elif mode == 'realize':
            body += '''
  spx_machine_reference_v1 reference = {wide(), wide(), wide(), wide(), wide(), word()};
  uint32_t native_address = 0U, model_address = 0U;
  spx_boundary_status a = actual_realize_reference(&native, &reference, permissions, nullable, one_past, &native_address);
  spx_boundary_status b = logical_realize_reference(&model, &reference, permissions, nullable, one_past, &model_address);
  __CPROVER_assert(a == b, "realization status survives renaming and instance permutation");
  __CPROVER_assert(a != SPX_BOUNDARY_OK || native_address == model_address,
      "realized address survives renaming and instance permutation");
  witness_success(a == SPX_BOUNDARY_OK && native_address != 0U && selectors[0] != 1U);
  witness_failure(a == SPX_BOUNDARY_EXPIRED);
  witness_memory(a == SPX_BOUNDARY_MEMORY_FAULT);
'''
        else:
            raise ValueError(mode)
    return declarations + namespace('actual') + namespace('logical') + '\nint main(void) {\n' + body + '\n}\n'


class ReferenceSelectorRenamingTests(unittest.TestCase):
    def check(self, mode, *, mutant=False):
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'renaming.c'
            path.write_text(fixture(mode, mutant=mutant))
            command = [cbmc, str(path), '--json-ui', '--unwind', '3', '--sat-solver', 'cadical']
            # Exhaust the four selector cases separately. All other inputs and
            # safety assertions remain unrestricted; coverage uses the full model.
            partitions = range(4) if mode == 'resolve' and not mutant else (None,)
            for selector_case in partitions:
                options = [] if selector_case is None else [f'-DSPX_SELECTOR_CASE={selector_case}']
                result = run_cbmc_properties(command=[*command, *options, '--trace', '--unwinding-assertions', '--bounds-check',
                    '--pointer-check', '--signed-overflow-check', '--undefined-shift-check'], timeout_seconds=30)
                self.assertEqual(result['status'], 'violated' if mutant else 'satisfied',
                                 f'{mode} selector {selector_case}: {result.get("detail")}')
            if mutant:
                self.assertIn('survives', result.get('detail', ''))
            else:
                witnesses = ['witness_success', 'witness_failure'] + ([] if mode == 'pair' else ['witness_memory'])
                if mode == 'resolve':
                    witnesses.append('witness_ambiguity')
                coverage = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                                          expected_functions=witnesses, timeout_seconds=30)
                self.assertEqual(coverage['status'], 'satisfied', coverage)

    def test_arbitrary_instance_match_preserves_every_range_policy(self):
        self.check('pair')

    def test_resolution_preserves_success_fault_and_ambiguity(self):
        self.check('resolve')

    def test_realization_preserves_metadata_expiry_and_addresses(self):
        self.check('realize')

    def test_inconsistent_instance_renaming_is_rejected(self):
        self.check('pair', mutant=True)

    def test_collapsing_producer_classes_changes_resolution(self):
        self.check('resolve', mutant=True)
