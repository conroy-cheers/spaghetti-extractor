"""Native inventory positions are mapped, never inferred from component ordinals."""

import copy
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.candidate.runtime_allocation_bindings import _bind_dynamic_external_object_rules
from spaghetti_extractor.components.bisimulation_allocation_producers import allocation_producer_correspondence
from spaghetti_extractor.components.bisimulation_reference_authority import checked_reference_authority
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.external.range_ownership import RangeOwnership
from spaghetti_extractor.external.range_release import RangeRelease
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_sites import authority as native_authority
from tests.unit.candidate.test_runtime_range_ownership import ownership_fixture, rules as native_rules
from .test_bisimulation_allocation_authority import allocation_authority

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def inventories():
    allocate, release, other = native_rules()
    unrelated = RangeOwnership('a.unrelated', None)
    other = replace(other, ownership=unrelated, release=RangeRelease('always', (), unrelated))
    ranges = tuple(replace(row, contract_identity_sha256='b' * 64) for row in (
        other, allocate, release, replace(allocate, instruction_rva=400)))
    image = replace(native_authority(), identity='image', domain=4, object_id=99,
                    lifetime='image', locator_kind='image_rva', locator_identity='image')
    allocation = replace(native_authority(), locator_offset=4, extent_mode='instance_remainder')
    blockers = []
    objects = _bind_dynamic_external_object_rules([image, allocation], ranges, blockers)
    assert not blockers, blockers
    inventory = {'object_rules': [row.payload() for row in objects],
                 'external_range_rules': [row.payload() for row in ranges]}
    return objects, ranges, inventory


def fixture(body, *, mutant=None, missing_inventory=False):
    objects, ranges, inventory = inventories()
    world = _world_source(max_writes=2, max_private_writes=1, max_calls=3, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
        reference_authority=allocation_authority(), image_size=131072,
        reference_runtime_inventory=None if missing_inventory else inventory)
    if mutant == 'family':
        old, new = 'family != producer->namespace_family', '0'
        assert world.count(old) == 1
        world = world.replace(old, new)
    if mutant == 'selector':
        old, new = 'allocation->native_generation, producer.namespace_selector, rule.object_id', 'allocation->native_generation, selector, rule.object_id'
        assert world.count(old) == 3
        world = world.replace(old, new)
    body = '''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)
''' + world + '''
static void native_add(uint32_t site, uint32_t base, uint32_t size) {
  select_site(site, 77U, size); output.eax = base;
  __CPROVER_assert(spx_native_record_range_allocation(&spx_native_external_range_rules[site],
      &event, &snapshot, &output) == SPX_CALL_OK, "native producer registers instance");
}
static spx_boundary_status bind_range(uint32_t index) {
  const spx_native_external_range *range = &spx_native_context_value.external_ranges[index];
  return spx_proof_bind_allocation_authority(&spx_source_world, range->start, range->size,
      range->ownership_family, range->ownership_owner, range->external_range_rule_selector,
      range->object_id, range->generation);
}
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  spx_native_context_value.external_lifecycle_sequence = 100U;
''' + body + '\n__CPROVER_cover(1);\n}\n'
    return ownership_fixture(body, native_rules=ranges, native_authorities=objects)


class ProducerCorrespondenceTests(unittest.TestCase):
    def test_full_inventory_maps_distinct_local_native_object_producer_and_family_positions(self):
        _, _, inventory = inventories()
        rows = allocation_producer_correspondence(checked_reference_authority(allocation_authority()), inventory)
        self.assertEqual(len(rows), 1)
        row = rows[0]
        self.assertEqual(row['native_object_selector'], 2)
        self.assertEqual(row['native_producer_selector'], 2)
        self.assertEqual(row['native_site_selectors'], [2, 4])
        self.assertEqual(row['native_family_selector'], 2)
        self.assertEqual(row['proof_family_selector'], 1)
        self.assertEqual(row['owner_argument'], 0)
        self.assertEqual(row['contract_identity_sha256'], 'b' * 64)

    def test_stale_missing_ambiguous_and_different_native_authorities_are_rejected(self):
        _, _, original = inventories()
        mutations = ('subject', 'missing', 'duplicate', 'object', 'extent', 'offset', 'profile', 'digest', 'truncated', 'boolean')
        for mutation in mutations:
            inventory = copy.deepcopy(original)
            if mutation == 'subject': inventory['object_rules'][1]['locator']['subject_rva'] = 4
            if mutation == 'missing': inventory['object_rules'].pop()
            if mutation == 'duplicate': inventory['object_rules'].append(copy.deepcopy(inventory['object_rules'][1]))
            if mutation == 'boolean': inventory['object_rules'][1]['generation'] = True
            if mutation == 'object': inventory['object_rules'][1]['object'] = 56
            if mutation == 'extent': inventory['object_rules'][1]['extent'] = 17
            if mutation == 'offset': inventory['object_rules'][1]['locator']['offset'] = 8
            if mutation == 'profile': inventory['external_range_rules'][3]['contract_identity_sha256'] = 'c' * 64
            if mutation == 'digest':
                inventory['external_range_rules'].pop()
                inventory['external_range_rules'][1]['contract_identity_sha256'] = None
            if mutation == 'truncated': inventory['external_range_rules'].pop(0)
            with self.subTest(mutation=mutation), self.assertRaises(BisimulationRefinementError):
                allocation_producer_correspondence(checked_reference_authority(allocation_authority()), inventory)

    def check(self, body, *, mutant=None, failure=None, missing_inventory=False):
        cbmc = shutil.which('cbmc')
        if cbmc is None: self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'producers.c'
            path.write_text(fixture(body, mutant=mutant, missing_inventory=missing_inventory))
            command = [cbmc, str(path), '--json-ui', '--unwind', '11', '--sat-solver', 'cadical']
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions',
                '--bounds-check', '--pointer-check', '--signed-overflow-check'], timeout_seconds=30)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertIn(failure, result.get('detail', ''))
            else:
                covered = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                                         expected_functions=['main'], timeout_seconds=30)
                self.assertEqual(covered['status'], 'satisfied', covered)

    def test_native_selector_family_and_generation_translate_and_survive_reuse(self):
        body = '''
  native_add(1U, 4096U, 64U);
  __CPROVER_assert(spx_native_context_value.external_ranges[0].ownership_family == 2U, "native family is second");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "proof uses its first family");
  __CPROVER_assert(bind_range(0U) == SPX_BOUNDARY_OK, "native family maps into proof family");
  __CPROVER_assert(spx_source_world.allocations[0].native_rule_selector == 1U, "proof stores its local authority index");
  spx_proof_authority_context context;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context) == SPX_BOUNDARY_OK,
      "project supplied native bindings");
  __CPROVER_assert(context.external_ranges[0].external_range_rule_selector == 2U,
      "projection preserves native producer selector");
  spx_machine_reference_v1 native, proof;
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4104U, 1U, 1U,
      "allocation", 0U, 0U, &native) == SPX_BOUNDARY_OK, "native reference");
  __CPROVER_assert(spx_proof_authority_resolve_reference(&context, 4104U, 1U, 1U,
      "allocation", 0U, 0U, &proof) == SPX_BOUNDARY_OK, "projected reference");
  __CPROVER_assert(native.domain == proof.domain && native.object == proof.object &&
      native.generation == proof.generation && native.extent == proof.extent && native.offset == proof.offset &&
      native.permissions == proof.permissions, "full reference tuple agrees");
  __CPROVER_assert(release(2U, 77U, 4096U, 1U) == SPX_CALL_OK, "native release");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "proof release uses proof family");
  native_add(3U, 4096U, 32U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 32U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "smaller allocation from second site");
  __CPROVER_assert(bind_range(0U) == SPX_BOUNDARY_OK, "repeated producer uses same class mapping");
  __CPROVER_assert(spx_source_world.allocations[1].native_generation > native.generation,
      "reused storage gets a new native lifetime");
'''
        self.check(body)
        self.check(body, mutant='selector', failure='projection preserves native producer selector')

    def test_equal_local_family_number_cannot_substitute_another_native_family(self):
        body = '''
  native_add(1U, 4096U, 64U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "proof allocation");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      2U, 55U, 101U) == SPX_BOUNDARY_TYPE_MISMATCH, "local family cannot stand in for native family");
'''
        self.check(body)
        self.check(body, mutant='family', failure='local family cannot stand in for native family')

    def test_missing_inventory_cannot_bind_and_supplied_inventory_cannot_open_normal_admission(self):
        self.check('''
  native_add(1U, 4096U, 64U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "local allocation");
  __CPROVER_assert(bind_range(0U) == SPX_BOUNDARY_TYPE_MISMATCH, "no invented producer correspondence");
''', missing_inventory=True)
        self.check('''
  native_add(1U, 4096U, 64U);
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "local allocation");
  __CPROVER_assert(bind_range(0U) == SPX_BOUNDARY_OK, "supplied correspondence");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference;
  (void)runtime.resolve_reference(runtime.context, 4104U, 1U, 1U, "allocation", 0U, 0U, &reference);
''', failure='spx-bisimulation-reference-locator-qualified')
