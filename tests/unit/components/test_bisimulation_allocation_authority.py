"""Native allocation events project into the existing proof reference resolver."""

import shutil
import re
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_range_ownership import ownership_fixture, rules as native_rules
from tests.unit.candidate.test_runtime_allocation_sites import authority as native_authority

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def allocation_authority(*, policy=None):
    rule = {
        'id': 'allocation', 'kind': 'external', 'domain': 3, 'object': 55,
        'generation': 1, 'extent': 16, 'extent_mode': 'instance_remainder',
        'permissions': 3, 'lifetime': 'allocation', 'interior_pointers': True,
        'locator': {'kind': 'external_allocation', 'allocation_id': 'fixture:allocator', 'offset': 4},
        'evidence_sha256': 'b' * 64, **(policy or {}),
    }
    if rule.get('extent_mode') is None:
        del rule['extent_mode']
    return MachineObjectAuthorityV2(machine_backend='x86-pe32',
        bindings={'original_pe_sha256': 'a' * 64}, rules=[rule]).to_payload()


def native_inventory():
    rule = replace(native_authority(), locator_subject_rva=1, locator_offset=4,
                   extent_mode="instance_remainder")
    return {"object_rules": [rule.payload()], "external_range_rules": [
        replace(item, contract_identity_sha256="b" * 64).payload() for item in native_rules()]}


def projection_fixture(body, *, mutant=None, policy=None, max_calls=3):
    world = _world_source(max_writes=2, max_private_writes=1, max_calls=max_calls, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
        reference_authority=allocation_authority(policy=policy), image_size=131072,
        reference_runtime_inventory=native_inventory())
    if mutant == 'generation':
        old, new = 'allocation->size, allocation->native_generation, producer.namespace_selector', 'allocation->size, allocation->generation, producer.namespace_selector'
    elif mutant == 'expired':
        old, new = 'allocation->live && allocation->native_rule_selector', 'allocation->native_rule_selector'
    elif mutant == 'snapshot':
        old, new = 'left->native_generation == right->native_generation', '1'
    elif mutant == 'history_bound':
        old, new = 'if (world->allocation_count > UINT32_C(3)) return SPX_BOUNDARY_MEMORY_FAULT;', ''
    if mutant:
        assert world.count(old) == (1 if mutant in {'snapshot', 'history_bound'} else max_calls)
        world = world.replace(old, new)
    helpers = '''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)
''' + world + '''
static spx_boundary_status bind(spx_proof_world *world, const spx_native_external_range *range) {
  return spx_proof_bind_allocation_authority(world, range->start, range->size,
      range->ownership_family, range->ownership_owner, 1U, range->object_id, range->generation);
}
static void own(uint32_t base, uint32_t size) {
  __CPROVER_assert(add(77U, base, size) == SPX_CALL_OK, "native allocation");
  const spx_native_external_range *range =
      &spx_native_context_value.external_ranges[spx_native_context_value.external_range_count - 1U];
  __CPROVER_assert(range->start == base, "native instance selected by its actual range");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, base, size,
      range->ownership_family, range->ownership_owner, 0U) == SPX_BOUNDARY_OK, "proof allocation");
  __CPROVER_assert(bind(&spx_source_world, range) == SPX_BOUNDARY_OK, "bind native allocation instance");
}
static spx_boundary_status projected_resolve(uint32_t address, spx_machine_reference_v1 *reference) {
  spx_proof_authority_context context;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_OK, "project live allocation instances");
  spx_boundary_status status = spx_proof_authority_resolve_reference(
      &context, address, 1U, 1U, "allocation", 0U, 0U, reference);
  if (status != SPX_BOUNDARY_OK) return status;
  return spx_proof_record_reference_origin(&spx_source_world, address, reference, 0U);
}
static spx_boundary_status projected_realize(spx_machine_reference_v1 reference, uint32_t *address) {
  spx_proof_authority_context context;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_OK, "project allocation instances for realization");
  spx_boundary_status status = spx_proof_authority_realize_reference(
      &context, &reference, 1U, 0U, 0U, address);
  if (status != SPX_BOUNDARY_OK) return status;
  return spx_proof_record_reference_origin(&spx_source_world, *address, &reference, 0U);
}
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
  spx_native_context_value.external_lifecycle_sequence = 100U;
''' + body + '\n__CPROVER_cover(1);\n}\n'
    source = ownership_fixture(helpers)
    # Only the fixture's authority table changes: the native resolver and owned
    # allocation/release bodies still come from the production renderer.
    old = '16U, 3U, 5U, 0U, 1U, 1U, 0U}'
    assert source.count(old) == 1
    return source.replace(old, '16U, 3U, 5U, 4U, 1U, 1U, 1U}')


def check_projection(root, cbmc, body, *, mutant=None, policy=None):
    _write_cbmc_stdint(root / 'stdint.h')
    (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
    path = root / 'projection.c'
    path.write_text(projection_fixture(body, mutant=mutant, policy=policy))
    command = [cbmc, str(path), '--json-ui', '--unwind', '11', '--sat-solver', 'cadical']
    result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions',
        '--bounds-check', '--pointer-check', '--signed-overflow-check'], timeout_seconds=30)
    return result, command


class AllocationAuthorityTests(unittest.TestCase):
    def test_constant_rule_selection_matches_indexed_loop_for_arbitrary_metadata(self):
        from spaghetti_extractor.components.bisimulation_allocation_authority import allocation_authority_source
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        generated = allocation_authority_source(prefix='p', capacity=4, rule_count=5,
            image_size=225280, producers=[None, {'selector': 1, 'family': 7, 'proof_family': 2},
                None, {'selector': 2, 'family': 8, 'proof_family': 3},
                {'selector': 3, 'family': 9, 'proof_family': 4}])
        types = generated[:generated.index('static spx_boundary_status spx_proof_bind_allocation_authority(')]
        actual = generated[generated.index('static spx_boundary_status spx_proof_allocation_authority_context('):]
        actual = actual.replace('spx_proof_allocation_authority_context', 'new_context')
        header = '''#include <stdint.h>
#define SPX_PROOF_IMAGE_BASE 4194304U
#define SPX_BOUNDARY_OK 0
#define SPX_BOUNDARY_UNSUPPORTED 1
#define SPX_BOUNDARY_MEMORY_FAULT 2
#define SPX_BOUNDARY_TYPE_MISMATCH 3
typedef uint32_t spx_boundary_status;
typedef struct { uint32_t locator_kind,locator_subject_rva; uint64_t object_id; } p_object_authority_rule;
static p_object_authority_rule p_object_authority_rules[5];
typedef struct { uint32_t base,size,family,live,native_rule_selector,native_generation; } spx_proof_allocation;
typedef struct { uint32_t allocation_count; spx_proof_allocation allocations[4]; } spx_proof_world;
typedef struct { uint32_t start,size,generation,external_range_rule_selector; uint64_t object_id; } p_external_range;
typedef struct { uint32_t image_base,image_size,external_range_count; p_external_range external_ranges[4]; } p_context;
static spx_proof_world source_world;
static void *spx_proof_origins_for(void *w) { return w == &source_world ? w : 0; }
'''
        reference = '''
static spx_boundary_status old_context(const spx_proof_world *world, p_context *context) {
  if (spx_proof_origins_for((void *)world) == 0 || context == 0)
    return SPX_BOUNDARY_UNSUPPORTED;
  *context = (p_context){SPX_PROOF_IMAGE_BASE,225280U,0U,{{0}}};
  if (world->allocation_count > 4U) return SPX_BOUNDARY_MEMORY_FAULT;
  for (uint32_t i = 0; i < world->allocation_count; ++i) {
    const spx_proof_allocation *allocation = &world->allocations[i];
    if ((allocation->native_rule_selector == 0U) != (allocation->native_generation == 0U))
      return SPX_BOUNDARY_TYPE_MISMATCH;
    if (!allocation->live || !allocation->native_rule_selector) continue;
    uint32_t selector = allocation->native_rule_selector;
    if (selector > 5U || !allocation->native_generation) return SPX_BOUNDARY_TYPE_MISMATCH;
    const p_object_authority_rule *rule = &p_object_authority_rules[selector-1U];
    const spx_proof_allocation_producer *producer = &spx_proof_allocation_producers[selector-1U];
    if (rule->locator_kind != 5U || !producer->namespace_selector ||
        rule->locator_subject_rva != producer->namespace_selector || allocation->family != producer->proof_family)
      return SPX_BOUNDARY_TYPE_MISMATCH;
    context->external_ranges[context->external_range_count++] = (p_external_range){
      allocation->base, allocation->size, allocation->native_generation,
      producer->namespace_selector, rule->object_id};
  }
  return SPX_BOUNDARY_OK;
}
'''
        body = '''
int main(void) {
 __CPROVER_havoc_object(&source_world);__CPROVER_havoc_object(&p_object_authority_rules);
 spx_proof_world arbitrary;
 uint32_t world_kind,null_context;__CPROVER_havoc_object(&world_kind);__CPROVER_havoc_object(&null_context);
 const spx_proof_world *world=world_kind==0U?0:world_kind==1U?&source_world:&arbitrary;
 p_context before,after;__CPROVER_havoc_object(&before);after=before;
 spx_boundary_status old_status=old_context(world,null_context?0:&before);
 spx_boundary_status new_status=new_context(world,null_context?0:&after);
 __CPROVER_assert(old_status==new_status,"return and error status agree for every selector and history");
 __CPROVER_assert(before.image_base==after.image_base && before.image_size==after.image_size && before.external_range_count==after.external_range_count,"partial projection headers and count agree");
 for(uint32_t i=0;i<4U;++i)
  __CPROVER_assert(before.external_ranges[i].start==after.external_ranges[i].start && before.external_ranges[i].size==after.external_ranges[i].size && before.external_ranges[i].generation==after.external_ranges[i].generation && before.external_ranges[i].external_range_rule_selector==after.external_ranges[i].external_range_rule_selector && before.external_ranges[i].object_id==after.external_ranges[i].object_id,"every written and unused range keeps its bytes, lifetime and identity");
}
'''
        wrong = actual.replace('case 2U: rule = p_object_authority_rules[1];',
                               'case 2U: rule = p_object_authority_rules[3];')
        self.assertNotEqual(wrong, actual)
        for name, implementation, expected in [('positive', actual, 'satisfied'),
                                              ('wrong-rule', wrong, 'violated')]:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _write_cbmc_stdint(root / 'stdint.h')
                source = root / 'projection.c'
                source.write_text(header + types + reference + implementation + body)
                result = run_cbmc_properties(command=[cbmc, str(source), '--json-ui', '--trace',
                    '--bounds-check', '--pointer-check', '--signed-overflow-check', '--unwind', '5',
                    '--unwinding-assertions', '--sat-solver', 'cadical'], timeout_seconds=30)
                self.assertEqual(result['status'], expected, result.get('detail'))

    def test_compacted_ranges_match_indexed_projection_for_arbitrary_metadata(self):
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        body = '''
  spx_proof_world arbitrary;
  spx_source_world = arbitrary;
  uint32_t world_kind, null_context;
  spx_proof_world *world = world_kind == 0U ? 0 : world_kind == 1U ? &spx_source_world : &arbitrary;
  spx_proof_authority_context expected, actual;
  actual = expected;
  spx_boundary_status a = spx_proof_indexed_authority_context(world, null_context ? 0 : &expected);
  spx_boundary_status b = spx_proof_allocation_authority_context(world, null_context ? 0 : &actual);
  __CPROVER_assert(a == b, "projection status corresponds for arbitrary metadata");
  __CPROVER_assert(actual.image_base == expected.image_base && actual.image_size == expected.image_size &&
      actual.external_range_count == expected.external_range_count, "projection headers and compacted count correspond");
  for (uint32_t i = 0; i < 4U; ++i)
    __CPROVER_assert(actual.external_ranges[i].start == expected.external_ranges[i].start &&
        actual.external_ranges[i].size == expected.external_ranges[i].size &&
        actual.external_ranges[i].generation == expected.external_ranges[i].generation &&
        actual.external_ranges[i].external_range_rule_selector == expected.external_ranges[i].external_range_rule_selector &&
        actual.external_ranges[i].object_id == expected.external_ranges[i].object_id,
        "every emitted and unused range preserves its native identity and order");
'''
        # Four records matches the current real cleanup model's capacity.
        source = projection_fixture(body, max_calls=4)
        match = re.search(r'static spx_boundary_status spx_proof_allocation_authority_context\(.*?\n}\n', source, re.S)
        self.assertIsNotNone(match)
        indexed = match.group().replace('spx_proof_allocation_authority_context(', 'spx_proof_indexed_authority_context(', 1)
        indexed, count = re.subn(
            r'      const spx_proof_authority_external_range range = \{(.*?)\n      };.*?'
            r'      context->external_range_count = \+\+range_count;',
            r'      context->external_ranges[context->external_range_count++] = (spx_proof_authority_external_range){\1\n      };',
            indexed, flags=re.S)
        self.assertEqual(count, 4)
        indexed = indexed.replace('  uint32_t range_count = UINT32_C(0);\n', '')
        self.assertNotIn('range_count;', indexed)
        for wrong in (False, True):
            with self.subTest(wrong_generation=wrong), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                _write_cbmc_stdint(root / 'stdint.h')
                (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
                actual = projection_fixture(body, mutant='generation', max_calls=4) if wrong else source
                actual = actual.replace('int main(void) {', indexed + '\nint main(void) {')
                path = root / 'projection.c'
                path.write_text(actual)
                result = run_cbmc_properties(command=[cbmc, str(path), '--json-ui', '--trace',
                    '--bounds-check', '--pointer-check', '--signed-overflow-check', '--unwind', '11',
                    '--unwinding-assertions', '--sat-solver', 'cadical'], timeout_seconds=30)
                self.assertEqual(result['status'], 'violated' if wrong else 'satisfied', result.get('detail'))
                if wrong:
                    self.assertIn('native identity and order', result['detail'])

    def test_history_capacity_cannot_silently_truncate_ranges(self):
        body = """
  spx_proof_authority_context context = {0};
  spx_source_world.allocation_count = 4U;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_MEMORY_FAULT && context.external_range_count == 0U,
      "overfull history cannot silently truncate its ranges");
"""
        self.check(body)
        self.check(body, mutant='history_bound', failure='overfull history cannot silently truncate')

    def check(self, body, *, mutant=None, policy=None, failure=None):
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            result, command = check_projection(Path(temporary), cbmc, body, mutant=mutant, policy=policy)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertIn(failure, result['detail'])
            else:
                cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                    expected_functions=['main'], timeout_seconds=30)
                self.assertEqual(cover['status'], 'satisfied', cover)

    def test_native_tuple_and_full_extent_survive_projection(self):
        body = '''
  uint32_t base, size, address;
  __CPROVER_assume(base >= 4096U && base <= 8192U && size >= 20U && size <= 512U);
  own(base, size);
  spx_machine_reference_v1 native, projected;
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, base + size - 1U,
      1U, 1U, "allocation", 0U, 0U, &native) == SPX_BOUNDARY_OK, "native tail resolves");
  __CPROVER_assert(projected_resolve(base + size - 1U, &projected) == SPX_BOUNDARY_OK,
      "projected tail resolves");
  __CPROVER_assert(native.domain == projected.domain && native.object == projected.object &&
      native.generation == projected.generation && native.extent == projected.extent &&
      native.offset == projected.offset && native.permissions == projected.permissions,
      "projected reference equals native tuple");
  __CPROVER_assert(projected.generation == 101U &&
      spx_source_origins.entries[0].lifetime_generation == 2U, "native epoch differs from proof birth token");
  __CPROVER_assert(projected_realize(native, &address) == SPX_BOUNDARY_OK &&
      address == base + size - 1U, "native reference realizes through projected namespace");
'''
        self.check(body)
        self.check(body, mutant='generation', failure='projected reference equals native tuple')

    def test_release_compaction_and_smaller_address_reuse_preserve_identity(self):
        body = '''
  uint32_t address;
  own(4096U, 64U); own(8192U, 96U);
  spx_machine_reference_v1 old = borrow(4104U), other = borrow(8200U);
  __CPROVER_assert(projected_realize(old, &address) == SPX_BOUNDARY_OK, "first native reference");
  __CPROVER_assert(projected_realize(other, &address) == SPX_BOUNDARY_OK, "other native reference");
  __CPROVER_assert(release(1U, 77U, 4096U, 1U) == SPX_CALL_OK, "native release compacts table");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "proof release preserves tombstone");
  spx_proof_authority_context context;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_OK && context.external_range_count == 1U,
      "projected inventory contains only live instances");
  __CPROVER_assert(projected_realize(old, &address) == SPX_BOUNDARY_EXPIRED,
      "released native reference expires in projected namespace");
  own(4096U, 32U);
  spx_machine_reference_v1 fresh;
  __CPROVER_assert(projected_resolve(4104U, &fresh) == SPX_BOUNDARY_OK &&
      fresh.extent == 28U && fresh.generation == 104U, "reuse has current extent and native generation");
  __CPROVER_assert(projected_realize(old, &address) == SPX_BOUNDARY_EXPIRED, "old reference stays expired");
  __CPROVER_assert(projected_realize(other, &address) == SPX_BOUNDARY_OK && address == 8200U,
      "compaction cannot change another instance identity");
'''
        self.check(body)
        self.check(body, mutant='expired', failure='projected inventory contains only live instances')

    def test_binding_requires_the_exact_live_allocation_and_native_class(self):
        self.check('''
  own(4096U, 64U);
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      1U, 55U, 101U) == SPX_BOUNDARY_OK, "identical binding is idempotent");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4097U, 63U, 1U, 77U,
      1U, 55U, 101U) != SPX_BOUNDARY_OK, "interior span cannot replace allocation origin");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 32U, 1U, 77U,
      1U, 55U, 101U) != SPX_BOUNDARY_OK, "wrong instance extent rejected");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 2U, 77U,
      1U, 55U, 101U) != SPX_BOUNDARY_OK, "wrong allocator family rejected");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 88U,
      1U, 55U, 101U) != SPX_BOUNDARY_OK, "wrong owner rejected");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      1U, 56U, 101U) != SPX_BOUNDARY_OK, "wrong native object class rejected");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      1U, 55U, 102U) != SPX_BOUNDARY_OK, "existing native generation cannot be rebound");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      0U, 55U, 101U) != SPX_BOUNDARY_OK, "missing rule selector rejected");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      2U, 55U, 101U) != SPX_BOUNDARY_OK, "out of range rule selector rejected");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      1U, 55U, 0U) != SPX_BOUNDARY_OK, "missing native generation rejected");
''')

    def test_retired_native_generation_cannot_be_reused_for_a_new_lifetime(self):
        self.check('''
  own(4096U, 64U);
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 77U, 1U)
      == SPX_BOUNDARY_OK, "retire proof lifetime");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 32U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "new local lifetime");
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 32U, 1U, 77U,
      1U, 55U, 101U) == SPX_BOUNDARY_TYPE_MISMATCH, "retired native generation is not reusable");
  __CPROVER_assert(spx_source_world.allocations[1].native_rule_selector == 0U,
      "rejected binding cannot publish an instance");
''')

    def test_call_lifetime_observations_include_the_native_correspondence(self):
        body = '''
  own(4096U, 64U);
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "paired allocation");
  __CPROVER_assert(bind(&spx_exact_world, &spx_native_context_value.external_ranges[0])
      == SPX_BOUNDARY_OK, "paired native binding");
  spx_proof_call call = {0};
  spx_proof_record_call_allocations(&call);
  __CPROVER_assert(spx_proof_replay_call_allocations(&call), "paired lifetime snapshot agrees");
  spx_source_world.allocations[0].native_generation++;
  __CPROVER_assert(!spx_proof_allocation_states_equal(), "native generation is part of final lifetime state");
  __CPROVER_assert(call.allocation_index >= call.allocation_count ||
      !spx_proof_replay_call_allocations(&call), "call snapshot detects altered native generation");
'''
        self.check(body)
        self.check(body, mutant='snapshot', failure='native generation is part of final lifetime state')

    def test_projection_does_not_admit_an_unqualified_runtime_locator(self):
        self.check('''
  own(4096U, 64U);
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference;
  (void)runtime.resolve_reference(runtime.context, 4104U, 1U, 1U,
      "allocation", 0U, 0U, &reference);
''', failure='spx-bisimulation-reference-locator-qualified')

    def test_unbound_and_zero_size_allocations_do_not_grant_byte_authority(self):
        self.check('''
  spx_machine_reference_v1 reference;
  spx_proof_authority_context context;
  __CPROVER_assert(spx_proof_bind_allocation_authority(&spx_source_world, 4096U, 64U, 1U, 77U,
      1U, 55U, 101U) == SPX_BOUNDARY_MEMORY_FAULT, "binding cannot create a missing lifetime");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "unbound proof lifetime");
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_OK && context.external_range_count == 0U, "unbound allocation is not a native instance");
  __CPROVER_assert(projected_resolve(4100U, &reference) != SPX_BOUNDARY_OK,
      "unbound local storage grants no native reference");
  own(8192U, 0U);
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_OK && context.external_range_count == 1U && context.external_ranges[0].size == 0U,
      "zero-sized allocation retains its native lifetime");
  __CPROVER_assert(projected_resolve(8192U, &reference) != SPX_BOUNDARY_OK,
      "zero-sized allocation grants no byte access");
''')

    def test_partial_instance_metadata_cannot_be_silently_dropped(self):
        self.check('''
  spx_proof_authority_context context;
  own(4096U, 64U);
  spx_source_world.allocations[0].native_rule_selector = 0U;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_TYPE_MISMATCH, "generation without a selector is malformed");
  spx_source_world.allocations[0].native_rule_selector = 1U;
  spx_source_world.allocations[0].native_generation = 0U;
  __CPROVER_assert(spx_proof_allocation_authority_context(&spx_source_world, &context)
      == SPX_BOUNDARY_TYPE_MISMATCH, "selector without a generation is malformed");
''')

    def test_rule_policy_must_match_native_allocation_admission(self):
        body = '''
  __CPROVER_assert(add(77U, 4096U, 64U) == SPX_CALL_OK, "native instance");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 64U, 1U, 77U, 0U)
      == SPX_BOUNDARY_OK, "proof lifetime");
  __CPROVER_assert(bind(&spx_source_world, &spx_native_context_value.external_ranges[0])
      == SPX_BOUNDARY_TYPE_MISMATCH, "wrong authority policy cannot bind a native allocation");
  __CPROVER_assert(spx_source_world.allocations[0].native_rule_selector == 0U,
      "unsupported policy does not publish a native instance");
'''
        for policy in ({'kind': 'image'}, {'lifetime': 'image', 'extent_mode': None}):
            with self.subTest(policy=policy):
                self.check(body, policy=policy)
