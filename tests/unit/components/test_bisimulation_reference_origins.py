"""Native logical identities retain separate proof storage and lifetime tokens."""

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_reference_origins import origin_declarations, reference_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class ReferenceOriginTests(unittest.TestCase):
    def test_constant_append_preserves_arbitrary_registry_and_capacity_observation(self):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        # Nineteen slots matches the retained real cleanup entry model. Test
        # the one-slot lowering separately, including arbitrary overfull counts.
        for capacity, mutant in ((1, None), (19, None), (19, "generation"), (19, "capacity")):
            with self.subTest(capacity=capacity, mutant=mutant), tempfile.TemporaryDirectory() as temporary:
                actual = reference_source(reference_capacity=capacity, nul_extent_cases="",
                    reference_private_check="  if (!public_range)").split(
                        "static spx_boundary_status spx_proof_resolve_reference", 1)[0]
                # Check the changed tail with arbitrary state at its boundary.
                # Earlier collision/private/lifetime checks are unchanged and
                # are exercised with the full runtime by the tests below.
                actual = '''static spx_boundary_status spx_proof_record_reference_origin(
    spx_proof_origins *origins, uint32_t address, uint64_t extent,
    uint64_t lifetime_generation, const spx_machine_reference_v1 *reference) {
''' + actual[actual.index("  __CPROVER_assert(origins->count") :]
                # Observe the original assertion's occurrence and truth, instead
                # of assuming its premise or excluding overflow from this test.
                actual, replaced = re.subn(r'__CPROVER_assert\((origins->count < UINT32_C\(\d+\)),\s*'
                    r'"spx-bisimulation-reference-capacity"\);',
                    r'capacity_checked = 1U; capacity_ok = (\1);', actual)
                self.assertEqual(replaced, 1)
                expected, replaced = re.subn(
                    r'  const spx_proof_origin incoming = \{(.*?)\n  };.*?  \+\+origins->count;',
                    r'  origins->entries[origins->count++] = (spx_proof_origin){\1\n  };', actual, flags=re.S)
                self.assertEqual(replaced, 1)
                expected = expected.replace("spx_proof_record_reference_origin(", "indexed_record(", 1)
                if mutant == "generation":
                    actual = actual.replace("extent, lifetime_generation,\n    address", "extent, lifetime_generation + 1U,\n    address")
                elif mutant == "capacity":
                    actual = actual.replace("capacity_ok = (origins->count <", "capacity_ok = (origins->count <=")
                fields = ("domain", "object", "generation", "extent", "lifetime_generation", "base", "permissions")
                equal = " && ".join(f"registry.entries[i].{f} == before.entries[i].{f}" for f in fields)
                source = '''#include "state-machine-runtime.h"
''' + origin_declarations(capacity) + '''
static spx_proof_origins registry;
static uint32_t capacity_checked, capacity_ok;
''' + expected + actual + f'''
int main(void) {{
  spx_proof_origins initial;
  spx_machine_reference_v1 reference;
  uint32_t address;
  uint64_t extent, lifetime;
  registry = initial;
  spx_boundary_status a = indexed_record(&registry, address, extent, lifetime, &reference);
  spx_proof_origins before = registry;
  uint32_t checked_before = capacity_checked, ok_before = capacity_ok;
  registry = initial; capacity_checked = 0U; capacity_ok = 0U;
  spx_boundary_status b = spx_proof_record_reference_origin(&registry, address, extent, lifetime, &reference);
  __CPROVER_assert(a == b, "origin enrollment status is preserved");
  __CPROVER_assert(capacity_checked == checked_before && capacity_ok == ok_before,
      "capacity assertion occurrence and truth are preserved");
  __CPROVER_assert(registry.count == before.count, "origin count is preserved");
  for (uint32_t i = 0U; i < {capacity}U; ++i)
    __CPROVER_assert({equal}, "every origin field and unused slot is preserved");
}}
'''
                root = Path(temporary)
                _write_cbmc_stdint(root / "stdint.h")
                (root / "state-machine-runtime.h").write_text(exact_runtime_header())
                path = root / "append.c"
                path.write_text(source)
                result = run_cbmc_properties(command=[cbmc, str(path), "--json-ui", "--trace",
                    "--bounds-check", "--pointer-check", "--signed-overflow-check", "--unwind", str(capacity + 1),
                    "--unwinding-assertions", "--sat-solver", "cadical"], timeout_seconds=60)
                self.assertEqual(result["status"], "violated" if mutant else "satisfied", result.get("detail"))
                if mutant:
                    self.assertIn("capacity assertion" if mutant == "capacity" else "every origin field", result["detail"])

    def check(self, body, *, mutant=None, failure=None, unwind=6):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        world = _world_source(max_writes=1, max_private_writes=1, max_calls=3, max_atomics=1,
            max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=((12288, 4),))
        original = world
        if mutant == "address":
            world = world.replace('*address = selected.base + (uint32_t)reference->offset;',
                                  '*address = (uint32_t)(reference->object + reference->offset);')
        elif mutant == "lifetime":
            world = world.replace('''!spx_proof_allocation_reference_live((spx_proof_world *)opaque,
          selected.base, selected.extent, selected.lifetime_generation, one_past)''', '0')
        elif mutant == "borrowed":
            world = world.replace('origins->entries[0].lifetime_generation == UINT64_C(1)',
                                  'origins->entries[0].generation == UINT64_C(1)')
        elif mutant == "collision":
            world = world.replace('existing->base != address || existing->lifetime_generation != lifetime_generation', '0')
        if mutant:
            self.assertNotEqual(world, original)
        body = '''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)
''' + world + '''
static void own(uint32_t address) {
  __CPROVER_assert(allocate(address) == SPX_CALL_OK, "native allocation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, address, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_OK, "proof allocation");
}
static spx_machine_reference_v1 remember(uint32_t address) {
  spx_machine_reference_v1 reference = borrow(address);
  __CPROVER_assert(spx_proof_record_reference_origin(&spx_source_world, address, &reference, 0U)
      == SPX_BOUNDARY_OK, "record native origin");
  return reference;
}
static uint32_t proof_address(spx_machine_reference_v1 reference) {
  uint32_t address = 0U;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK, "mapped reference is live");
  return address;
}
int main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
''' + body + '\n  __CPROVER_cover(1);\n}\n'
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "origins.c"
            source.write_text(allocation_fixture_source(body, domain=0x100000003, object_id=0x200000037))
            command = [cbmc, str(source), "--json-ui", "--unwind", str(unwind), "--sat-solver", "cadical"]
            result = run_cbmc_properties(command=[*command, "--trace", "--unwinding-assertions",
                "--bounds-check", "--pointer-check", "--signed-overflow-check"], timeout_seconds=30)
            self.assertEqual(result["status"], "violated" if failure else "satisfied", result.get("detail"))
            if failure:
                self.assertIn(failure, result["detail"])
            else:
                cover = run_cbmc_cover(command=[*command, "-DSPX_TEST_COVER", "--cover", "cover"],
                                       expected_functions=["main"], timeout_seconds=30)
                self.assertEqual(cover["status"], "satisfied", cover)

    def test_native_ids_and_interior_offsets_map_to_distinct_physical_allocations(self):
        body = '''
  own(4096U); own(8192U);
  spx_machine_reference_v1 left = remember(4100U), right = remember(8196U);
  __CPROVER_assert(left.object == right.object && left.generation != right.generation,
      "native allocation instances share a class but have different generations");
  __CPROVER_assert(spx_source_origins.entries[0].base == 4096U &&
      spx_source_origins.entries[0].lifetime_generation != left.generation,
      "physical lifetime is independent of native generation");
  __CPROVER_assert(proof_address(left) == 4100U && proof_address(right) == 8196U,
      "opaque identities realize at their physical locations");
'''
        self.check(body)
        self.check(body, mutant="address", failure="opaque identities realize at their physical locations")

    def test_release_and_address_reuse_do_not_revive_old_native_references(self):
        body = '''
  own(4096U);
  spx_machine_reference_v1 old = remember(4100U);
  __CPROVER_assert(spx_native_release_external_range(4096U, 101U) == SPX_CALL_OK, "native release");
  __CPROVER_assert(spx_proof_release_allocation(&spx_source_world, 4096U, 1U, 0U, 1U)
      == SPX_BOUNDARY_OK, "proof release");
  own(4096U);
  __CPROVER_assert(spx_proof_record_reference_origin(&spx_source_world, 4100U, &old, 0U)
      == SPX_BOUNDARY_TYPE_MISMATCH, "old identity cannot be assigned to a new lifetime");
  spx_machine_reference_v1 fresh = remember(4100U);
  __CPROVER_assert(fresh.object == old.object && fresh.generation != old.generation,
      "native address reuse changes generation");
  __CPROVER_assert(proof_address(fresh) == 4100U, "new lifetime is usable");
  uint32_t address;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &old, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_EXPIRED, "old native origin remains expired");
'''
        self.check(body)
        self.check(body, mutant="lifetime", failure="old native origin remains expired")

    def test_borrowed_storage_is_reserved_by_physical_base_and_lifetime_token(self):
        body = '''
  __CPROVER_assert(allocate(8192U) == SPX_CALL_OK && allocate(4096U) == SPX_CALL_OK,
      "native caller owns incoming storage");
  spx_machine_reference_v1 reference = remember(4100U);
  __CPROVER_assert(reference.generation == 2U && spx_source_origins.entries[0].lifetime_generation == 1U,
      "borrowed proof lifetime does not equal native generation");
  __CPROVER_assert(spx_proof_allocate(&spx_source_world, 4096U, 16U, 1U, 0U, 0U)
      == SPX_BOUNDARY_MEMORY_FAULT, "cannot allocate over borrowed native storage");
'''
        self.check(body)
        self.check(body, mutant="borrowed", failure="cannot allocate over borrowed native storage")

    def test_one_logical_identity_cannot_be_rebound_to_different_storage(self):
        body = '''
  own(4096U); own(8192U);
  spx_machine_reference_v1 reference = remember(4100U);
  __CPROVER_assert(spx_proof_record_reference_origin(&spx_source_world, 8196U, &reference, 0U)
      == SPX_BOUNDARY_TYPE_MISMATCH, "conflicting identity mapping is rejected");
'''
        self.check(body)
        self.check(body, mutant="collision", failure="conflicting identity mapping is rejected")

    def test_repeated_resolution_and_interior_origins_do_not_spend_capacity(self):
        self.check('''
  own(4096U);
  spx_machine_reference_v1 reference = remember(4100U);
  for (uint32_t i = 0U; i < 20U; ++i) {
    reference.offset = i % 16U;
    __CPROVER_assert(spx_proof_record_reference_origin(&spx_source_world, 4096U + reference.offset,
        &reference, 0U) == SPX_BOUNDARY_OK, "same native origin is idempotent");
    spx_machine_reference_v1 flat;
    __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, 16384U, 4U, 1U, 0, 0U, 0U,
        &flat) == SPX_BOUNDARY_OK, "canonical resolution is idempotent");
  }
  __CPROVER_assert(spx_source_origins.count == 2U, "capacity counts origins instead of repeated resolutions");
''', unwind=22)

    def test_unregistered_or_forged_native_metadata_cannot_realize(self):
        for mutation in ("reference.domain++;", "reference.object++;", "reference.generation++;",
                         "reference.extent++;", "reference.permissions = 0U;", "reference.offset = 17U;"):
            with self.subTest(mutation=mutation):
                self.check('''
  own(4096U);
  spx_machine_reference_v1 reference = borrow(4100U);
  uint32_t address;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &reference, 1U, 0U, 0U, &address)
      != SPX_BOUNDARY_OK, "unregistered native identity is rejected");
  reference = remember(4100U);
''' + mutation + '''
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &reference, 1U, 0U, 0U, &address)
      != SPX_BOUNDARY_OK, "forged native identity is rejected");
''')

    def test_symbolic_storage_and_offsets_preserve_the_native_mapping(self):
        self.check('''
  uint32_t base, offset;
  __CPROVER_havoc_object(&base); __CPROVER_havoc_object(&offset);
  __CPROVER_assume(base != 0U && base <= UINT32_MAX - 16U && offset <= 12U);
  __CPROVER_assume((uint64_t)base + 16U <= spx_source_world.private_low ||
      base >= spx_source_world.private_high);
  __CPROVER_assume((uint64_t)base + 16U <= 12288U || base >= 12292U);
  own(base);
  spx_machine_reference_v1 reference = remember(base + offset);
  __CPROVER_assert(proof_address(reference) == base + offset,
      "symbolic native offset realizes within its physical object");
''')

    def test_enrollment_rejects_private_bytes_before_the_visible_pointer(self):
        self.check('''
  uint32_t base = spx_source_world.private_high - 8U;
  __CPROVER_assert(allocate(base) == SPX_CALL_OK, "native caller allocation");
  spx_machine_reference_v1 reference = borrow(base + 8U);
  __CPROVER_assert(spx_proof_record_reference_origin(&spx_source_world, base + 8U,
      &reference, 0U) == SPX_BOUNDARY_MEMORY_FAULT,
      "the full native origin must exclude unexposed private bytes");
  __CPROVER_assert(spx_source_origins.count == 0U, "rejection does not enroll an origin");
''')

    def test_distinct_origins_still_fail_closed_at_the_capacity_bound(self):
        self.check('''
  own(4096U);
  spx_machine_reference_v1 reference = borrow(4100U);
  for (uint32_t i = 0U; i < 12U; ++i) {
    reference.object += 1U;
    (void)spx_proof_record_reference_origin(&spx_source_world, 4100U, &reference, 0U);
  }
''', unwind=14, failure="spx-bisimulation-reference-capacity")
