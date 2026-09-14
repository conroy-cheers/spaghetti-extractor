"""Allocation-backed canonical extents come from checked live range instances."""

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.candidate.behavioral_c import write_spx_behavioral_c_package
from spaghetti_extractor.candidate.runtime import plan_shared_module_runtime
from spaghetti_extractor.candidate.runtime_sources import render_canonical_runtime_sources
from spaghetti_extractor.candidate.runtime_render import _native_runtime_source
from tests.unit.components import test_bisimulation_reference_authority as proof_fixture
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2, MachineObjectAuthorityError
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from .test_runtime_allocation_lifetime import allocation_fixture_source
from .test_runtime_canonical import _inputs

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def dynamic_rule():
    return {"id": "variable-buffer", "kind": "external", "domain": 9, "object": 77, "generation": 1,
            "extent": 16, "extent_mode": "instance_remainder", "permissions": 3, "lifetime": "allocation",
            "locator": {"kind": "external_allocation", "allocation_id": "allocator", "offset": 4},
            "interior_pointers": True, "evidence_sha256": "a" * 64}


def make_authority(rule):
    return MachineObjectAuthorityV2(machine_backend="x86-pe32-loader-relative-v2",
        bindings={"module_interface_sha256": "b" * 64}, rules=[rule])


def check_extent(root, cbmc, body, *, mode=1, offset=4, mutant=None):
    _write_cbmc_stdint(root / 'stdint.h')
    (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
    source = allocation_fixture_source('''
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
int main(void) {
  uint32_t address = 0;
  spx_machine_reference_v1 reference;
''' + body + '\n  __CPROVER_cover(1);\n}\n', extent_mode=mode, locator_offset=offset)
    if mutant == 'fixed':
        source = source.replace('rule->extent_mode == 1U ? range->size - rule->locator_offset : rule->extent', 'rule->extent')
    elif mutant == 'unchecked_extent':
        source = source.replace('reference->extent != selected_extent ||', '0 ||')
    path = root / 'extent.c'
    path.write_text(source)
    command = [str(cbmc), str(path), '--json-ui', '--unwind', '6', '--unwindset', 'spx_native_object_rule_identity_equal.0:11', '--sat-solver', 'cadical']
    result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions', '--bounds-check',
        '--pointer-check', '--signed-overflow-check'], timeout_seconds=30)
    cover = None
    if result['status'] == 'satisfied':
        cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                               expected_functions=['main'], timeout_seconds=30)
    return result, cover


class DynamicExtentTests(unittest.TestCase):
    def check(self, body, *, failure=None, **options):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as temporary:
            result, cover = check_extent(Path(temporary), cbmc, body, **options)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertEqual(result['detail'], failure)
            else:
                self.assertEqual(cover['status'], 'satisfied', cover)

    def test_variable_size_and_interior_tail_use_live_instance_remainder(self):
        body = '''
  uint32_t size;
  __CPROVER_assume(size >= 20U && size <= 1024U);
  __CPROVER_assert(spx_native_add_external_range(4096U, size, 100U, 1U, 7U, 55U) == SPX_CALL_OK,
      "register variable allocation");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4096U + size - 1U,
      1U, 1U, "allocation", 0U, 0U, &reference) == SPX_BOUNDARY_OK,
      "last allocated byte resolves");
  __CPROVER_assert(reference.extent == size - 4U && reference.offset == size - 5U,
      "canonical allocation remainder");
  __CPROVER_assert(realize(reference, &address) == SPX_BOUNDARY_OK && address == 4096U + size - 1U,
      "interior native reference round trip");
'''
        self.check(body)
        self.check(body, mutant='fixed', failure='last allocated byte resolves')

    def test_fixed_rules_keep_their_original_extent(self):
        self.check('''
  __CPROVER_assert(spx_native_add_external_range(4096U, 64U, 100U, 1U, 7U, 55U) == SPX_CALL_OK, "allocate");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4104U, 1U, 1U, 0, 0U, 0U,
      &reference) == SPX_BOUNDARY_OK && reference.extent == 16U && reference.offset == 4U,
      "fixed extent is unchanged");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4159U, 1U, 1U, 0, 0U, 0U,
      &reference) == SPX_BOUNDARY_MEMORY_FAULT, "fixed authority excludes allocation tail");
''', mode=0)

    def test_one_past_and_forged_extent_are_checked_against_actual_range(self):
        body = '''
  __CPROVER_assert(spx_native_add_external_range(4096U, 64U, 100U, 1U, 7U, 55U) == SPX_CALL_OK, "allocate");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4160U, 0U, 1U, 0, 0U, 0U,
      &reference) == SPX_BOUNDARY_MEMORY_FAULT, "one past requires permission");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4160U, 0U, 1U, 0, 0U, 1U,
      &reference) == SPX_BOUNDARY_OK && reference.extent == 60U && reference.offset == 60U,
      "one past native remainder");
  __CPROVER_assert(spx_native_realize_reference(&spx_native_context_value, &reference, 1U, 0U, 1U,
      &address) == SPX_BOUNDARY_OK && address == 4160U, "one past round trip");
  reference.offset = 1U;
  reference.extent = 16U;
  __CPROVER_assert(realize(reference, &address) == SPX_BOUNDARY_MEMORY_FAULT, "forged extent rejected");
'''
        self.check(body)
        self.check(body, mutant='unchecked_extent', failure='forged extent rejected')

    def test_reused_address_changes_generation_and_size_without_reviving_old_view(self):
        self.check('''
  __CPROVER_assert(spx_native_add_external_range(4096U, 64U, 100U, 1U, 7U, 55U) == SPX_CALL_OK, "first");
  spx_machine_reference_v1 old = borrow(4104U);
  __CPROVER_assert(spx_native_add_external_range(8192U, 96U, 100U, 1U, 7U, 55U) == SPX_CALL_OK, "second");
  spx_machine_reference_v1 other = borrow(8200U);
  __CPROVER_assert(old.extent == 60U && other.extent == 92U && old.generation != other.generation,
      "instances retain distinct extents and generations");
  __CPROVER_assert(spx_native_release_external_range(4096U, 101U) == SPX_CALL_OK, "release");
  __CPROVER_assert(spx_native_add_external_range(4096U, 32U, 100U, 1U, 7U, 55U) == SPX_CALL_OK, "reuse");
  reference = borrow(4104U);
  __CPROVER_assert(reference.extent == 28U && reference.generation != old.generation, "fresh smaller instance");
  __CPROVER_assert(realize(old, &address) == SPX_BOUNDARY_EXPIRED, "old origin stays expired");
  __CPROVER_assert(realize(other, &address) == SPX_BOUNDARY_OK && address == 8200U, "other origin is unchanged");
''')

    def test_short_allocation_and_overflow_do_not_create_authority(self):
        self.check('''
  __CPROVER_assert(spx_native_add_external_range(4096U, 19U, 100U, 1U, 7U, 55U) == SPX_CALL_OK, "short range");
  __CPROVER_assert(spx_native_resolve_reference(&spx_native_context_value, 4100U, 1U, 1U, 0, 0U, 0U,
      &reference) == SPX_BOUNDARY_MEMORY_FAULT, "rule minimum must fit after offset");
  __CPROVER_assert(spx_native_add_external_range(4294967280U, 32U, 100U, 1U, 7U, 55U)
      == SPX_CALL_UNIMPLEMENTED, "allocation extent must not wrap");
''')

    def test_strict_mode_round_trip_preserves_legacy_rule_bytes(self):
        dynamic = make_authority(dynamic_rule())
        self.assertEqual(MachineObjectAuthorityV2.parse(dynamic.to_payload()).to_payload(), dynamic.to_payload())
        fixed = dynamic_rule(); del fixed['extent_mode']
        self.assertEqual(make_authority(fixed).rules[0].to_payload(), fixed)
        for mode in ('fixed', 'unknown', None, 1):
            bad = {**dynamic_rule(), 'extent_mode': mode}
            with self.subTest(mode=mode), self.assertRaises(MachineObjectAuthorityError):
                make_authority(bad)
        bad = {**dynamic_rule(), 'locator': {'kind': 'image_rva', 'image_id': 'fixture', 'rva': 4096}}
        with self.assertRaises(MachineObjectAuthorityError): make_authority(bad)
        with self.assertRaises(MachineObjectAuthorityError):
            make_authority({**dynamic_rule(), 'lifetime': 'image'})
        with self.assertRaisesRegex(MachineObjectAuthorityError, 'checked live range'):
            dynamic.realize_instances({dynamic.rules[0].locator.selector: 4096})

    def test_native_plan_retains_mode_but_missing_producer_still_blocks(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = _inputs(root, additional_object_rules=[dynamic_rule()])
            write_spx_behavioral_c_package(transfer_plan=inputs['transfer_plan'], out=root / 'behavioral')
            render_canonical_runtime_sources(transfer_plan=inputs['transfer_plan'],
                execution_closure=inputs['execution_closure'],
                resolved_external_environment=inputs['resolved_external_environment'],
                native_ingress_plan=inputs['native_ingress_plan'], out=root / 'runtime')
            plan = plan_shared_module_runtime(behavioral_c_package=root / 'behavioral',
                transfer_plan=inputs['transfer_plan'], runtime_plan=root / 'runtime/module-runtime-plan.json',
                native_ingress_plan=root / 'runtime/native-ingress-plan.json', execution_closure=inputs['execution_closure'],
                resolved_external_environment=inputs['resolved_external_environment'],
                object_authority=root / 'machine-object-authority.json')
            rule = next(row for row in plan.object_authority_rules if row.identity == 'variable-buffer')
            self.assertEqual(rule.extent_mode_code, 1)
            self.assertEqual(rule.payload()['extent_mode'], 'instance_remainder')
            emitted = next(line for line in _native_runtime_source(plan).splitlines() if '"variable-buffer"' in line)
            self.assertTrue(emitted.endswith('0x00000000U, 1U, 1U },'), emitted)
            self.assertTrue(any(row['category'] == 'runtime_external_allocation_locator_unresolved'
                                for row in plan.object_authority_blockers))

    def test_dynamic_extent_does_not_admit_an_unqualified_proof_instance(self):
        proof_fixture.ReferenceAuthorityTests().check('''
  (void)runtime.resolve_reference(runtime.context, 4198404U, 4U, 1U, 0, 0U, 0U, &reference);
''', authority=make_authority(dynamic_rule()).to_payload(),
            failure='spx-bisimulation-reference-locator-qualified')

    def test_generated_native_helpers_execute_and_cross_compile(self):
        host = shutil.which('cc')
        pe32 = shutil.which('i686-w64-mingw32-gcc')
        self.assertIsNotNone(host)
        self.assertIsNotNone(pe32)
        source = '#define __CPROVER_assert(c, m) do { if (!(c)) __builtin_trap(); } while (0)\n' + allocation_fixture_source('''
int main(void) {
  const uint32_t sizes[] = {20U, 31U, 64U, 1024U};
  spx_machine_reference_v1 previous = {0};
  for (uint32_t index = 0; index < 4U; ++index) {
    uint32_t address, size = sizes[index];
    spx_machine_reference_v1 reference;
    if (spx_native_add_external_range(4096U, size, 100U, 1U, 7U, 55U) != SPX_CALL_OK) return 1;
    if (spx_native_resolve_reference(&spx_native_context_value, 4096U + size - 1U, 1U, 1U,
        "allocation", 0U, 0U, &reference) != SPX_BOUNDARY_OK) return 2;
    if (reference.extent != size - 4U || reference.offset != size - 5U) return 3;
    if (realize(reference, &address) != SPX_BOUNDARY_OK || address != 4096U + size - 1U) return 4;
    if (index && realize(previous, &address) != SPX_BOUNDARY_EXPIRED) return 5;
    previous = reference;
    if (spx_native_release_external_range(4096U, 101U) != SPX_CALL_OK) return 6;
  }
  return 0;
}
''', extent_mode=1, locator_offset=4)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            (root / 'native.c').write_text(source)
            binary = root / 'native'
            for command in ([host, '-std=c11', str(root / 'native.c'), '-o', str(binary)],
                            [pe32, '-std=c11', '-c', str(root / 'native.c'), '-o', str(root / 'native.obj')],
                            [str(binary)]):
                result = subprocess.run(command, capture_output=True, text=True, timeout=30)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
