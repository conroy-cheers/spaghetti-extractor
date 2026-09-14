"""Generated namespace projection is compared with the native context pipeline."""

import copy
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
from spaghetti_extractor.components.bisimulation_reference_authority import checked_reference_authority, reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance, world_reference_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_allocation_calls import inputs
from tests.unit.components.test_bisimulation_reference_authority import authority_payload

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": ("profiles/pe32-kernel32-runtime-v1.json",)}


def options(capacity=2, *, interior=True, empty=False):
    authority, inventory, bindings = inputs()
    rules = copy.deepcopy(authority['rules']) + authority_payload(ambiguous=True)['rules']
    for rule in rules:
        rule['interior_pointers'] = interior
    inventory['object_rules'][0]['interior_pointers'] = interior
    if empty:
        rules[0]['extent'] = 0
        inventory['object_rules'][0]['extent'] = 0
    authority = MachineObjectAuthorityV2(machine_backend=authority['machine_backend'],
        bindings=authority['bindings'], rules=rules).to_payload()
    return dict(max_writes=1, max_private_writes=1, max_calls=capacity, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, service_bindings=bindings, private_ranges=(),
        reference_authority=authority, reference_runtime_inventory=inventory, image_size=131072)


class WorldNamespaceTests(unittest.TestCase):
    def law(self, *, capacity=1, interior=True, empty=False, mutation=None):
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        opts = options(capacity, interior=interior, empty=empty)
        authority = opts['reference_authority']
        native = _world_source(**opts)
        assurance = world_reference_assurance()
        projected = world_reference_source(authority=checked_reference_authority(authority),
            capacity=capacity, image_size=opts['image_size'], prefix='spx_proof_authority', assurance=assurance)
        if mutation is not None:
            dynamic_index = next(i for i, rule in enumerate(authority['rules'])
                                 if rule['locator']['kind'] == 'external_allocation')
            before, after = {
                'family': (f'world->allocations[0].family == spx_proof_allocation_producers[{dynamic_index}].proof_family', '1U'),
                'expiry': ('if (found == 0U && dynamic_seen != 0U) return SPX_BOUNDARY_EXPIRED;', ''),
                'permissions': ('(allowed & permissions) != permissions', '0U'),
            }[mutation]
            self.assertIn(before, projected)
            projected = projected.replace(before, after)
        fields = ('domain', 'object', 'generation', 'offset', 'extent', 'permissions')
        equal = ' && '.join(f'left.{field} == right.{field}' for field in fields)
        body = '''
int main(void) {
  spx_proof_world input;
  spx_source_world = input;
  unsigned char snapshot[sizeof(spx_source_world)];
  __CPROVER_array_copy(snapshot, &spx_source_world);
  spx_proof_authority_context context;
  spx_boundary_status native_status = spx_proof_allocation_authority_context(&spx_source_world, &context);
  spx_boundary_status projected_status = spx_proof_authority_world_context_status(&spx_source_world);
  __CPROVER_assert(native_status == projected_status, "namespace:context-status");
  if (native_status == SPX_BOUNDARY_OK) {
    uint32_t address, requested, permission, nullable, one_past, selector_index;
    const char *selector = selector_index == 0U ? 0 : selector_index == 1U ? "text" :
        selector_index == 2U ? "image-buffer" : selector_index == 3U ? "overlap" : "unknown";
    spx_machine_reference_v1 initial, left, right;
    left = right = initial;
    native_status = spx_proof_authority_resolve_reference(&context, address, requested,
        permission, selector, nullable, one_past, &left);
    projected_status = spx_proof_authority_world_resolve_reference(&spx_source_world, address, requested,
        permission, selector, nullable, one_past, &right);
    __CPROVER_assert(native_status == projected_status, "namespace:resolve-status");
    __CPROVER_assert(EQUAL, "namespace:resolve-output-including-failure");
    uint32_t left_address, right_address;
    right_address = left_address;
    native_status = spx_proof_authority_realize_reference(&context, &initial,
        permission, nullable, one_past, &left_address);
    projected_status = spx_proof_authority_world_realize_reference(&spx_source_world, &initial,
        permission, nullable, one_past, &right_address);
    __CPROVER_assert(native_status == projected_status, "namespace:realize-status");
    __CPROVER_assert(left_address == right_address, "namespace:realize-output-including-failure");
  }
  uint32_t probe;
  __CPROVER_assume(probe < sizeof(spx_source_world));
  __CPROVER_assert(snapshot[probe] == ((unsigned char *)&spx_source_world)[probe], "namespace:world-frame");
}
'''.replace('EQUAL', equal)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root/'stdint.h')
            (root/'state-machine-runtime.h').write_text(exact_runtime_header())
            source = root/'namespace.c'
            source.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n'+native+'\n'+projected+body)
            return run_cbmc_properties(command=[cbmc, str(source), '--json-ui', '--trace',
                '--unwind', '3', '--unwinding-assertions', '--bounds-check', '--pointer-check',
                '--signed-overflow-check', '--undefined-shift-check', '--sat-solver', 'cadical',
                *reference_authority_unwind_arguments(authority, allocation_capacity=capacity),
                *runtime_assurance_defines(assurance)], timeout_seconds=90)

    def test_arbitrary_native_worlds_and_inputs_preserve_status_outputs_and_frame(self):
        for capacity, interior, empty in ((1, True, False), (3, False, False), (2, True, True)):
            with self.subTest(capacity=capacity, interior=interior, empty=empty):
                result = self.law(capacity=capacity, interior=interior, empty=empty)
                self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_wrong_family_expiry_and_permissions_are_detected(self):
        for mutation in ('family', 'expiry', 'permissions'):
            with self.subTest(mutation=mutation):
                result = self.law(mutation=mutation)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn('namespace:', result['detail'])

    def test_native_bodies_are_absent_and_cannot_invalidate_projected_source(self):
        opts = options()
        assurance = world_reference_assurance()
        before = _world_source(**opts, runtime_assurance=assurance)
        paths = (
            'spaghetti_extractor.transfer.reference_namespace._reference_dynamic_source',
            'spaghetti_extractor.transfer.reference_namespace._reference_resolution_source',
            'spaghetti_extractor.transfer.reference_namespace._reference_realization_source',
            'spaghetti_extractor.components.bisimulation_allocation_authority._allocation_context_source',
            'spaghetti_extractor.components.bisimulation_reference_authority._native_reference_helpers',
        )
        for path in paths:
            with self.subTest(path=path), patch(path, side_effect=AssertionError('native body requested')):
                self.assertEqual(before, _world_source(**opts, runtime_assurance=assurance))
        for name in ('spx_proof_authority_resolve_reference(', 'spx_proof_authority_realize_reference(',
                     'spx_proof_allocation_authority_context(', 'spx_proof_authority_dynamic_external_object_instance('):
            self.assertNotIn(name, before)

    def test_unimplemented_contract_or_unsupported_namespace_is_rejected(self):
        from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
        for kind in ('digest', 'backend', 'authority'):
            opts = options()
            assurance = world_reference_assurance()
            if kind == 'digest': assurance['contracts'][0]['contract_sha256'] = 'a'*64
            elif kind == 'backend': opts['reference_authority']['machine_backend'] = 'other'
            else: opts['reference_authority'] = None
            with self.subTest(kind=kind), self.assertRaises(BisimulationRefinementError):
                _world_source(**opts, runtime_assurance=assurance)
