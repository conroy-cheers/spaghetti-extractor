"""Real allocation profiles drive the paired call oracle and lifetime snapshots."""

import copy
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.runtime_canonical_common import _checked_contract
from spaghetti_extractor.candidate.runtime_external_range_validation import _external_range_rules
from spaghetti_extractor.components.bisimulation_call_allocation import checked_lifetime_effect
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_typed_services import _proof_call_specs
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_sites import authority as native_authority, checked_site, native_inventory
from tests.unit.candidate.test_runtime_contract_identity import selected_row
from tests.unit.semantic_providers.test_allocation_inputs import authority

TESTKIT = {'fixtures': ('cbmc', 'compiler'), 'resources': ('profiles/pe32-kernel32-runtime-v1.json',)}


def inputs(*, size_policy=None):
    sites, bindings = [], []
    for index, symbol in enumerate(('GlobalAlloc', 'GlobalFree')):
        row, template = selected_row(symbol), checked_site(index)
        if index == 0 and size_policy is not None:
            row['contract']['payload']['result_register_relations'][0]['size'] = size_policy
            row['contract']['profile_id'] = 'fixture-size-policy'
            row['contract']['profile_sha256'] = canonical_sha256_v3(row['contract']['payload'])
        checked = _checked_contract(row=row, call=SimpleNamespace(argument_nodes=(), instruction_rva=template.instruction_rva), escape_index={})
        sites.append(replace(template, dll='kernel32.dll', symbol=symbol, checked_external_contract=checked,
            abi_metadata_sha256=canonical_sha256_v3(checked.profile_effect_payload()),
            target_resolution_evidence={'kind': 'resolved-external-environment-v1', 'sha256': 'd' * 64,
                                       'identity': ['kernel32.dll', 'symbol', symbol]}))
        bindings.append({'service_id': symbol, 'provider_kind': 'external_call',
            'external_effect_contract': checked.profile_effect_payload(),
            'external_contract_identity_sha256': checked.identity_sha256(),
            'abi_template': checked.abi_template, 'argument_offsets': list(range(0, checked.argument_words * 4, 4)),
            'events': [{'instruction_rva': template.instruction_rva, 'event_index': 0, 'return_rva': template.return_rva,
                        'checked_external_contract': checked.payload()}]})
    rules, _, blockers = _external_range_rules(native_inventory(sites), None, resolved_environment_sha256='d' * 64)
    assert not blockers
    model = authority()
    selector = next(index for index, row in enumerate(rules, 1) if row.action == 'add_result_range')
    native = replace(native_authority(), identity='text', extent=1, locator_subject_rva=selector,
                     locator_identity=selected_row()['contract']['payload']['id'], extent_mode='instance_remainder')
    inventory = {'object_rules': [native.payload()], 'external_range_rules': [row.payload() for row in rules]}
    return model.to_payload(), inventory, bindings


def fixture(body, *, typed_source=False, typed_exact=False, mutant=None, size_policy=None, finish_only=False,
            local_requirements=None, max_calls=3, max_writes=3, extra_bindings=(), summary_current_zero=False,
            reference_authority=None, runtime_assurance=None):
    model, inventory, bindings = inputs(size_policy=size_policy)
    if reference_authority is not None:
        model = reference_authority
    bindings = [*bindings, *extra_bindings]
    specs = _proof_call_specs(bindings, allow_lifetime_effects=True)
    world = _world_source(max_writes=max_writes, max_private_writes=1, max_calls=max_calls, max_atomics=1,
        max_shadow_bytes=1, max_nul_views=1, service_bindings=bindings, private_ranges=(),
        reference_authority=model, reference_runtime_inventory=inventory if local_requirements is None else None,
        reference_allocation_requirements=local_requirements, image_size=0x20000,
        typed_exact_recording=typed_exact, summary_current_zero=summary_current_zero,
        runtime_assurance=runtime_assurance)
    if mutant == 'source-effect':
        old = '    spx_proof_apply_lifetime_call(&spx_source_world, call, UINT32_C(0));'
        assert world.count(old) == 1
        world = world.replace(old, '')
    elif mutant == 'double-typed-effect':
        old = '  if (spx_proof_typed_lifetime_applied) return;'
        assert world.count(old) == 1
        world = world.replace(old, '')
    helpers = f'''
static uint32_t invoke(uint32_t exact, uint32_t allocation, uint32_t first, uint32_t size) {{
  spx_proof_world *world = exact ? &spx_exact_world : &spx_source_world;
  uint32_t result;
  if (exact ? {int(typed_exact)}U : {int(typed_source)}U) {{
    spx_proof_typed_service_begin(world, allocation ? {specs[0]['spec_id']}U : {specs[1]['spec_id']}U);
    spx_proof_typed_service_argument(0U, first);
    if (allocation) spx_proof_typed_service_argument(1U, size);
    if (!allocation && {int(finish_only)}U) {{ spx_proof_typed_service_finish(); return 0U; }}
    result = spx_proof_typed_service_result();
    __CPROVER_assert(result == spx_proof_typed_service_result(), "repeated result is stable");
    if (allocation && result) __CPROVER_assert(world->allocation_count > 0U,
        "allocation is live before typed result returns");
    spx_proof_typed_service_finish();
    return result;
  }}
  spx_stack_input arguments[] = {{{{0U, 4U, first}}, {{4U, 4U, size}}}};
  spx_call_event event = {{.kind=SPX_CALL_EXTERNAL_IMPORT,
      .instruction_rva=allocation ? {specs[0]['instruction_rva']}U : {specs[1]['instruction_rva']}U,
      .return_rva=allocation ? {specs[0]['return_rva']}U : {specs[1]['return_rva']}U,
      .call_index=0U, .stack_inputs=arguments, .stack_input_count=allocation ? 2U : 1U}};
  spx_machine_state input = {{.esp=8388608U}}, output = {{0}};
  spx_call_status status = exact ? spx_proof_exact_external_call(0, &event, &input, &output)
                               : spx_proof_source_external_call(0, &event, &input, &output);
  __CPROVER_assert(status == SPX_CALL_OK, "call returns normally");
  return output.eax;
}}
int main(void) {{
  spx_proof_reset_worlds(8388608U, 256U);
  uint32_t fault = 0U;
{body}
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "final public bytes and lifetime state agree");
  __CPROVER_cover(1);
}}
'''
    return ('#include "state-machine-runtime.h"\n#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n'
            '#ifndef SPX_TEST_COVER\n#define __CPROVER_cover(condition) ((void)0)\n#endif\n' + world + helpers)


class AllocationCallTests(unittest.TestCase):
    def check(self, body, *, failure=None, unwind=4, **options):
        cbmc = shutil.which('cbmc')
        if cbmc is None:
            self.skipTest('CBMC unavailable')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            path = root / 'allocation-calls.c'
            path.write_text(fixture(body, **options))
            from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
            command = [cbmc, str(path), '--json-ui', '--unwind', str(unwind), '--sat-solver', 'cadical',
                       *runtime_assurance_defines(options.get('runtime_assurance'))]
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions', '--bounds-check',
                '--pointer-check', '--signed-overflow-check', '--undefined-shift-check'], timeout_seconds=30)
            self.assertEqual(result['status'], 'violated' if failure else 'satisfied', result.get('detail'))
            if failure:
                self.assertIn(failure, result.get('detail', ''))
            else:
                coverage = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                                          expected_functions=['main'], timeout_seconds=30)
                self.assertEqual(coverage['status'], 'satisfied', coverage)

    def test_allocation_release_and_smaller_reuse_through_raw_and_typed_calls(self):
        body = '''
  uint32_t first = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(first == 4096U);
  __CPROVER_assert(spx_proof_exact_read(0, first, 1U, &fault) == 0U && !fault, "zero initialization");
  __CPROVER_assume(invoke(1U, 0U, first, 0U) == 0U);
  spx_proof_exact_read(0, first, 1U, &fault);
  __CPROVER_assert(fault != 0U, "released exact bytes expire");
  uint32_t second = invoke(1U, 1U, 0U, 8U);
  __CPROVER_assume(second == first);
  __CPROVER_assert(spx_exact_world.allocations[0].native_generation != spx_exact_world.allocations[1].native_generation,
      "address reuse gets a distinct native lifetime");
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == first, "paired allocation result");
  __CPROVER_assert(invoke(0U, 0U, first, 0U) == 0U, "paired successful release");
  spx_proof_source_read(0, first, 1U, &fault);
  __CPROVER_assert(fault != 0U, "released source bytes expire");
  __CPROVER_assert(invoke(0U, 1U, 0U, 8U) == second, "paired reuse");
  __CPROVER_assert(spx_source_world.allocation_count == 2U, "one instance per successful allocation");
'''
        for typed_source, typed_exact in ((False, False), (True, False), (True, True)):
            with self.subTest(typed_source=typed_source, typed_exact=typed_exact):
                self.check(body, typed_source=typed_source, typed_exact=typed_exact)

    def test_conditional_issued_access_does_not_revive_released_or_reused_storage(self):
        from spaghetti_extractor.components.bisimulation_issued_access import issued_access_assurance
        body = '''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assume(invoke(1U, 1U, 64U, 8U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 4096U, "paired allocation");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference;
  uint32_t address;
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4096U, 16U, 1U,
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "native allocation origin");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      == SPX_BOUNDARY_OK && address == 4096U, "live allocation resolves");
  __CPROVER_assert(spx_proof_source_read(0, address, 1U, &fault) == 0U && !fault,
      "realization preserves initialized contents");
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) == 0U, "paired release");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      != SPX_BOUNDARY_OK, "released origin expires");
  __CPROVER_assert(invoke(0U, 1U, 64U, 8U) == 4096U, "paired address reuse");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 1U, 0U, 0U, &address)
      != SPX_BOUNDARY_OK, "new allocation cannot revive old reference");
'''
        from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance
        from spaghetti_extractor.components.bisimulation_world_memory import allocation_byte_projection_assurance
        combined = allocation_byte_projection_assurance()
        combined['contracts'] += issued_access_assurance()['contracts'] + world_reference_assurance()['contracts']
        for assurance in (None, issued_access_assurance(), world_reference_assurance(), combined):
            with self.subTest(conditional=assurance is not None):
                self.check(body, typed_source=True, runtime_assurance=assurance, unwind=6)

    def test_null_allocation_and_failed_release_preserve_their_distinct_outcomes(self):
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 0U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 0U, "paired null result");
  __CPROVER_assert(!spx_exact_world.allocation_count && !spx_source_world.allocation_count,
      "null allocation creates no instance");
''', typed_source=True, typed_exact=True)
        self.check('''
  uint32_t pointer = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(pointer == 4096U);
  __CPROVER_assume(invoke(1U, 0U, pointer, 0U) != 0U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == pointer, "paired allocation");
  __CPROVER_assert(invoke(0U, 0U, pointer, 0U) != 0U, "paired failed release");
  __CPROVER_assert(spx_proof_source_read(0, pointer, 1U, &fault) == 0U && !fault,
      "failed release preserves live contents");
''', typed_source=True)

    def test_unsupported_flags_and_source_substitutions_are_proof_failures(self):
        self.check('  invoke(1U, 1U, 2U, 16U);', failure='allocation-argument-domain')
        self.check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  invoke(0U, 1U, 0U, 16U);
''', typed_source=True, failure='lifetime-typed-arguments')

    def test_missing_or_double_transition_is_detected(self):
        body = '''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  invoke(0U, 1U, 64U, 16U);
'''
        self.check(body, mutant='source-effect', failure='final public bytes and lifetime state agree')
        self.check(body, typed_source=True, mutant='double-typed-effect', failure='allocation-response')

    def test_fixed_scaled_and_product_sizes_replay_uninitialized_memory(self):
        for policy, expected in (({'kind': 'fixed', 'bytes': 12}, 12),
                                 ({'kind': 'argument', 'argument': 1, 'scale': 2}, 16),
                                 ({'kind': 'product', 'left_argument': 1, 'right_argument': 1}, 64)):
            with self.subTest(policy=policy):
                self.check(f'''
  uint32_t pointer = invoke(1U, 1U, 0U, 8U);
  __CPROVER_assume(pointer != 0U);
  __CPROVER_assert(spx_exact_world.allocations[0].size == {expected}U, "checked size expression");
  uint32_t byte = spx_proof_exact_read(0, pointer, 1U, &fault);
  __CPROVER_assert(!fault, "uninitialized allocation is readable");
  __CPROVER_assert(invoke(0U, 1U, 0U, 8U) == pointer, "paired allocation");
  __CPROVER_assert(spx_proof_source_read(0, pointer, 1U, &fault) == byte && !fault,
      "uninitialized bytes have the same fresh origin");
''', typed_source=True, size_policy=policy)

    def test_capacity_exhaustion_cannot_be_assumed_away_as_an_invalid_response(self):
        self.check('''
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 4096U, 16U, 1U, 0U, 0U) == SPX_BOUNDARY_OK, "first incoming instance");
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 8192U, 16U, 1U, 0U, 0U) == SPX_BOUNDARY_OK, "second incoming instance");
  __CPROVER_assert(spx_proof_allocate(&spx_exact_world, 12288U, 16U, 1U, 0U, 0U) == SPX_BOUNDARY_OK, "third incoming instance");
  invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(0);
''', failure='allocation-capacity')

    def test_ignored_release_result_still_commits_once_at_typed_finish(self):
        self.check('''
  uint32_t pointer = invoke(1U, 1U, 64U, 16U);
  __CPROVER_assume(pointer != 0U);
  invoke(1U, 0U, pointer, 0U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == pointer, "paired allocation");
  invoke(0U, 0U, pointer, 0U);
  __CPROVER_assert(spx_source_world.allocations[0].live == (spx_exact_world.calls[1].response_eax != 0U),
      "ignored result retains the checked release success condition");
''', typed_source=True, typed_exact=True, finish_only=True)

    def test_normal_admission_remains_closed_and_native_effect_substitution_fails(self):
        model, inventory, bindings = inputs()
        with self.assertRaisesRegex(BisimulationRefinementError, 'proof_service_lifetime_effect_unsupported'):
            _proof_call_specs(bindings)
        for field, value in (('size_argument', 0), ('allocation', None), ('argument_count', 1),
                             ('argument_base_offset', 4),
                             ('allocation', {'argument_masks': [{'argument_index': False, 'allowed_mask': 64}],
                                             'initialization': {'kind': 'argument_flag', 'argument_index': 0, 'mask': 64}})):
            changed = copy.deepcopy(inventory)
            next(row for row in changed['external_range_rules'] if row['action'] == 'add_result_range')[field] = value
            with self.subTest(field=field), self.assertRaises(BisimulationRefinementError):
                _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                    max_shadow_bytes=1, max_nul_views=1, service_bindings=bindings, private_ranges=(),
                    reference_authority=model, reference_runtime_inventory=changed, image_size=0x20000)
        payload = copy.deepcopy(bindings[0]['external_effect_contract'])
        payload['result_register_relations'][0]['allocation'] = None
        with self.assertRaisesRegex(BisimulationRefinementError, 'explicit ownership and initialization'):
            checked_lifetime_effect(payload, argument_words=2)
        indirect = copy.deepcopy(bindings)
        indirect[0]['captured_target_projection'] = {'kind': 'fixture-indirect-target'}
        with self.assertRaisesRegex(BisimulationRefinementError, 'checked direct CALL frame'):
            _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                max_shadow_bytes=1, max_nul_views=1, service_bindings=indirect, private_ranges=(),
                reference_authority=model, reference_runtime_inventory=inventory, image_size=0x20000)
