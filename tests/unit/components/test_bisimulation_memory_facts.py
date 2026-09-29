"""Constant current-memory suffixes are constructed before observation."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path

from spaghetti_extractor.components.bisimulation import BisimulationSyncV1, ComponentBisimulationError
from spaghetti_extractor.components import bisimulation_memory_facts as facts
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_assurance import runtime_assurance_defines
from spaghetti_extractor.components.bisimulation_world_namespace import world_reference_assurance
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_local_views import local_view_specs
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties, run_cbmc_cover
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_allocation_calls import inputs
from tests.unit.components.test_bisimulation_local_views import authored_view

TESTKIT = {"fixtures": ("cbmc", "compiler", "jq"), "resources": (
    "profiles/pe32-kernel32-runtime-v1.json", "nix/jq/strong-contextual-proof.jq")}


def operation(*, nullable=False, count=1):
    authored, _, recipe, _ = authored_view()
    payload = authored.syncs[0].to_payload()
    payload["captures"][0]["encoding"]["nullable"] = nullable
    payload["memory_facts"] = [{"id": f"tail{i}", "kind": "filled_suffix", "view": "scratch",
        "start": {"op": "const", "value": 4, "width": 32}, "byte": 0} for i in range(count)]
    authored = replace(authored, syncs=(BisimulationSyncV1.parse(payload, "suffix cut"),))
    return authored, recipe


def private_count(authored):
    payload = authored.syncs[0].to_payload()
    payload['captures'].append({'kind': 'source_state', 'id': 'count', 'mode': 'machine_codec',
        'projection': {'kind': 'stack', 'at': 'entry', 'offset': 28, 'width': 32},
        'encoding': {'op': 'state_input', 'name': 'count'}, 'decoding': {'op': 'projected_value'}})
    for fact in payload['memory_facts']:
        fact['start'] = {'op': 'state_input', 'name': 'count'}
    return replace(authored, syncs=(BisimulationSyncV1.parse(payload, 'private count'),))


def private_buffer(authored):
    payload = authored.syncs[0].to_payload()
    next(row for row in payload['captures'] if row['id'] == 'scratch')['projection']['base'] = {
        'kind': 'stack', 'at': 'entry', 'offset': 12, 'width': 32}
    return replace(authored, syncs=(BisimulationSyncV1.parse(payload, 'private buffer'),))


class MemoryFactTests(unittest.TestCase):
    def check(self, body, *, nullable=False, coverage=False, changed=None, count=1, private_writes=1, assurance=None,
              stack_accesses=()):
        authored, recipe = operation(nullable=nullable, count=count)
        if changed:
            authored = changed(authored)
        authority, inventory, _ = inputs()
        specs = local_view_specs(authored, component_id="counter",
            overlay_entry={"object_authority_selectors": {"scratch": "text"}}, authority=authority)
        world = _world_source(max_writes=2, max_private_writes=private_writes, max_calls=1,
            maximum_input_allocations=1, max_atomics=1, max_shadow_bytes=1, max_nul_views=1,
            memory_fact_capacity=facts.capacity(authored), service_bindings=[], private_ranges=(),
            exact_stack_accesses=stack_accesses,
            reference_authority=authority, reference_runtime_inventory=inventory, image_size=0x20000, runtime_assurance=assurance)
        prefix = world + facts.source(authored, specs, authority, runtime_assurance=assurance) + f'''
static void setup(void) {{
  spx_proof_reset_worlds(8388608U,256U);
  spx_proof_allocation row={{.base=4096U,.size=16U,.family={recipe['family']}U,
      .generation=2U,.live=1U,.native_rule_selector={recipe['native_rule_selector']}U,
      .native_generation=42U,.birth_class_selector={recipe['birth_class_selector']}U,.zero_initialized=1U}};
  __CPROVER_assert(spx_proof_restore_allocation_input(&spx_exact_world,&row)==SPX_BOUNDARY_OK &&
      spx_proof_restore_allocation_input(&spx_source_world,&row)==SPX_BOUNDARY_OK,"paired inputs");
}}
'''
        name = facts.symbols(authored.syncs[0], authored.syncs[0].memory_facts[0])
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            source = root / 'fact.c'
            source.write_text('#include "state-machine-runtime.h"\n#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' +
                prefix + '\nint main(void) { setup(); spx_machine_state state={0}; state.ebx=4096U;\n' +
                body.replace('FACT', name).replace('SECOND', facts.symbols(authored.syncs[0], authored.syncs[0].memory_facts[-1])) + '\n}\n')
            command = [shutil.which('cbmc'), str(source), '--json-ui', '--function', 'main', '--unwind', '3',
                '--sat-solver', 'cadical', *runtime_assurance_defines(assurance), *reference_authority_unwind_arguments(authority, allocation_capacity=2)]
            if coverage:
                return run_cbmc_cover(command=[*command, '--cover', 'cover'], expected_functions=['main'], timeout_seconds=40)
            return run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions', '--bounds-check',
                '--pointer-check', '--signed-overflow-check', '--undefined-shift-check'], timeout_seconds=40)

    def test_projected_namespace_serves_one_and_more_than_seven_memory_facts(self):
        for count in (1, 9):
            for assurance in (None, world_reference_assurance()):
                with self.subTest(count=count, projected=assurance is not None):
                    result = self.check("""
  FACT_initialize(&state);
  SECOND_check(&state);
  __CPROVER_assert(spx_proof_exact_byte(4100U) == 0U, "projected consumer reads current suffix");
  __CPROVER_assert(spx_exact_origins.count == 0U && spx_exact_world.write_count == 0U,
      "memory observer neither issues origins nor writes memory");
""", count=count, assurance=assurance)
                    self.assertEqual(result['status'], 'satisfied', result.get('detail'))
                    result = self.check("""
  spx_exact_world.allocations[0].native_generation = 0U;
  uint64_t begin, end;
  __CPROVER_assert(!SECOND_domain(&state, &begin, &end), "malformed context rejected by observer");
""", count=count, assurance=assurance)
                    self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_constructor_preserves_arbitrary_prefix_and_installs_universal_suffix(self):
        result = self.check('''
  FACT_initialize(&state);
  __CPROVER_assume(spx_proof_exact_byte(4096U)==71U);
  FACT_check(&state);
  uint32_t probe=spx_nondet_u32();
  __CPROVER_assert(probe<4100U || probe>=4112U || spx_proof_exact_byte(probe)==0U,"complete suffix");
  __CPROVER_assert(spx_proof_exact_byte(4096U)==71U,"prefix is current memory despite birth zeros");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"paired input correspondence");
  __CPROVER_assert(spx_exact_origins.count==0U && spx_source_origins.count==0U,"facts do not enroll origins");
''')
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_private_stack_coordinate_does_not_rewrite_its_own_input(self):
        result = self.check('''
  state.esp=8388608U;
  uint32_t fault=0U;
  spx_proof_exact_write(0,state.esp+28U,4U,4U,&fault);
  FACT_initialize(&state);
  __CPROVER_assert(!spx_initial_fill_observed,"private coordinate is not a public observation");
  FACT_check(&state);
  __CPROVER_assert(spx_proof_exact_read(0,state.esp+28U,4U,&fault)==4U && !fault,"coordinate remains current private input");
  __CPROVER_assert(spx_proof_exact_byte(4100U)==0U,"stack bound selects suffix");
''', changed=private_count)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_stack_buffer_preserves_current_pointer_offset_and_paired_contents(self):
        body = '''
  state.esp=8388608U; uint32_t fault=0U, interior=spx_nondet_u32();
  __CPROVER_assume(interior<=12U);
  spx_proof_exact_write(0,state.esp+12U,4U,4096U+interior,&fault);
  __CPROVER_assert(!fault,"pointer word written");
  FACT_initialize(&state);
  __CPROVER_assert(!spx_initial_fill_observed,"private pointer does not observe public input");
  uint64_t begin=0U,end=0U;
  __CPROVER_assert(FACT_domain(&state,&begin,&end) && begin==4100U+interior && end==4112U,
      "current interior pointer retains allocation remainder");
  FACT_check(&state);
  uint32_t probe=spx_nondet_u32();
  __CPROVER_assert((uint64_t)probe<begin || probe>=4112U || spx_proof_exact_byte(probe)==0U,
      "all current suffix bytes");
  __CPROVER_assert(spx_proof_exact_read(0,state.esp+12U,4U,&fault)==4096U+interior && !fault,
      "constructing heap contents preserves pointer storage");
  __CPROVER_assert(spx_proof_world_public_memory_equal(),"paired public contents");
'''
        result = self.check(body, changed=private_buffer)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check(body+'\n__CPROVER_cover(1);', changed=private_buffer, coverage=True)
        self.assertEqual(result['status'], 'satisfied', result)

    def test_stack_buffer_and_suffix_coordinate_share_checked_private_reader(self):
        result = self.check('''
  state.esp=8388608U; uint32_t fault=0U;
  spx_proof_exact_write(0,state.esp+12U,4U,4096U,&fault);
  spx_proof_exact_write(0,state.esp+28U,4U,4U,&fault);
  FACT_initialize(&state); FACT_check(&state);
  __CPROVER_assert(spx_proof_exact_read(0,state.esp+12U,4U,&fault)==4096U && !fault,
      "pointer preserved with stack suffix coordinate");
  __CPROVER_assert(spx_proof_exact_read(0,state.esp+28U,4U,&fault)==4U && !fault,
      "suffix coordinate preserved with stack pointer");
''', changed=lambda authored: private_buffer(private_count(authored)), private_writes=2)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_stack_buffer_null_requires_readable_pointer_storage(self):
        result = self.check('''
  state.esp=8388608U; uint32_t fault=0U;
  spx_proof_exact_write(0,state.esp+12U,4U,0U,&fault);
  FACT_initialize(&state); FACT_check(&state);
  __CPROVER_assert(!spx_initial_fill_observed,"null pointer leaves public contents unobserved");
''', nullable=True, changed=private_buffer)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        from spaghetti_extractor.components.bisimulation_native_admission import native_admission_assurance
        # The shared residual permission is unconstrained: readable private
        # storage is an obligation, not a consequence of frame membership.
        result = self.check('''
  state.esp=8388608U;
  uint64_t begin,end; (void)FACT_domain(&state,&begin,&end);
''', nullable=True, changed=private_buffer, assurance=native_admission_assurance())
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('coordinate-readable', result['detail'])

    def test_stack_buffer_rejects_stale_contents_expiry_and_unbacked_coordinates(self):
        setup = '''state.esp=8388608U; uint32_t fault=0U;
          spx_proof_exact_write(0,state.esp+12U,4U,4097U,&fault);'''
        for body, diagnostic in (
            ('state.esp=4096U-12U; FACT_initialize(&state);', 'coordinate-private'),
            (setup+'''(void)spx_proof_initial_byte(4096U);
                (void)FACT_coordinate_read(state.esp+12U,4U); FACT_initialize(&state);''', 'construction-order'),
            (setup+'''FACT_initialize(&state); __CPROVER_assume(spx_proof_exact_byte(4100U)==71U);
                spx_proof_exact_write(0,state.esp+12U,4U,4096U,&fault); FACT_check(&state);''', 'contents'),
            (setup+'''FACT_initialize(&state); spx_exact_world.allocations[0].live=0U;
                FACT_check(&state);''', 'output-domain'),
        ):
            with self.subTest(diagnostic=diagnostic):
                result = self.check(body, changed=private_buffer, private_writes=2)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn(diagnostic, result['detail'])

    def test_stack_cache_waits_for_initial_memory_construction(self):
        result = self.check('''
  __CPROVER_assert(!spx_initial_fill_observed,"reset does not observe initial memory");
  FACT_initialize(&state);
  uint32_t fault=0U;
  uint32_t expected=(uint32_t)__CPROVER_uninterpreted_spx_initial_byte(8388612U) |
      ((uint32_t)__CPROVER_uninterpreted_spx_initial_byte(8388613U) << 8U) |
      ((uint32_t)__CPROVER_uninterpreted_spx_initial_byte(8388614U) << 16U) |
      ((uint32_t)__CPROVER_uninterpreted_spx_initial_byte(8388615U) << 24U);
  __CPROVER_assert(spx_proof_exact_read(0,8388612U,4U,&fault)==expected && !fault,
      "cold cache preserves arbitrary initial stack bytes");
  __CPROVER_assert(spx_proof_source_read(0,8388612U,4U,&fault)==expected && !fault,
      "paired initial stack bytes agree");
  spx_proof_exact_write(0,8388612U,4U,0x11223344U,&fault);
  __CPROVER_assert(spx_proof_exact_read(0,8388612U,4U,&fault)==0x11223344U && !fault,
      "full store populates cache");
  spx_proof_exact_write(0,8388613U,1U,0xaaU,&fault);
  __CPROVER_assert(spx_proof_exact_read(0,8388612U,4U,&fault)==0x1122aa44U && !fault,
      "partial store invalidates cached word");
  spx_proof_reset_worlds(8388608U,256U);
  __CPROVER_assert(!spx_initial_fill_observed,"second reset does not observe memory");
  __CPROVER_assert(spx_proof_exact_read(0,8388612U,4U,&fault)==expected && !fault,
      "reset cannot reuse a prior cached store");
''', stack_accesses=((4, 4),), private_writes=2)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check('''
  (void)spx_proof_initial_byte(4096U);
  FACT_initialize(&state);
''', stack_accesses=((4, 4),))
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('construction-order', result['detail'])

    def test_private_coordinate_cannot_hide_heap_reads_or_prior_observations(self):
        for body, diagnostic in (
            ('state.esp=4096U-28U; FACT_initialize(&state);', 'coordinate-private'),
            ('''state.esp=8388608U; uint32_t fault=0U;
                spx_proof_exact_write(0,state.esp+28U,4U,4U,&fault);
                (void)spx_proof_initial_byte(4096U);
                (void)FACT_coordinate_read(state.esp+28U,4U);
                FACT_initialize(&state);''', 'construction-order'),
        ):
            with self.subTest(diagnostic=diagnostic):
                result = self.check(body, changed=private_count)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn(diagnostic, result['detail'])

    def test_outgoing_fact_uses_the_current_stack_bound(self):
        result = self.check('''
  state.esp=8388608U; uint32_t fault=0U;
  spx_proof_exact_write(0,state.esp+28U,4U,4U,&fault);
  FACT_initialize(&state);
  __CPROVER_assume(spx_proof_exact_byte(4096U)==71U);
  spx_proof_exact_write(0,state.esp+28U,4U,0U,&fault);
  FACT_check(&state);
''', changed=private_count, private_writes=2)
        self.assertEqual(result['status'], 'violated', result.get('detail'))
        self.assertIn('contents', result['detail'])

    def test_inactive_nullable_view_does_not_read_a_stack_coordinate(self):
        result = self.check('''
  state.ebx=0U; state.esp=0U;
  FACT_initialize(&state); FACT_check(&state);
''', nullable=True, changed=private_count)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))

    def test_current_write_expiry_and_late_installation_fail(self):
        for body, failure in [
            ('FACT_initialize(&state); uint32_t fault=0; spx_proof_exact_write(0,4101U,1U,7U,&fault); FACT_check(&state);', 'contents'),
            ('FACT_initialize(&state); spx_exact_world.allocations[0].live=0U; FACT_check(&state);', 'output-domain'),
            ('(void)spx_proof_exact_byte(4101U); FACT_initialize(&state);', 'construction-order')]:
            with self.subTest(failure=failure):
                result = self.check(body)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn(failure, result.get('detail', ''))

    def test_null_view_is_inactive_and_constructed_domain_is_reachable(self):
        result = self.check('''state.ebx=0U; FACT_initialize(&state); FACT_check(&state);
  __CPROVER_assert(spx_initial_fill_observed==0U,"inactive fact observes no memory");''', nullable=True)
        self.assertEqual(result['status'], 'satisfied', result.get('detail'))
        result = self.check('FACT_initialize(&state); __CPROVER_cover(1);', coverage=True)
        self.assertEqual(result['status'], 'satisfied', result)

    def test_overlapping_facts_require_compatible_bytes_and_nonvacuity(self):
        body = 'FACT_initialize(&state); SECOND_initialize(&state); __CPROVER_cover(1);'
        result = self.check(body, count=2, coverage=True)
        self.assertEqual(result['status'], 'satisfied', result)

        def conflict(authored):
            payload = authored.syncs[0].to_payload()
            payload['memory_facts'][1]['byte'] = 7
            return replace(authored, syncs=(BisimulationSyncV1.parse(payload, 'conflict'),))

        result = self.check(body, count=2, coverage=True, changed=conflict)
        self.assertNotEqual(result['status'], 'satisfied', result)
        # Empty suffixes may carry different constants without inconsistency.
        def empty(authored):
            authored = conflict(authored)
            payload = authored.syncs[0].to_payload()
            payload['memory_facts'][1]['start']['value'] = 16
            return replace(authored, syncs=(BisimulationSyncV1.parse(payload, 'empty'),))

        result = self.check(body, count=2, coverage=True, changed=empty)
        self.assertEqual(result['status'], 'satisfied', result)

    def check_reader_phases(self, *, stack, buffer_stack=False):
        from spaghetti_extractor.components.bisimulation_allocation_cuts import history_metadata
        from spaghetti_extractor.components.bisimulation_local_views import local_view_metadata
        from spaghetti_extractor.components.bisimulation_refinement import _required_assertion_descriptions
        authored, _ = operation()
        if stack:
            authored = private_count(authored)
        if buffer_stack:
            authored = private_buffer(authored)
        sync = authored.syncs[0]
        planned = {"operation_id": "run", "source": {"syncs": [sync.to_payload()]},
            "exact": {"control_edges": [{"source_unit_id": sync.exact_unit_id, "target_unit_id": sync.exact_unit_id}]}}
        checks = _required_assertion_descriptions(authored=authored, proof_function="main",
            active_start_sync_id="cut", next_sync_ids={"cut"}, logical_projection={"results": [], "state": []},
            continuous_acyclic=False, typed_call_positions=[])
        metadata = {**facts.metadata(authored), **history_metadata(authored), **local_view_metadata(authored)}
        model = {**metadata, "obligation_id": "sync:cut", "selected_unit_ids": [sync.exact_unit_id],
            "required_assertion_descriptions": checks}
        document = {"proof_plan": {"operations": [planned]}, "proof": {"models": {"operation_models": [
            {**metadata, "operation_id": "run", "obligation_models": [model]}]}}}
        module = Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq'
        for phase in (None, 'construction-order', 'input-domain', 'output-domain', 'contents',
                      *facts.coordinate_phases(sync, sync.memory_facts[0])):
            changed = copy.deepcopy(document)
            row = changed['proof']['models']['operation_models'][0]['obligation_models'][0]
            if phase:
                row['required_assertion_descriptions'].remove(facts.description(sync, sync.memory_facts[0], phase))
                with self.assertRaisesRegex(ValueError, 'construction or successor'):
                    facts.validate_model(planned, row)
            else:
                facts.validate_model(planned, row)
            result = run_jq_reader([shutil.which('jq'), '-e', module.read_text()+'\nspx_cut_capture_codecs'],
                input=json.dumps(changed), text=True, capture_output=True)
            self.assertEqual(result.returncode, 1 if phase else 0, result.stderr)

    def test_both_readers_require_every_incoming_and_outgoing_phase(self):
        self.check_reader_phases(stack=False)
        self.check_reader_phases(stack=True)
        self.check_reader_phases(stack=False, buffer_stack=True)
        self.check_reader_phases(stack=True, buffer_stack=True)

    def test_schema_and_independent_reader_bind_the_rule(self):
        authored, _ = operation()
        sync = authored.syncs[0]
        planned = {"source": {"syncs": [sync.to_payload()]}}
        facts.validate_model(planned, facts.metadata(authored))
        module = Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq'
        for mutation in (None, 'byte', 'start', 'view', 'policy', 'null', 'false'):
            payload = copy.deepcopy(planned)
            model = facts.metadata(authored)
            fact = payload['source']['syncs'][0]['memory_facts'][0]
            if mutation in ('null', 'false'): payload['source']['syncs'][0]['memory_facts'] = None if mutation == 'null' else False
            if mutation == 'byte': fact['byte'] = 256
            if mutation == 'start': fact['start'] = {'op': 'byte_read', 'name': 'scratch', 'index': {'op': 'const', 'value': 0, 'width': 32}}
            if mutation == 'view': fact['view'] = 'unknown'
            if mutation == 'policy': model['memory_fact_policy'] = 'unchecked'
            if mutation:
                with self.assertRaises(ValueError): facts.validate_model(payload, model)
            checked = run_jq_reader([shutil.which('jq'), '-e', module.read_text() +
                '\n.planned as $p | .model | spx_memory_fact_model($p)'],
                input=json.dumps({'planned': payload, 'model': model}), text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0 if mutation is None else 1, checked.stderr)


if __name__ == '__main__':
    unittest.main()
