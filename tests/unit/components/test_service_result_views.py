"""Nullable result views retain checked extents and live access after service return."""

import copy
import json
from .jq_reader import run as run_jq_reader
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_allocation_classes import allocation_class_requirement
from spaghetti_extractor.components.capabilities import spx_portable_reference_runtime_v5_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.contextual_bisimulation import _trusted_adapter_lowering_used, validate_contextual_refinement_v2
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.machine_overlay_result_views import result_view_lines, result_view_runtime_helpers
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from spaghetti_extractor.semantic_objects.object_authority import MachineObjectAuthorityV2
from . import test_bisimulation_allocation_calls as calls
from . import test_bisimulation_lifetime_admission as lifetime
from .test_bisimulation_allocation_namespace import inputs
from .test_bisimulation_lifetime_admission import checked_fixture, interface_fixture
from .test_bisimulation_service_effects import rehash_model

TESTKIT = {'fixtures': ('cbmc', 'compiler', 'jq'), 'resources': (
    'profiles/pe32-kernel32-runtime-v1.json', 'nix/jq/strong-contextual-proof.jq')}


def runtime_fixture(body, *, max_calls=1, requested_extent=1, minimum_extent=1):
    authority, requirements = inputs()
    rules = [dict(rule, extent=minimum_extent) for rule in authority.to_payload()['rules']]
    authority = MachineObjectAuthorityV2(machine_backend=authority.machine_backend,
        bindings=authority.bindings, rules=rules)
    requirements = [allocation_class_requirement(rule, effect=old['effect'],
        argument_words=old['argument_words'], contract_identity_sha256=old['contract_identity_sha256'])
        for rule, old in zip(authority.rules, requirements)]
    # Each case issues at most one public write in each world. Keep its checked
    # transcript bound local to the case; allocation initialization is separate.
    source = calls.fixture(body, typed_source=True, local_requirements=requirements,
                           max_calls=max_calls, max_writes=1, reference_authority=authority.to_payload())
    helpers = '\n'.join(result_view_runtime_helpers()) + '\n' + spx_portable_reference_runtime_v5_source()
    bundle = interface_fixture(buffer_view=True)
    prepared = checked_fixture(None, preparation_only=True, buffer_view=True)
    projection = next(r['result_projection'] for r in prepared['service_bindings'] if r['service_id'] == 'allocate')
    projection['requested_extent']['value'] = requested_extent
    decoder = result_view_lines(signature=bundle.intent.schema.signature_index['allocate'],
        types=bundle.intent.schema.type_index, projection=projection, authority_selectors={'allocated': 'text'},
        runtime='runtime', result_word='result',
        failure=['    __CPROVER_assert(0, "returned view decoding failed");', '    return (spx_view_v5){0};'])
    helpers += '\nstatic spx_view_v5 decode_result(spx_runtime *runtime, uint32_t result, uint32_t logical_size) {\n'
    helpers += '\n'.join(decoder) + '\n}\n'
    return '#include "portable-component.h"\n' + source.replace('int main(void) {', helpers + '\nint main(void) {')


START = '''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 4096U, "paired allocation");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_machine_reference_v1 reference = {0};
  spx_view_v5 view = decode_result(&runtime, 4096U, 16U);
'''


class ServiceResultViewTests(unittest.TestCase):
    def test_empty_authority_extent_policy_matches_independent_reader(self):
        authority, _ = inputs()
        program = (Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq').read_text()
        for mutation in ('empty', 'nonempty', 'fixed', 'image', 'lifetime', 'negative', 'boolean'):
            rule = dict(authority.to_payload()['rules'][0], extent=0)
            if mutation == 'nonempty': rule['extent'] = 1
            if mutation == 'fixed': rule.pop('extent_mode')
            if mutation == 'image': rule['kind'] = 'image'
            if mutation == 'lifetime': rule['lifetime'] = 'image'
            if mutation == 'negative': rule['extent'] = -1
            if mutation == 'boolean': rule['extent'] = False
            expected = mutation in ('empty', 'nonempty')
            with self.subTest(mutation=mutation):
                if expected:
                    model = MachineObjectAuthorityV2(machine_backend=authority.machine_backend,
                        bindings=authority.bindings, rules=[rule])
                    self.assertEqual(MachineObjectAuthorityV2.parse(model.to_payload()).rules[0].extent, rule['extent'])
                else:
                    with self.assertRaises(ValueError):
                        MachineObjectAuthorityV2(machine_backend=authority.machine_backend,
                            bindings=authority.bindings, rules=[rule])
                result = run_jq_reader([shutil.which('jq'), '-e', program+'\nspx_reference_authority_extents'],
                    input=json.dumps({'rules':[rule]}), capture_output=True, text=True)
                self.assertEqual(result.returncode, 0 if expected else 1, result.stderr)

    def test_production_overlay_and_reference_api_compile_for_host_and_pe32(self):
        prepared = checked_fixture(None, preparation_only=True, buffer_view=True)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            headers = render_component_c_headers_v5(interface_fixture(buffer_view=True), {'run': 'authored_run'})
            for name, source in headers.items(): (root / name).write_text(source)
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            (root / 'overlay.c').write_text(prepared['production_overlay_source'])
            (root / 'references.c').write_text('#include "portable-component.h"\n' + spx_portable_reference_runtime_v5_source())
            for compiler in ('cc', 'i686-w64-mingw32-gcc'):
                executable = shutil.which(compiler)
                self.assertIsNotNone(executable, f'declared compiler fixture lacks {compiler}')
                for name in ('overlay', 'references'):
                    with self.subTest(compiler=compiler, source=name):
                        result = subprocess.run([executable, '-std=c11', '-Wall', '-Wextra', '-Werror',
                            '-I', str(root), '-c', str(root / (name + '.c')), '-o', str(root / (name + '.o'))],
                            text=True, capture_output=True)
                        self.assertEqual(result.returncode, 0, result.stderr)

    def test_nullable_type_is_bound_to_service_results(self):
        projected = _logical_projection(interface_fixture(buffer_view=True))
        interface = ProofKernelComponentInterface.parse(projected)
        view = next(t for t in interface.types if t.kind == 'view')
        self.assertTrue(view.nullable)
        self.assertEqual(interface.to_payload(), projected)
        for location in ('operation', 'service', 'record', 'nullable'):
            changed = copy.deepcopy(projected)
            if location == 'operation':
                changed['operations'][0]['parameters'] = [{'id': 'buffer', 'type_id': view.identity}]
            if location == 'service':
                changed['services'][0]['parameter_type_ids'] = [view.identity]
            if location == 'record':
                changed['types'].append({'id': 'nested', 'kind': 'record', 'fields': [{'id': 'buffer', 'type_id': view.identity}]})
            if location == 'nullable':
                next(t for t in changed['types'] if t['id'] == view.identity)['nullable'] = 1
            with self.subTest(location=location), self.assertRaises(ValueError):
                ProofKernelComponentInterface.parse(changed)

    def test_both_readers_bind_shared_result_decoder(self):
        fixture = lifetime.LifetimeAdmissionTests()
        model = fixture.model(buffer_view=True)
        self.assertTrue(_trusted_adapter_lowering_used(model))
        self.assertTrue(fixture.jq_accepts(model))
        renderer = model['trusted_adapter_lowering']['renderer']
        renderer['implementation_files'] = [r for r in renderer['implementation_files']
                                             if r['path'] != 'machine_overlay_result_views.py']
        renderer['implementation_closure_sha256'] = canonical_sha256_v3(renderer['implementation_files'])
        rehash_model(model)
        with self.assertRaises(ValueError):
            _trusted_adapter_lowering_used(model)
        self.assertFalse(fixture.jq_accepts(model))

    def test_decoder_requires_exact_origin_and_extent_policy(self):
        bundle = interface_fixture(buffer_view=True)
        prepared = checked_fixture(None, preparation_only=True, buffer_view=True)
        projection = next(r['result_projection'] for r in prepared['service_bindings'] if r['service_id'] == 'allocate')
        signature = bundle.intent.schema.signature_index['allocate']
        for mutation in ('register', 'phase', 'extent', 'requested'):
            changed = copy.deepcopy(projection)
            if mutation == 'register': changed['base']['register'] = 'ebx'
            if mutation == 'phase': changed['base']['at'] = 'entry'
            if mutation == 'extent': changed['extent'] = {'kind': 'constant', 'value': 8, 'width': 32}
            if mutation == 'requested': changed['requested_extent'] = {'kind': 'register', 'register': 'eax', 'width': 32, 'at': 'call'}
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                result_view_lines(signature=signature, types=bundle.intent.schema.type_index,
                    projection=changed, authority_selectors={'allocated': 'text'}, runtime='runtime',
                    result_word='result', failure=['return (spx_view_v5){0};'])

    def runtime_check(self, body, *, max_calls=1, requested_extent=1, minimum_extent=1, failure=None):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / 'stdint.h')
            (root / 'state-machine-runtime.h').write_text(exact_runtime_header())
            headers = render_component_c_headers_v5(interface_fixture(buffer_view=True), {'run': 'authored_run'})
            for name, source in headers.items(): (root / name).write_text(source)
            path = root / 'views.c'
            path.write_text(runtime_fixture(body, max_calls=max_calls, requested_extent=requested_extent,
                                           minimum_extent=minimum_extent))
            command = [cbmc, str(path), '--json-ui', '--unwind', '7', '--sat-solver', 'cadical']
            result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions', '--bounds-check',
                '--pointer-check', '--signed-overflow-check', '--undefined-shift-check'], timeout_seconds=30)
            self.assertEqual(result['status'], 'satisfied' if failure is None else 'violated', result.get('detail'))
            if failure is not None:
                self.assertEqual(result.get('detail'), failure)
                return
            cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                expected_functions=['main'], timeout_seconds=30)
            self.assertEqual(cover['status'], 'satisfied', cover)

    def test_write_accessor_updates_public_memory(self):
        # The fixture compares all public bytes and lifetime state at exit.
        self.runtime_check(START + '''
  spx_proof_exact_write(0, 4099U, 1U, 7U, &fault);
  __CPROVER_assert(spx_view_write_u8(&view, 3U, 7U) == SPX_REF_OK, "write through live view");
''')

    def test_read_accessor_observes_public_memory(self):
        self.runtime_check(START + '''
  uint8_t observed = 0U;
  spx_proof_exact_write(0, 4099U, 1U, 7U, &fault);
  spx_proof_source_write(0, 4099U, 1U, 7U, &fault);
  __CPROVER_assert(spx_view_read_u8(&view, 3U, &observed) == SPX_REF_OK && observed == 7U,
      "read through live view");
''')

    def test_accessors_check_bounds_metadata_and_nullable_results(self):
        self.runtime_check(START + '''
  uint8_t observed = 0U;
  __CPROVER_assert(spx_view_write_u8(&view, 16U, 8U) != SPX_REF_OK, "view bounds");
  __CPROVER_assert(view.write(view.access_context, view.base, 15U, 2U, 8U) != 0U, "crossing span");
  __CPROVER_assert(view.write(view.access_context, view.base, UINT64_MAX, 1U, 8U) != 0U, "offset overflow");
  spx_view_v5 changed = {0};
  __CPROVER_assert(spx_view_read_u8(&changed, 0U, &observed) != SPX_REF_OK &&
      spx_view_write_u8(&changed, 0U, 8U) != SPX_REF_OK, "null view has no access");
''')

    def test_accessors_reject_forged_reference_metadata(self):
        for mutation in ('view.base.extent++;', 'view.base.generation++;', 'view.base.permissions = 7U;'):
            with self.subTest(mutation=mutation):
                self.runtime_check(START + mutation + '''
  __CPROVER_assert(spx_view_write_u8(&view, 0U, 8U) != SPX_REF_OK, "forged metadata");
''')

    def test_failed_allocation_returns_an_empty_view_without_accessors(self):
        self.runtime_check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 16U) == 0U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 16U) == 0U, "paired allocation failure");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_view_v5 view = decode_result(&runtime, 0U, 16U);
  __CPROVER_assert(view.base.object == 0U && view.base.generation == 0U &&
      view.base.domain == 0U && view.base.offset == 0U && view.base.extent == 0U &&
      view.base.permissions == 0U && view.extent == 0U && view.read == 0 && view.write == 0 &&
      view.read_u8 == 0 && view.write_u8 == 0 && view.context == 0 && view.access_context == 0,
      "allocation failure returns a canonical null view with no borrowed accessors");
''')

    def test_live_empty_result_preserves_identity_without_granting_byte_access(self):
        body = '''
  __CPROVER_assume(invoke(1U, 1U, 64U, 0U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 0U) == 4096U, "paired empty allocation");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_view_v5 view = decode_result(&runtime, 4096U, 0U);
  __CPROVER_assert(view.base.object != 0U && view.base.generation != 0U &&
      view.base.extent == 0U && view.extent == 0U, "live empty is distinct from null");
  uint8_t byte = 77U;
  __CPROVER_assert(spx_view_read_u8(&view, 0U, &byte) != SPX_REF_OK &&
      spx_view_write_u8(&view, 0U, 1U) != SPX_REF_OK, "empty view grants no byte access");
  spx_machine_reference_v1 reference = {view.base.domain, view.base.object, view.base.generation,
      view.base.offset, view.base.extent, view.base.permissions};
  uint32_t address = 0U;
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 3U, 0U, 1U, &address)
      == SPX_BOUNDARY_OK && address == 4096U, "empty identity round trip");
'''
        self.runtime_check(body, requested_extent=0, minimum_extent=0)
        self.runtime_check(body, requested_extent=1, minimum_extent=0, failure='returned view decoding failed')
        self.runtime_check(body, requested_extent=0, minimum_extent=1, failure='returned view decoding failed')

    def test_empty_result_identity_expires_across_release_and_address_reuse(self):
        self.runtime_check('''
  __CPROVER_assume(invoke(1U, 1U, 64U, 0U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 0U) == 4096U, "paired empty allocation");
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_view_v5 old = decode_result(&runtime, 4096U, 0U);
  spx_machine_reference_v1 reference = {old.base.domain, old.base.object, old.base.generation,
      old.base.offset, old.base.extent, old.base.permissions};
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) == 0U, "paired empty release");
  uint32_t address = 0U;
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 3U, 0U, 1U, &address)
      != SPX_BOUNDARY_OK, "released empty reference expires");
  __CPROVER_assume(invoke(1U, 1U, 64U, 8U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 8U) == 4096U, "paired reused address");
  __CPROVER_assert(runtime.realize_reference(runtime.context, &reference, 3U, 0U, 1U, &address)
      != SPX_BOUNDARY_OK, "empty reference stays expired after address reuse");
  spx_view_v5 fresh = decode_result(&runtime, 4096U, 8U);
  uint8_t byte = 77U;
  __CPROVER_assert(fresh.base.generation != old.base.generation &&
      spx_view_read_u8(&fresh, 0U, &byte) == SPX_REF_OK && byte == 0U,
      "fresh nonempty view uses its new lifetime");
''', requested_extent=0, minimum_extent=0, max_calls=3)

    def test_zero_byte_projection_does_not_admit_a_nonempty_view_at_one_past(self):
        self.runtime_check(START + '''
  (void)decode_result(&runtime, 4112U, 1U);
''', requested_extent=0, failure='returned view decoding failed')

    def test_release_and_smaller_reuse_do_not_revive_copied_view(self):
        self.runtime_check(START + '''
  spx_view_v5 copy = view;
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) == 0U);
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) == 0U, "paired release");
  __CPROVER_assert(spx_view_write_u8(&copy, 0U, 9U) != SPX_REF_OK, "released view rejects");
  __CPROVER_assume(invoke(1U, 1U, 64U, 8U) == 4096U);
  __CPROVER_assert(invoke(0U, 1U, 64U, 8U) == 4096U, "paired address reuse");
  __CPROVER_assert(spx_view_write_u8(&copy, 0U, 9U) != SPX_REF_OK, "copied generation stays expired");
  __CPROVER_assert(runtime.resolve_reference(runtime.context, 4096U, 1U, 3U,
      "text", 0U, 0U, &reference) == SPX_BOUNDARY_OK, "renewed result reference");
  view.base.generation = reference.generation; view.base.extent = reference.extent; view.extent = 8U;
  uint8_t observed = 9U;
  __CPROVER_assert(spx_view_read_u8(&view, 0U, &observed) == SPX_REF_OK && observed == 0U,
      "renewed view reads new allocation");
''', max_calls=3)

    def test_failed_release_preserves_existing_view_access(self):
        self.runtime_check(START + '''
  __CPROVER_assume(invoke(1U, 0U, 4096U, 0U) != 0U);
  __CPROVER_assert(invoke(0U, 0U, 4096U, 0U) != 0U, "paired failed release");
  uint8_t observed = 9U;
  __CPROVER_assert(spx_view_read_u8(&view, 0U, &observed) == SPX_REF_OK && observed == 0U,
      "failed release keeps the returned view live");
''', max_calls=2)

    def test_normal_proof_and_readers_accept_mutable_nullable_result(self):
        # Integration uses the existing production ceiling. The retained full
        # operation still exceeds the separate 30-second interactive target.
        with tempfile.TemporaryDirectory() as temporary:
            result, artifact = checked_fixture(Path(temporary), cbmc=Path(shutil.which('cbmc')),
                buffer_view=True, timeout_seconds=300)
            self.assertEqual(result['status'], 'satisfied', result.get('issues'))
            validate_contextual_refinement_v2(artifact['proof'], proof_plan=artifact['proof_plan'], exact_c_slice=artifact['exact_c_slice'])
            program = (Path(__file__).resolve().parents[3] / 'nix/jq/strong-contextual-proof.jq').read_text()
            checked = run_jq_reader([shutil.which('jq'), '-e', program + '\nspx_strong_contextual_proof'],
                input=json.dumps(artifact), text=True, capture_output=True)
            self.assertEqual(checked.returncode, 0, checked.stderr or checked.stdout)

    def test_normal_proof_rejects_changed_byte_before_release(self):
        with tempfile.TemporaryDirectory() as temporary:
            result, _ = checked_fixture(Path(temporary), cbmc=Path(shutil.which('cbmc')),
                buffer_view=True, wrong_byte=True, timeout_seconds=300)
            self.assertEqual(result['status'], 'violated', result.get('issues'))
