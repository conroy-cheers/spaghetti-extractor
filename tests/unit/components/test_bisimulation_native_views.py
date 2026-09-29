"""Native decoder and cut barrier agree on full origins and interior views."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.contextual_bisimulation import validate_contextual_refinement_v2
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_native_views import native_view_specs
from spaghetti_extractor.components.bisimulation_reference_authority import reference_authority_unwind_arguments
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_view_extent import shared_view_admission_source
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION
from spaghetti_extractor.components.machine_overlay_v5 import _view_projection_lines, _view_runtime_helpers
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_reference_authority import authority_payload
from tests.unit.components.test_bisimulation_normal_exits import check_normal_exit
from tests.unit.components import test_bisimulation_view_admission as cut_fixture
from tests.unit.components.test_dynamic_state_storage import state_fixture

TESTKIT = {"fixtures": ("cbmc", "compiler")}


def check_native_cut(root, cbmc, *, mutation="", remainder=False, legacy=False, ambiguous=False,
                     nul_extent=None, roundtrip=False, bad_decoding=False, resumed=False, reject_realization=0,
                     invariant=None, offset_value=3):
    authority = authority_payload(ambiguous=ambiguous)
    payload = cut_fixture.CutViewAdmissionTests()._intent().to_payload()
    projection = payload["operations"][0]["syncs"][0]["captures"][0]["projection"]
    if invariant is not None:
        payload["operations"][0]["syncs"][0]["invariant"] = invariant
    if remainder:
        projection["extent"] = {"kind": "origin_remainder"}
    if roundtrip:
        decoding = {"op": "sub32", "args": [{"op": "projected_value"},
                                             {"op": "bytes_address", "name": "buffer"}]}
        if bad_decoding:
            decoding = {"op": "add32", "args": [decoding, {"op": "const", "value": 1, "width": 32}]}
        payload["operations"][0]["syncs"][0]["captures"].append({
            "kind": "source_state", "id": "offset", "mode": "machine_codec",
            "projection": {"kind": "register", "register": "eax", "width": 32, "at": "entry"},
            "encoding": {"op": "add32", "args": [{"op": "bytes_address", "name": "buffer"},
                                                   {"op": "state_input", "name": "offset"}]},
            "decoding": decoding})
    authored = ComponentBisimulationIntentV1.create(component_id="views", operations=payload["operations"]).operations[0]
    specs = {"buffer": {"permissions": 1, "selector": '"image-buffer"'}}
    header = _render_proof_header(authored=authored, image_base=0x400000, unit_rvas={"cut": 4096},
                                 active_target_sync_ids={"scan"}, active_start_sync_id="scan" if resumed else None,
                                 native_specs=None if legacy else specs,
                                 nul_view_ids=frozenset() if nul_extent is None else frozenset({"buffer"}))
    if roundtrip:
        header = "extern unsigned int test_realizations;\n" + header
        needle = '"spx-bisimulation-capture-roundtrip:scan:offset"); ' + chr(92)
        assert header.count(needle) == 1
        header = header.replace(needle, needle + '\n    __CPROVER_assert(test_realizations == 1U, '
            '"roundtrip reuses validated address"); ' + chr(92))
    (root / "proof.h").write_text(header)
    _write_cbmc_stdint(root / "stdint.h")
    (root / "state-machine-runtime.h").write_text(exact_runtime_header())
    bundle, _ = state_fixture()
    for name, text in render_component_c_headers_v5(bundle, {"run": "unused_run"}).items():
        (root / name).write_text(text)
    world = _world_source(max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                         max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
                         reference_authority=authority, image_size=65536)
    changes = {
        "": "", "move": "buffer->base.offset += 1; view_context->address += 1; spx_proof_exact_output.ebx += 1;"
            + ("buffer->extent -= 1; view_context->extent -= 1;" if remainder else ""),
        "domain": "buffer->base.domain += 1;", "object": "buffer->base.object += 1;",
        "generation": "buffer->base.generation += 1;", "offset": "buffer->base.offset += 1;",
        "permissions": "buffer->base.permissions = 1;", "reference_extent": "buffer->base.extent -= 1;",
        "visible_extent": "buffer->extent -= 1; view_context->extent -= 1;",
        "namespace": "buffer->base.object += 1; buffer->base.offset = 0; buffer->base.extent = 8;",
    }
    projection_lines = _view_projection_lines(value=SimpleNamespace(access="read"), projection=projection,
        name="input", scalar_arguments={}, authority_selectors={"buffer": "image-buffer"})
    source = root / "cut.c"
    source.write_text('''#include "proof.h"
#include "portable-component-implementation.h"
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
''' + world + '\nconst uint32_t spx_proof_private_high_offset = 256U;\n' + shared_view_admission_source(private_ranges=(), image_base=0x400000, image_size=65536)
        + '\n'.join(_view_runtime_helpers(need_read=True, need_write=False)).removeprefix(VIEW_CONTEXT_DECLARATION) + '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
void spx_bisimulation_relation_witness(void) {}
uint32_t spx_proof_exact_output_read(uint32_t address, uint32_t width) {
  uint32_t fault = 0; return spx_proof_exact_read(0, address, width, &fault);
}
uint32_t spx_proof_source_output_read(uint32_t address, uint32_t width) {
  uint32_t fault = 0; return spx_proof_source_read(0, address, width, &fault);
}
uint32_t spx_proof_world_calls_equal(void) { return 1; }
uint32_t spx_proof_world_atomics_equal(void) { return 1; }
uint32_t spx_proof_world_connected_calls_equal(void) { return 1; }
void run(spx_view_v5 *buffer) {
  spx_component_view_context *view_context = buffer->context;
  SPX_PROOF_BEGIN(run);
''' + changes[mutation] + '''
  __CPROVER_cover(1);
  SPX_PROOF_SYNC(scan, 1, buffer);
}
spx_step_result entry(spx_runtime *rt, spx_machine_state *state) {
''' + '\n'.join(projection_lines) + '''
  run(&input_view);
  return (spx_step_result){SPX_RETURN, 0, 0};
}
void main(void) {
  spx_proof_reset_worlds(8388608U, 256U);
''' + (f'  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent(4198404U) == {nul_extent}U);\n'
         '  spx_proof_register_nul_view(4198404U, 4U);\n' if nul_extent is not None else '') + '''
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  spx_proof_exact_output.ebx = 4198404U;
  spx_proof_exact_output.esp = 8388608U;
  spx_proof_exact_result = (spx_step_result){SPX_JUMP, 4096U, 0U};
  spx_machine_state state = spx_proof_exact_output;
  entry(&runtime, &state);
}
''')
    if roundtrip:
        text = source.read_text().replace('void run(spx_view_v5 *buffer) {', '''
unsigned int test_realizations;
static spx_boundary_status test_realize(void *opaque, const spx_machine_reference_v1 *reference,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  ++test_realizations;
  return spx_proof_authority_runtime_realize(opaque, reference, permissions, nullable, one_past, address);
}
void run(spx_view_v5 *buffer) {
  uint32_t offset = 3U;''').replace('SPX_PROOF_SYNC(scan, 1, buffer);',
                                  'SPX_PROOF_SYNC(scan, 1, buffer, offset);')
        text = text.replace('  spx_runtime runtime = spx_proof_runtime(&spx_source_world);',
            '  spx_runtime runtime = spx_proof_runtime(&spx_source_world);\n  runtime.realize_reference = test_realize;')
        text = text.replace('  spx_proof_exact_output.ebx = 4198404U;',
            '  spx_proof_exact_output.ebx = 4198404U;\n  spx_proof_exact_output.eax = 4198407U;')
        text = text.replace('uint32_t offset = 3U;', f'uint32_t offset = {offset_value}U;')
        text = text.replace('spx_proof_exact_output.eax = 4198407U;',
                            f'spx_proof_exact_output.eax = {4198404 + offset_value}U;')
        if resumed:
            text = text.replace('  spx_machine_state state = spx_proof_exact_output;',
                '  spx_proof_start = 1U;\n  spx_proof_exact_input = spx_proof_exact_output;\n'
                '  spx_machine_state state = spx_proof_exact_output;')
            text = text.replace('  __CPROVER_cover(1);\n  SPX_PROOF_SYNC(scan, 1, buffer, offset);',
                '  SPX_PROOF_SYNC(scan, 1, buffer, offset);\n  __CPROVER_cover(1);')
        if reject_realization:
            text = text.replace('  ++test_realizations;', '  ++test_realizations;\n'
                f'  if (test_realizations == {reject_realization}U) return SPX_BOUNDARY_MEMORY_FAULT;')
        source.write_text(text)
    command = [str(cbmc), str(source), '--json-ui', '--unwind', '2', '--sat-solver', 'cadical',
               *reference_authority_unwind_arguments(authority)]
    result = run_cbmc_properties(command=[*command, '--trace', '--unwinding-assertions', '--pointer-check',
                                        '--bounds-check', '--signed-overflow-check'], timeout_seconds=30)
    cover = None
    if result['status'] == 'satisfied':
        cover = run_cbmc_cover(command=[*command, '-DSPX_TEST_COVER', '--cover', 'cover'],
                               expected_functions=['run'], timeout_seconds=30)
    return result, cover


class NativeCutViewTests(unittest.TestCase):
    def test_nul_invariant_distinguishes_termination_from_origin_capacity(self):
        invariant = {"op": "ult32", "args": [{"op": "state_input", "name": "offset"},
                                             {"op": "nul_extent", "name": "buffer"}]}
        for offset in (7, 8):
            with self.subTest(offset=offset), tempfile.TemporaryDirectory() as temporary:
                result, cover = check_native_cut(Path(temporary), shutil.which('cbmc'),
                    remainder=True, nul_extent=8, roundtrip=True, invariant=invariant, offset_value=offset)
                self.assertEqual(result['status'], 'satisfied' if offset == 7 else 'violated', result.get('detail'))
                if offset == 7:
                    self.assertEqual(cover['status'], 'satisfied', cover)
                else:
                    self.assertEqual(result['detail'], 'spx-bisimulation-invariant:scan')
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaisesRegex(BisimulationRefinementError, 'canonical captured NUL-view'):
                check_native_cut(Path(temporary), shutil.which('cbmc'), roundtrip=True, invariant=invariant)

    def test_resumed_address_sites_keep_each_runtime_failure_visible(self):
        for reject in (0, 2, 3):
            with self.subTest(reject=reject), tempfile.TemporaryDirectory() as temporary:
                result, cover = check_native_cut(Path(temporary), shutil.which('cbmc'),
                    roundtrip=True, resumed=True, reject_realization=reject)
                self.assertEqual(result['status'], 'violated' if reject else 'satisfied', result.get('detail'))
                if reject:
                    self.assertEqual(result['detail'], 'spx-bisimulation-view-reference-address')
                    self.assertEqual(result['source']['function'],
                        f'__CPROVER_spx_view_address_site_{reject - 2}')
                else:
                    self.assertEqual(cover['status'], 'satisfied', cover)
                    for index in range(3):
                        self.assertIn(f'__CPROVER_spx_view_address_site_{index}.assertion.1',
                            result['property_ids'])

    def test_outgoing_roundtrip_reuses_address_but_still_checks_the_decoder(self):
        for wrong in (False, True):
            with self.subTest(wrong=wrong), tempfile.TemporaryDirectory() as temporary:
                result, cover = check_native_cut(Path(temporary), shutil.which('cbmc'),
                    roundtrip=True, bad_decoding=wrong)
                self.assertEqual(result['status'], 'violated' if wrong else 'satisfied', result.get('detail'))
                if wrong:
                    self.assertEqual(result['detail'], 'spx-bisimulation-capture-roundtrip:scan:offset')
                else:
                    self.assertEqual(cover['status'], 'satisfied', cover)

    def test_native_origin_extents_and_pointer_movement_cross_real_barrier(self):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        for remainder in (False, True):
            for mutation in ('', 'move'):
                with self.subTest(remainder=remainder, mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                    result, cover = check_native_cut(Path(temporary), cbmc, remainder=remainder, mutation=mutation)
                    self.assertEqual(result['status'], 'satisfied', result.get('detail'))
                    self.assertEqual(cover['status'], 'satisfied', cover)

    def test_native_metadata_and_namespace_forgery_are_rejected(self):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        for mutation in ('domain', 'object', 'generation', 'offset', 'permissions', 'reference_extent',
                         'visible_extent', 'namespace'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                result, _ = check_native_cut(Path(temporary), cbmc, mutation=mutation, ambiguous=True)
                self.assertEqual(result['status'], 'violated', result.get('detail'))
                self.assertIn('spx-bisimulation-capture-', result['detail'])

    def test_previous_flat_cut_rejects_a_valid_native_view(self):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as temporary:
            result, _ = check_native_cut(Path(temporary), cbmc, legacy=True)
            self.assertEqual(result['status'], 'violated', result)
            self.assertEqual(result['detail'], 'spx-bisimulation-capture-extent:scan:buffer')

    def test_nul_extent_fits_remaining_native_origin_without_defining_its_size(self):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        for extent in (8, 13):
            with self.subTest(extent=extent), tempfile.TemporaryDirectory() as temporary:
                result, cover = check_native_cut(Path(temporary), cbmc, remainder=True, nul_extent=extent)
                self.assertEqual(result['status'], 'satisfied' if extent == 8 else 'violated', result.get('detail'))
                if extent == 8:
                    self.assertEqual(cover['status'], 'satisfied', cover)
                else:
                    self.assertEqual(result['detail'], 'spx-bisimulation-capture-extent:scan:buffer')

    def test_full_checker_composes_native_view_entry_and_resumed_exit(self):
        cbmc = shutil.which('cbmc')
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as temporary:
            result = check_normal_exit(Path(temporary), cbmc=Path(cbmc),
                reference_authority=authority_payload(ambiguous=True), reference_view=True)
            self.assertEqual(result['status'], 'satisfied', [row.get('detail') for row in result['issues']])
            payload = json.loads((Path(temporary) / 'contextual-refinement-result.json').read_text())
            for mutation in ('missing', 'false'):
                stale = copy.deepcopy(payload['proof'])
                if mutation == 'missing':
                    del stale['policy']['native_cut_reference_decoding']
                else:
                    stale['policy']['native_cut_reference_decoding'] = False
                stale['receipt_sha256'] = canonical_sha256_v3({k: v for k, v in stale.items() if k != 'receipt_sha256'})
                with self.subTest(policy=mutation), self.assertRaisesRegex(ValueError, 'policy'):
                    validate_contextual_refinement_v2(stale, proof_plan=payload['proof_plan'],
                                                      exact_c_slice=payload['exact_c_slice'])

    def test_decoder_uses_bound_operation_selector(self):
        interface = SimpleNamespace(operation_index=lambda: {'run': SimpleNamespace(parameters=[
            SimpleNamespace(identity='buffer', type_id='view')])},
            type_index=lambda: {'view': SimpleNamespace(kind='view', nullable=False, access='read')})
        entry = {'object_authority_selectors': {'buffer': 'image-buffer'}}
        projection = {'parameters': [{'id': 'buffer', 'projection': {'authority': {'id': 'buffer'}}}]}
        specs = native_view_specs(interface, 'run', entry, authority_payload(), projection)
        self.assertEqual(specs, {'buffer': {'permissions': 1, 'selector': '"image-buffer"'}})
        for invalid in ({}, {'object_authority_selectors': {'buffer': 'missing'}}):
            with self.assertRaises(BisimulationRefinementError):
                native_view_specs(interface, 'run', invalid, authority_payload(), projection)
