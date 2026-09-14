"""Address consumers execute with the actual native reference namespace."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.components.bisimulation_connected import _observe_memory, render_connected_summary_wrapper
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.bisimulation_exact import _render_proof_header
from spaghetti_extractor.components.bisimulation_harness import _render_source_expression
from spaghetti_extractor.components.bisimulation_reference_transport import (
    connected_reference_transport_source, machine_reference_expression, view_address_expression,
)
from spaghetti_extractor.components.bisimulation_view_context import view_context_proof_source
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_cover, run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.candidate.test_runtime_allocation_lifetime import allocation_fixture_source
from tests.unit.components import test_bisimulation_view_admission as cut_fixture

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


class NativeReferenceTransportTests(unittest.TestCase):
    def check(self, body, *, prefix="", failure=None, proof_header=None, cover_function="main"):
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC unavailable")
        bundle = self.bundle()
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            (root / "connected-proof-summary.h").write_text('#define SPX_PROOF_CONNECTED_CAPACITY 1\n')
            for name, content in render_component_c_headers_v5(bundle, {"compare": "regions_equal"}).items():
                (root / name).write_text(content)
            source = root / "transport.c"
            source.write_text(allocation_fixture_source('''
#include "portable-component-implementation.h"
#ifndef SPX_TEST_COVER
#define __CPROVER_cover(condition) ((void)0)
#endif
''' + (proof_header or view_context_proof_source()) + prefix + '''
int main(void) {
  __CPROVER_assert(allocate(4096U) == SPX_CALL_OK, "native allocation");
  spx_machine_reference_v1 issued = borrow(4100U);
  spx_runtime runtime = {.context=&spx_native_context_value, .realize_reference=spx_native_realize_reference};
  spx_component_view_context view_context = {&runtime, 4100U, 8U, 3U};
  spx_view_v5 view = {.context=&view_context, .access_context=&view_context,
      .base={issued.domain, issued.object, issued.generation, issued.offset, issued.extent, issued.permissions},
      .extent=8U, .element_width=1U};
  spx_view_v5 *buffer = &view;
''' + body + ('\n  __CPROVER_cover(1);' if cover_function == "main" else '')
                + '\n}\n', domain=0x100000003, object_id=0x200000037))
            command = [cbmc, str(source), "--json-ui", "--unwind", "6", "--sat-solver", "cadical",
                *(["--unwindset", "spx_native_object_rule_identity_equal.0:11"] if proof_header else [])]
            result = run_cbmc_properties(command=[*command, "--trace", "--unwinding-assertions",
                "--bounds-check", "--pointer-check", "--signed-overflow-check"], timeout_seconds=30)
            self.assertEqual(result["status"], "violated" if failure else "satisfied", result.get("detail"))
            if failure:
                self.assertIn(failure, result["detail"])
            else:
                cover = run_cbmc_cover(command=[*command, "-DSPX_TEST_COVER", "--cover", "cover"],
                                       expected_functions=[cover_function], timeout_seconds=30)
                self.assertEqual(cover["status"], "satisfied", cover)

    def checked_native_cut(self, *, mutation="", index=7, active=True, failure=None):
        payload = cut_fixture.CutViewAdmissionTests()._intent().to_payload()
        sync = payload["operations"][0]["syncs"][0]
        sync["captures"][0]["projection"]["extent"]["value"] = 8
        sync["captures"][0]["projection"]["requested_extent"]["value"] = 8
        read = {"op": "byte_read", "name": "buffer", "index": {"op": "const", "value": index, "width": 32}}
        predicate = {"op": "eq", "args": [read, {"op": "const", "value": 23, "width": 32}]}
        sync["invariant"] = predicate if active else {"op": "ite", "args": [{"op": "false"}, predicate, {"op": "true"}]}
        authored = ComponentBisimulationIntentV1.create(component_id="views", operations=payload["operations"]).operations[0]
        header = _render_proof_header(authored=authored, image_base=4194304, unit_rvas={"cut": 4096},
            active_target_sync_ids={"scan"}, native_specs={"buffer": {"permissions": 1, "selector": '"allocation"'}})
        # Unrelated paired-world obligations are explicit fixture premises. The
        # reference and lifetime checks execute the real native namespace bodies.
        prefix = '''
uint32_t spx_proof_start, spx_proof_resumed, spx_proof_relation_probe;
spx_machine_state spx_proof_exact_input, spx_proof_exact_output;
spx_step_result spx_proof_exact_result;
uint32_t spx_proof_view_admitted(uint32_t address,uint32_t extent,uint32_t stack) { return 1U; }
uint32_t spx_proof_world_memory_range_equal(uint32_t base,uint64_t extent) {
  __CPROVER_assert(base==4096U && extent==16U,"cut still observes the full origin"); return 1U;
}
uint32_t spx_proof_exact_output_read(uint32_t address,uint32_t width) {
  __CPROVER_assert(address==spx_proof_exact_output.ebx+7U && width==1U,"checked cut byte address"); return 23U;
}
uint32_t spx_proof_world_calls_equal(void) { return 1U; }
uint32_t spx_proof_world_atomics_equal(void) { return 1U; }
uint32_t spx_proof_world_public_memory_equal(void) { return 1U; }
uint32_t spx_proof_world_allocation_cut_admitted(void) { return 1U; }
uint32_t spx_proof_world_connected_calls_equal(void) { __CPROVER_cover(1); return 1U; }
void run(spx_view_v5 *buffer) {
  SPX_PROOF_BEGIN(run);
''' + mutation + '''
  SPX_PROOF_SYNC(scan,1,buffer);
}
'''
        self.check('''
  runtime.resolve_reference=spx_native_resolve_reference;
  spx_proof_exact_output.ebx=4100U;
  spx_proof_exact_output.esp=8388608U;
  spx_proof_exact_result=(spx_step_result){SPX_BRANCH,4096U,0U};
  run(buffer);
''', prefix=prefix, proof_header=header, failure=failure,
            cover_function="spx_proof_world_connected_calls_equal")

    def test_checked_cut_address_requires_current_lifetime_and_descriptor(self):
        for mutation, failure in (("", None),
            ("buffer->base.offset++; ((spx_component_view_context *)buffer->context)->address++; spx_proof_exact_output.ebx++;", None),
            ("buffer->base.generation++;", "spx-bisimulation-capture-metadata:scan:buffer"),
            ("spx_native_release_external_range(4096U,101U);", "spx-bisimulation-capture-metadata:scan:buffer")):
            with self.subTest(mutation=mutation):
                self.checked_native_cut(mutation=mutation, failure=failure)

    def test_checked_cut_byte_access_retains_bounds_and_conditional_evaluation(self):
        self.checked_native_cut(index=8, failure="spx-bisimulation-view-reference-byte-index")
        self.checked_native_cut(index=0xffffffff, active=False)

    def bundle(self):
        path = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        return compile_component_interface_v5(ComponentInterfaceIntentV1.parse(json.loads(path.read_text())))

    def test_source_address_and_byte_reads_use_realized_interior_location(self):
        address = _render_source_expression({"op": "bytes_address", "name": "buffer"}, memory="input")
        read = _render_source_expression({"op": "byte_read", "name": "buffer",
            "index": {"op": "const", "value": 7}}, memory="output")
        self.check(f'__CPROVER_assert({address} == 4100U && {read} == 23U, "realized byte expressions");', prefix='''
uint32_t spx_proof_exact_output_read(uint32_t address, uint32_t width) {
  __CPROVER_assert(address == 4107U && width == 1U, "read uses interior address and index");
  return 23U;
}
''')
        self.check('__CPROVER_assert((uint32_t)view.base.object == 4100U, "object arithmetic mutant");',
                   failure="object arithmetic mutant")

    def test_cut_context_reference_relation_rejects_invalid_native_origins(self):
        reference = machine_reference_expression("view.base")
        for mutation, expected in (("", True), ("view.base.object++;", False),
                ("view.base.generation++;", False), ("view.base.offset = 17U;", False),
                ("view.base.extent++;", False), ("view.base.permissions = 0U;", False),
                ("view.extent = 13U; view_context.extent = 13U;", False),
                ("view_context.address++;", False), ("runtime.realize_reference = 0;", False),
                ("spx_native_release_external_range(4096U, 101U);", False)):
            with self.subTest(mutation=mutation):
                self.check(mutation + f'''
  __CPROVER_assert(__CPROVER_spx_view_reference_matches(&view_context, {reference}, view.extent, 4100U)
      == {int(expected)}U, "native cut reference admission");
''')

    def test_view_byte_read_rejects_visible_overread_without_wrapping(self):
        for index in (8, 0xffffffff):
            with self.subTest(index=index):
                self.check(f'(void){view_address_expression("buffer", index=f"UINT32_C({index})")};',
                           failure="spx-bisimulation-view-reference-byte-index")

    def test_full_reference_memory_starts_before_an_interior_view(self):
        world = '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + _world_source(
            max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
            max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=())
        body = '''
  spx_proof_reset_worlds(8388608U, 256U);
  uint32_t fault = 0U;
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 7U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 8U, &fault);
  __CPROVER_assert(spx_proof_world_memory_range_equal(4100U, 12U), "interior suffix matches");
  uint32_t base = OBJECT_BASE;
  __CPROVER_assert(spx_proof_world_memory_range_equal(base, view.base.extent), "prefix mismatch is observed");
'''
        self.check(body.replace("OBJECT_BASE", view_address_expression("buffer", object_start=True)),
                   prefix=world, failure="prefix mismatch is observed")
        # Starting at the interior pointer drops the differing prefix.
        self.check(body.replace("OBJECT_BASE", view_address_expression("buffer")), prefix=world)

    def connected(self, *, moved=False, erase=False, expired=False):
        wrapper = render_connected_summary_wrapper(bundle=self.bundle(),
            operation_symbols={"compare": "regions_equal"}, summary_ids={"compare": 0})
        if erase:
            lines = wrapper.splitlines()
            indices = [i for i, line in enumerate(lines) if 'summary-reference-address-match' in line]
            self.assertEqual(len(indices), 2)
            removed = {i + offset for i in indices for offset in (0, 1)}
            wrapper = '\n'.join(line for i, line in enumerate(lines) if i not in removed)
        prefix = connected_reference_transport_source() + wrapper + '''
struct fixture_service {spx_runtime *runtime; uint32_t replay;};
uint32_t spx_proof_connected_is_replay(void *opaque) {return ((struct fixture_service *)opaque)->replay;}
uint32_t spx_proof_connected_0000_begin(void *opaque) {return 0U;}
void spx_proof_connected_0000_finish(uint32_t position) {}
void spx_proof_connected_0000_replay(uint32_t position) {}
void spx_proof_connected_0000_observe_range(uint32_t position, uint64_t address, uint64_t extent) {
  __CPROVER_assert(address == 4100U && extent == 8U, "connected observation uses physical span");
}
uint8_t spx_proof_connected_impl_0000_regions_equal(spx_memory_regions_equal_context_v5 *context,
    const spx_view_v5 *left, const spx_view_v5 *right, uint32_t count) {return 1U;}
'''
        self.check('''
  struct fixture_service service = {&runtime, 0U};
  spx_memory_regions_equal_services_v5 services = {.context=&service};
  spx_memory_regions_equal_context_v5 context = {.services=&services};
  __CPROVER_assert(regions_equal(&context, &view, &view, 8U) == 1U, "exact connected call");
  service.replay = 1U;
''' + ('spx_native_release_external_range(4096U, 101U);\n' if expired else '') + '''
  spx_native_context second = spx_native_context_value;
''' + ('second.external_ranges[0].start = 8192U;\n' if moved else '') + '''
  runtime.context = &second;
  __CPROVER_assert(regions_equal(&context, &view, &view, 8U) == 1U, "source connected call");
''', prefix=prefix, failure=('summary-reference-address' if expired else
                            'summary-reference-address-match' if moved and not erase else None))

    def test_connected_observations_realize_both_worlds(self):
        self.connected()

    def test_equal_reference_metadata_cannot_hide_different_physical_mapping(self):
        self.connected(moved=True)

    def test_removed_replay_address_check_restores_false_acceptance(self):
        self.connected(moved=True, erase=True)

    def test_connected_replay_rejects_an_expired_origin_despite_equal_metadata(self):
        self.connected(expired=True)

    def test_plain_reference_observations_cover_remaining_bytes_and_canonical_null(self):
        value = SimpleNamespace(interpretation="reference", access="read", nullable=True)
        observed = '\n'.join(_observe_memory(value, "ref", "test", address_slot="saved"))
        replay = '\n'.join(_observe_memory(value, "ref", "test", address_slot="saved", replay=True))
        for null in (False, True):
            with self.subTest(null=null):
                self.check('''
  struct fixture_service {spx_runtime *runtime;} service = {&runtime};
  struct fixture_services {void *context;} services = {&service};
  struct fixture_context {struct fixture_services *services;} data = {&services}, *context = &data;
  uint32_t saved[1], position = 0U;
  spx_ref_v1 ref = ''' + ('(spx_ref_v1){0};\n' if null else 'view.base;\n') + observed + replay,
                    prefix=connected_reference_transport_source() + f'''
void test_observe_range(uint32_t position, uint64_t address, uint64_t extent) {{
  __CPROVER_assert(address == {0 if null else 4100}U && extent == {0 if null else 12}U,
      "reference observation uses the realized remaining span");
}}
''')
