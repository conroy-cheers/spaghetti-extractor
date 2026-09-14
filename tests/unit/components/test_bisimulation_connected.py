from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_connected import render_connected_summary_wrapper
from spaghetti_extractor.components.bisimulation_connected import (
    _connected_replay_source,
)
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.bisimulation_reference_transport import connected_reference_transport_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1,
    compile_component_interface_v5,
)
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


INTERFACE_PATH = "targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json"
TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",),
}


class ConnectedSummaryMemoryTests(unittest.TestCase):
    def _check(self, *, before: str, after: str = "", after_replay: str = "") -> dict[str, object]:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            world = _world_source(
                max_writes=3,
                max_private_writes=2,
                max_calls=1,
                max_atomics=1,
                max_shadow_bytes=2,
                max_nul_views=1,
                service_bindings=(),
                private_ranges=(),
            )
            replay = "\n".join(_connected_replay_source(
                [{"summary_id": 0, "summary_capacity": 1}],
                max_writes=3, max_calls=1, max_atomics=1,
            ))
            source = root / "memory.c"
            source.write_text(
                '#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n'
                + world + replay + '''
void main(void) {
  uint32_t fault = 0;
  spx_proof_reset_worlds(UINT32_C(8388608), UINT32_C(256));
  spx_proof_reset_connected_summaries();
  spx_runtime exact_runtime = spx_proof_runtime(&spx_exact_world);
  spx_runtime source_runtime = spx_proof_runtime(&spx_source_world);
  spx_proof_connected_service_prefix exact_service = {&exact_runtime};
  spx_proof_connected_service_prefix source_service = {&source_runtime};
''' + before + '''
  uint32_t position = spx_proof_connected_0000_begin(&exact_service);
''' + after + '''
  spx_proof_connected_0000_finish(position);
  position = spx_proof_connected_0000_begin(&source_service);
  spx_proof_connected_0000_replay(position);
  __CPROVER_assert(spx_proof_connected_summaries_equal(), "paired-calls");
''' + after_replay + '''
}
'''
            )
            return run_cbmc_properties(
                command=[cbmc, str(source), "--json-ui", "--trace",
                         "--unwind", "4", "--unwinding-assertions",
                         "--bounds-check", "--pointer-check", "--sat-solver", "cadical"],
                timeout_seconds=30,
            )

    def test_crossing_replay_updates_private_and_public_bytes(self) -> None:
        result = self._check(before='''
  spx_proof_exact_write(0, 8388863U, 1U, 0x55U, &fault);
  spx_proof_source_write(0, 8388863U, 1U, 0x55U, &fault);
''', after='''
  spx_proof_exact_write(0, 8388863U, 2U, 0x2311U, &fault);
''', after_replay='''
  __CPROVER_assert(spx_proof_source_read(0, 8388863U, 2U, &fault) == 0x2311U,
      "replayed-crossing-store");
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_equal_write_counts_do_not_authorize_different_input_memory(self) -> None:
        result = self._check(before='''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 23U, &fault);
''')
        self.assertEqual(result["status"], "violated", result)
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-memory:0")

    def test_input_snapshot_is_taken_before_connected_effects(self) -> None:
        result = self._check(
            before='''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 17U, &fault);
''',
            after='''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 23U, &fault);
''',
        )
        self.assertEqual(result["status"], "satisfied", result)

    def test_same_memory_with_different_write_order_is_admitted(self) -> None:
        result = self._check(before='''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_exact_world, 4097U, 1U, 23U, &fault);
  spx_proof_write_world(&spx_source_world, 4097U, 1U, 23U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 17U, &fault);
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_unexposed_compiler_private_memory_need_not_match(self) -> None:
        result = self._check(before='''
  spx_proof_write_world(&spx_exact_world, 8388608U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 8388608U, 1U, 23U, &fault);
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_exposed_private_input_memory_must_match(self) -> None:
        result = self._check(
            before='''
  spx_proof_write_world(&spx_exact_world, 8388608U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 8388608U, 1U, 23U, &fault);
''',
            after='''
  spx_proof_connected_0000_observe_range(position, 8388608U, 1U);
''',
        )
        self.assertEqual(result["status"], "violated", result)
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-memory:0")

    def test_partially_overlapping_writes_compare_effective_bytes(self) -> None:
        result = self._check(before='''
  spx_proof_write_world(&spx_exact_world, 4096U, 2U, 0x1711U, &fault);
  spx_proof_write_world(&spx_exact_world, 4097U, 1U, 0x23U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 2U, 0x2311U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 0x11U, &fault);
''')
        self.assertEqual(result["status"], "satisfied", result)

    def test_overwritten_extra_source_write_does_not_change_input_memory(self) -> None:
        result = self._check(
            before='''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 19U, &fault);
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 17U, &fault);
''',
            after='''
  spx_proof_write_world(&spx_exact_world, 4096U, 1U, 23U, &fault);
''',
        )
        self.assertEqual(result["status"], "satisfied", result)

    def test_same_address_does_not_hide_expired_view_generation(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        interface_path = Path(__file__).resolve().parents[3] / INTERFACE_PATH
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
            json.loads(interface_path.read_text())
        ))
        symbols = {"compare": "regions_equal"}
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for name, content in render_component_c_headers_v5(bundle, symbols).items():
                (root / name).write_text(content)
            (root / "connected-proof-summary.h").write_text(
                "#define SPX_PROOF_CONNECTED_CAPACITY 1\n"
            )
            wrapper = render_connected_summary_wrapper(
                bundle=bundle, operation_symbols=symbols, summary_ids={"compare": 0},
            )
            source = root / "generation.c"
            source.write_text('#include "state-machine-runtime.h"\n' + connected_reference_transport_source() + wrapper + '''
struct fixture_service {spx_runtime *runtime; uint32_t replay;};
static spx_boundary_status fixture_reference(void *opaque, const spx_machine_reference_v1 *ref,
    uint32_t permissions, uint32_t nullable, uint32_t one_past, uint32_t *address) {
  if (ref->domain != 1U || ref->object != 4096U || ref->generation != 1U ||
      ref->extent != 1U || ref->offset != 0U || ref->permissions != 1U || permissions != 1U)
    return SPX_BOUNDARY_MEMORY_FAULT;
  *address = 4096U; return SPX_BOUNDARY_OK;
}
uint32_t spx_proof_connected_is_replay(void *opaque) {
  return ((struct fixture_service *)opaque)->replay;
}
uint32_t spx_proof_connected_0000_begin(void *opaque) { (void)opaque; return 0; }
void spx_proof_connected_0000_finish(uint32_t p) { (void)p; }
void spx_proof_connected_0000_replay(uint32_t p) { (void)p; }
void spx_proof_connected_0000_observe_range(uint32_t p, uint64_t a, uint64_t n) {
  (void)p; (void)a; (void)n;
}
uint8_t spx_proof_connected_impl_0000_regions_equal(
    spx_memory_regions_equal_context_v5 *c,
    const spx_view_v5 *a, const spx_view_v5 *b, uint32_t count) {
  (void)c; (void)a; (void)b; (void)count; return 1;
}
void main(void) {
  spx_runtime runtime = {.realize_reference=fixture_reference};
  struct fixture_service service = {&runtime, 0U};
  spx_memory_regions_equal_services_v5 services = {0};
  services.context = &service;
  spx_memory_regions_equal_context_v5 context = {0};
  context.services = &services;
  spx_view_v5 view = {0};
  view.base.domain = 1; view.base.object = 4096; view.base.generation = 1;
  view.base.extent = 1; view.base.permissions = 1;
  view.extent = 1; view.element_width = 1;
  (void)regions_equal(&context, &view, &view, 1);
  service.replay = 1U;
  view.base.generation = 2;
  (void)regions_equal(&context, &view, &view, 1);
}
''')
            result = run_cbmc_properties(
                command=[cbmc, str(source), "--json-ui", "--trace",
                         "--bounds-check", "--pointer-check", "--sat-solver", "cadical"],
                timeout_seconds=30,
            )
        self.assertEqual(result["status"], "violated", result)
        self.assertEqual(result["detail"], "spx-bisimulation-connected-summary-input:0")


if __name__ == "__main__":
    unittest.main()
