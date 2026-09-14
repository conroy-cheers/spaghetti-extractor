from __future__ import annotations

import shutil
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import (
    ComponentInterfaceIntentV1, compile_component_interface_v5,
)
from spaghetti_extractor.components.machine_overlay_logical_views_v5 import bounded_view_argument_lines
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header


TESTKIT = {
    "fixtures": ("cbmc", "compiler"),
    "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",),
}


class ProofReferenceTests(unittest.TestCase):
    def test_connected_subview_rebuilds_access_and_rejects_invalid_origins(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        interface = Path(__file__).resolve().parents[3] / TESTKIT["resources"][0]
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(
            json.loads(interface.read_text())
        ))
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for name, content in render_component_c_headers_v5(bundle, {"compare": "compare"}).items():
                (root / name).write_text(content)
            source = root / "subviews.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                             '#include "portable-component-implementation.h"\n'
                             '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + _world_source(
                max_writes=2, max_private_writes=1, max_calls=1, max_atomics=1,
                max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
            ) + '\n' + '\n'.join(_view_runtime_helpers(need_read=True, need_write=False)) + '''
typedef struct { spx_runtime *runtime; uint32_t *service_fault; } service;
uint32_t admitted;
uint8_t adapt(service *caller, const spx_view_v5 *input, uint32_t count) {
''' + '\n'.join(bounded_view_argument_lines(
                name="input", extent="(uint64_t)count", access="read", selector="0",
                zero_result="return 0;",
            )) + '''
  uint8_t byte = 0;
  uint64_t wide = 0;
  ++admitted;
  __CPROVER_assert(input_argument->base.object == 4100U &&
      input_argument->base.offset == 0U && input_argument->base.extent == count,
      "canonical requested span");
  __CPROVER_assert(input_argument->read_u8(input_argument->context, 0, &byte) == 0
      && byte == 23U, "subview reads its own first byte");
  __CPROVER_assert(input_argument->read(input_argument->access_context,
      input_argument->base, 0, 1, &wide) == 0 && wide == 23U,
      "span reader uses rebuilt context");
  __CPROVER_assert(input_argument->read_u8(input_argument->context, count, &byte) != 0,
      "bounded callback rejects overread");
  return 1;
}
void main(void) {
  uint32_t fault = 0U;
  spx_proof_reset_worlds(8388608U, 256U);
  spx_runtime runtime = spx_proof_runtime(&spx_source_world);
  service caller = {&runtime, &fault};
  spx_machine_reference_v1 issued;
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, 4096U, 16U,
      1U, 0, 0U, 0U, &issued) == SPX_BOUNDARY_OK, "issue original view");
  spx_proof_write_world(&spx_source_world, 4096U, 1U, 17U, &fault);
  spx_proof_write_world(&spx_source_world, 4100U, 1U, 23U, &fault);
  spx_component_view_context original_context = {&runtime, 4096U, 16U, 1U};
  spx_view_v5 view = {0};
  view.base = (spx_ref_v1){1, 4096, 1, 4, 16, 1};
  view.extent = 12; view.element_width = 1;
  view.context = &original_context; view.read_u8 = spx_component_view_read;
  __CPROVER_assert(adapt(&caller, &view, 7) == 1 && fault == 0, "valid subview");
  view.base = (spx_ref_v1){1, 4100, 1, 0, 7, 1}; view.extent = 7;
  __CPROVER_assert(adapt(&caller, &view, 7) == 1 && fault == 0, "canonical view");
  view.base.generation = 2;
  __CPROVER_assert(adapt(&caller, &view, 7) == 0 && fault != 0, "expired origin");
  view.base.generation = 1; fault = 0; view.base.permissions = 0;
  __CPROVER_assert(adapt(&caller, &view, 7) == 0 && fault != 0, "read denied");
  view.base.permissions = 1; fault = 0; view.extent = 6;
  __CPROVER_assert(adapt(&caller, &view, 7) == 0 && fault != 0, "view too short");
  view.extent = 7; fault = 0; view.base.extent = 6;
  __CPROVER_assert(adapt(&caller, &view, 7) == 0 && fault != 0, "origin too short");
  view.base.extent = 100; fault = 0;
  __CPROVER_assert(adapt(&caller, &view, 7) == 0 && fault != 0, "forged larger origin");
  __CPROVER_assert(admitted == 2, "invalid views never reach child");
}
''')
            result = run_cbmc_properties(
                command=[cbmc, str(source), "--json-ui", "--unwind", "4",
                         "--unwinding-assertions", "--bounds-check", "--pointer-check",
                         "--sat-solver", "cadical"], timeout_seconds=30,
            )
            self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_realization_checks_metadata_before_returning_an_address(self) -> None:
        cbmc = shutil.which("cbmc")
        if cbmc is None:
            self.skipTest("CBMC is unavailable")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "references.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                             '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + _world_source(
                max_writes=1, max_private_writes=1, max_calls=1, max_atomics=1,
                max_shadow_bytes=1, max_nul_views=1, service_bindings=(), private_ranges=(),
            ) + '''
void main(void) {
  spx_machine_reference_v1 ref = {1, 4096, 1, 4, 16, 1};
  uint32_t address = 99U;
  spx_machine_reference_v1 issued;
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, 4096U, 16U,
      1U, 0, 0U, 0U, &issued) == SPX_BOUNDARY_OK, "issue origin");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 0, &address)
      == SPX_BOUNDARY_OK && address == 4100U, "interior reference");
  ref.generation = 2;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 0, &address)
      == SPX_BOUNDARY_EXPIRED, "stale generation");
  ref.generation = 1; ref.domain = 2;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 0, &address)
      != SPX_BOUNDARY_OK, "foreign domain");
  ref.domain = 1;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 2, 0, 0, &address)
      != SPX_BOUNDARY_OK, "missing write permission");
  ref.offset = 17;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 1, &address)
      != SPX_BOUNDARY_OK, "outside object");
  ref.offset = 16;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 0, &address)
      != SPX_BOUNDARY_OK, "one past denied");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 1, &address)
      == SPX_BOUNDARY_OK && address == 4112U, "one past admitted");
  ref.object = 4294967295ULL; ref.offset = 0; ref.extent = 2;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 0, &address)
      != SPX_BOUNDARY_OK, "object exceeds address space");
  ref = (spx_machine_reference_v1){0};
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 1, 0, &address)
      == SPX_BOUNDARY_OK && address == 0U, "canonical null");
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 0, 0, &address)
      != SPX_BOUNDARY_OK, "nonnullable null");
  ref.extent = 1;
  __CPROVER_assert(spx_proof_realize_reference(&spx_source_world, &ref, 1, 1, 0, &address)
      != SPX_BOUNDARY_OK, "malformed null");
  spx_machine_reference_v1 exact_view, source_view;
  spx_proof_register_nul_view(8192U, 8U);
  __CPROVER_assert(spx_proof_resolve_reference(&spx_exact_world, 8192U, 7U,
      1U, 0, 0U, 0U, &exact_view) == SPX_BOUNDARY_OK, "exact known origin");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, 8192U, 7U,
      1U, 0, 0U, 0U, &source_view) == SPX_BOUNDARY_OK, "source known origin");
  __CPROVER_assert(exact_view.extent == source_view.extent && exact_view.extent >= 8U,
      "origin metadata is shared between worlds");
  /* A short NUL view can alias a larger fixed view. The declared fixed range
     remains admitted by the shared arbitrary-public-memory model. */
  spx_source_world.nul_view_extents[0] = 1U;
  spx_exact_world.nul_view_extents[0] = 1U;
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, 8192U, 4U,
      1U, 0, 0U, 0U, &source_view) == SPX_BOUNDARY_OK && source_view.extent == 4U,
      "fixed view is not shortened by an aliased NUL view");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_exact_world, 8192U, 1U,
      1U, 0, 0U, 0U, &exact_view) == SPX_BOUNDARY_OK && exact_view.extent == 1U,
      "short view keeps its own extent");
}
''')
            result = run_cbmc_properties(
                command=[cbmc, str(source), "--json-ui", "--unwind", "4",
                         "--unwinding-assertions", "--bounds-check", "--pointer-check",
                         "--sat-solver", "cadical"], timeout_seconds=30,
            )
            self.assertEqual(result["status"], "satisfied", result.get("detail"))
