"""Exposed stack bytes are shared observations, including partial aliases."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_view_extent import (
    shared_view_admission_source, shared_view_initialization,
)
from spaghetti_extractor.components.bisimulation_world import _world_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class ExposedStackTests(unittest.TestCase):
    def _check(self, body, *, failure=None, capacity=3, private_ranges=(), support=""):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            source = root / "stack.c"
            source.write_text('#include "state-machine-runtime.h"\n'
                '#define SPX_PROOF_IMAGE_BASE UINT32_C(4194304)\n' + _world_source(
                    max_writes=8, max_private_writes=8, max_calls=1, max_atomics=1,
                    max_shadow_bytes=8, max_nul_views=1, service_bindings=(),
                    private_ranges=private_ranges, exact_stack_accesses=((8, 4),),
                    max_exposed_stack_views=capacity,
                ) + 'static uint32_t spx_proof_private_high_offset = 4096U;\n' + support + '''
void check(void) {
  const uint32_t stack = 1048560U, cell = stack + 8U;
  uint32_t fault = 0U;
  spx_machine_reference_v1 reference;
  spx_proof_reset_worlds(stack, 4096U);
''' + body + '\n}\n')
            result = run_cbmc_properties(command=[cbmc, str(source), "--function", "check",
                "--json-ui", "--unwind", "4", "--unwinding-assertions", "--bounds-check",
                "--pointer-check", "--stop-on-fail"], timeout_seconds=15)
            self.assertEqual(result["status"], "satisfied" if failure is None else "violated", result)
            if failure is not None:
                self.assertEqual(result["detail"], failure)

    def test_default_world_keeps_unqualified_stack_views_private(self):
        self._check('''
  __CPROVER_assert(spx_proof_is_private(&spx_source_world, cell), "default private frame");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, cell, 4U,
      1U, 0, 0U, 0U, &reference) != SPX_BOUNDARY_OK, "no implicit exposure");
''', capacity=0)

    def test_private_range_equality_is_checked_before_exposure(self):
        for source_value in (7, 8):
            with self.subTest(source_value=source_value):
                self._check('''
  spx_proof_write_world(&spx_exact_world, cell, 4U, 7U, &fault);
  spx_proof_write_world(&spx_source_world, cell, 4U, ''' + str(source_value) + '''U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "private bytes excluded from public comparison");
  __CPROVER_assert(spx_proof_world_memory_range_equal(cell, 4U), "prospective shared range agrees");
''', capacity=0, failure=None if source_value == 7 else "prospective shared range agrees")
        self._check('''
  __CPROVER_assert(!spx_proof_world_memory_range_equal(UINT32_C(4294967293), 4U),
      "wrapping comparison rejected");
  __CPROVER_assert(spx_proof_world_memory_range_equal(cell, 0U), "empty comparison");
''', capacity=0)

    def test_caller_stack_cell_aliases_and_crossing_writes_are_observed(self):
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  __CPROVER_assert(spx_proof_is_private(&spx_exact_world, cell) == 0U &&
      spx_proof_is_private(&spx_source_world, cell + 3U) == 0U &&
      spx_proof_is_private(&spx_exact_world, cell - 1U) == 1U &&
      spx_proof_is_private(&spx_source_world, cell + 4U) == 1U, "only declared bytes are shared");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, cell, 4U,
      3U, 0, 0U, 0U, &reference) == SPX_BOUNDARY_OK, "resolve count cell at ESP plus eight");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_exact_world, cell + 2U, 2U,
      1U, 0, 0U, 0U, &reference) == SPX_BOUNDARY_OK, "overlapping input view");
  spx_proof_write_world(&spx_exact_world, cell, 4U, 0x11223344U, &fault);
  spx_proof_write_world(&spx_source_world, cell, 2U, 0x3344U, &fault);
  spx_proof_write_world(&spx_source_world, cell + 2U, 2U, 0x1122U, &fault);
  __CPROVER_assert(spx_proof_exact_read(0, cell, 4U, &fault) == 0x11223344U &&
      spx_proof_source_read(0, cell + 1U, 2U, &fault) == 0x2233U, "shared aliases see writes");
  spx_proof_write_world(&spx_exact_world, cell - 1U, 4U, 0xaabbcc11U, &fault);
  spx_proof_write_world(&spx_source_world, cell - 1U, 4U, 0xaabbcc99U, &fault);
  spx_proof_write_world(&spx_exact_world, cell + 1U, 1U, 0x77U, &fault);
  spx_proof_write_world(&spx_source_world, cell + 1U, 1U, 0x77U, &fault);
  __CPROVER_assert(spx_proof_exact_read(0, cell, 4U, &fault) == 0x11aa77ccU &&
      spx_proof_source_read(0, cell, 4U, &fault) == 0x11aa77ccU, "crossing store and cache invalidation");
  __CPROVER_assert(fault == 0U && spx_proof_world_public_memory_equal(), "shared bytes agree");
''')

    def test_omitted_stack_write_cannot_hide_in_private_history(self):
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  spx_proof_write_world(&spx_exact_world, cell, 4U, 0x11223344U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "omitted stack write");
''', failure="omitted stack write")
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  spx_proof_initialize_source(cell, 4U, 7U);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "source frame overwrote shared cell");
''', failure="source frame overwrote shared cell")

    def test_frame_reconstruction_preserves_borrowed_bytes_before_relation(self):
        for mutation in (False, True):
            with self.subTest(mutation=mutation):
                self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  uint32_t previous = spx_proof_source_read(0, cell, 1U, &fault);
  spx_proof_initialize_source(cell, 1U, previous ''' + ('^ 1U' if mutation else '') + ''');
  spx_proof_initialize_source(cell, 1U, previous);
  __CPROVER_assert(__CPROVER_spx_source_frame_preserved, "borrowed frame preserved");
  /* A later incoming relation must not erase the failed frame obligation. */
  __CPROVER_assume(spx_proof_source_read(0, cell, 1U, &fault) == previous);
''', failure="borrowed frame preserved" if mutation else None)
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  spx_proof_initialize_source(cell - 1U, 1U, 7U);
  __CPROVER_assert(__CPROVER_spx_source_frame_preserved, "private frame may be reconstructed");
''')

    def test_canonical_view_inputs_expose_full_alias_extent_at_caller_frame(self):
        register = lambda name: {"kind": "register", "register": name, "width": 32, "at": "entry"}
        constant = lambda value: {"kind": "constant", "value": value, "width": 32}
        projections = {
            "count": {"kind": "view", "base": {"kind": "offset", "at": "entry",
                "base": register("ebp"), "offset_bytes": -4},
                "requested_extent": constant(4), "extent": constant(4)},
            "text": {"kind": "bytes_view", "base": register("esi"), "extent_id": None},
        }
        interface = SimpleNamespace(
            operation_index=lambda: {"run": SimpleNamespace(parameters=[
                SimpleNamespace(identity=name, type_id=name) for name in projections])},
            type_index=lambda: {name: SimpleNamespace(nullable=False,
                nul_terminated=name == "text", extent_kind=None) for name in projections})
        operation = {"parameters": [{"id": name, "projection": projection}
                                    for name, projection in projections.items()]}
        sync = SimpleNamespace(private_stack_scope=None, captures=[SimpleNamespace(identity=name, mode="machine_codec",
            projection=SimpleNamespace(payload=projection)) for name, projection in projections.items()])
        support = shared_view_admission_source(private_ranges=(), image_base=4194304, image_size=65536)
        for start in (None, sync):
            with self.subTest(resumed=start is not None):
                initialization = shared_view_initialization(interface=interface, operation_id="run",
                    operation_projection=operation, sync=start, proof_function="check")
                self._check('''
  spx_machine_state initial_state = {0};
  initial_state.esp = stack; initial_state.ebp = stack + 12U; initial_state.esi = cell;
  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent(cell) == 8U);
''' + '\n'.join(initialization) + '''
  __CPROVER_assert(spx_proof_range_is_public(&spx_source_world, cell, 8U),
      "fixed view shares full aliased NUL reference beyond its visible four bytes");
  __CPROVER_assert(!spx_proof_range_is_public(&spx_source_world, cell, 9U), "exposure is bounded");
  spx_proof_write_world(&spx_exact_world, cell + 6U, 1U, 7U, &fault);
  __CPROVER_assert(spx_proof_world_public_memory_equal(), "omitted alias tail write");
''', capacity=2, support=support, failure="omitted alias tail write")
        for missing in ("count", "text"):
            with self.subTest(missing=missing), self.assertRaises(BisimulationRefinementError):
                shared_view_initialization(interface=interface, operation_id="run",
                    operation_projection=operation, proof_function="check",
                    sync=SimpleNamespace(captures=[c for c in sync.captures if c.identity != missing]))

    def test_shared_admission_rejects_private_objects_wrap_and_image_overlap(self):
        self._check('''
  __CPROVER_assert(spx_proof_view_admitted(cell, 4U, stack), "borrowed caller cell admitted");
  __CPROVER_assert(!spx_proof_view_admitted(0U, 4U, stack) &&
      !spx_proof_view_admitted(UINT32_C(4294967293), 4U, stack), "null and wrap rejected");
  __CPROVER_assert(!spx_proof_view_admitted(cell, 4U, 4194304U) &&
      !spx_proof_view_admitted(cell, 4U, 512U) &&
      !spx_proof_view_admitted(cell, 4U, UINT32_MAX), "valid disjoint stack required");
  __CPROVER_assert(!spx_proof_view_admitted(8190U, 4U, stack) &&
      !spx_proof_view_admitted(8195U, 1U, stack), "fixed private object protected");
  __CPROVER_assert(spx_proof_view_admitted(8196U, 1U, stack), "private range end excluded");
''', support=shared_view_admission_source(private_ranges=((8192, 4),),
                                        image_base=4194304, image_size=65536))

    def test_interval_union_is_order_independent_and_rejects_gaps(self):
        for middle, admitted in ((10, True), (11, False)):
            with self.subTest(middle=middle):
                self._check('''
  spx_proof_expose_stack_view(stack + 12U, 2U);
  spx_proof_expose_stack_view(stack + ''' + str(middle) + '''U, 2U);
  spx_proof_expose_stack_view(stack + 8U, 2U);
  __CPROVER_assert((spx_proof_resolve_reference(&spx_source_world, cell, 6U,
      1U, 0, 0U, 0U, &reference) == SPX_BOUNDARY_OK) == ''' + str(int(admitted)) + ''',
      "complete span coverage required");
''')

    def test_reference_may_cross_into_only_the_exposed_part_of_a_frame(self):
        self._check('''
  uint32_t low = stack - 1024U;
  spx_proof_expose_stack_view(low, 2U);
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, low - 2U, 4U,
      1U, 0, 0U, 0U, &reference) == SPX_BOUNDARY_OK, "public prefix and exposed suffix");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, low - 2U, 5U,
      1U, 0, 0U, 0U, &reference) != SPX_BOUNDARY_OK, "unexposed suffix is rejected");
''')

    def test_fixed_private_objects_cannot_be_exposed(self):
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  __CPROVER_assert(spx_proof_is_private(&spx_source_world, cell) == 1U,
      "owned private object retained");
  __CPROVER_assert(spx_proof_resolve_reference(&spx_source_world, cell, 4U,
      3U, 0, 0U, 0U, &reference) != SPX_BOUNDARY_OK, "private object cannot become a borrowed view");
''', private_ranges=((1048568, 4),))

    def test_exposure_after_effects_is_rejected(self):
        for effect in (
            'spx_proof_write_world(&spx_exact_world, cell, 4U, 7U, &fault);',
            'spx_proof_write_world(&spx_source_world, 8192U, 1U, 7U, &fault);',
            'spx_proof_initialize_source(cell, 4U, 7U);',
        ):
            with self.subTest(effect=effect):
                self._check(effect + '\nspx_proof_expose_stack_view(cell, 4U);',
                            failure="spx-bisimulation-exposed-stack-before-effects")

    def test_invalid_range_capacity_and_reset(self):
        for address, extent in ((0, 4), (0xfffffffd, 4)):
            with self.subTest(address=address):
                self._check(f'spx_proof_expose_stack_view({address}U, {extent}U);',
                            failure="spx-bisimulation-exposed-stack-range")
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  spx_proof_expose_stack_view(cell, 4U);
''', capacity=1, failure="spx-bisimulation-exposed-stack-capacity")
        self._check('''
  spx_proof_expose_stack_view(cell, 4U);
  spx_proof_expose_stack_view(UINT32_C(4294967292), 4U);
  __CPROVER_assert(spx_proof_range_is_public(&spx_exact_world, UINT32_C(4294967292), 4U) &&
      !spx_proof_range_is_public(&spx_exact_world, UINT32_C(4294967292), 5U) &&
      !spx_proof_range_is_public(&spx_exact_world, cell, UINT64_C(18446744073709551615)),
      "public extent cannot wrap either address width");
  __CPROVER_assert(spx_proof_range_is_public(&spx_exact_world, cell, 4U), "registered span");
  spx_proof_reset_worlds(stack, 4096U);
  __CPROVER_assert(!spx_proof_range_is_public(&spx_exact_world, cell, 4U), "exposure ends at reset");
''')


if __name__ == "__main__":
    unittest.main()
