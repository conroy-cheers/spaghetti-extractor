"""Cut admission recreates visible/reference extents and aliased NUL origins."""

from __future__ import annotations

import shutil
import json
import tempfile
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.components.bisimulation_harness import _VIEW_ADMISSION_SOURCE
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_view_extent import cut_view_extent_relation, shared_view_initialization, shared_view_admission_source
from spaghetti_extractor.components.bisimulation import ComponentBisimulationIntentV1
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.interface_ir import ProofKernelComponentInterface
from spaghetti_extractor.components.refinement_v5 import _logical_projection
from spaghetti_extractor.components.machine_binding import MachineProjectionV1
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {"fixtures": ("cbmc", "compiler"), "resources": (
    "targets/gnu-hello/intent/bisimulation/bounded-string-length.json",
    "targets/gnu-hello/intent/bindings-v5/bounded-string-length.json",
    "targets/gnu-hello/intent/interfaces-v5/bounded-string-length.json",
    "targets/gnu-hello/intent/bisimulation/ascii-string-compare.json",
)}


def _register(name):
    return {"kind": "register", "register": name, "width": 32, "at": "entry"}


def _constant(value):
    return {"kind": "constant", "width": 32, "value": value}


def _capture(identity, projection):
    return SimpleNamespace(identity=identity, kind="parameter", mode="machine_codec", projection=projection)


def _sync(*, bounded=False, bounded_text=False, text_minimum=None):
    text = _capture("text", {"kind": "bytes_view", "base": _register("esi"),
                             "extent_id": "length" if bounded_text else None})
    if text_minimum is not None:
        text.projection = {"kind": "view", "base": _register("esi"),
                           "requested_extent": _constant(text_minimum),
                           "extent": {"kind": "origin_remainder"}}
    count = _capture("count", {"kind": "bytes_view", "base": _register("ebx"), "extent_id": "length"}
                     if bounded else {"kind": "view", "base": _register("ebx"),
                                      "requested_extent": _constant(4), "extent": _constant(4)})
    return SimpleNamespace(captures=[text, count, _capture("length", _register("ecx"))], private_stack_scope=None)


class ViewExtentTests(unittest.TestCase):
    def test_hello_compare_preserves_scope_below_and_above_image(self):
        path = Path(__file__).parents[3] / TESTKIT["resources"][3]
        sync = ComponentBisimulationIntentV1.parse(json.loads(path.read_text())).operations[0].syncs[0]
        self.assertEqual(sync.private_stack_scope.to_payload(), {"register": "esp", "offset": 28})
        admission = shared_view_admission_source(private_ranges=(), image_base=4194304, image_size=217088)
        # Retained left/right capture counterexamples: three pushes and SUB ESP,16.
        # One crosses minimum ESP; the other crosses the whole-image exclusion.
        cases = ((1051, 4335104, 5632, 4325378, 23041, 24),
                 (4412429, 4331136, 1664, 4395010, 9728, 477))
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "compare-scope.c"
            for entry, left_address, left_offset, right_address, left_nul, right_nul in cases:
                with self.subTest(entry=entry):
                    checks = []
                    for capture in sync.captures[:2]:
                        arguments = dict(capture=capture, nul_view_ids=frozenset({"left", "right"}),
                                         state="reached", read="exact_read", native=True)
                        relation = cut_view_extent_relation(sync=sync, **arguments)
                        unscoped = cut_view_extent_relation(sync=replace(sync, private_stack_scope=None), **arguments)
                        name = capture.identity
                        checks.extend([
                            f'__CPROVER_assert(({relation}), "{name} retains invocation scope");',
                            f'__CPROVER_assert(!({unscoped}), "{name} rejects current ESP anchor");',
                            f'{name}->extent += 1U;',
                            f'__CPROVER_assert(!({relation}), "{name} rejects altered extent");',
                            f'{name}->extent -= 1U;',
                            'terminator = 1U;',
                            f'__CPROVER_assert(!({relation}), "{name} rejects nonzero terminator");',
                            'terminator = 0U;',
                        ])
                    source.write_text('''#include <stdint.h>
const uint32_t spx_proof_private_high_offset = 4096U;
''' + admission + f'''
static uint32_t terminator;
uint32_t exact_read(uint32_t address, uint32_t width) {{
  if (width == 4U && address == {entry + 4}U) return {left_address}U;
  if (width == 4U && address == {entry + 8}U) return {right_address}U;
  return terminator;
}}
uint32_t spx_proof_source_output_read(uint32_t address, uint32_t width) {{ return terminator; }}
uint32_t __CPROVER_uninterpreted_spx_nul_extent(uint32_t address);
void check(void) {{
  struct {{ uint32_t esp; }} reached = {{{entry - 28}U}};
  struct view {{ struct {{ uint64_t extent, offset; }} base; uint64_t extent; }}
      l = {{{{29184ULL, {left_offset}ULL}}, {29184 - left_offset}ULL}},
      r = {{{{512ULL, 2ULL}}, 510ULL}}, *left = &l, *right = &r;
  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent({left_address}U) == {left_nul}U);
  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent({right_address}U) == {right_nul}U);
  {''.join(checks)}
}}
''')
                    result = run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--function", "check",
                        "--json-ui", "--unwind", "2", "--stop-on-fail", "--bounds-check", "--pointer-check"],
                        timeout_seconds=10)
                    self.assertEqual(result["status"], "satisfied", result)

    def test_hello_capture_preserves_invocation_scope_after_saved_register_push(self):
        path = Path(__file__).parents[3] / "targets/gnu-hello/intent/bisimulation/bounded-string-length.json"
        sync = ComponentBisimulationIntentV1.parse(json.loads(path.read_text())).operations[0].syncs[0]
        self.assertEqual(sync.private_stack_scope.to_payload(), {"register": "esp", "offset": 4})
        arguments = dict(capture=sync.captures[0], nul_view_ids=frozenset(),
                         state="reached", read="exact_read", native=True)
        relation = cut_view_extent_relation(sync=sync, **arguments)
        unscoped = cut_view_extent_relation(sync=replace(sync, private_stack_scope=None), **arguments)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "scope.c"
            source.write_text('''#include <stdint.h>
const uint32_t spx_proof_private_high_offset = 4096U;
''' + _VIEW_ADMISSION_SOURCE + f'''
void check(void) {{
  /* Retained predecessor counterexample: entry ESP 1025, then PUSH EBX. */
  struct {{ uint32_t ebx, ecx, esp; }} reached = {{4345860U, 256U, 1021U}};
  struct {{ struct {{ uint64_t extent, offset; }} base; uint64_t extent; }}
      value = {{{{29184ULL, 16388ULL}}, 256ULL}}, *buffer = &value;
  __CPROVER_assert(({relation}), "captured view retains the invocation scope");
  __CPROVER_assert(!({unscoped}), "current ESP cannot replace the invocation anchor");
  buffer->extent = 257ULL;
  __CPROVER_assert(!({relation}), "transport still rejects a changed visible extent");
}}
''')
            result = run_cbmc_properties(command=[shutil.which("cbmc"), str(source), "--function", "check",
                "--json-ui", "--unwind", "2", "--stop-on-fail"], timeout_seconds=10)
            self.assertEqual(result["status"], "satisfied", result)

    def test_hello_scan_cut_uses_captured_base_and_extent(self):
        root = Path(__file__).parents[3] / "targets/gnu-hello/intent"
        def read(folder):
            return json.loads((root / folder / "bounded-string-length.json").read_text())
        intent = ComponentBisimulationIntentV1.parse(read("bisimulation"))
        bundle = compile_component_interface_v5(ComponentInterfaceIntentV1.parse(read("interfaces-v5")))
        interface = ProofKernelComponentInterface.parse(_logical_projection(bundle))
        projection = read("bindings-v5")["operations"][0]["machine_projection"]["operation"]
        sync = intent.operations[0].syncs[0]
        arguments = dict(interface=interface, operation_id="length", operation_projection=projection,
                         proof_function="scan")
        rendered = "\n".join(shared_view_initialization(sync=sync, **arguments))
        def unparenthesized(value):
            return value.replace("(", "").replace(")", "")
        self.assertIn("__CPROVER_spx_view_base_0 = uint32_tinitial_state.ebx", unparenthesized(rendered))
        self.assertIn("__CPROVER_spx_view_extent_0 = uint64_tinitial_state.ecx", unparenthesized(rendered))
        relation = cut_view_extent_relation(sync=sync, capture=sync.captures[0],
            nul_view_ids=frozenset(), state="reached", read="exact_read")
        self.assertIn("buffer->base.extent == uint64_treached.ecx", unparenthesized(relation))
        self.assertIn("buffer->extent == uint64_treached.ecx", unparenthesized(relation))
        bare = replace(sync.captures[0], projection=MachineProjectionV1.parse(
            sync.captures[0].projection.payload["base"], "old bare buffer capture"))
        with self.assertRaisesRegex(BisimulationRefinementError, "requires a captured view"):
            shared_view_initialization(sync=replace(sync, captures=(bare, *sync.captures[1:])), **arguments)

    def test_missing_canonical_inputs_fail_closed(self):
        sync = _sync(bounded=True)
        for mutation in ("nul", "length"):
            with self.subTest(mutation=mutation):
                changed = SimpleNamespace(captures=[c for c in sync.captures if c.identity != mutation])
                with self.assertRaises(BisimulationRefinementError):
                    cut_view_extent_relation(sync=changed, capture=sync.captures[1],
                        nul_view_ids=frozenset({"nul" if mutation == "nul" else "text"}),
                        state="machine", read="exact_read")

    def test_extent_aliases_and_nul_admission(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        defaults = dict(alias=False, nul=8, text_reference=8, text_visible=8,
                        count_reference=4, count_visible=4, bounded=False,
                        bounded_text=False, text_minimum=None, length=4, exact_end=0, source_end=0,
                        text_address=16384, esp=5120, valid=True)
        cases = [
            {},  # Earlier zero bytes are permitted: only the declared end is checked.
            dict(alias=True, nul=2, text_reference=2, text_visible=2),
            dict(alias=True, count_reference=8),
            dict(alias=True, count_reference=4, valid=False),
            dict(alias=True, count_reference=8, count_visible=8, valid=False),
            dict(text_visible=4, valid=False),
            dict(nul=0, text_reference=1, text_visible=1, valid=False),
            dict(exact_end=1, valid=False),
            dict(source_end=1, valid=False),
            dict(text_address=10000, esp=9000, valid=False),
            dict(text_address=0xfffffffc, valid=False),
            dict(text_address=0xfffffff8),
            dict(text_minimum=4),
            dict(text_minimum=4, nul=2, text_reference=4, text_visible=4, valid=False),
            dict(bounded=True, length=5, count_reference=5, count_visible=5),
            dict(bounded=True, length=5, count_reference=5, count_visible=4, valid=False),
            dict(bounded=True, length=0, count_reference=0, count_visible=0),
            dict(bounded=True, alias=True, length=5, count_reference=8, count_visible=5),
            dict(bounded_text=True, length=0, text_visible=0),
        ]
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "extent.c"
            for overrides in cases:
                case = {**defaults, **overrides}
                with self.subTest(**overrides):
                    sync = _sync(bounded=case["bounded"], bounded_text=case["bounded_text"],
                                 text_minimum=case["text_minimum"])
                    relations = [cut_view_extent_relation(sync=sync, capture=capture,
                        nul_view_ids=frozenset({"text"}), state="machine", read="exact_read")
                        for capture in sync.captures[:2]]
                    source.write_text('''#include <stdint.h>
const uint32_t spx_proof_private_high_offset = 4096U;
''' + _VIEW_ADMISSION_SOURCE + f'''
uint32_t __CPROVER_uninterpreted_spx_nul_extent(uint32_t address);
uint32_t exact_read(uint32_t address, uint32_t width) {{ return {case['exact_end']}U; }}
uint32_t spx_proof_source_output_read(uint32_t address, uint32_t width) {{ return {case['source_end']}U; }}
typedef struct {{ struct {{ uint64_t extent; }} base; uint64_t extent; }} view;
void check(void) {{
  struct {{uint32_t esi, ebx, ecx, esp;}} machine = {{
    {case['text_address']}U, {case['text_address'] if case['alias'] else 16416}U,
    {case['length']}U, {case['esp']}U }};
  __CPROVER_assume(__CPROVER_uninterpreted_spx_nul_extent(machine.esi) == {case['nul']}U);
  view text_value = {{{{ {case['text_reference']}ULL }}, {case['text_visible']}ULL}};
  view count_value = {{{{ {case['count_reference']}ULL }}, {case['count_visible']}ULL}};
  view *text = &text_value, *count = &count_value;
  __CPROVER_assert(({relations[0]}) && ({relations[1]}), "cut extents must reconstruct");
}}
''')
                    result = run_cbmc_properties(command=[cbmc, str(source), "--function", "check",
                        "--json-ui", "--unwind", "2", "--stop-on-fail"], timeout_seconds=10)
                    self.assertEqual(result["status"], "satisfied" if case["valid"] else "violated", result)
                    if not case["valid"]:
                        self.assertEqual(result["detail"], "cut extents must reconstruct")
