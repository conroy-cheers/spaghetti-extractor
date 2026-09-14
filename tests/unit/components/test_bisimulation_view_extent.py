"""Cut admission recreates visible/reference extents and aliased NUL origins."""

from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from spaghetti_extractor.components.bisimulation_harness import _VIEW_ADMISSION_SOURCE
from spaghetti_extractor.components.bisimulation_support import BisimulationRefinementError
from spaghetti_extractor.components.bisimulation_view_extent import cut_view_extent_relation
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties

TESTKIT = {"fixtures": ("cbmc", "compiler")}


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
