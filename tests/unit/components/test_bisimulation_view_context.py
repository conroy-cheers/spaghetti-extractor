"""View reconstruction preserves the callback context and full runtime tuple."""

from __future__ import annotations

import re
import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_view_context import RUNTIME_FIELDS, view_context_proof_source
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.machine_overlay_v5 import _view_runtime_helpers
from spaghetti_extractor.components.machine_overlay_logical_views_v5 import VIEW_CONTEXT_DECLARATION
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header

TESTKIT = {"fixtures": ("cbmc", "compiler")}


class ViewContextTests(unittest.TestCase):
    def test_snapshot_inventory_covers_every_runtime_member(self):
        body = exact_runtime_header().split("struct spx_runtime {", 1)[1].split("};", 1)[0]
        fields = []
        for declaration in body.strip().rstrip(";").split(";"):
            pointer = re.search(r"\(\*([a-z_]+)\)", declaration)
            fields.append(pointer.group(1) if pointer else declaration.strip().split()[-1].lstrip("*"))
        self.assertEqual(tuple(fields), RUNTIME_FIELDS)
        self.assertTrue("\n".join(_view_runtime_helpers(need_read=True, need_write=True)).startswith(
            VIEW_CONTEXT_DECLARATION))

    def test_context_contents_and_runtime_dispatch_must_reconstruct(self):
        cbmc = shutil.which("cbmc")
        self.assertIsNotNone(cbmc)
        cases = [
            ("", "&context", 16384, 4, True),
            ("context.address += 4U;", "&context", 16384, 4, False),
            ("context.address += 4U;", "&context", 16388, 4, True),
            ("context.extent = 2U;", "&context", 16384, 4, False),
            ("context.extent = 2U;", "&context", 16384, 2, True),
            ("context.permissions = 1U;", "&context", 16384, 4, False),
            ("context.permissions = 1U; context.permissions = 3U;", "&context", 16384, 4, True),
            ("", "0", 16384, 4, False),
            ("", "&other_context", 16384, 4, False),
            ("context.runtime = &other_runtime;", "&context", 16384, 4, False),
            ("runtime.context = &other_context;", "&context", 16384, 4, False),
            ("runtime.image_base = 7U;", "&context", 16384, 4, False),
            ("runtime.read = 0;", "&context", 16384, 4, False),
            ("runtime.record_access_violation = (spx_access_violation_handler)read_word;",
             "&context", 16384, 4, False),
        ]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "state-machine-runtime.h").write_text(exact_runtime_header())
            for mutation, pointer, address, extent, expected in cases:
                with self.subTest(mutation=mutation, pointer=pointer, address=address, extent=extent):
                    source = root / "context.c"
                    source.write_text('#include "state-machine-runtime.h"\n' + view_context_proof_source() + '''
uint32_t read_word(void *opaque, uint32_t address, uint32_t width, uint32_t *fault) {
  *fault = 0U; return 7U;
}
void check(void) {
  spx_runtime runtime = {.read = read_word};
  spx_runtime other_runtime = runtime;
  spx_component_view_context context = {&runtime, 16384U, 4U, 3U};
  spx_component_view_context other_context = context;
  const __CPROVER_spx_view_context_snapshot snapshot = __CPROVER_spx_snapshot_view_context(&context);
''' + mutation + f'''
  __CPROVER_assert(__CPROVER_spx_view_context_matches(&snapshot, {pointer}, {address}U, {extent}ULL),
                   "context must reconstruct");
}}
''')
                    result = run_cbmc_properties(command=[cbmc, str(source), "--function", "check",
                        "--json-ui", "--unwind", "2", "--stop-on-fail"], timeout_seconds=10)
                    self.assertEqual(result["status"], "satisfied" if expected else "violated", result)
                    if not expected:
                        self.assertEqual(result["detail"], "context must reconstruct")
