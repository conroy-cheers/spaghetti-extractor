"""Source-package binding and vetoes for the local read-only contract checker."""
from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.components.bisimulation_readonly_contracts import check_readonly_source_contracts
from spaghetti_extractor.components.source import build_component_source_package
from tests.unit.components.test_bisimulation_readonly_model import COMPARISON, fixed_readonly_bundle


TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


def check_source(root: Path, body=COMPARISON, *, prefix="", output_name="proof", timings=None, bundle=None,
                 checker=check_readonly_source_contracts):
    root.mkdir(parents=True, exist_ok=True)
    source = root / "authored.c"
    source.write_text('#include "portable-component-implementation.h"\n' + prefix + '''
uint8_t regions_equal(spx_memory_regions_equal_context_v5 *context,
 const spx_view_v5 *left, const spx_view_v5 *right, uint32_t count) {
''' + body + '\n}\n')
    build_component_source_package(lift_unit_id="memory-regions-equal", files={"authored.c": source},
        shared_inputs={}, operation_symbols={"compare": "regions_equal"}, out_dir=root / "source")
    return checker(bundle=fixed_readonly_bundle() if bundle is None else bundle, package=root / "source",
        output=root / output_name, goto_cc=Path(shutil.which("goto-cc")),
        goto_instrument=Path(shutil.which("goto-instrument")), cbmc=Path(shutil.which("cbmc")),
        timeout_seconds=30, unwind=6, timings=timings)


class ReadonlyContractTests(unittest.TestCase):
    def setUp(self):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc")):
            self.skipTest("CBMC tools are unavailable")

    def test_checked_loop_binds_sources_models_and_complete_options(self):
        with tempfile.TemporaryDirectory() as directory:
            timings = []
            result = check_source(Path(directory), timings=timings)
        self.assertEqual(result["status"], "satisfied", [(row.get("kind"), row.get("detail")) for row in result["checks"]])
        self.assertIs(result["authorizing"], False)
        self.assertEqual(result["receipt_sha256"], canonical_sha256_v3({key: value for key, value in result.items() if key != "receipt_sha256"}))
        self.assertEqual({row["kind"] for row in result["checks"]}, {"source_opacity", "frame", "input_dependence"})
        self.assertEqual({row["phase"] for row in timings}, {"preparation", "compiler", "model", "solver"})
        self.assertNotIn("timings", result)
        self.assertIn("--no-self-loops-to-assumptions", result["checker_options"])
        self.assertIn("--unwinding-assertions", result["checker_options"])
        self.assertTrue(any(row["kind"] == "loops" and row["rows"] for row in result["inventories"]))

    def test_transport_observation_rejects_before_solver(self):
        with tempfile.TemporaryDirectory() as directory:
            timings = []
            result = check_source(Path(directory), 'return left->context == right->context;', timings=timings)
        self.assertEqual(result["status"], "incomplete")
        self.assertFalse(any(row["phase"] == "solver" for row in timings))

    def test_source_intrinsics_reject_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check_source(Path(directory), '__CPROVER_assume(0); return 0;')
            self.assertFalse((Path(directory) / "proof").exists())
        self.assertEqual(result["code"], "readonly_summary_source_profile_rejected")

    def test_recursive_source_requires_an_inductive_rule(self):
        with tempfile.TemporaryDirectory() as directory:
            result = check_source(Path(directory), 'return regions_equal(context,left,right,count);')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("code") == "readonly_contract_recursion_unsupported" for row in result["checks"]))

    def test_unbound_included_header_rejects_before_compilation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside.h").write_text("#define OUTSIDE 7\n")
            result = check_source(root / "check", 'return OUTSIDE;', prefix=f'#include "{root / "outside.h"}"\n')
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any(row.get("code") == "readonly_contract_unbound_include" for row in result["checks"]))
        self.assertFalse(any(row["step"] == "authored-compile" for row in result["commands"]))

    def test_source_edit_changes_exact_binding(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = check_source(root / "first", 'return 0;')
            second = check_source(root / "second", 'return 1;')
        self.assertEqual((first["status"], second["status"]), ("satisfied", "satisfied"))
        self.assertEqual(first["interface_sha256"], second["interface_sha256"])
        self.assertNotEqual(first["source_package"]["implementation_sha256"], second["source_package"]["implementation_sha256"])
        self.assertNotEqual(first["receipt_sha256"], second["receipt_sha256"])
