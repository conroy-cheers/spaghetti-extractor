"""Solver checks of the fixed readable-input domain and empty frame."""
from __future__ import annotations

import copy
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary.model import BoundarySchemaV1
from spaghetti_extractor.components.bisimulation_readonly_model import (
    fixed_readonly_summary_operations, render_readonly_source_model,
)
from spaghetti_extractor.components.cbmc_backend import run_cbmc_properties
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.transfer.runtime_abi import exact_runtime_header
from tests.unit.components.test_bisimulation_readonly_summary import readonly_bundle


TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}
COMPARISON = '''
  (void)context;
  if (count > left->extent || count > right->extent) return 0;
  if (left == right) return 1;
  for (uint32_t i=0; i<count; ++i) {
    uint8_t a,b;
    if (spx_view_read_u8(left,i,&a) || spx_view_read_u8(right,i,&b)) return 0;
    if (a!=b) return 0;
  }
  return 1;
'''


def fixed_readonly_bundle(extents=(4, 4)):
    intent = readonly_bundle().intent
    schema = intent.schema.to_payload()
    signatures = copy.deepcopy(schema["signatures"])
    for signature in signatures:
        if signature["id"] == "operation.compare":
            for index, extent in enumerate(extents):
                signature["parameters"][index]["extent"] = {"kind": "fixed", "bytes": extent, "value_id": None}
    operations = copy.deepcopy(list(intent.operations))
    for index, extent in enumerate(extents):
        operations[0]["source_values"][index]["extent"] = {"kind": "fixed", "bytes": extent, "value_id": None}
    return compile_component_interface_v5(ComponentInterfaceIntentV1.create(
        component_id=intent.component_id,
        schema=BoundarySchemaV1.create(schema_id=intent.schema.schema_id, types=intent.schema.types, signatures=signatures),
        state=(), operations=operations, effects=(), services=(),
        protocol_states=intent.protocol_states, initial_protocol_state=intent.initial_protocol_state,
    ))


def check_model(root: Path, body: str, *, frame=False, model_transform=None, extents=(4, 4),
                bundle=None, renderer=render_readonly_source_model, unwind=6):
    bundle = fixed_readonly_bundle(extents) if bundle is None else bundle
    root.mkdir(parents=True, exist_ok=True)
    _write_cbmc_stdint(root / "stdint.h")
    (root / "stddef.h").write_text("typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
    (root / "state-machine-runtime.h").write_text(exact_runtime_header())
    for name, source in render_component_c_headers_v5(bundle, {"compare": "regions_equal"}).items():
        (root / name).write_text(source)
    generated, entry = renderer(bundle=bundle, operation_id="compare", symbol="regions_equal",
                                                  kind="frame" if frame else "input_dependence")
    if model_transform:
        generated = model_transform(generated)
    (root / "model.c").write_text(generated)
    (root / "author.c").write_text('''#include "portable-component-implementation.h"
uint8_t regions_equal(spx_memory_regions_equal_context_v5 *context,
 const spx_view_v5 *left, const spx_view_v5 *right, uint32_t count) {
''' + body + '\n}\n')
    command = [shutil.which("goto-cc"), "--i386-win32", "-I", str(root), str(root / "model.c"),
               str(root / "author.c"), "--function", entry, "-o", str(root / "model.goto")]
    compiled = subprocess.run(command, capture_output=True, text=True)
    if compiled.returncode:
        raise AssertionError(compiled.stderr)
    checked = root / "model.goto"
    if frame:
        checked = root / "checked.goto"
        instrument = subprocess.run([shutil.which("goto-instrument"), "--dfcc", entry, "--enforce-contract",
            "regions_equal", str(root / "model.goto"), str(checked)], capture_output=True, text=True)
        if instrument.returncode:
            raise AssertionError(instrument.stderr)
    return run_cbmc_properties(command=[shutil.which("cbmc"), str(checked), "--function", entry,
        "--json-ui", "--trace", "--bounds-check", "--pointer-check", "--signed-overflow-check",
        "--undefined-shift-check", "--div-by-zero-check", "--unwind", str(unwind), "--unwinding-assertions",
        "--no-self-loops-to-assumptions", "--sat-solver", "cadical"], timeout_seconds=30)


class ReadonlyModelTests(unittest.TestCase):
    def check(self, body, **options):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument", "cbmc")):
            self.skipTest("CBMC tools are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            return check_model(Path(directory), body, **options)

    def test_domain_comes_from_interface_not_solver_bound(self):
        self.assertIsNone(fixed_readonly_summary_operations(readonly_bundle()))
        self.assertEqual(fixed_readonly_summary_operations(fixed_readonly_bundle()), ("compare",))

    def test_loop_with_arbitrary_count_and_related_bytes(self):
        for frame in (False, True):
            with self.subTest(frame=frame):
                result = self.check(COMPARISON, frame=frame)
                self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_private_context_and_nondeterministic_result_reject(self):
        for body in ('return context->state.reserved;', 'uint8_t arbitrary; return arbitrary;'):
            with self.subTest(body=body):
                self.assertEqual(self.check(body)["status"], "violated")

    def test_restored_private_write_violates_frame(self):
        result = self.check('context->state.reserved ^= 1; context->state.reserved ^= 1; return 0;', frame=True)
        self.assertEqual(result["status"], "violated", result.get("detail"))
        self.assertIn("assignable", result["detail"])

    def test_loop_without_progress_rejects(self):
        self.assertEqual(self.check('while (1) {} return 0;')["status"], "violated")

    def test_descriptor_aliases_and_large_scalar_values_are_admitted(self):
        for assertion in ('left != right', 'count <= 4U'):
            with self.subTest(assertion=assertion):
                result = self.check(f'__CPROVER_assert({assertion}, "domain must remain open"); return 0;')
                self.assertEqual(result["status"], "violated")

    def test_distinct_descriptor_extents_and_read_fault_outcome(self):
        result = self.check('uint8_t byte; return spx_view_read_u8(left,count,&byte);', extents=(3, 4))
        self.assertEqual(result["status"], "satisfied", result.get("detail"))

    def test_byte_map_correspondence_is_necessary(self):
        def separate_bytes(source):
            source = source.replace('uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t);',
                'uint8_t __CPROVER_uninterpreted_readonly_byte(uint32_t, uint32_t);\nstatic uint32_t spx_side;')
            source = source.replace('__CPROVER_uninterpreted_readonly_byte(address+i)',
                                    '__CPROVER_uninterpreted_readonly_byte(address+i, spx_side)')
            return source.replace('  uint8_t spx_result_right', '  spx_side=1U;\n  uint8_t spx_result_right')
        result = self.check('uint8_t byte; spx_view_read_u8(left,0,&byte); return byte;', model_transform=separate_bytes)
        self.assertEqual(result["status"], "violated")
