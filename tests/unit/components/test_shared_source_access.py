"""Real hand-authored state/service source retains opaque transport boundaries."""

import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_readonly_access import (
    SHARED_ACCESS_POLICY, check_memory_source_access,
)
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from .test_hand_defined_boundaries import FIXTURE, shared_buffer_bundle

TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("tests/fixtures/hand-defined-boundaries/resource-text",)}


class SharedSourceAccessTests(unittest.TestCase):
    def inventory(self, source):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument")):
            self.skipTest("CBMC compiler tools are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "stddef.h").write_text("typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
            for name, text in render_component_c_headers_v5(shared_buffer_bundle(), {"get": "resource_text"}).items():
                (root / name).write_text(text)
            (root / "author.c").write_text(source)
            compiled = subprocess.run([shutil.which("goto-cc"), "--i386-win32", "-I", str(root),
                str(root / "author.c"), "--function", "resource_text", "-o", str(root / "author.goto")],
                capture_output=True, text=True, timeout=30)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            inventory = subprocess.run([shutil.which("goto-instrument"), "--show-goto-functions", "--json-ui",
                str(root / "author.goto")], capture_output=True, text=True, check=True, timeout=30)
            return next(row["functions"] for row in json.loads(inventory.stdout) if "functions" in row)

    def check(self, source, *, shared=True):
        return check_memory_source_access(self.inventory(source), operation_symbols=("resource_text",),
            context_tag="tag-spx_resource_text_context_v5", mutable=True,
            boundary_bundle=shared_buffer_bundle() if shared else None)

    def test_actual_helper_admits_logical_state_and_its_own_service_transport(self):
        source = (FIXTURE / "resource-text.c").read_text()
        result = self.check(source)
        self.assertEqual(result["status"], "satisfied", result["issues"])
        self.assertEqual(result["policy"], SHARED_ACCESS_POLICY)
        self.assertEqual(result["interface_sha256"], shared_buffer_bundle().interface.interface_sha256)
        self.assertEqual(result["call_edges"], [["resource_text", "service:load_string"]])
        self.assertFalse(result["authorizing"])
        # A new opacity rule does not silently widen the stateless certificate.
        self.assertEqual(self.check(source, shared=False)["status"], "incomplete")

    def test_private_context_and_service_representation_observations_reject(self):
        expressions = (
            "(uint32_t)context->services->context",
            "context->services->load_string == 0",
            "context->protocol_state",
            "(uint32_t)&context->state.buffer.base",
            "context->state.buffer.access_context == context->state.module.access_context",
        )
        original = (FIXTURE / "resource-text.c").read_text()
        for expression in expressions:
            with self.subTest(expression=expression):
                source = original.replace("uint64_t module;", "uint64_t module; id += " + expression + ";")
                self.assertEqual(self.check(source)["status"], "incomplete")

    def test_service_context_substitution_and_callback_escape_reject(self):
        source = (FIXTURE / "resource-text.c").read_text()
        wrong = source.replace("context->services->context,", "context->state.buffer.access_context,")
        self.assertEqual(self.check(wrong)["status"], "incomplete")
        escaped = source.replace("uint64_t module;", "uint64_t module; void *escaped = context->services->context; (void)escaped;")
        self.assertEqual(self.check(escaped)["status"], "incomplete")

    def test_whole_context_copy_and_hidden_helper_observation_reject(self):
        source = (FIXTURE / "resource-text.c").read_text()
        copied = source.replace("uint64_t module;", "uint64_t module; spx_resource_text_context_v5 copied = *context; (void)copied;")
        self.assertEqual(self.check(copied)["status"], "incomplete")
        hidden = source.replace("spx_view_v5 resource_text", '''
#line 1 "trusted-boundary-runtime.c"
static uint32_t hidden(const spx_view_v5 *v) { return (uint32_t)v->access_context; }
spx_view_v5 resource_text''').replace("uint64_t module;", "uint64_t module; id += hidden(&context->state.buffer);")
        self.assertEqual(self.check(hidden)["status"], "incomplete")
