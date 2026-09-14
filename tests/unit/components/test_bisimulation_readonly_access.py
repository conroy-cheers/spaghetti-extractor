"""Actual compiler inventories exercise the read-only transport profile."""
from __future__ import annotations

import copy
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.components.bisimulation_readonly_access import check_readonly_source_access
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.inductive_refinement import _write_cbmc_stdint
from tests.unit.components.test_bisimulation_readonly_summary import readonly_bundle

TESTKIT = {"fixtures": ("cbmc", "compiler"),
           "resources": ("targets/gnu-hello/intent/interfaces-v5/memory-regions-equal.json",)}


class ReadonlyAccessTests(unittest.TestCase):
    def inventory(self, body, *, prefix=""):
        if not all(shutil.which(tool) for tool in ("goto-cc", "goto-instrument")):
            self.skipTest("CBMC compiler tools are unavailable")
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _write_cbmc_stdint(root / "stdint.h")
            (root / "stddef.h").write_text("typedef unsigned int size_t;\ntypedef int ptrdiff_t;\n#define NULL ((void *)0)\n")
            for name, text in render_component_c_headers_v5(readonly_bundle(), {"compare": "regions_equal"}).items():
                (root / name).write_text(text)
            source = '#include "portable-component-implementation.h"\n' + prefix + '''
uint8_t regions_equal(spx_memory_regions_equal_context_v5 *context,
 const spx_view_v5 *left, const spx_view_v5 *right, uint32_t count) {
''' + body + '\n}\n'
            (root / "author.c").write_text(source)
            compiled = subprocess.run([shutil.which("goto-cc"), "--i386-win32", "-I", str(root), str(root / "author.c"),
                "--function", "regions_equal", "-o", str(root / "author.goto")], capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            inventory = subprocess.run([shutil.which("goto-instrument"), "--show-goto-functions", "--json-ui", str(root / "author.goto")],
                                       capture_output=True, text=True, check=True)
            return next(row["functions"] for row in json.loads(inventory.stdout) if "functions" in row)

    def check(self, functions):
        return check_readonly_source_access(functions, operation_symbols=("regions_equal",),
                                            context_tag="tag-spx_memory_regions_equal_context_v5")

    def test_direct_byte_loop_and_descriptor_equality_are_admitted(self):
        result = self.check(self.inventory('''
 (void)context;
 if (left == right) return 1;
 for (uint32_t i=0; i<count; ++i) {
   uint8_t a,b;
   if (left->read_u8(left->context,i,&a) || right->read_u8(right->context,i,&b)) return 0;
   if (a!=b) return 0;
 }
 return 1;
'''))
        self.assertEqual(result["status"], "satisfied", result["issues"])

    def test_public_helper_and_logical_metadata_are_admitted(self):
        result = self.check(self.inventory('''
 (void)context;
 uint8_t byte;
 if (count >= left->extent || left->base.permissions != right->base.permissions) return 0;
 return spx_view_read_u8(left,count,&byte) == 0 && byte == 0;
'''))
        self.assertEqual(result["status"], "satisfied", result["issues"])

    def test_span_read_must_keep_descriptor_context_and_reference_together(self):
        for context, reference, expected in (("left", "left", "satisfied"),
                                             ("right", "left", "incomplete"),
                                             ("left", "right", "incomplete")):
            with self.subTest(context=context, reference=reference):
                result = self.check(self.inventory(f'''uint64_t byte;
 return left->read({context}->access_context,{reference}->base,0,1,&byte) == 0;'''))
                self.assertEqual(result["status"], expected, result["issues"])

    def test_transport_and_object_representation_observations_reject(self):
        cases = (
            'return left->context == right->context;',
            'return left->read_u8 == right->read_u8;',
            'return (uint32_t)left;',
            'return left < right;',
            'return left + 1 == right;',
            'return context->protocol_state;',
            'uint32_t *p = (uint32_t *)&left->base.permissions; return *p;',
            'union U { spx_view_v5 view; unsigned char bytes[128]; } u; u.view=*left; return u.bytes[0];',
        )
        for body in cases:
            with self.subTest(body=body):
                result = self.check(self.inventory(body))
                self.assertEqual(result["status"], "incomplete", result)

    def test_line_directives_cannot_hide_an_authored_helper(self):
        prefix = '''#line 1 "trusted-view-runtime.c"
static uint8_t hidden(const spx_view_v5 *v) { return (uint32_t)v->context; }
'''
        result = self.check(self.inventory('return hidden(left);', prefix=prefix))
        self.assertEqual(result["status"], "incomplete")
        self.assertTrue(any("hidden" in issue["function"] for issue in result["issues"]))

    def test_global_and_static_storage_are_not_readable_inputs(self):
        for prefix, body in (("uint8_t external;", "return external;"),
                             ("static uint8_t hidden;", "return hidden;"),
                             ("", "static uint8_t hidden; return hidden;")):
            with self.subTest(prefix=prefix, body=body):
                self.assertEqual(self.check(self.inventory(body, prefix=prefix))["status"], "incomplete")

    def test_unknown_calls_and_incomplete_instruction_inventories_reject(self):
        result = self.check(self.inventory('return hidden();', prefix='uint8_t hidden(void);\n'))
        self.assertEqual(result["status"], "incomplete")
        functions = self.inventory('(void)context; return 0;')
        body = next(row for row in functions if row["name"] == "regions_equal")
        for mutation in ("code", "opcode"):
            mutated = copy.deepcopy(functions)
            candidate = next(row for row in mutated if row["name"] == "regions_equal")
            index = next(i for i, row in enumerate(body["instructions"]) if row["instructionId"] == "SET_RETURN_VALUE")
            if mutation == "code":
                candidate["instructions"][index].pop("code")
            else:
                candidate["instructions"][index]["instructionId"] = "UNMODELED"
            self.assertEqual(self.check(mutated)["status"], "incomplete")
