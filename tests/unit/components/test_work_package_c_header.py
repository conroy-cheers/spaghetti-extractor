"""A source edit uses the same C ABI before and after component start --apply."""
from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.boundary import BoundarySchemaV1
from spaghetti_extractor.components.component_c_v5 import render_component_c_headers_v5
from spaghetti_extractor.components.interface_package_v5 import ComponentInterfaceIntentV1, compile_component_interface_v5
from spaghetti_extractor.components.work_package_v6 import _render_public_header


class WorkPackageCHeaderTests(unittest.TestCase):
    def test_one_authored_function_compiles_against_both_headers(self) -> None:
        compiler = shutil.which("cc")
        if compiler is None:
            self.skipTest("host C compiler is unavailable")
        value = {"id": "value", "type_id": "u32", "interpretation": "value",
                 "access": "none", "nullable": False, "provider_domain": None,
                 "resource_kind": None, "extent": {"kind": "none", "bytes": None, "value_id": None}}
        result = {**value, "id": "result"}
        schema = BoundarySchemaV1.create(schema_id="leaf", types=[
            {"id": "u32", "kind": "integer", "width_bits": 32, "signed": False},
            {"id": "run.fn", "kind": "function", "calling_convention": "cdecl",
             "parameter_type_ids": ["u32"], "result_type_id": "u32", "variadic": False}],
            signatures=[{"id": "run", "function_type_id": "run.fn", "parameters": [value], "results": [result]}])
        intent = ComponentInterfaceIntentV1.create(component_id="leaf", schema=schema,
            state=[], services=[], effects=[], protocol_states=["ready"], initial_protocol_state="ready",
            operations=[{"id": "run", "signature_id": "run", "source_values": [value, result],
                         "projection_entries": [{"source_id": name, "target": {
                             "root": root, "value_id": name, "fields": []}}
                             for root, name in (("parameter", "value"), ("result", "result"))],
                         "lifecycle_bindings": [], "lifecycle_additional_roots": {"state": []},
                         "checked_interaction_contract_ids": [], "effect_ids": [], "allowed_service_ids": [],
                         "pre_states": ["ready"], "post_states": ["ready"]}])
        bundle = compile_component_interface_v5(intent)
        symbols = {"run": "authored_run"}
        source = '''#include "component.h"
uint32_t authored_run(spx_leaf_context_v5 *context, uint32_t value) {
  SPX_PROOF_BEGIN(run);
  (void)context;
  return value + UINT32_C(1);
}
'''
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "component.h").write_text(_render_public_header(bundle, symbols))
            for name, content in render_component_c_headers_v5(bundle, symbols).items():
                (root / name).write_text(content)
            for installed in (False, True):
                path = root / "authored.c"
                path.write_text(source.replace('"component.h"', '"portable-component-implementation.h"')
                                if installed else source)
                result = subprocess.run([compiler, "-std=c11", "-Wall", "-Wextra", "-Werror",
                                         "-fsyntax-only", "-I", str(root), str(path)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
