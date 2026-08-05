from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_interface_ast import (
    EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
    extract_external_interface_profile,
)
from spaghetti_extractor.external_interface_profiles import (
    load_external_interface_profile,
)
from spaghetti_extractor.util import sha256_file


class ExternalInterfaceAstTests(unittest.TestCase):
    def test_extracts_vtable_slots_factory_arity_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "example.h"
            header.write_text("reviewed header\n", encoding="ascii")
            spec = root / "spec.json"
            spec.write_text(json.dumps({
                "format": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
                "id": "fixture",
                "model": "x86-pe32",
                "headers": [{
                    "include": "example.h",
                    "sha256": sha256_file(header),
                }],
                "interface_prefixes": ["IWidget"],
                "factories": [{
                    "id": "example.dll!Create",
                    "import": {"dll": "example.dll", "symbol": "Create"},
                    "declaration": "Create",
                    "out_interfaces": [{
                        "argument_index": 1,
                        "interface_id": "IWidget",
                    }],
                }],
            }), encoding="utf-8")
            ast = root / "ast.json"
            ast.write_text(json.dumps({"kind": "TranslationUnitDecl", "inner": [
                {
                    "kind": "TypedefDecl",
                    "name": "LPWIDGET",
                    "type": {"qualType": "struct IWidget *"},
                },
                {
                    "kind": "TypedefDecl",
                    "name": "LPLPWIDGET",
                    "type": {"qualType": "LPWIDGET *"},
                },
                {
                    "kind": "RecordDecl",
                    "name": "IWidgetVtbl",
                    "inner": [
                        {
                            "kind": "FieldDecl",
                            "name": "Release",
                            "type": {
                                "qualType": "ULONG (*)(IWidget *) __attribute__((stdcall))"
                            },
                        },
                        {
                            "kind": "FieldDecl",
                            "name": "Duplicate",
                            "type": {
                                "qualType": (
                                    "HRESULT (*)(IWidget *, LPLPWIDGET) "
                                    "__attribute__((stdcall))"
                                )
                            },
                        },
                    ],
                },
                {
                    "kind": "FunctionDecl",
                    "name": "Create",
                    "type": {
                        "qualType": (
                            "HRESULT (GUID *, LPWIDGET *) "
                            "__attribute__((stdcall))"
                        )
                    },
                },
            ]}), encoding="utf-8")
            output = root / "profile.json"

            result = extract_external_interface_profile(
                ast_json=ast,
                spec=spec,
                headers=[header],
                out=output,
            )
            loaded = load_external_interface_profile(output)

        self.assertEqual(result["counts"]["methods"], 2)
        self.assertEqual(result["factories"][0]["argument_words"], 2)
        self.assertEqual(
            result["interfaces"][0]["methods"][1]["out_interfaces"],
            [{
                "argument_index": 1,
                "interface_id": "IWidget",
                "write_width": 4,
            }],
        )
        self.assertEqual(loaded.interfaces[0].methods[1].offset, 4)

    def test_header_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "example.h"
            header.write_text("changed\n", encoding="ascii")
            spec = root / "spec.json"
            spec.write_text(json.dumps({
                "format": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
                "id": "fixture",
                "model": "x86-pe32",
                "headers": [{"include": "example.h", "sha256": "0" * 64}],
                "interface_prefixes": ["IWidget"],
                "factories": [],
            }), encoding="utf-8")
            ast = root / "ast.json"
            ast.write_text("{}", encoding="ascii")
            with self.assertRaisesRegex(Exception, "digest mismatch"):
                extract_external_interface_profile(
                    ast_json=ast,
                    spec=spec,
                    headers=[header],
                    out=root / "out.json",
                )


if __name__ == "__main__":
    unittest.main()
