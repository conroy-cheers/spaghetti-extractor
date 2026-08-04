from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.external_function_ast import (
    EXTERNAL_FUNCTION_EXTRACTION_SPEC_FORMAT,
    extract_external_function_profile,
)
from spaghetti_extractor.stage_binary import StageAInputError
from spaghetti_extractor.util import sha256_file
from tests.pe_fixtures import pe32_import_image


def function(
    name: str,
    parameters: list[tuple[str, str]],
    *,
    qualified: str | None = None,
) -> dict[str, object]:
    return {
        "kind": "FunctionDecl",
        "name": name,
        "type": {
            "qualType": qualified
            or "int (void) __attribute__((stdcall))",
        },
        "inner": [
            {
                "kind": "ParmVarDecl",
                "type": {
                    "qualType": spelled,
                    "desugaredQualType": desugared,
                },
            }
            for spelled, desugared in parameters
        ],
    }


class ExternalFunctionAstTests(unittest.TestCase):
    def test_extracts_exact_fixed_word_arity(self) -> None:
        result = self._extract([
            function(
                "WriteValue",
                [("HANDLE", "void *"), ("DWORD", "unsigned long")],
                qualified="int (HANDLE, DWORD) __attribute__((stdcall))",
            ),
        ])

        self.assertEqual(result["status"], "complete")
        entry = result["machine_import_signatures"][0]
        self.assertEqual(entry["argument_words"], 2)
        self.assertTrue(entry["override"])

    def test_unsupported_by_value_parameter_is_an_explicit_gap(self) -> None:
        result = self._extract([
            function(
                "WriteValue",
                [("LARGE_VALUE", "struct LARGE_VALUE")],
                qualified="int (LARGE_VALUE) __attribute__((stdcall))",
            ),
        ])

        self.assertEqual(result["status"], "incomplete")
        self.assertEqual(
            result["gaps"][0]["code"],
            "sdk_declaration_parameter_width_unsupported",
        )

    def test_rejects_header_drift(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "windows.h"
            header.write_text("reviewed", encoding="utf-8")
            spec = self._write_spec(root, header)
            header.write_text("changed", encoding="utf-8")
            ast = root / "ast.json"
            ast.write_text(json.dumps(function("WriteValue", [])), encoding="utf-8")
            original = root / "original.exe"
            original.write_bytes(
                pe32_import_image(b"\xc3", symbol="WriteValue")
            )

            with self.assertRaises(StageAInputError):
                extract_external_function_profile(
                    ast_json=ast,
                    spec=spec,
                    headers=[header],
                    original_pe=original,
                    out=root / "profile.json",
                )

    def _extract(self, declarations: list[dict[str, object]]) -> dict[str, object]:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "windows.h"
            header.write_text("reviewed", encoding="utf-8")
            spec = self._write_spec(root, header)
            ast = root / "ast.json"
            ast.write_text(json.dumps({"inner": declarations}), encoding="utf-8")
            original = root / "original.exe"
            original.write_bytes(
                pe32_import_image(b"\xc3", symbol="WriteValue")
            )
            return extract_external_function_profile(
                ast_json=ast,
                spec=spec,
                headers=[header],
                original_pe=original,
                out=root / "profile.json",
            )

    @staticmethod
    def _write_spec(root: Path, header: Path) -> Path:
        spec = root / "spec.json"
        spec.write_text(json.dumps({
            "format": EXTERNAL_FUNCTION_EXTRACTION_SPEC_FORMAT,
            "id": "fixture",
            "model": "x86-pe32",
            "headers": [{
                "include": header.name,
                "sha256": sha256_file(header),
            }],
            "dlls": ["kernel32.dll"],
        }), encoding="utf-8")
        return spec


if __name__ == "__main__":
    unittest.main()
