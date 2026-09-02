from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from spaghetti_extractor.native_realization.build import (
    NativeRealizationBuildError,
    _checked_native_symbol,
    _json_object,
)
from spaghetti_extractor.native_realization.build_v2 import (
    _native_objects_v2,
    _realized_definitions_v2,
)


class NativeRealizationBuildTests(unittest.TestCase):
    def test_json_input_must_be_an_object(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "input.json"
            path.write_text("[]", encoding="utf-8")
            with self.assertRaisesRegex(
                NativeRealizationBuildError, "must be a JSON object"
            ):
                _json_object(path, "fixture")

    def test_linked_symbol_requires_one_compatible_section(self) -> None:
        symbols = {"entry": {"symbol": "entry", "rva": 0x2100}}
        sections = [{
            "rva_start": 0x2000,
            "rva_end": 0x3000,
            "executable": True,
        }]
        self.assertEqual(
            _checked_native_symbol(
                symbols, sections, "entry", executable=True
            ),
            symbols["entry"],
        )
        with self.assertRaisesRegex(
            NativeRealizationBuildError, "compatible section"
        ):
            _checked_native_symbol(
                symbols, sections, "entry", executable=False
            )
        self.assertIsNone(
            _checked_native_symbol(
                symbols, sections, "missing", executable=True
            )
        )

    def test_object_inventory_deduplicates_bytes_and_preserves_provider(self) -> None:
        digest = "a" * 64
        objects = _native_objects_v2({
                "objects": [
                    {
                        "object_sha256": digest,
                        "source": {
                            "owner": "behavioral_c",
                            "role": "function",
                        },
                        "selected_provider": {
                            "provider_ids": ["generated.main"],
                            "definition_ids": ["definition:entry"],
                            "obligation_ids": [],
                        },
                    },
                    {
                        "object_sha256": digest,
                        "source": {
                            "owner": "shared_module_runtime",
                            "role": "ingress_bridge",
                        },
                        "selected_provider": {
                            "provider_ids": ["runtime.main"],
                            "definition_ids": [],
                            "obligation_ids": ["obligation:ingress"],
                        },
                    },
                ],
            })
        self.assertEqual(
            objects,
            [{
                "object_sha256": digest,
                "role": "ingress",
                "provider_ids": ["generated.main", "runtime.main"],
                "definition_ids": ["definition:entry"],
                "obligation_ids": ["obligation:ingress"],
                "section_ids": [],
            }],
        )

    def test_dynamic_export_uses_checked_loader_service_address(self) -> None:
        definition_id = "definition:dynamic"
        symbol_id = "external:function-import:dynamic"
        linked = SimpleNamespace(
            semantic_object=SimpleNamespace(payload={"symbols": [{
                "symbol_id": symbol_id,
                "declaration": {
                    "declaration_role": "loader_service",
                    "dll": "msvcrt.dll",
                    "symbol": "___lc_codepage_func",
                    "ordinal": None,
                    "loader_service_contract_sha256": "a" * 64,
                },
            }]}),
            payload={"definitions": [{
                "definition_id": definition_id,
                "definition_kind": "external_function",
            }]},
        )
        selection = SimpleNamespace(payload={"definition_selections": [{
            "definition_id": definition_id,
            "symbol_id": symbol_id,
            "provider_id": "external.main",
            "provider_kind": "external_environment",
            "qualification_sha256": "b" * 64,
            "native_symbol": "spx_external_dynamic",
        }]})
        realized, blockers = _realized_definitions_v2(
            linked=linked,
            selection=selection,
            original_interface={"imports": []},
            native_symbols={},
            linked_sections=[],
        )
        self.assertEqual(blockers, [])
        self.assertEqual(realized[0]["implementation_rva"], None)
        self.assertEqual(realized[0]["address"], {
            "kind": "loader_resolved_export",
            "dll": "msvcrt.dll",
            "symbol": "___lc_codepage_func",
            "ordinal": None,
            "loader_service_contract_sha256": "a" * 64,
        })

    def test_missing_ordinary_import_remains_a_blocker(self) -> None:
        definition_id = "definition:ordinary"
        symbol_id = "external:function-import:ordinary"
        linked = SimpleNamespace(
            semantic_object=SimpleNamespace(payload={"symbols": [{
                "symbol_id": symbol_id,
                "declaration": {
                    "declaration_role": "machine_import",
                    "dll": "msvcrt.dll",
                    "symbol": "puts",
                    "ordinal": None,
                    "loader_service_contract_sha256": None,
                },
            }]}),
            payload={"definitions": [{
                "definition_id": definition_id,
                "definition_kind": "external_function",
            }]},
        )
        selection = SimpleNamespace(payload={"definition_selections": [{
            "definition_id": definition_id,
            "symbol_id": symbol_id,
            "provider_id": "external.main",
            "provider_kind": "external_environment",
            "qualification_sha256": "b" * 64,
            "native_symbol": "spx_external_puts",
        }]})
        realized, blockers = _realized_definitions_v2(
            linked=linked,
            selection=selection,
            original_interface={"imports": []},
            native_symbols={},
            linked_sections=[],
        )
        self.assertEqual(realized[0]["address"], {
            "kind": "loader_import", "iat_rva": 0,
        })
        self.assertEqual(blockers, [{
            "code": "external_import_address_unresolved",
            "definition_id": definition_id,
        }])

if __name__ == "__main__":
    unittest.main()
