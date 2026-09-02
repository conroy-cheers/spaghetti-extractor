from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace

from spaghetti_extractor.native_realization.receipt_v2 import (
    NativeRealizationV2,
    NativeRealizationV2Error,
    build_native_realization_v2,
)


def _linked(*, complete: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        identity="1" * 64,
        payload={
            "status": "complete" if complete else "incomplete",
            "bindings": {
                "module_interface_sha256": "5" * 64,
                "qualified_platform_sha256": "6" * 64,
            },
        },
    )


def _selection(*, complete: bool = True) -> SimpleNamespace:
    return SimpleNamespace(
        identity="2" * 64,
        payload={
            "status": "complete" if complete else "incomplete",
            "bindings": {"linked_semantic_module_sha256": "1" * 64},
            "qualification_sha256s": ["3" * 64, "4" * 64],
            "definition_selections": [
                {
                    "definition_id": "definition:generated",
                    "symbol_id": "original:function:entry",
                    "provider_id": "generated.main",
                    "provider_kind": "generated_behavioral_c",
                    "qualification_sha256": "3" * 64,
                    "native_symbol": "spx_entry",
                },
                {
                    "definition_id": "definition:runtime",
                    "symbol_id": "platform:runtime:memory",
                    "provider_id": "runtime.main",
                    "provider_kind": "qualified_runtime",
                    "qualification_sha256": "4" * 64,
                    "native_symbol": "spx_runtime",
                },
            ],
            "obligation_selections": [{
                "obligation_id": "obligation:memory",
                "provider_id": "runtime.main",
                "provider_kind": "qualified_runtime",
                "qualification_sha256": "4" * 64,
                "native_symbol": "spx_runtime",
                "receipt_sha256": "7" * 64,
            }],
        },
    )


def _facts() -> dict[str, object]:
    return {
        "qualified_platform_sha256": "6" * 64,
        "original_module_interface_sha256": "5" * 64,
        "providers": [
            {
                "provider_id": "generated.main",
                "provider_kind": "generated_behavioral_c",
                "qualification_sha256": "3" * 64,
                "artifact_sha256": "8" * 64,
                "semantic_slice_sha256": "9" * 64,
                "tool_sha256s": ["a" * 64],
                "definition_ids": ["definition:generated"],
                "obligation_ids": [],
            },
            {
                "provider_id": "runtime.main",
                "provider_kind": "qualified_runtime",
                "qualification_sha256": "4" * 64,
                "artifact_sha256": "b" * 64,
                "semantic_slice_sha256": "c" * 64,
                "tool_sha256s": ["d" * 64],
                "definition_ids": ["definition:runtime"],
                "obligation_ids": ["obligation:memory"],
            },
        ],
        "definitions": [
            {
                "definition_id": "definition:generated",
                "symbol_id": "original:function:entry",
                "provider_id": "generated.main",
                "provider_kind": "generated_behavioral_c",
                "qualification_sha256": "3" * 64,
                "native_symbol": "spx_entry",
                "address": {"kind": "linked_rva", "rva": 0x2000},
                "implementation_rva": 0x2000,
                "bridge_class_id": None,
            },
            {
                "definition_id": "definition:runtime",
                "symbol_id": "platform:runtime:memory",
                "provider_id": "runtime.main",
                "provider_kind": "qualified_runtime",
                "qualification_sha256": "4" * 64,
                "native_symbol": "spx_runtime",
                "address": {"kind": "linked_rva", "rva": 0x2100},
                "implementation_rva": 0x2100,
                "bridge_class_id": None,
            },
        ],
        "obligations": [{
            "obligation_id": "obligation:memory",
            "provider_id": "runtime.main",
            "provider_kind": "qualified_runtime",
            "qualification_sha256": "4" * 64,
            "native_symbol": "spx_runtime",
            "receipt_sha256": "7" * 64,
            "implementation_rva": 0x2100,
        }],
        "native_objects": [
            {
                "object_sha256": "e" * 64,
                "role": "generated_behavioral_c",
                "provider_ids": ["generated.main"],
                "definition_ids": ["definition:generated"],
                "obligation_ids": [],
                "section_ids": [],
            },
            {
                "object_sha256": "f" * 64,
                "role": "runtime",
                "provider_ids": ["runtime.main"],
                "definition_ids": ["definition:runtime"],
                "obligation_ids": ["obligation:memory"],
                "section_ids": [],
            },
        ],
        "bridges": [],
        "runtime": {
            "qualification_sha256": "4" * 64,
            "tls_layout_sha256": "0" * 64,
            "private_stack_size": 0x100000,
            "support_import_ids": [],
            "required_symbols": [
                {"symbol": "spx_entry", "rva": 0x2000, "role": "entry"},
                {"symbol": "spx_runtime", "rva": 0x2100, "role": "runtime"},
            ],
            "obligation_receipt_sha256s": ["7" * 64],
        },
        "link": {
            "payload_sha256": "1" * 64,
            "linker_map_sha256": "2" * 64,
            "relocation_inventory_sha256": "3" * 64,
            "section_table_sha256": "4" * 64,
            "entry_symbols": ["spx_entry"],
        },
        "loader_surface": {
            "entry_rva": 0x2000,
            "exports_sha256": "5" * 64,
            "imports_sha256": "6" * 64,
            "tls_sha256": "7" * 64,
            "base_relocations_sha256": "8" * 64,
            "resources_sha256": None,
            "load_config_sha256": None,
        },
        "candidate": {
            "filename": "fixture.exe",
            "sha256": "9" * 64,
            "size": 4096,
            "module_interface_sha256": "a" * 64,
        },
        "pinned_code_layout_requirements": [],
    }


class NativeRealizationV2Tests(unittest.TestCase):
    def test_total_definition_and_obligation_realization_is_complete(self) -> None:
        payload = build_native_realization_v2(
            linked_semantic_module=_linked(),
            implementation_selection=_selection(),
            **_facts(),
        )
        self.assertEqual(payload["status"], "complete")
        self.assertEqual(payload["blockers"], [])
        NativeRealizationV2.parse(payload)

    def test_missing_runtime_object_and_obligation_fail_closed(self) -> None:
        facts = _facts()
        facts["native_objects"] = facts["native_objects"][:1]
        facts["obligations"] = []
        payload = build_native_realization_v2(
            linked_semantic_module=_linked(),
            implementation_selection=_selection(),
            **facts,
        )
        codes = {row["code"] for row in payload["blockers"]}
        self.assertIn("selected_provider_object_not_linked", codes)
        self.assertIn("selected_obligation_not_realized", codes)

    def test_self_hash_is_checked(self) -> None:
        payload = build_native_realization_v2(
            linked_semantic_module=_linked(),
            implementation_selection=_selection(),
            **_facts(),
        )
        stale = copy.deepcopy(payload)
        stale["candidate"]["size"] += 1
        with self.assertRaisesRegex(NativeRealizationV2Error, "self hash is stale"):
            NativeRealizationV2.parse(stale)

    def test_checked_loader_resolved_export_is_a_complete_address(self) -> None:
        facts = _facts()
        selection = _selection()
        selection.payload["definition_selections"][0] = {
            **selection.payload["definition_selections"][0],
            "provider_kind": "external_environment",
        }
        facts["providers"][0]["provider_kind"] = "external_environment"
        facts["definitions"][0] = {
            **facts["definitions"][0],
            "provider_kind": "external_environment",
            "address": {
                "kind": "loader_resolved_export",
                "dll": "msvcrt.dll",
                "symbol": "___lc_codepage_func",
                "ordinal": None,
                "loader_service_contract_sha256": "d" * 64,
            },
            "implementation_rva": None,
        }
        payload = build_native_realization_v2(
            linked_semantic_module=_linked(),
            implementation_selection=selection,
            **facts,
        )
        self.assertEqual(payload["status"], "complete")
        NativeRealizationV2.parse(payload)

    def test_loader_resolved_export_requires_exact_identity_and_contract(self) -> None:
        cases = (
            (7, "d" * 64, "exactly one symbol or ordinal"),
            (None, "not-a-digest", "lowercase SHA-256"),
        )
        for ordinal, contract, message in cases:
            with self.subTest(message=message):
                facts = _facts()
                facts["definitions"][0]["address"] = {
                    "kind": "loader_resolved_export",
                    "dll": "msvcrt.dll",
                    "symbol": "___lc_codepage_func",
                    "ordinal": ordinal,
                    "loader_service_contract_sha256": contract,
                }
                with self.assertRaisesRegex(NativeRealizationV2Error, message):
                    build_native_realization_v2(
                        linked_semantic_module=_linked(),
                        implementation_selection=_selection(),
                        **facts,
                    )


if __name__ == "__main__":
    unittest.main()
