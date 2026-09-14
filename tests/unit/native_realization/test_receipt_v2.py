from __future__ import annotations

import copy
import unittest
from types import SimpleNamespace

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
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
    portable_core = {
        "format": "spaghetti-extractor-portable-dispatch-link-receipt-v1",
        "status": "complete",
        "activation_authorized": True,
        "bindings": {
            "implementation_selection_sha256": "2" * 64,
            "payload_sha256": "1" * 64,
            "linker_map_sha256": "2" * 64,
        },
        "registry": None,
        "entries": [],
        "policy": {
            "strong_module_registry_required_when_portable": True,
            "one_strong_implementation_symbol_per_entry": True,
            "exact_selected_object_membership_required": True,
            "contextual_bisimulation_authority_required": True,
            "weak_or_duplicate_fallback_forbidden": True,
            "source_only_authority": False,
        },
        "blockers": [],
    }
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
        "portable_dispatch_link_receipt": {
            **portable_core,
            "receipt_sha256": canonical_sha256_v3(portable_core),
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

    def test_portable_definition_requires_exact_strong_dispatch_receipt(self) -> None:
        selection = _selection()
        selection.payload["definition_selections"][0]["provider_kind"] = (
            "qualified_portable_c"
        )
        facts = _facts()
        facts["providers"][0]["provider_kind"] = "qualified_portable_c"
        facts["definitions"][0].update({
            "symbol_id": "original:function:entry",
            "provider_kind": "qualified_portable_c",
        })
        facts["native_objects"][0]["role"] = "portable_c"
        facts["native_objects"].insert(0, {
            "object_sha256": "0" * 64,
            "role": "loader_support",
            "provider_ids": [],
            "definition_ids": [],
            "obligation_ids": [],
            "section_ids": [],
        })
        receipt = facts["portable_dispatch_link_receipt"]
        receipt.update({
            "registry": {
                "source_sha256": "1" * 64,
                "object_sha256": "0" * 64,
                "symbol_rvas": {
                    "spx_region_override_count": 0x2200,
                    "spx_region_override_lookup": 0x2210,
                    "spx_region_overrides": 0x2240,
                },
            },
            "entries": [{
                "component_id": "fixture",
                "operation_id": "entry",
                "entry_unit_id": "entry",
                "owned_unit_ids": ["entry"],
                "entry_rva": 0x1000,
                "native_symbol": "spx_entry",
                "provider_id": "generated.main",
                "qualification_sha256": "3" * 64,
                "contextual_refinement_sha256": "4" * 64,
                "contextual_proof_sha256": "5" * 64,
                "provider_object_manifest_sha256": "6" * 64,
                "implementation_source_sha256": "7" * 64,
                "implementation_object_sha256": "e" * 64,
                "linked_rva": 0x2000,
            }],
        })
        receipt["receipt_sha256"] = canonical_sha256_v3({
            key: value for key, value in receipt.items()
            if key != "receipt_sha256"
        })
        payload = build_native_realization_v2(
            linked_semantic_module=_linked(),
            implementation_selection=selection,
            **facts,
        )
        NativeRealizationV2.parse(payload)

        stale = copy.deepcopy(payload)
        portable = stale["portable_dispatch_link_receipt"]
        portable["policy"]["source_only_authority"] = True
        portable["receipt_sha256"] = canonical_sha256_v3({
            key: value for key, value in portable.items()
            if key != "receipt_sha256"
        })
        stale["native_realization_sha256"] = canonical_sha256_v3({
            key: value for key, value in stale.items()
            if key != "native_realization_sha256"
        })
        with self.assertRaisesRegex(
            NativeRealizationV2Error, "portable dispatch link policy",
        ):
            NativeRealizationV2.parse(stale)

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
