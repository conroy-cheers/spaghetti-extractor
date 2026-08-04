from __future__ import annotations

import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.cli import main
from spaghetti_extractor.external_operation_profiles import (
    EXTERNAL_OPERATION_CONTRACT_FORMAT,
    EXTERNAL_OPERATION_PROFILE_FORMAT,
    parse_external_operation_profile,
)
from spaghetti_extractor.source_operation_catalog import (
    NON_AUTHORITATIVE_RENDERING_METADATA,
    SOURCE_OPERATION_CATALOG_FORMAT,
    SOURCE_OPERATION_RENDERING_FORMAT,
    SourceOperationCatalogError,
    bind_source_operation_catalog,
    load_source_operation_catalog,
    render_source_operation_rows,
    render_source_operations,
)


_PROFILE_SHA256 = "a" * 64


def _catalog(*entries: dict[str, object]) -> dict[str, object]:
    return {
        "format": SOURCE_OPERATION_CATALOG_FORMAT,
        "catalog_id": "fixture-source-operations",
        "operation_profile_sha256": _PROFILE_SHA256,
        "entries": list(entries),
        "rendering_metadata": copy.deepcopy(
            NON_AUTHORITATIVE_RENDERING_METADATA
        ),
    }


def _entry(
    operation_id: str, rendering: dict[str, object], *, suffix: str = "rendering"
) -> dict[str, object]:
    return {
        "id": f"{operation_id}:{suffix}",
        "operation_id": operation_id,
        "rendering": rendering,
    }


class SourceOperationCatalogTests(unittest.TestCase):
    def test_cli_renders_against_the_normalized_operation_profile_identity(self) -> None:
        profile_payload = {
            "format": EXTERNAL_OPERATION_PROFILE_FORMAT,
            "id": "write-profile",
            "model": "x86-pe32",
            "status": "complete",
            "provenance": {"kind": "fixture"},
            "table_views": [],
            "operations": [{
                "id": "write-file",
                "abi_template": "pe32-stdcall-v1",
                "argument_words": 2,
                "environment_contract_id": "pure",
                "output_rules": [],
            }],
            "selectors": [{
                "kind": "direct_import",
                "operation_id": "write-file",
                "import": {"dll": "kernel32.dll", "symbol": "WriteFile"},
            }],
            "environment_contracts": [{
                "format": EXTERNAL_OPERATION_CONTRACT_FORMAT,
                "id": "pure",
                "status": "complete",
                "memory_footprints": [],
                "world_effects": [],
            }],
        }
        profile_sha256 = parse_external_operation_profile(profile_payload).sha256
        catalog_payload = {
            **_catalog(_entry(
                "write-file",
                {
                    "kind": "direct_import",
                    "symbol": "WriteFile",
                    "headers": ["windows.h"],
                },
            )),
            "operation_profile_sha256": profile_sha256,
        }

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            profile_path = root / "profile.json"
            catalog_path = root / "catalog.json"
            operations_path = root / "operations.json"
            output_path = root / "rendering.json"
            profile_path.write_text(json.dumps(profile_payload), encoding="utf-8")
            catalog_path.write_text(json.dumps(catalog_payload), encoding="utf-8")
            operations_path.write_text(json.dumps({
                "operations": [{
                    "operation_id": "write-file",
                    "arguments": ["handle", "buffer"],
                }],
            }), encoding="utf-8")

            with contextlib.redirect_stdout(io.StringIO()):
                status = main([
                    "stage-b-render-source-operations",
                    "--catalog", str(catalog_path),
                    "--operation-profile", str(profile_path),
                    "--operations", str(operations_path),
                    "--out", str(output_path),
                ])
            rendered = json.loads(output_path.read_text(encoding="utf-8"))

        self.assertEqual(status, 0)
        self.assertEqual(rendered["status"], "complete")
        self.assertEqual(
            rendered["operations"][0]["call_expression"],
            "WriteFile(handle, buffer)",
        )

    def test_catalog_is_profile_bound_self_hashed_and_loadable(self) -> None:
        payload = _catalog(_entry(
            "write-file",
            {
                "kind": "direct_import",
                "symbol": "WriteFile",
                "headers": ["windows.h"],
            },
        ))

        bound = bind_source_operation_catalog(payload)
        rebound = bind_source_operation_catalog(bound)

        self.assertEqual(bound, rebound)
        self.assertRegex(bound["catalog_sha256"], r"^[0-9a-f]{64}$")
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "catalog.json"
            path.write_text(json.dumps(bound), encoding="utf-8")
            self.assertEqual(load_source_operation_catalog(path), bound)

    def test_catalog_rejects_stale_hash_and_authority_escalation(self) -> None:
        payload = _catalog()
        payload["catalog_sha256"] = "b" * 64
        with self.assertRaisesRegex(SourceOperationCatalogError, "stale"):
            bind_source_operation_catalog(payload)

        payload = _catalog()
        payload["rendering_metadata"]["authorizes_candidate_qualification"] = True
        with self.assertRaisesRegex(SourceOperationCatalogError, "non-authoritative"):
            bind_source_operation_catalog(payload)

    def test_catalog_strictly_rejects_unknown_fields_and_malformed_renderers(self) -> None:
        payload = _catalog()
        payload["comment"] = "not part of v1"
        with self.assertRaisesRegex(SourceOperationCatalogError, "unexpected"):
            bind_source_operation_catalog(payload)

        malformed = _catalog(_entry(
            "write-file",
            {
                "kind": "direct_import",
                "symbol": "WriteFile();",
                "headers": ["windows.h"],
            },
        ))
        with self.assertRaisesRegex(SourceOperationCatalogError, "C identifier"):
            bind_source_operation_catalog(malformed)

    def test_direct_import_renders_arguments_and_required_headers(self) -> None:
        catalog = _catalog(_entry(
            "write-file",
            {
                "kind": "direct_import",
                "symbol": "WriteFile",
                "headers": ["windows.h"],
            },
        ))

        rendered = render_source_operations(
            catalog=catalog,
            operation_profile_sha256=_PROFILE_SHA256,
            operations=[{
                "evidence_id": "call-17",
                "operation_id": "write-file",
                "arguments": ["handle", 'buffer_for("(")', "length"],
                "unrelated_upstream_evidence": {"rva": 0x1234},
            }],
        )

        self.assertEqual(rendered["format"], SOURCE_OPERATION_RENDERING_FORMAT)
        self.assertEqual(rendered["status"], "complete")
        self.assertEqual(
            rendered["operations"][0]["call_expression"],
            'WriteFile(handle, buffer_for("("), length)',
        )
        self.assertEqual(rendered["required_headers"], ["windows.h"])
        self.assertEqual(
            rendered["rendering_metadata"],
            NON_AUTHORITATIVE_RENDERING_METADATA,
        )

    def test_com_and_c_table_methods_use_explicit_receiver_policy(self) -> None:
        catalog = _catalog(
            _entry(
                "com-release",
                {
                    "kind": "com_table_method",
                    "method": "Release",
                    "headers": ["unknwn.h"],
                },
            ),
            _entry(
                "stream-read",
                {
                    "kind": "c_table_method",
                    "table_member": "ops",
                    "method": "read",
                    "pass_receiver": True,
                    "headers": ["stream.h"],
                },
            ),
            _entry(
                "table-flush",
                {
                    "kind": "c_table_method",
                    "table_member": None,
                    "method": "flush",
                    "pass_receiver": False,
                    "headers": [],
                },
            ),
        )

        rendered = render_source_operations(
            catalog=catalog,
            operation_profile_sha256=_PROFILE_SHA256,
            operations=[
                {
                    "operation_id": "com-release",
                    "arguments": [],
                    "receiver": "unknown",
                },
                {
                    "operation_id": "stream-read",
                    "recovered_arguments": [
                        {"index": 1, "expression": "size"},
                        {"index": 0, "expression": "buffer"},
                    ],
                    "recovered_receiver": {"expression": "stream"},
                },
                {
                    "operation_id": "table-flush",
                    "arguments": [],
                    "receiver": "table",
                },
            ],
        )

        self.assertEqual(
            [row["call_expression"] for row in rendered["operations"]],
            [
                "unknown->lpVtbl->Release(unknown)",
                "stream->ops->read(stream, buffer, size)",
                "table->flush()",
            ],
        )
        self.assertEqual(rendered["required_headers"], ["stream.h", "unknwn.h"])

    def test_resolver_result_is_called_only_through_cataloged_pointer_type(self) -> None:
        catalog = _catalog(_entry(
            "resolved-callback",
            {
                "kind": "resolver_function_pointer",
                "pointer_type": "resolved_callback_fn",
                "headers": ["callbacks.h"],
            },
        ))

        rendered = render_source_operations(
            catalog=catalog,
            operation_profile_sha256=_PROFILE_SHA256,
            operations=[{
                "operation_id": "resolved-callback",
                "arguments": ["context", "value"],
                "resolver_result": {"expression": "resolved_proc"},
            }],
        )

        self.assertEqual(
            rendered["operations"][0]["call_expression"],
            "((resolved_callback_fn)(resolved_proc))(context, value)",
        )

    def test_registered_callback_uses_generic_typed_pointer_rendering(self) -> None:
        catalog = _catalog(_entry(
            "registered-callback",
            {
                "kind": "typed_function_pointer",
                "pointer_type": "window_callback_fn",
                "headers": ["callbacks.h"],
            },
        ))

        rendered = render_source_operations(
            catalog=catalog,
            operation_profile_sha256=_PROFILE_SHA256,
            operations=[{
                "operation_id": "registered-callback",
                "arguments": ["window", "message"],
                "recovered_target": {"expression": "callback"},
            }],
        )

        self.assertEqual(
            rendered["operations"][0]["call_expression"],
            "((window_callback_fn)(callback))(window, message)",
        )

    def test_finite_dispatch_emits_each_evidence_backed_alternative_without_default(self) -> None:
        catalog = _catalog(_entry(
            "finite-handler",
            {
                "kind": "finite_dispatch",
                "alternatives": [
                    {
                        "value": 4,
                        "rendering": {
                            "kind": "direct_import",
                            "symbol": "HandleFour",
                            "headers": ["handlers.h"],
                        },
                    },
                    {
                        "value": 9,
                        "rendering": {
                            "kind": "resolver_function_pointer",
                            "pointer_type": "handler_fn",
                            "headers": ["handler_types.h"],
                        },
                    },
                ],
            },
        ))

        rendered = render_source_operation_rows(
            catalog=catalog,
            operation_profile_sha256=_PROFILE_SHA256,
            operation_evidence_rows=[{
                "operation_id": "finite-handler",
                "arguments": ["value"],
                "resolver_result": "resolved_handler",
                "dispatch": {
                    "selector_expression": "handler_kind",
                    "possible_values": [9, 4],
                },
            }],
        )

        row = rendered["operations"][0]
        self.assertIsNone(row["call_expression"])
        self.assertEqual(
            row["dispatch_alternatives"],
            [
                {
                    "value": 4,
                    "condition": "handler_kind == 4u",
                    "call_expression": "HandleFour(value)",
                    "required_headers": ["handlers.h"],
                },
                {
                    "value": 9,
                    "condition": "handler_kind == 9u",
                    "call_expression": "((handler_fn)(resolved_handler))(value)",
                    "required_headers": ["handler_types.h"],
                },
            ],
        )
        self.assertNotIn("default", row)

    def test_missing_and_ambiguous_catalog_entries_are_repairs(self) -> None:
        duplicate_a = _entry(
            "duplicate",
            {"kind": "direct_import", "symbol": "First", "headers": []},
            suffix="first",
        )
        duplicate_b = _entry(
            "duplicate",
            {"kind": "direct_import", "symbol": "Second", "headers": []},
            suffix="second",
        )

        rendered = render_source_operations(
            catalog=_catalog(duplicate_a, duplicate_b),
            operation_profile_sha256=_PROFILE_SHA256,
            operations=[
                {"operation_id": "missing", "arguments": []},
                {"operation_id": "duplicate", "arguments": []},
            ],
        )

        self.assertEqual(rendered["status"], "incomplete")
        self.assertEqual(
            [item["reason"] for item in rendered["repair_items"]],
            ["missing_catalog_entry", "ambiguous_catalog_entry"],
        )
        self.assertTrue(all(
            row["call_expression"] is None
            and row["status"] == "repair_required"
            for row in rendered["operations"]
        ))
        self.assertEqual(
            rendered["repair_items"][1]["details"]["candidate_entry_ids"],
            ["duplicate:first", "duplicate:second"],
        )

    def test_missing_receiver_resolver_and_dispatch_arm_are_repairs(self) -> None:
        catalog = _catalog(
            _entry(
                "method",
                {
                    "kind": "com_table_method",
                    "method": "Run",
                    "headers": [],
                },
            ),
            _entry(
                "callback",
                {
                    "kind": "resolver_function_pointer",
                    "pointer_type": "callback_fn",
                    "headers": [],
                },
            ),
            _entry(
                "dispatch",
                {
                    "kind": "finite_dispatch",
                    "alternatives": [
                        {
                            "value": 1,
                            "rendering": {
                                "kind": "direct_import",
                                "symbol": "One",
                                "headers": [],
                            },
                        },
                        {
                            "value": 2,
                            "rendering": {
                                "kind": "direct_import",
                                "symbol": "Two",
                                "headers": [],
                            },
                        },
                    ],
                },
            ),
        )

        rendered = render_source_operations(
            catalog=catalog,
            operation_profile_sha256=_PROFILE_SHA256,
            operations=[
                {"operation_id": "method", "arguments": []},
                {"operation_id": "callback", "arguments": []},
                {
                    "operation_id": "dispatch",
                    "arguments": [],
                    "dispatch": {
                        "selector_expression": "kind",
                        "possible_values": [1, 3],
                    },
                },
            ],
        )

        self.assertEqual(
            [item["reason"] for item in rendered["repair_items"]],
            [
                "missing_recovered_receiver",
                "missing_resolver_result",
                "missing_dispatch_alternative",
            ],
        )
        self.assertEqual(
            rendered["repair_items"][2]["details"], {"missing_values": [3]}
        )

    def test_profile_binding_mismatch_fails_before_rendering(self) -> None:
        with self.assertRaisesRegex(SourceOperationCatalogError, "different"):
            render_source_operations(
                catalog=_catalog(),
                operation_profile_sha256="b" * 64,
                operations=[],
            )


if __name__ == "__main__":
    unittest.main()
