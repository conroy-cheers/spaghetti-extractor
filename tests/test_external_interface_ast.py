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
    ExternalInterfaceProfileError,
    SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    load_external_interface_profile,
)
from spaghetti_extractor.machine_import_profiles import (
    load_machine_import_profile_set,
)
from spaghetti_extractor.stage_binary import StageAInputError
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
                "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
                "headers": [{
                    "include": "example.h",
                    "sha256": sha256_file(header),
                }],
                "interface_prefixes": ["IWidget"],
                "opaque_resource_types": ["HWND"],
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
                    "kind": "TypedefDecl",
                    "name": "HWND",
                    "type": {"qualType": "struct HWND__ *"},
                },
                {
                    "kind": "RecordDecl",
                    "name": "IWidgetVtbl",
                    "inner": [
                        {
                            "kind": "FieldDecl",
                            "name": "Release",
                            "type": {
                                "qualType": (
                                    "ULONG (*)(IWidget *, HWND) "
                                    "__attribute__((stdcall))"
                                )
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
            invalid_spec = root / "invalid-spec.json"
            invalid_payload = json.loads(spec.read_text(encoding="utf-8"))
            invalid_payload["opaque_resource_types"] = ["MISSPELLED_HANDLE"]
            invalid_spec.write_text(json.dumps(invalid_payload), encoding="utf-8")
            with self.assertRaisesRegex(
                StageAInputError,
                "opaque resource type is absent from the pinned AST",
            ):
                extract_external_interface_profile(
                    ast_json=ast,
                    spec=invalid_spec,
                    headers=[header],
                    out=root / "invalid-profile.json",
                )
            loaded = load_external_interface_profile(output)
            machine_profile = load_machine_import_profile_set([output])

            missing_frame = json.loads(output.read_text(encoding="utf-8"))
            del missing_frame["interfaces"][0]["methods"][0][
                "caller_memory_frame"
            ]
            missing_frame_path = root / "missing-frame.json"
            missing_frame_path.write_text(
                json.dumps(missing_frame), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ExternalInterfaceProfileError,
                "has no complete caller-memory frame",
            ):
                load_external_interface_profile(missing_frame_path)

            missing_import_frame = json.loads(
                output.read_text(encoding="utf-8")
            )
            del missing_import_frame["machine_import_signatures"][0][
                "caller_memory_frame"
            ]
            missing_import_frame_path = root / "missing-import-frame.json"
            missing_import_frame_path.write_text(
                json.dumps(missing_import_frame), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                Exception,
                "same-library callthrough has no exact caller-memory frame",
            ):
                load_machine_import_profile_set([missing_import_frame_path])

        self.assertEqual(result["counts"]["methods"], 2)
        self.assertEqual(result["factories"][0]["argument_words"], 2)
        self.assertEqual(
            result["factories"][0]["machine_abi"],
            {
                "template": "pe32-stdcall-v1",
                "preserved_registers": ["ebp", "ebx", "edi", "esi"],
                "clobbered_registers": ["eax", "ecx", "edx"],
                "callee_cleanup": True,
            },
        )
        for contract in (
            result["factories"][0],
            *result["interfaces"][0]["methods"],
        ):
            self.assertEqual(
                contract["machine_abi"], result["factories"][0]["machine_abi"]
            )
            self.assertEqual(
                contract["effect_model"]["kind"],
                SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
            )
            self.assertEqual(
                contract["effect_model"]["target_relation"],
                "same-pinned-native-interface-target",
            )
            self.assertEqual(
                contract["effect_model"]["library_relation"],
                "same-runtime-native-library-binding",
            )
            self.assertEqual(
                contract["effect_model"]["invocation_relation"],
                "one-to-one",
            )
            self.assertEqual(
                contract["effect_model"]["pointed_to_footprints"],
                "not-inferred-from-c-types",
            )
            self.assertEqual(
                contract["memory_effect"], "sameNativeTargetCallThrough"
            )
            self.assertEqual(contract["memory_footprints"], [])
            self.assertEqual(
                contract["world_effect"], "sameNativeTargetCallThrough"
            )
            self.assertEqual(contract["callback_effect"], "none")
        self.assertEqual(
            result["machine_import_signatures"][0]["out_interface_relations"],
            [{
                "argument_index": 1,
                "interface_id": "IWidget",
                "write_width": 4,
                "object_size": 4,
                "vtable_size": 8,
                "nullable": True,
                "success_condition": "hresult_succeeded_eax",
            }],
        )
        self.assertEqual(
            result["interfaces"][0]["methods"][1]["out_interfaces"],
            [{
                "argument_index": 1,
                "interface_id": "IWidget",
                "write_width": 4,
            }],
        )
        self.assertEqual(
            result["factories"][0]["caller_memory_frame"]["arguments"],
            [
                {
                    "argument_index": 0,
                    "role": "caller_memory",
                    "access": "read_write",
                    "extent": "enclosing_object",
                    "retention": "during_call",
                },
                {
                    "argument_index": 1,
                    "role": "caller_memory",
                    "access": "read_write",
                    "extent": "fixed_word",
                    "retention": "during_call",
                },
            ],
        )
        self.assertEqual(
            result["interfaces"][0]["methods"][0][
                "caller_memory_frame"
            ]["arguments"],
            [
                {
                    "argument_index": 0,
                    "role": "interface_resource",
                    "access": "read_write",
                    "extent": "opaque_resource",
                    "retention": "during_call",
                },
                {
                    "argument_index": 1,
                    "role": "interface_resource",
                    "access": "read_write",
                    "extent": "opaque_resource",
                    "retention": "during_call",
                },
            ],
        )
        self.assertEqual(
            result["interfaces"][0]["methods"][1][
                "caller_memory_frame"
            ]["arguments"][1],
            {
                "argument_index": 1,
                "role": "caller_memory",
                "access": "read_write",
                "extent": "fixed_word",
                "retention": "during_call",
            },
        )
        self.assertEqual(
            machine_profile.contracts[0].contract["caller_memory_frame"],
            result["machine_import_signatures"][0]["caller_memory_frame"],
        )
        self.assertEqual(loaded.interfaces[0].methods[1].offset, 4)
        method_target = loaded.interfaces[0].methods[1].target_json(
            profile_id=loaded.profile_id,
            profile_sha256=loaded.sha256,
        )
        self.assertEqual(
            method_target["effect_model"]["kind"],
            SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        )
        self.assertEqual(method_target["memory_footprints"], [])

    def test_callback_method_requires_explicit_lifetime_protocol(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "example.h"
            header.write_text("reviewed header\n", encoding="ascii")
            spec = root / "spec.json"
            base_spec = {
                "format": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
                "id": "callback-fixture",
                "model": "x86-pe32",
                "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
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
                        "argument_index": 0,
                        "interface_id": "IWidget",
                    }],
                }],
            }
            spec.write_text(json.dumps(base_spec), encoding="utf-8")
            ast = root / "ast.json"
            ast.write_text(json.dumps({
                "kind": "TranslationUnitDecl",
                "inner": [
                    {
                        "kind": "TypedefDecl",
                        "name": "ENUMPROC",
                        "type": {
                            "qualType": (
                                "BOOL (*)(IWidget *, void *) "
                                "__attribute__((stdcall))"
                            )
                        },
                    },
                    {
                        "kind": "RecordDecl",
                        "name": "IWidgetVtbl",
                        "inner": [
                            {
                                "kind": "FieldDecl",
                                "name": "Release",
                                "type": {
                                    "qualType": (
                                        "ULONG (*)(IWidget *) "
                                        "__attribute__((stdcall))"
                                    )
                                },
                            },
                            {
                                "kind": "FieldDecl",
                                "name": "Enumerate",
                                "type": {
                                    "qualType": (
                                        "HRESULT (*)(IWidget *, void *, ENUMPROC) "
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
                                "HRESULT (IWidget **) __attribute__((stdcall))"
                            )
                        },
                    },
                ],
            }), encoding="utf-8")
            output = root / "profile.json"

            incomplete = extract_external_interface_profile(
                ast_json=ast,
                spec=spec,
                headers=[header],
                out=output,
            )
            method = incomplete["interfaces"][0]["methods"][1]
            self.assertEqual(method["callback_effect"], "explicit")
            self.assertEqual(method["callback_contract_status"], "incomplete")
            self.assertEqual(
                method["callback_source"],
                {"kind": "argument_word", "argument": 2},
            )
            self.assertEqual(method["callback_abi"]["argument_words"], 2)
            self.assertIn(
                "callback_lifetime_and_nullability_unspecified",
                method["callback_contract_blockers"],
            )
            loaded = load_external_interface_profile(output)
            self.assertEqual(
                loaded.interfaces[0].methods[1].effects.callback_status,
                "incomplete",
            )

            complete_spec = dict(base_spec)
            complete_spec["method_callbacks"] = [{
                "interface_id": "IWidget",
                "method": "Enumerate",
                "argument_index": 2,
                "lifetime": "during_call",
                "nullable": False,
            }]
            spec.write_text(json.dumps(complete_spec), encoding="utf-8")
            complete = extract_external_interface_profile(
                ast_json=ast,
                spec=spec,
                headers=[header],
                out=output,
            )
            callback = complete["interfaces"][0]["methods"][1]
            self.assertEqual(callback["callback_contract_status"], "complete")
            self.assertEqual(callback["callback_lifetime"], "during_call")
            self.assertEqual(callback["callback_contract_blockers"], [])

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
                "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
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

    def test_missing_same_library_call_through_opt_in_fails_closed(self) -> None:
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
                "factories": [],
            }), encoding="utf-8")
            ast = root / "ast.json"
            ast.write_text("{}", encoding="ascii")

            with self.assertRaisesRegex(
                Exception, "does not opt into.*same-library call-through"
            ):
                extract_external_interface_profile(
                    ast_json=ast,
                    spec=spec,
                    headers=[header],
                    out=root / "out.json",
                )


if __name__ == "__main__":
    unittest.main()
