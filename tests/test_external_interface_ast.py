from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.external.interface_ast import (
    EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
    extract_external_interface_profile,
)
from spaghetti_extractor.external.interface_profiles import (
    ExternalInterfaceProfileError,
    InterfaceLocalCellRelation,
    InterfaceLocalCellVariant,
    SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
    load_external_interface_profile,
    parse_interface_local_cell_relation,
    select_interface_local_cell_variant,
)
from spaghetti_extractor.external.machine_import_profiles import (
    load_machine_import_profile_set,
)
from spaghetti_extractor.external.machine_callback_boundary import (
    interface_callback_boundary_catalog_v1,
)
from spaghetti_extractor.errors import ToolkitInputError
from spaghetti_extractor.util import sha256_file


class ExternalInterfaceAstTests(unittest.TestCase):
    def test_local_cell_variants_are_disjoint_and_selected_exactly(self) -> None:
        def variant(identity: str, *, value: int) -> dict[str, object]:
            return {
                "id": identity,
                "discriminants": [
                    {"word_index": 0, "mask": 0xFFFFFFFF, "value": value}
                ],
                "input_word_indices": [0],
                "output_word_indices": [1],
                "output_condition": "hresult_succeeded_eax",
                "failure_preserved_word_indices": [],
                "failure_observed_word_indices": [1],
            }

        relation = parse_interface_local_cell_relation(
            {
                "argument_index": 1,
                "extent_words": 2,
                "variants": [variant("one", value=1), variant("two", value=2)],
            }
        )
        self.assertEqual(
            select_interface_local_cell_variant(relation, {0: 2}).identity,
            "two",
        )
        for initial_words in ({}, {0: 3}):
            with self.assertRaisesRegex(
                ExternalInterfaceProfileError,
                "does not select exactly one footprint variant",
            ):
                select_interface_local_cell_variant(relation, initial_words)

        overlapping = {
            "argument_index": 1,
            "extent_words": 2,
            "variants": [
                variant("broad", value=1),
                {
                    **variant("narrow", value=1),
                    "discriminants": [{"word_index": 0, "mask": 0xFF, "value": 1}],
                },
            ],
        }
        with self.assertRaisesRegex(ExternalInterfaceProfileError, "variants overlap"):
            parse_interface_local_cell_relation(overlapping)

        failure_on_always = variant("always", value=1)
        failure_on_always["output_condition"] = "always"
        with self.assertRaisesRegex(ExternalInterfaceProfileError, "is inconsistent"):
            parse_interface_local_cell_relation(
                {
                    "argument_index": 1,
                    "extent_words": 2,
                    "variants": [failure_on_always],
                }
            )

        duplicate = relation.variants[0]
        malformed_relation = InterfaceLocalCellRelation(
            argument_index=1,
            extent_words=2,
            variants=(
                duplicate,
                InterfaceLocalCellVariant(
                    identity="duplicate",
                    discriminants=duplicate.discriminants,
                    input_word_indices=duplicate.input_word_indices,
                    output_word_indices=duplicate.output_word_indices,
                    output_condition=duplicate.output_condition,
                    failure_preserved_word_indices=(1,),
                    failure_observed_word_indices=(),
                ),
            ),
        )
        with self.assertRaisesRegex(
            ExternalInterfaceProfileError,
            "does not select exactly one footprint variant",
        ):
            select_interface_local_cell_variant(malformed_relation, {0: 1})

    def test_extracts_vtable_slots_factory_arity_and_outputs(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "example.h"
            header.write_text("reviewed header\n", encoding="ascii")
            spec = root / "spec.json"
            spec.write_text(
                json.dumps(
                    {
                        "format": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
                        "id": "fixture",
                        "model": "x86-pe32",
                        "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
                        "headers": [
                            {
                                "include": "example.h",
                                "sha256": sha256_file(header),
                            }
                        ],
                        "interface_prefixes": ["IWidget"],
                        "opaque_resource_types": ["HWND"],
                        "method_local_cells": [
                            {
                                "interface_id": "IWidget",
                                "method": "FillRecord",
                                "argument_index": 1,
                                "extent_words": 2,
                                "variants": [
                                    {
                                        "id": "default",
                                        "discriminants": [],
                                        "input_word_indices": [0],
                                        "output_word_indices": [1],
                                        "output_condition": "always",
                                        "failure_preserved_word_indices": [],
                                        "failure_observed_word_indices": [],
                                    }
                                ],
                            }
                        ],
                        "factories": [
                            {
                                "id": "example.dll!Create",
                                "import": {"dll": "example.dll", "symbol": "Create"},
                                "declaration": "Create",
                                "out_interfaces": [
                                    {
                                        "argument_index": 1,
                                        "interface_id": "IWidget",
                                    }
                                ],
                            }
                        ],
                    }
                ),
                encoding="utf-8",
            )
            ast = root / "ast.json"
            ast.write_text(
                json.dumps(
                    {
                        "kind": "TranslationUnitDecl",
                        "inner": [
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
                                    {
                                        "kind": "FieldDecl",
                                        "name": "FillRecord",
                                        "type": {
                                            "qualType": (
                                                "HRESULT (*)(IWidget *, DWORD *) "
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
                        ],
                    }
                ),
                encoding="utf-8",
            )
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
                ToolkitInputError,
                "opaque resource type is absent from the pinned AST",
            ):
                extract_external_interface_profile(
                    ast_json=ast,
                    spec=invalid_spec,
                    headers=[header],
                    out=root / "invalid-profile.json",
                )

            def reject_local_cell_spec(
                name: str,
                relation: dict[str, object],
                message: str,
            ) -> None:
                invalid_local_spec = root / f"{name}-spec.json"
                local_payload = json.loads(spec.read_text(encoding="utf-8"))
                local_payload["method_local_cells"] = [relation]
                invalid_local_spec.write_text(
                    json.dumps(local_payload), encoding="utf-8"
                )
                with self.assertRaisesRegex(ToolkitInputError, message):
                    extract_external_interface_profile(
                        ast_json=ast,
                        spec=invalid_local_spec,
                        headers=[header],
                        out=root / f"{name}-profile.json",
                    )

            valid_local_relation = invalid_payload["method_local_cells"][0]
            reject_local_cell_spec(
                "unused-local-cell",
                {**valid_local_relation, "method": "MissingMethod"},
                "local-cell specifications do not match pinned AST methods",
            )
            reject_local_cell_spec(
                "receiver-local-cell",
                {**valid_local_relation, "argument_index": 0},
                "local-cell relation contradicts its AST pointer",
            )
            reject_local_cell_spec(
                "unordered-local-cell",
                {
                    **valid_local_relation,
                    "extent_words": 3,
                    "variants": [
                        {
                            **valid_local_relation["variants"][0],
                            "input_word_indices": [1, 0],
                        }
                    ],
                },
                "inputs are invalid",
            )
            duplicate_local_spec = root / "duplicate-local-cell-spec.json"
            duplicate_payload = json.loads(spec.read_text(encoding="utf-8"))
            duplicate_payload["method_local_cells"] *= 2
            duplicate_local_spec.write_text(
                json.dumps(duplicate_payload), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ToolkitInputError,
                "method local-cell specifications are duplicated",
            ):
                extract_external_interface_profile(
                    ast_json=ast,
                    spec=duplicate_local_spec,
                    headers=[header],
                    out=root / "duplicate-local-cell-profile.json",
                )
            loaded = load_external_interface_profile(output)
            machine_profile = load_machine_import_profile_set([output])

            missing_frame = json.loads(output.read_text(encoding="utf-8"))
            del missing_frame["interfaces"][0]["methods"][0]["caller_memory_frame"]
            missing_frame_path = root / "missing-frame.json"
            missing_frame_path.write_text(json.dumps(missing_frame), encoding="utf-8")
            with self.assertRaisesRegex(
                ExternalInterfaceProfileError,
                "has no complete caller-memory frame",
            ):
                load_external_interface_profile(missing_frame_path)

            missing_import_frame = json.loads(output.read_text(encoding="utf-8"))
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

            malformed_local_profile = json.loads(output.read_text(encoding="utf-8"))
            malformed_local_profile["interfaces"][0]["methods"][2]["local_cells"][0][
                "variants"
            ][0]["output_word_indices"] = [2]
            malformed_local_profile_path = root / "malformed-local-profile.json"
            malformed_local_profile_path.write_text(
                json.dumps(malformed_local_profile), encoding="utf-8"
            )
            with self.assertRaisesRegex(
                ExternalInterfaceProfileError,
                "outputs are invalid",
            ):
                load_external_interface_profile(malformed_local_profile_path)

        self.assertEqual(result["counts"]["methods"], 3)
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
            self.assertEqual(contract["memory_effect"], "sameNativeTargetCallThrough")
            self.assertEqual(contract["memory_footprints"], [])
            self.assertEqual(contract["world_effect"], "sameNativeTargetCallThrough")
            self.assertEqual(contract["callback_effect"], "none")
        self.assertEqual(
            result["machine_import_signatures"][0]["out_interface_relations"],
            [
                {
                    "argument_index": 1,
                    "interface_id": "IWidget",
                    "write_width": 4,
                    "object_size": 4,
                    "vtable_size": 12,
                    "nullable": True,
                    "success_condition": "hresult_succeeded_eax",
                }
            ],
        )
        self.assertEqual(
            result["interfaces"][0]["methods"][1]["out_interfaces"],
            [
                {
                    "argument_index": 1,
                    "interface_id": "IWidget",
                    "write_width": 4,
                }
            ],
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
            result["interfaces"][0]["methods"][0]["caller_memory_frame"]["arguments"],
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
            result["interfaces"][0]["methods"][0]["argument_interfaces"],
            [{"argument_index": 0, "interface_id": "IWidget"}],
        )
        self.assertEqual(
            result["interfaces"][0]["methods"][1]["argument_interfaces"],
            [{"argument_index": 0, "interface_id": "IWidget"}],
        )
        self.assertEqual(
            result["interfaces"][0]["methods"][1]["caller_memory_frame"]["arguments"][
                1
            ],
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
        relation = {
            "argument_index": 1,
            "extent_words": 2,
            "variants": [
                {
                    "id": "default",
                    "discriminants": [],
                    "input_word_indices": [0],
                    "output_word_indices": [1],
                    "output_condition": "always",
                    "failure_preserved_word_indices": [],
                    "failure_observed_word_indices": [],
                }
            ],
        }
        self.assertEqual(
            result["interfaces"][0]["methods"][2]["local_cells"],
            [relation],
        )
        self.assertEqual(
            loaded.interfaces[0].methods[2].local_cells[0].as_json(), relation
        )
        self.assertEqual(loaded.interfaces[0].methods[1].offset, 4)
        self.assertEqual(
            loaded.interfaces[0].methods[0].arguments[0].as_json(),
            {"argument_index": 0, "interface_id": "IWidget"},
        )
        method_target = (
            loaded.interfaces[0]
            .methods[1]
            .target_json(
                profile_id=loaded.profile_id,
                profile_sha256=loaded.sha256,
            )
        )
        self.assertEqual(
            method_target["effect_model"]["kind"],
            SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
        )
        self.assertEqual(method_target["memory_footprints"], [])
        local_target = (
            loaded.interfaces[0]
            .methods[2]
            .target_json(
                profile_id=loaded.profile_id,
                profile_sha256=loaded.sha256,
            )
        )
        self.assertEqual(local_target["local_cells"], [relation])

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
                "headers": [
                    {
                        "include": "example.h",
                        "sha256": sha256_file(header),
                    }
                ],
                "interface_prefixes": ["IWidget"],
                "factories": [
                    {
                        "id": "example.dll!Create",
                        "import": {"dll": "example.dll", "symbol": "Create"},
                        "declaration": "Create",
                        "out_interfaces": [
                            {
                                "argument_index": 0,
                                "interface_id": "IWidget",
                            }
                        ],
                    }
                ],
            }
            spec.write_text(json.dumps(base_spec), encoding="utf-8")
            ast = root / "ast.json"
            ast.write_text(
                json.dumps(
                    {
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
                    }
                ),
                encoding="utf-8",
            )
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
            complete_spec["method_callbacks"] = [
                {
                    "interface_id": "IWidget",
                    "method": "Enumerate",
                    "argument_index": 2,
                    "lifetime": "during_call",
                    "nullable": False,
                    "argument_origins": [
                        {
                            "argument_index": 0,
                            "kind": "interface_object",
                            "interface_id": "IWidget",
                        }
                    ],
                }
            ]
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
            self.assertEqual(
                callback["callback_abi"]["result"],
                {
                    "kind": "word",
                    "register": "eax",
                },
            )
            self.assertEqual(
                callback["callback_arguments"],
                [
                    {
                        "argument_index": 0,
                        "kind": "interface_object",
                        "interface_id": "IWidget",
                    }
                ],
            )

            loaded_complete = load_external_interface_profile(output)
            method_target = (
                loaded_complete.interfaces[0]
                .methods[1]
                .target_json(
                    profile_id=loaded_complete.profile_id,
                    profile_sha256=loaded_complete.sha256,
                )
            )
            target_core = {
                "profile_id": loaded_complete.profile_id,
                "profile_sha256": loaded_complete.sha256,
                "interface_id": "IWidget",
                "method": method_target,
            }
            catalog = interface_callback_boundary_catalog_v1(
                {
                    **target_core,
                    "method_contract_sha256": canonical_sha256_v3(target_core),
                },
                abi_dialect="pe32-i386-gnu-v1",
            )
            self.assertIsNotNone(catalog)
            assert catalog is not None
            self.assertEqual(catalog["kind"], "checked_interface_callback")
            self.assertEqual(
                catalog["callback_protocol"]["signature"]["result"],
                {
                    "kind": "word",
                    "register": "eax",
                },
            )
            self.assertEqual(
                catalog["callback_arguments"],
                [
                    {
                        "argument_index": 0,
                        "kind": "interface_object",
                        "interface_id": "IWidget",
                    }
                ],
            )

            ast_payload = json.loads(ast.read_text(encoding="utf-8"))
            callback_type = ast_payload["inner"][0]["type"]["qualType"]
            ast_payload["inner"][0]["type"]["qualType"] = (
                "double (*)(IWidget *, void *) __attribute__((stdcall))"
            )
            ast.write_text(json.dumps(ast_payload), encoding="utf-8")
            unsupported = extract_external_interface_profile(
                ast_json=ast,
                spec=spec,
                headers=[header],
                out=root / "unsupported-profile.json",
            )
            unsupported_callback = unsupported["interfaces"][0]["methods"][1]
            self.assertEqual(
                unsupported_callback["callback_contract_status"], "incomplete"
            )
            self.assertIsNone(unsupported_callback["callback_abi"])
            self.assertIn(
                "callback_machine_abi_unsupported",
                unsupported_callback["callback_contract_blockers"],
            )
            ast_payload["inner"][0]["type"]["qualType"] = callback_type
            ast.write_text(json.dumps(ast_payload), encoding="utf-8")

            complete_spec["method_callbacks"][0]["argument_origins"][0][
                "interface_id"
            ] = "INotTheDeclaredType"
            spec.write_text(json.dumps(complete_spec), encoding="utf-8")
            with self.assertRaisesRegex(
                ToolkitInputError, "contradicts the pinned AST type"
            ):
                extract_external_interface_profile(
                    ast_json=ast,
                    spec=spec,
                    headers=[header],
                    out=output,
                )

    def test_header_digest_mismatch_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            header = root / "example.h"
            header.write_text("changed\n", encoding="ascii")
            spec = root / "spec.json"
            spec.write_text(
                json.dumps(
                    {
                        "format": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
                        "id": "fixture",
                        "model": "x86-pe32",
                        "effect_model": SAME_LIBRARY_CALL_THROUGH_EFFECT_MODEL,
                        "headers": [{"include": "example.h", "sha256": "0" * 64}],
                        "interface_prefixes": ["IWidget"],
                        "factories": [],
                    }
                ),
                encoding="utf-8",
            )
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
            spec.write_text(
                json.dumps(
                    {
                        "format": EXTERNAL_INTERFACE_EXTRACTION_SPEC_FORMAT,
                        "id": "fixture",
                        "model": "x86-pe32",
                        "headers": [
                            {
                                "include": "example.h",
                                "sha256": sha256_file(header),
                            }
                        ],
                        "interface_prefixes": ["IWidget"],
                        "factories": [],
                    }
                ),
                encoding="utf-8",
            )
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
