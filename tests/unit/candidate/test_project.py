from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tests.pe_fixtures import (
    pe32_export_image,
    pe32_import_image,
    pe32_image_with_writable_data,
    pe32_load_config_image,
    pe32_resource_image,
)

from spaghetti_extractor.pe32.formats import (
    PE32_LOAD_OBSERVATION_FORMAT,
    PE32_PROJECT_INTENT_FORMAT,
)
from spaghetti_extractor.native_realization.receipt_v2 import (
    NativeRealizationV2Error,
)
from spaghetti_extractor.pe32.module_interface import Pe32ModuleInterfaceV2
from spaghetti_extractor.semantic_link.module_v2 import LinkedSemanticModuleV2
from spaghetti_extractor.artifacts.artifact_set import canonical_sha256_v3
from spaghetti_extractor.candidate.project import (
    write_pe32_module_interface,
    write_pe32_observed_load_graph,
    write_pe32_project_completion,
    write_pe32_project_load_plan,
)
from spaghetti_extractor.candidate.project_load_plan import (
    _resolved_physical_frame_v3,
)
from spaghetti_extractor.roundtrip_fuzz.image_io import write_spx_load_image_contract
from spaghetti_extractor.errors import ToolkitInputError


def _empty_portable_dispatch_receipt(
    *, selection_sha256: str, payload_sha256: str, linker_map_sha256: str,
) -> dict[str, object]:
    core: dict[str, object] = {
        "format": "spaghetti-extractor-portable-dispatch-link-receipt-v1",
        "status": "complete",
        "activation_authorized": True,
        "bindings": {
            "implementation_selection_sha256": selection_sha256,
            "payload_sha256": payload_sha256,
            "linker_map_sha256": linker_map_sha256,
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
    return {**core, "receipt_sha256": canonical_sha256_v3(core)}


def _native_realization_payload(
    filename: str, candidate_sha256: str, *, pinned: bool = False,
) -> dict[str, object]:
    provider = "fixture.provider"
    symbol = "fixture:entry"
    core: dict[str, object] = {
        "format": "spaghetti-extractor-native-realization-v2",
        "status": "complete",
        "ready_for_observation": True,
        "bindings": {
            "linked_semantic_module_sha256": "1" * 64,
            "implementation_selection_sha256": "2" * 64,
            "qualified_platform_sha256": "3" * 64,
            "original_module_interface_sha256": "4" * 64,
        },
        "providers": [{
            "provider_id": provider,
            "provider_kind": "generated_behavioral_c",
            "qualification_sha256": "5" * 64,
            "artifact_sha256": "6" * 64,
            "semantic_slice_sha256": "7" * 64,
            "tool_sha256s": ["8" * 64],
            "definition_ids": ["definition:entry"],
            "obligation_ids": [],
        }],
        "definitions": [{
            "definition_id": "definition:entry",
            "symbol_id": symbol,
            "provider_id": provider,
            "provider_kind": "generated_behavioral_c",
            "qualification_sha256": "5" * 64,
            "native_symbol": "fixture_entry",
            "address": {"kind": "linked_rva", "rva": 4096},
            "implementation_rva": 4096,
            "bridge_class_id": None,
        }],
        "obligations": [],
        "native_objects": [{
            "object_sha256": "8" * 64,
            "role": "generated_behavioral_c",
            "provider_ids": [provider],
            "definition_ids": ["definition:entry"],
            "obligation_ids": [],
            "section_ids": [".text"],
        }],
        "bridges": [],
        "runtime": {
            "qualification_sha256": "9" * 64,
            "tls_layout_sha256": "a" * 64,
            "private_stack_size": 1048576,
            "support_import_ids": [],
            "required_symbols": [{
                "symbol": "fixture_entry", "rva": 4096, "role": "entry",
            }],
            "obligation_receipt_sha256s": [],
        },
        "link": {
            "payload_sha256": "b" * 64,
            "linker_map_sha256": "c" * 64,
            "relocation_inventory_sha256": "d" * 64,
            "section_table_sha256": "e" * 64,
            "entry_symbols": ["fixture_entry"],
        },
        "portable_dispatch_link_receipt": _empty_portable_dispatch_receipt(
            selection_sha256="2" * 64,
            payload_sha256="b" * 64,
            linker_map_sha256="c" * 64,
        ),
        "loader_surface": {
            "entry_rva": 4096,
            "exports_sha256": "f" * 64,
            "imports_sha256": "0" * 64,
            "tls_sha256": "1" * 64,
            "base_relocations_sha256": "2" * 64,
            "resources_sha256": None,
            "load_config_sha256": None,
        },
        "candidate": {
            "filename": filename,
            "sha256": candidate_sha256,
            "size": 4096,
            "module_interface_sha256": "3" * 64,
        },
        "pinned_code_layout_requirements": ([{
            "authority_id": "pinned:app",
            "original_module_sha256": "a" * 64,
            "candidate_module_sha256": candidate_sha256,
            "linker_layout_sha256": "b" * 64,
            "resolved_external_environment_sha256": "1" * 64,
            "required_image_base": 0x400000,
            "rva_bindings": [{
                "source_rva": 0x1010,
                "candidate_rva": 0x1010,
            }],
            "observed_fields": ["Eip"],
        }] if pinned else []),
        "blockers": [],
    }
    return {
        **core,
        "native_realization_sha256": canonical_sha256_v3(core),
    }


class MultiImageProjectTests(unittest.TestCase):
    def test_repeated_catalog_projection_of_one_frame_is_not_a_conflict(self) -> None:
        frame = {"id": "physical-call-frame-v3:fixture", "transport": {}}
        environment = {
            "canonical_boundaries": [{
                "artifacts": {"physical_call_frame_v3": {"payload": frame}},
            }],
            "machine_import_contracts": [{
                "boundary": {"physical_call_frame_v3": frame},
            }],
            "loader_service_contracts": [],
        }
        self.assertEqual(
            _resolved_physical_frame_v3(
                environment, "physical-call-frame-v3:fixture"
            ),
            frame,
        )

        conflicting = json.loads(json.dumps(environment))
        conflicting["machine_import_contracts"][0]["boundary"][
            "physical_call_frame_v3"
        ]["transport"] = {"subject": "another"}
        with self.assertRaisesRegex(ToolkitInputError, "conflicts"):
            _resolved_physical_frame_v3(
                conflicting, "physical-call-frame-v3:fixture"
            )

    def test_resource_tree_and_content_are_exact_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "resources.exe"
            content = b"checked-resource\0"
            image.write_bytes(pe32_resource_image(content))
            contract = root / "load-image.json"
            write_spx_load_image_contract(original_pe=image, out=contract)
            payload = write_pe32_module_interface(
                image_id="resources",
                original_pe=image,
                load_image_contract=contract,
                out=root / "interface",
            )
            parsed = Pe32ModuleInterfaceV2.parse(
                payload, expected_image_id="resources", require_complete=True,
            ).payload
            self.assertEqual(parsed["counts"]["resource_directories"], 3)
            self.assertEqual(parsed["counts"]["resource_entries"], 3)
            self.assertEqual(parsed["counts"]["resource_data_entries"], 1)
            self.assertEqual(parsed["counts"]["resource_bytes"], len(content))
            resources = parsed["resources"]
            self.assertEqual(
                resources["directories"][0]["entries"][0]["name"]["text"],
                "CUSTOM",
            )
            leaf = resources["data_entries"][0]
            self.assertEqual(bytes.fromhex(leaf["content_hex"]), content)
            self.assertEqual(
                leaf["locator"],
                {"kind": "image_section", "section_index": 1, "offset": 0x80},
            )

            malformed = json.loads(json.dumps(payload))
            malformed["resources"]["data_entries"][0]["content_hex"] = "00"
            malformed["interface_sha256"] = canonical_sha256_v3({
                key: value for key, value in malformed.items()
                if key != "interface_sha256"
            })
            with self.assertRaisesRegex(ToolkitInputError, "content extent"):
                Pe32ModuleInterfaceV2.parse(malformed)

    def test_base_relocation_inventory_is_exact_and_content_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "relocations.exe"
            image.write_bytes(pe32_image_with_writable_data(
                b"\xc3",
                relocation_offsets=[0],
                relocation_page_rva=0x2000,
                data=(0x401000).to_bytes(4, "little"),
            ))
            contract = root / "load-image.json"
            write_spx_load_image_contract(original_pe=image, out=contract)
            payload = write_pe32_module_interface(
                image_id="relocations",
                original_pe=image,
                load_image_contract=contract,
                out=root / "interface",
            )
            parsed = Pe32ModuleInterfaceV2.parse(
                payload, expected_image_id="relocations",
                require_complete=True,
            )
            self.assertEqual(parsed.payload["counts"]["relocation_blocks"], 1)
            self.assertEqual(parsed.payload["counts"]["relocation_slots"], 2)
            self.assertEqual(parsed.payload["counts"]["base_relocations"], 1)
            relocation = parsed.payload["base_relocations"][0][
                "relocations"
            ][0]
            self.assertEqual(
                (relocation["kind"], relocation["target_rva"],
                 relocation["preferred_value"]),
                ("highlow", 0x2000, 0x401000),
            )

            stale = json.loads(json.dumps(payload))
            stale["base_relocations"][0]["relocations"][0][
                "preferred_value"
            ] += 1
            with self.assertRaisesRegex(ToolkitInputError, "self hash"):
                Pe32ModuleInterfaceV2.parse(stale)

            malformed = json.loads(json.dumps(payload))
            malformed["base_relocations"][0]["relocations"][0][
                "slot_index"
            ] = 1
            malformed["interface_sha256"] = canonical_sha256_v3({
                key: value for key, value in malformed.items()
                if key != "interface_sha256"
            })
            with self.assertRaisesRegex(ToolkitInputError, "every block slot"):
                Pe32ModuleInterfaceV2.parse(malformed)

    def test_load_config_pointer_catalog_is_exact_and_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            image = root / "load-config.exe"
            image.write_bytes(pe32_load_config_image())
            contract = root / "load-image.json"
            write_spx_load_image_contract(original_pe=image, out=contract)
            interface_root = root / "interface"
            payload = write_pe32_module_interface(
                image_id="load-config",
                original_pe=image,
                load_image_contract=contract,
                out=interface_root,
            )
            parsed = Pe32ModuleInterfaceV2.parse(
                payload, expected_image_id="load-config",
                require_complete=True,
            )
            self.assertEqual(parsed.payload["load_config"]["structure_size"], 196)
            self.assertEqual(
                [
                    row["name"]
                    for row in parsed.payload["load_config"]["typed_tables"]
                ],
                [
                    "guard_address_taken_iat_entries",
                    "guard_long_jump_targets",
                    "guard_eh_continuation_targets",
                ],
            )

            malformed = json.loads(json.dumps(payload))
            malformed["load_config"]["pointer_fields"][2][
                "pointer_kind"
            ] = "va_code"
            malformed["interface_sha256"] = canonical_sha256_v3({
                key: value for key, value in malformed.items()
                if key != "interface_sha256"
            })
            with self.assertRaisesRegex(
                ToolkitInputError, "pointer field classification"
            ):
                Pe32ModuleInterfaceV2.parse(malformed)

    def test_duplicate_slots_resolve_to_one_target_export_without_collapsing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            importer = root / "app.exe"
            provider = root / "private.dll"
            importer.write_bytes(
                pe32_import_image(
                    b"\xc3", symbol="Ping", dll="private.dll", cell_count=2
                )
            )
            provider.write_bytes(
                pe32_export_image(b"\xc3", symbol="Ping", dll="private.dll")
            )
            app_contract = root / "app-load.json"
            dll_contract = root / "dll-load.json"
            write_spx_load_image_contract(original_pe=importer, out=app_contract)
            write_spx_load_image_contract(original_pe=provider, out=dll_contract)
            app_interface = root / "app-interface"
            dll_interface = root / "dll-interface"
            write_pe32_module_interface(
                image_id="app", original_pe=importer,
                load_image_contract=app_contract, out=app_interface,
            )
            write_pe32_module_interface(
                image_id="private", original_pe=provider,
                load_image_contract=dll_contract, out=dll_interface,
            )
            provider_payload = json.loads(
                (dll_interface / "module-interface.json").read_text(
                    encoding="utf-8"
                )
            )
            parsed_interface = Pe32ModuleInterfaceV2.parse(
                provider_payload,
                expected_image_id="private",
                require_complete=True,
            )
            self.assertEqual(parsed_interface.image_id, "private")
            malformed_interface = json.loads(json.dumps(provider_payload))
            malformed_interface["export_directory"]["slots"][0][
                "ordinal"
            ] += 1
            malformed_interface["interface_sha256"] = canonical_sha256_v3({
                key: value
                for key, value in malformed_interface.items()
                if key != "interface_sha256"
            })
            with self.assertRaisesRegex(ToolkitInputError, "not contiguous"):
                Pe32ModuleInterfaceV2.parse(malformed_interface)
            intent = root / "project-intent.json"
            intent.write_text(json.dumps({
                "format": PE32_PROJECT_INTENT_FORMAT,
                "project_id": "fixture",
                "root_image_id": "app",
                "images": [
                    {
                        "image_id": "app", "filename": "app.exe", "aliases": [],
                        "ownership": "target", "implementation": "behavioral_c",
                    },
                    {
                        "image_id": "private", "filename": "private.dll", "aliases": [],
                        "ownership": "target", "implementation": "behavioral_c",
                    },
                    {
                        "image_id": "msvcrt", "filename": "msvcrt.dll", "aliases": [],
                        "ownership": "runtime", "implementation": "native_host",
                    },
                ],
                "target_distribution_roots": ["bin"],
                "host_environment": {"id": "wine", "sha256": "1" * 64},
            }, sort_keys=True), encoding="utf-8")
            plan_root = root / "plan"
            app_payload = json.loads(
                (app_interface / "module-interface.json").read_text(
                    encoding="utf-8"
                )
            )
            physical_frame_id = "physical-frame-v3:fixture-ping"
            physical_frame = {
                "id": physical_frame_id,
                "transport": {
                    "format": "fixture-frame-v1",
                    "id": "fixture-transport",
                    "subject": {"kind": "call", "id": "Ping"},
                    "transfer_kind": "import",
                    "target": "i686-pc-windows-gnu",
                    "calling_convention": "cdecl",
                    "arguments": [],
                    "results": [],
                    "stack": {"cleanup": "caller", "cleanup_bytes": 0},
                },
            }
            import_uses = [{
                "effect_id": "import-use-effect-v2:" + row["slot_id"],
                "slot_id": row["slot_id"],
                "use_kind": "code",
                "importer_physical_frame_id": physical_frame_id,
                "importer_physical_frame": physical_frame,
            } for row in app_payload["imports"]]
            def semantic_member(interface_root: Path) -> SimpleNamespace:
                return SimpleNamespace(
                    module_interface_path=(
                        interface_root / "module-interface.json"
                    ),
                    resolved_external_environment=SimpleNamespace(
                        payload={
                            "status": "complete",
                            "target": {
                                "abi": "pe32-i686-mingw32",
                                "data_layout": "pe32-ilp32-v1",
                            },
                            "canonical_boundaries": [{
                                "artifacts": {
                                    "physical_call_frame_v3": {
                                        "payload": physical_frame,
                                    },
                                },
                            }],
                        },
                    ),
                    machine_object_authority=SimpleNamespace(
                        rules=(), data_export_anchors=(),
                    ),
                )

            def linked_payload(
                identity: str, effects: dict[str, object],
            ) -> dict[str, object]:
                return {
                    "linked_semantic_module_sha256": identity,
                    "bindings": {
                        "resolved_external_environment_sha256": "e" * 64,
                        "resolved_external_environment_content_sha256": (
                            "f" * 64
                        ),
                    },
                    "effects": effects,
                    "active_objects": [],
                }

            linked_by_path = {
                root / "app-linked-semantic-module.json":
                    LinkedSemanticModuleV2(
                        payload=linked_payload("a" * 64, {
                            "export_capabilities": [],
                            "import_uses": import_uses,
                        }),
                        semantic_object=semantic_member(app_interface),
                    ),
                root / "private-linked-semantic-module.json":
                    LinkedSemanticModuleV2(
                        payload=linked_payload("b" * 64, {
                            "export_capabilities": [{
                                "capability_id": "export-capability-v1:fixture",
                                "target_rva": provider_payload[
                                    "export_directory"
                                ]["slots"][0]["rva"],
                                "physical_frame_id": physical_frame_id,
                                "physical_frame": physical_frame,
                                "exports": [{"name": "Ping", "ordinal": 1}],
                            }],
                            "import_uses": [],
                        }),
                        semantic_object=semantic_member(dll_interface),
                    ),
            }
            with patch.object(
                LinkedSemanticModuleV2,
                "load",
                side_effect=lambda path: linked_by_path[Path(path)],
            ):
                plan = write_pe32_project_load_plan(
                    intent=intent,
                    linked_semantic_modules={
                        "app": root / "app-linked-semantic-module.json",
                        "private": root
                        / "private-linked-semantic-module.json",
                    },
                    out=plan_root,
                )

            self.assertEqual(plan["status"], "complete")
            self.assertEqual(plan["counts"]["images"], 3)
            self.assertIsNone(
                next(row for row in plan["images"] if row["image_id"] == "msvcrt")
                ["interface_sha256"]
            )
            self.assertEqual(len(plan["edges"]), 2)
            self.assertEqual(len({row["slot_id"] for row in plan["edges"]}), 2)
            self.assertEqual(
                {row["resolution"]["provider_image_id"] for row in plan["edges"]},
                {"private"},
            )

            realizations: dict[str, Path] = {}
            candidate_hashes = {"app": "4" * 64, "private": "5" * 64}
            for image_id in ("app", "private"):
                path = root / f"{image_id}-native-realization.json"
                path.write_text(json.dumps(_native_realization_payload(
                    "app.exe" if image_id == "app" else "private.dll",
                    candidate_hashes[image_id],
                    pinned=image_id == "app",
                )), encoding="utf-8")
                realizations[image_id] = path
            observation = root / "observation.json"
            observation.write_text(json.dumps({
                "format": PE32_LOAD_OBSERVATION_FORMAT,
                "project_id": "fixture",
                "environment_sha256": "1" * 64,
                "runner_sha256": "2" * 64,
                "trace_sha256": "3" * 64,
                "process_exit_code": 0,
                "modules": [
                    {
                        "loader_name": "app.exe",
                        "resolved_path": "C:/fixture/app.exe",
                        "sha256": "4" * 64,
                        "origin": "target_distribution",
                        "image_id": "app",
                        "loaded_base": 0x400000,
                    },
                    {
                        "loader_name": "private.dll",
                        "resolved_path": "C:/fixture/private.dll",
                        "sha256": "5" * 64,
                        "origin": "target_distribution",
                        "image_id": "private",
                        "loaded_base": 0x500000,
                    },
                ],
                "slots": [
                    {
                        "slot_id": edge["slot_id"],
                        "resolution": {
                            "kind": "target_image",
                            "provider_image_id": "private",
                        },
                    }
                    for edge in plan["edges"]
                ],
            }), encoding="utf-8")
            observed_root = root / "observed"
            observed = write_pe32_observed_load_graph(
                load_plan=plan_root / "project-load-plan.json",
                observation=observation,
                out=observed_root,
            )
            self.assertEqual(observed["status"], "qualified")
            completion = write_pe32_project_completion(
                load_plan=plan_root / "project-load-plan.json",
                native_realizations=realizations,
                observed_load_graph=observed_root / "observed-load-graph.json",
                out=root / "completion",
            )
            self.assertEqual(completion["status"], "complete")
            self.assertEqual(completion["blockers"], [])

            wrong_observation = root / "wrong-base-observation.json"
            wrong_payload = json.loads(observation.read_text(encoding="utf-8"))
            wrong_payload["modules"][0]["loaded_base"] = 0x600000
            wrong_observation.write_text(
                json.dumps(wrong_payload), encoding="utf-8"
            )
            wrong_root = root / "wrong-observed"
            write_pe32_observed_load_graph(
                load_plan=plan_root / "project-load-plan.json",
                observation=wrong_observation,
                out=wrong_root,
            )
            wrong_completion = write_pe32_project_completion(
                load_plan=plan_root / "project-load-plan.json",
                native_realizations=realizations,
                observed_load_graph=wrong_root / "observed-load-graph.json",
                out=root / "wrong-completion",
            )
            self.assertEqual(wrong_completion["status"], "incomplete")
            self.assertIn(
                "observed_pinned_layout_base_mismatch",
                {row["category"] for row in wrong_completion["blockers"]},
            )
            malformed_path = root / "malformed-native-realization.json"
            malformed_path.write_text(json.dumps({
                "format": "spaghetti-extractor-native-realization-v2",
                "status": "complete",
            }), encoding="utf-8")
            with self.assertRaises(NativeRealizationV2Error):
                write_pe32_project_completion(
                    load_plan=plan_root / "project-load-plan.json",
                    native_realizations={
                        **realizations,
                        "app": malformed_path,
                    },
                    observed_load_graph=(
                        observed_root / "observed-load-graph.json"
                    ),
                    out=root / "malformed-completion",
                )

            next(
                row for row in plan["images"] if row["image_id"] == "private"
            )["implementation"] = "native_host"
            plan["plan_sha256"] = canonical_sha256_v3({
                key: value for key, value in plan.items() if key != "plan_sha256"
            })
            native_plan = root / "native-project-plan.json"
            native_plan.write_text(json.dumps(plan), encoding="utf-8")
            incomplete = write_pe32_project_completion(
                load_plan=native_plan,
                native_realizations=realizations,
                observed_load_graph=observed_root / "observed-load-graph.json",
                out=root / "incomplete",
            )
            self.assertEqual(incomplete["status"], "incomplete")
            self.assertIn(
                "target_image_not_lifted",
                {row["category"] for row in incomplete["blockers"]},
            )


if __name__ == "__main__":
    unittest.main()
